"""
scope — Authorization boundary enforcement.

The README and .env.example both promise: "The server will reject any
target not in scope." config.py has always parsed ALLOWED_SCOPE and
BLOCKED_TARGETS into `scope_list` / `blocked_list` — but until this
module existed, nothing in server.py ever read those properties. Every
active-scanning tool would happily fire at any target it was given.
That's the one promise a bug-bounty tool can't break.

This module is the single source of truth for "is it OK to send traffic
at this target right now". server.py is expected to call it from every
handler that touches a target over the network — as opposed to passive
third-party lookups (whois, crt.sh, Shodan, Wayback/gau) that never
contact the target itself and are intentionally exempt.

Supports:
  - Exact match:        example.com
  - Subdomain wildcard:  *.example.com  (matches api.example.com, a.b.example.com,
                                          and the bare apex example.com)
  - IPv4/IPv6 CIDR:      192.168.1.0/24
  - Bare IP:             10.0.0.5

`evaluate()` is a pure, synchronous, hostname/IP-string check — no network
access, safe to call anywhere, fully unit-testable. It has one gap: a
hostname that matches ALLOWED_SCOPE can still *resolve* to something on
BLOCKED_TARGETS (a misconfigured or since-changed DNS record, or an
attacker-controlled DNS-rebinding setup where the name resolves to
169.254.169.254 or a private range at scan time). `resolve_and_check()`
wraps `evaluate()` with that resolution step for callers that can await —
every server.py handler that actually sends a network request should use
it instead of the plain `evaluate()`.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    # Populated only by resolve_and_check() — empty for the plain evaluate() path.
    resolved_ips: tuple[str, ...] = field(default=())
    resolution_warning: str | None = None


def _host_from_target(target: str) -> str:
    """Strip scheme/path/port/userinfo from a URL-or-host string down to a bare host."""
    t = target.strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    t = t.split("@")[-1]  # strip userinfo (user:pass@host)
    if t.startswith("[") and "]" in t:  # IPv6 literal in brackets, e.g. [::1]:8443
        return t[1 : t.index("]")]
    t = t.rsplit(":", 1)[0] if t.count(":") == 1 else t  # strip :port (not IPv6)
    return t.strip(".").lower()


def _is_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _matches_pattern(host: str, pattern: str) -> bool:
    pattern = pattern.strip().lower()
    if not pattern:
        return False

    # CIDR range, e.g. 10.0.0.0/8
    if "/" in pattern:
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            ip = _is_ip(host)
            return ip is not None and ip in network
        except ValueError:
            return False

    # Wildcard subdomain, e.g. *.example.com — also matches the bare apex.
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) or host == pattern[2:]

    # Exact host or exact IP match
    return host == pattern


def _matches_any(host: str, patterns: list[str]) -> str | None:
    """Return the first pattern that matches `host`, or None."""
    for pattern in patterns:
        if _matches_pattern(host, pattern):
            return pattern
    return None


def evaluate(target: str, *, scope_list: list[str], blocked_list: list[str]) -> ScopeDecision:
    """
    Decide whether `target` (a domain, host, IP, CIDR member, or full URL)
    is allowed to be scanned.

    Rules (checked in order):
      1. No target given                        -> denied
      2. Matches BLOCKED_TARGETS                 -> always denied, no exceptions
      3. ALLOWED_SCOPE is empty                  -> allowed (open mode; user's responsibility)
      4. ALLOWED_SCOPE is set and target matches -> allowed
      5. ALLOWED_SCOPE is set and no match        -> denied
    """
    host = _host_from_target(target)
    if not host:
        return ScopeDecision(False, "No target provided.")

    blocked_hit = _matches_any(host, blocked_list)
    if blocked_hit:
        return ScopeDecision(
            False,
            f"'{host}' matches a permanently blocked target/range ('{blocked_hit}'). "
            "This is a hard-coded safety rail (localhost, cloud metadata IP, private "
            "ranges) and cannot be overridden by ALLOWED_SCOPE.",
        )

    if not scope_list:
        return ScopeDecision(
            True,
            "ALLOWED_SCOPE is empty — running in open mode. "
            "Set ALLOWED_SCOPE in .env to restrict scans to authorized targets.",
        )

    scope_hit = _matches_any(host, scope_list)
    if scope_hit:
        return ScopeDecision(True, f"'{host}' matches allowed scope entry '{scope_hit}'.")

    return ScopeDecision(
        False,
        f"'{host}' is not in ALLOWED_SCOPE ({', '.join(scope_list)}). "
        "Add it to .env if you have authorization to test it.",
    )


async def default_resolve(host: str, timeout: float) -> list[str]:
    """Resolve `host` to its A/AAAA addresses. Raises on failure or timeout."""
    loop = asyncio.get_running_loop()
    infos = await asyncio.wait_for(
        loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP),
        timeout=timeout,
    )
    return sorted({str(info[4][0]) for info in infos})


Resolver = Callable[[str, float], Awaitable[list[str]]]


async def resolve_and_check(
    target: str,
    *,
    scope_list: list[str],
    blocked_list: list[str],
    resolver: Resolver = default_resolve,
    timeout: float = 5.0,
    strict: bool = False,
) -> ScopeDecision:
    """
    Same decision as evaluate(), plus a check of what the hostname actually
    resolves to right now. Closes the gap where a name matches ALLOWED_SCOPE
    but its current DNS record points at something on BLOCKED_TARGETS —
    classic DNS-rebinding territory (an in-scope subdomain repointed at
    169.254.169.254 or a private range between the scope check and the
    request, or just a stale/misconfigured record).

    Only ever narrows the decision (allowed -> denied), never widens it —
    a resolved IP is checked against BLOCKED_TARGETS only, not used to grant
    scope the hostname didn't already have.

    If resolution fails or times out: with strict=False (default), this does
    NOT deny the request — a flaky resolver shouldn't block an otherwise-
    authorized scan — and returns the hostname-level decision with
    `resolution_warning` set, so callers can surface that the IP-level check
    was inconclusive. With strict=True, a resolution failure denies the
    request instead: for environments that would rather fail closed than
    scan without IP-level verification.
    """
    decision = evaluate(target, scope_list=scope_list, blocked_list=blocked_list)
    if not decision.allowed:
        return decision  # already denied on the hostname alone; no need to resolve

    host = _host_from_target(target)
    if _is_ip(host) is not None:
        return decision  # bare IP target — nothing to resolve, nothing to rebind

    try:
        resolved = await resolver(host, timeout)
    except Exception as exc:
        warning = (
            f"Could not resolve '{host}' to verify its current IP against "
            f"BLOCKED_TARGETS ({exc})."
        )
        if strict:
            return ScopeDecision(
                False,
                f"{warning} STRICT_SCOPE is enabled, which denies targets that "
                "can't be resolved and verified rather than proceeding on the "
                "hostname match alone.",
                resolution_warning=warning,
            )
        return ScopeDecision(
            allowed=decision.allowed,
            reason=decision.reason,
            resolution_warning=f"{warning} Proceeding on the hostname match alone.",
        )

    for ip in resolved:
        blocked_hit = _matches_any(ip, blocked_list)
        if blocked_hit:
            return ScopeDecision(
                False,
                f"'{host}' currently resolves to '{ip}', which matches a "
                f"permanently blocked range ('{blocked_hit}'). Rejected even "
                "though the hostname itself is in scope, to prevent DNS "
                "rebinding / a stale record pointing at a forbidden address.",
                resolved_ips=tuple(resolved),
            )

    return ScopeDecision(decision.allowed, decision.reason, resolved_ips=tuple(resolved))


class OutOfScopeError(Exception):
    """Raised by server.py handlers when a target fails the scope check."""

    def __init__(self, target: str, decision: ScopeDecision):
        self.target = target
        self.decision = decision
        super().__init__(decision.reason)

    def as_dict(self) -> dict:
        return {
            "error": "target_out_of_scope",
            "target": self.target,
            "reason": self.decision.reason,
            "guidance": {
                "next_steps": [
                    "Use the check_scope tool to test a target before scanning it.",
                    "Add the target to ALLOWED_SCOPE in .env if you're authorized to test it, "
                    "then restart the container.",
                    "Never scan targets you don't have explicit written permission to test.",
                ]
            },
        }
