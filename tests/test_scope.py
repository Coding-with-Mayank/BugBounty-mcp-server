"""Tests for mcp_server.scope — authorization boundary enforcement.

This module is what makes ALLOWED_SCOPE / BLOCKED_TARGETS (which config.py
has always parsed, but which nothing used to check) actually mean something.
It's the one promise a bug-bounty tool can't get wrong, so it gets the
thickest test coverage in this suite.
"""
from __future__ import annotations

import pytest

from mcp_server.scope import OutOfScopeError, evaluate, resolve_and_check

BLOCKED = ["localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254", "10.0.0.0/8", "192.168.0.0/16"]


class TestOpenMode:
    def test_empty_scope_allows_any_host(self):
        d = evaluate("example.com", scope_list=[], blocked_list=BLOCKED)
        assert d.allowed is True

    def test_empty_scope_still_blocks_blocklist(self):
        d = evaluate("127.0.0.1", scope_list=[], blocked_list=BLOCKED)
        assert d.allowed is False


class TestBlockedTargets:
    @pytest.mark.parametrize("target", ["localhost", "127.0.0.1", "169.254.169.254"])
    def test_exact_blocked_matches(self, target):
        d = evaluate(target, scope_list=["*.example.com"], blocked_list=BLOCKED)
        assert d.allowed is False

    def test_private_cidr_blocked(self):
        d = evaluate("192.168.1.50", scope_list=[], blocked_list=BLOCKED)
        assert d.allowed is False

    def test_cloud_metadata_blocked_even_if_in_scope(self):
        # Blocklist always wins, even over an explicit scope entry.
        d = evaluate("169.254.169.254", scope_list=["169.254.169.254"], blocked_list=BLOCKED)
        assert d.allowed is False

    def test_ten_dot_cidr_blocks_any_member(self):
        d = evaluate("10.5.5.5", scope_list=[], blocked_list=BLOCKED)
        assert d.allowed is False


class TestAllowedScope:
    def test_exact_domain_match(self):
        d = evaluate("example.com", scope_list=["example.com"], blocked_list=BLOCKED)
        assert d.allowed is True

    def test_wildcard_matches_subdomain(self):
        d = evaluate("api.example.com", scope_list=["*.example.com"], blocked_list=BLOCKED)
        assert d.allowed is True

    def test_wildcard_matches_nested_subdomain(self):
        d = evaluate("a.b.example.com", scope_list=["*.example.com"], blocked_list=BLOCKED)
        assert d.allowed is True

    def test_wildcard_matches_bare_apex_too(self):
        d = evaluate("example.com", scope_list=["*.example.com"], blocked_list=BLOCKED)
        assert d.allowed is True

    def test_wildcard_does_not_match_unrelated_domain(self):
        # api.example.com.evil.com must NOT match *.example.com — this is the
        # classic subdomain-suffix bypass. The suffix check must anchor on
        # the dot, not do a bare substring match.
        d = evaluate("example.com.evil.com", scope_list=["*.example.com"], blocked_list=BLOCKED)
        assert d.allowed is False

    def test_lookalike_domain_not_matched_by_substring(self):
        # notexample.com must not match a scope entry for example.com.
        d = evaluate("notexample.com", scope_list=["example.com"], blocked_list=BLOCKED)
        assert d.allowed is False

    def test_out_of_scope_domain_rejected(self):
        d = evaluate("not-my-target.com", scope_list=["example.com"], blocked_list=BLOCKED)
        assert d.allowed is False

    def test_cidr_scope_allows_member_ip(self):
        d = evaluate("192.168.1.50", scope_list=["192.168.1.0/24"], blocked_list=[])
        assert d.allowed is True

    def test_cidr_scope_rejects_non_member_ip(self):
        d = evaluate("192.168.2.50", scope_list=["192.168.1.0/24"], blocked_list=[])
        assert d.allowed is False

    def test_bare_ip_exact_match(self):
        d = evaluate("203.0.113.5", scope_list=["203.0.113.5"], blocked_list=[])
        assert d.allowed is True

    def test_malformed_cidr_pattern_never_matches_or_crashes(self):
        d = evaluate("example.com", scope_list=["not-a-cidr/99"], blocked_list=[])
        assert d.allowed is False


class TestTargetParsing:
    def test_strips_scheme_and_path(self):
        d = evaluate(
            "https://api.example.com/v1/users?id=1",
            scope_list=["*.example.com"],
            blocked_list=BLOCKED,
        )
        assert d.allowed is True

    def test_strips_port(self):
        d = evaluate("example.com:8443", scope_list=["example.com"], blocked_list=BLOCKED)
        assert d.allowed is True

    def test_strips_userinfo(self):
        d = evaluate(
            "https://user:pass@example.com/path", scope_list=["example.com"], blocked_list=BLOCKED
        )
        assert d.allowed is True

    def test_ipv6_literal_in_brackets(self):
        d = evaluate("[::1]:8443", scope_list=[], blocked_list=["::1"])
        assert d.allowed is False

    def test_case_insensitive(self):
        d = evaluate("API.EXAMPLE.COM", scope_list=["*.example.com"], blocked_list=BLOCKED)
        assert d.allowed is True

    def test_trailing_dot_normalized(self):
        d = evaluate("example.com.", scope_list=["example.com"], blocked_list=BLOCKED)
        assert d.allowed is True

    def test_empty_target_denied(self):
        d = evaluate("", scope_list=[], blocked_list=BLOCKED)
        assert d.allowed is False

    def test_whitespace_only_target_denied(self):
        d = evaluate("   ", scope_list=[], blocked_list=BLOCKED)
        assert d.allowed is False


class TestOutOfScopeError:
    def test_error_carries_target_and_serializes(self):
        d = evaluate("evil.com", scope_list=["example.com"], blocked_list=BLOCKED)
        assert d.allowed is False
        err = OutOfScopeError("evil.com", d)
        payload = err.as_dict()
        assert payload["error"] == "target_out_of_scope"
        assert payload["target"] == "evil.com"
        assert "next_steps" in payload["guidance"]

    def test_error_message_matches_decision_reason(self):
        d = evaluate("evil.com", scope_list=["example.com"], blocked_list=BLOCKED)
        err = OutOfScopeError("evil.com", d)
        assert str(err) == d.reason


class TestFullRangeBlocklistCoverage:
    """
    config.py's shipped BLOCKED_TARGETS default used to block only
    127.0.0.1 (not the rest of the loopback range) and had no
    172.16.0.0/12 or IPv6 coverage at all. These test the *ranges*
    directly against scope.evaluate, independent of what config.py ships.
    """

    FULL = [
        "localhost", "127.0.0.0/8", "0.0.0.0", "169.254.0.0/16", "169.254.169.254",
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "::1", "fe80::/10", "fc00::/7",
    ]

    @pytest.mark.parametrize("ip", ["127.0.0.1", "127.0.0.2", "127.255.255.255"])
    def test_full_loopback_range_blocked(self, ip):
        assert evaluate(ip, scope_list=[], blocked_list=self.FULL).allowed is False

    def test_middle_rfc1918_range_blocked(self):
        # 172.16.0.0/12 sits between the 10/8 and 192.168/16 ranges and was
        # previously missing from the default entirely.
        assert evaluate("172.20.5.5", scope_list=[], blocked_list=self.FULL).allowed is False

    def test_link_local_range_blocked_not_just_metadata_ip(self):
        assert evaluate("169.254.1.1", scope_list=[], blocked_list=self.FULL).allowed is False

    def test_ipv6_loopback_blocked(self):
        assert evaluate("::1", scope_list=[], blocked_list=self.FULL).allowed is False

    def test_ipv6_link_local_blocked(self):
        assert evaluate("fe80::1", scope_list=[], blocked_list=self.FULL).allowed is False

    def test_ipv6_unique_local_blocked(self):
        assert evaluate("fd12:3456:789a::1", scope_list=[], blocked_list=self.FULL).allowed is False

    def test_shipped_config_default_has_full_coverage(self):
        """Regression test against the actual default in config.py, not a
        hand-copied list here — catches the two from drifting apart again."""
        from mcp_server.config import Settings

        blocked = Settings(allowed_scope="", blocked_targets=Settings.model_fields["blocked_targets"].default).blocked_list
        for ip in ["127.0.0.5", "172.20.1.1", "169.254.1.1", "::1", "fe80::1"]:
            assert evaluate(ip, scope_list=[], blocked_list=blocked).allowed is False, (
                f"{ip} should be blocked by config.py's actual shipped default"
            )


@pytest.mark.asyncio
class TestResolveAndCheck:
    """resolve_and_check() — the DNS-resolution-aware wrapper around evaluate().
    Uses an injected fake resolver throughout; never touches live DNS."""

    async def test_denies_when_resolved_ip_is_blocked(self):
        async def resolver(host, timeout):
            return ["169.254.169.254"]

        d = await resolve_and_check(
            "in-scope-but-rebinding.com",
            scope_list=["in-scope-but-rebinding.com"],
            blocked_list=["169.254.169.254"],
            resolver=resolver,
        )
        assert d.allowed is False
        assert "resolves to" in d.reason
        assert d.resolved_ips == ("169.254.169.254",)

    async def test_allows_when_resolved_ip_is_clean(self):
        async def resolver(host, timeout):
            return ["93.184.216.34"]

        d = await resolve_and_check(
            "example.com", scope_list=["example.com"], blocked_list=["169.254.169.254"],
            resolver=resolver,
        )
        assert d.allowed is True
        assert d.resolved_ips == ("93.184.216.34",)

    async def test_skips_resolution_for_bare_ip_target(self):
        async def must_not_be_called(host, timeout):
            raise AssertionError("resolver called for a bare IP - nothing to resolve")

        d = await resolve_and_check(
            "203.0.113.5", scope_list=["203.0.113.5"], blocked_list=[],
            resolver=must_not_be_called,
        )
        assert d.allowed is True

    async def test_skips_resolution_when_already_out_of_scope(self):
        async def must_not_be_called(host, timeout):
            raise AssertionError("resolver called for an already-denied hostname")

        d = await resolve_and_check(
            "evil.com", scope_list=["example.com"], blocked_list=[],
            resolver=must_not_be_called,
        )
        assert d.allowed is False

    async def test_resolution_failure_does_not_deny(self):
        async def failing_resolver(host, timeout):
            raise OSError("simulated DNS failure")

        d = await resolve_and_check(
            "example.com", scope_list=["example.com"], blocked_list=[],
            resolver=failing_resolver,
        )
        assert d.allowed is True
        assert d.resolution_warning is not None

    async def test_resolution_timeout_does_not_deny(self):
        async def hanging_resolver(host, timeout):
            raise TimeoutError("simulated timeout")

        d = await resolve_and_check(
            "example.com", scope_list=["example.com"], blocked_list=[],
            resolver=hanging_resolver,
        )
        assert d.allowed is True
        assert d.resolution_warning is not None

    async def test_multiple_resolved_ips_any_blocked_denies(self):
        async def multi_ip_resolver(host, timeout):
            return ["93.184.216.34", "169.254.169.254"]

        d = await resolve_and_check(
            "example.com", scope_list=["example.com"], blocked_list=["169.254.169.254"],
            resolver=multi_ip_resolver,
        )
        assert d.allowed is False


@pytest.mark.asyncio
class TestStrictScope:
    """strict=True flips resolution-failure handling from fail-open (default)
    to fail-closed, for environments that would rather a scan not run at all
    than run without IP-level verification."""

    async def test_strict_denies_on_resolution_failure(self):
        async def failing_resolver(host, timeout):
            raise OSError("simulated DNS failure")

        d = await resolve_and_check(
            "example.com", scope_list=["example.com"], blocked_list=[],
            resolver=failing_resolver, strict=True,
        )
        assert d.allowed is False
        assert d.resolution_warning is not None

    async def test_strict_denies_on_timeout(self):
        async def hanging_resolver(host, timeout):
            raise TimeoutError("simulated timeout")

        d = await resolve_and_check(
            "example.com", scope_list=["example.com"], blocked_list=[],
            resolver=hanging_resolver, strict=True,
        )
        assert d.allowed is False

    async def test_strict_still_allows_on_successful_clean_resolution(self):
        async def resolver(host, timeout):
            return ["93.184.216.34"]

        d = await resolve_and_check(
            "example.com", scope_list=["example.com"], blocked_list=["169.254.169.254"],
            resolver=resolver, strict=True,
        )
        assert d.allowed is True

    async def test_strict_still_denies_on_blocked_resolved_ip(self):
        async def resolver(host, timeout):
            return ["169.254.169.254"]

        d = await resolve_and_check(
            "example.com", scope_list=["example.com"], blocked_list=["169.254.169.254"],
            resolver=resolver, strict=True,
        )
        assert d.allowed is False

    async def test_non_strict_is_the_default(self):
        async def failing_resolver(host, timeout):
            raise OSError("simulated DNS failure")

        # No strict= passed at all - must match the documented default (False).
        d = await resolve_and_check(
            "example.com", scope_list=["example.com"], blocked_list=[],
            resolver=failing_resolver,
        )
        assert d.allowed is True
