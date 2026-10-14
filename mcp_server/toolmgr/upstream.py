"""
upstream.py — "what is the newest release I'm allowed to install?"

Official sources only, in the manifest-independent order below:

  1. Go module proxy (proxy.golang.org)  — the very service `go install` pulls
     from, so a version found here is, by construction, installable.
  2. GitHub Releases API (api.github.com) — fallback, and the source for
     nuclei-templates (not a Go module). Honours GITHUB_TOKEN / GH_TOKEN, sent
     ONLY to api.github.com, to lift the anonymous rate limit.

No HTML scraping. HTTPS only, host allowlist (enforced again on every
redirect), bounded response size, short timeouts, and a circuit breaker so an
offline machine fails fast instead of stalling on every tool in turn.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import versions
from .manifest import ToolSpec
from .security import atomic_write_json, read_json
from .versions import Version

ALLOWED_HOSTS = frozenset({"proxy.golang.org", "api.github.com"})
MAX_RESPONSE = 2 * 1024 * 1024
USER_AGENT = "bugbounty-mcp-toolmgr"
_ERROR_TTL = 600          # remember a failed lookup this long (seconds)
_BREAKER_LIMIT = 3


class UpstreamError(Exception):
    """A lookup failed (network, rate limit, bad payload). Never fatal: callers keep what works."""


class Offline(UpstreamError):
    """Offline mode, or the circuit breaker tripped."""


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        u = urllib.parse.urlsplit(newurl)
        if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS:
            raise UpstreamError(f"refusing redirect to {u.scheme}://{u.hostname}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Http:
    """Tiny GET-only client. Tests substitute anything with a .get(url) -> bytes."""

    def __init__(self, timeout: float = 8, offline: bool = False):
        self.timeout, self.offline, self._failures = timeout, offline, 0
        self._opener = urllib.request.build_opener(_SafeRedirect)

    def get(self, url: str) -> bytes:
        u = urllib.parse.urlsplit(url)
        if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS:
            raise UpstreamError(f"refusing to fetch {url!r}: not an allowed https host")
        if self.offline:
            raise Offline("offline mode")
        if self._failures >= _BREAKER_LIMIT:
            raise Offline("network looks unavailable (several lookups in a row failed)")
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json, text/plain"}
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if token and u.hostname == "api.github.com":
            headers["Authorization"] = f"Bearer {token}"
        try:
            with self._opener.open(urllib.request.Request(url, headers=headers), timeout=self.timeout) as r:
                data = r.read(MAX_RESPONSE + 1)
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 410):          # "no such module/major" is an answer, not an outage
                raise UpstreamError(f"HTTP {exc.code}") from exc
            self._failures += 1
            hint = ""
            if exc.code in (403, 429) and u.hostname == "api.github.com":
                hint = " (GitHub rate limit — set GITHUB_TOKEN)"
            elif exc.code in (403, 407):
                hint = f" (is {u.hostname} reachable from this network/proxy?)"
            raise UpstreamError(f"HTTP {exc.code}{hint}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            self._failures += 1
            raise UpstreamError(f"network error: {getattr(exc, 'reason', exc)}") from exc
        if len(data) > MAX_RESPONSE:
            raise UpstreamError("response too large")
        self._failures = 0
        return data


def escape_module_path(path: str) -> str:
    """Go proxy case-encoding: every upper-case letter becomes !lower (OJ -> !o!j)."""
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), path)


def _json(http: Any, url: str) -> Any:
    try:
        return json.loads(http.get(url))
    except (ValueError, RecursionError) as exc:      # RecursionError: a deeply nested JSON bomb
        raise UpstreamError(f"bad JSON from {urllib.parse.urlsplit(url).hostname}") from exc


def goproxy_versions(http: Any, module: str) -> list[Version]:
    url = f"https://proxy.golang.org/{escape_module_path(module)}/@v/list"
    out = []
    for line in http.get(url).decode("utf-8", "replace").splitlines():
        v = versions.parse(line.strip())
        if v:
            out.append(v)
    return out


def goproxy_exists(http: Any, module: str) -> bool:
    """Does this module path (e.g. a hypothetical .../v4) exist at all?"""
    try:
        http.get(f"https://proxy.golang.org/{escape_module_path(module)}/@v/list")
        return True
    except Offline:
        raise
    except UpstreamError as exc:
        if "HTTP 404" in str(exc) or "HTTP 410" in str(exc):
            return False
        raise


def github_versions(http: Any, repo: str) -> list[Version]:
    data = _json(http, f"https://api.github.com/repos/{repo}/releases?per_page=100")
    if not isinstance(data, list):
        raise UpstreamError("unexpected GitHub payload")
    out = []
    for rel in data:
        if isinstance(rel, dict) and not rel.get("draft") and not rel.get("prerelease"):
            v = versions.parse(str(rel.get("tag_name", "")))
            if v:
                out.append(v)
    return out


@dataclass
class Latest:
    version: Version | None          # newest stable inside the tested range
    newer_major: Version | None      # newest stable of a HIGHER major, if one exists
    above_ceiling: Version | None    # newer than manifest max_version (same major)
    source: str
    error: str | None = None


def _pick(vs: list[Version], spec: ToolSpec) -> tuple[Version | None, Version | None]:
    stable = [v for v in vs if v.is_stable and v.major == spec.tested_major and v >= spec.min_version]
    inside = [v for v in stable if not (spec.max_version and v > spec.max_version)]
    above = [v for v in stable if spec.max_version and v > spec.max_version]
    return (max(inside) if inside else None, max(above) if above else None)


def latest_for(spec: ToolSpec, http: Any, probe_majors: int = 2) -> Latest:
    """Newest release inside the tested envelope, plus a heads-up about newer majors."""
    errors: list[str] = []
    for source in ("goproxy", "github"):
        try:
            vs = (goproxy_versions(http, spec.module_path()) if source == "goproxy"
                  else github_versions(http, spec.repo))
        except Offline:
            raise
        except UpstreamError as exc:
            errors.append(f"{source}: {exc}")
            continue
        best, above = _pick(vs, spec)
        if best is None:
            errors.append(f"{source}: no stable release in v{spec.tested_major}.x")
            continue
        newer = None
        try:
            newer = _newer_major(spec, http, vs if source == "github" else None, probe_majors)
        except Offline:
            raise
        except UpstreamError:
            pass
        return Latest(best, newer, above, source)
    return Latest(None, None, None, "none", "; ".join(errors))


def _newer_major(spec: ToolSpec, http: Any, github_vs: list[Version] | None, probe: int) -> Version | None:
    if github_vs is not None:
        higher = [v for v in github_vs if v.is_stable and v.major > spec.tested_major]
        return max(higher) if higher else None
    if not spec.major_in_path and spec.tested_major >= 2:
        return None                    # no /vN paths to probe for this module
    found = None
    for m in range(spec.tested_major + 1, spec.tested_major + 1 + probe):
        if m == 1:                     # v0 -> v1 share one module path
            vs = [v for v in goproxy_versions(http, spec.module_path(0)) if v.major == 1 and v.is_stable]
            if vs:
                found = max(vs)
            continue
        mod = f"{spec.module}/v{m}" if m >= 2 else spec.module
        if not goproxy_exists(http, mod):
            break
        vs = [v for v in goproxy_versions(http, mod) if v.is_stable and v.major == m]
        if vs:
            found = max(vs)
    return found


def latest_release_tag(http: Any, repo: str) -> Version | None:
    """Newest stable GitHub release (used for nuclei-templates)."""
    vs = github_versions(http, repo)
    return max(vs) if vs else None


class Cache:
    """Throttle: a result younger than `ttl` seconds is reused instead of re-fetched."""

    def __init__(self, path: Path | None, ttl_hours: float = 24, now: Callable[[], float] = time.time):
        self.path, self.ttl, self.now = path, ttl_hours * 3600, now
        self._data: dict = (read_json(path, {}) if path else {}) or {}
        self._dirty = False

    def get(self, key: str, allow_stale: bool = False) -> Any | None:
        e = self._data.get(key)
        if not isinstance(e, dict):
            return None
        age = self.now() - float(e.get("at", 0))
        ttl = _ERROR_TTL if e.get("error") else self.ttl
        if allow_stale or age < ttl:
            return e
        return None

    def put(self, key: str, value: dict) -> None:
        self._data[key] = {**value, "at": self.now()}
        self._dirty = True

    def age_hours(self, key: str) -> float | None:
        e = self._data.get(key)
        return (self.now() - float(e["at"])) / 3600 if isinstance(e, dict) and "at" in e else None

    def save(self) -> None:
        if self.path and self._dirty:
            with contextlib.suppress(OSError):
                atomic_write_json(self.path, self._data)
            self._dirty = False


def latest_cached(spec: ToolSpec, http: Any, cache: Cache, refresh: bool = False) -> Latest:
    """latest_for() behind the cache. Offline + stale cache => stale answer, flagged."""
    key = f"latest:{spec.name}"
    if not refresh:
        e = cache.get(key)
        if e and not e.get("error"):
            return _from_cache(e)
        if e and e.get("error"):
            return Latest(None, None, None, "cache", e["error"])
    try:
        res = latest_for(spec, http)
    except Offline as exc:
        stale = cache.get(key, allow_stale=True)
        if stale and not stale.get("error"):
            lt = _from_cache(stale)
            lt.error = f"offline — showing cached answer ({exc})"
            return lt
        return Latest(None, None, None, "none", str(exc))
    if res.version is None:
        cache.put(key, {"error": res.error or "lookup failed"})
    else:
        cache.put(key, {
            "version": str(res.version), "source": res.source,
            "newer_major": str(res.newer_major) if res.newer_major else None,
            "above_ceiling": str(res.above_ceiling) if res.above_ceiling else None,
        })
    return res


def _from_cache(e: dict) -> Latest:
    return Latest(versions.parse(e.get("version")), versions.parse(e.get("newer_major")),
                  versions.parse(e.get("above_ceiling")), f"{e.get('source', '?')} (cached)")
