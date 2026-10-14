"""
versions.py — version parsing, ordering and the upgrade-policy classifier.

Deliberately small and dependency-free: it must run in the Docker build's Go
stage (plain Alpine + python3) as well as in the project venv.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

# Strict semver-ish: optional leading v, three numeric parts, optional
# pre-release, optional +build (Go's "+incompatible" lands here).
_STRICT = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")
# "1.22" / "v1.22" (Go toolchain versions, manifest min_go_version)
_LOOSE = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?$")
# Release tags that are safe to hand to `go install ...@<tag>`.
_GO_TAG = re.compile(r"^v\d+\.\d+\.\d+$")
# Default "find a version in tool output" pattern. The lookbehind rejects
# things like "go1.22.1" so a banner mentioning the Go toolchain can't win.
DEFAULT_VERSION_REGEX = r"(?<![\w.])v?(\d+\.\d+\.\d+)(?![\w.]*\d)"


@total_ordering
@dataclass(frozen=True)
class Version:
    major: int
    minor: int
    patch: int
    pre: str | None = None

    def _key(self) -> tuple:
        # A release sorts above any of its own pre-releases.
        pre_key: tuple = (1,) if self.pre is None else (0, *_pre_key(self.pre))
        return (self.major, self.minor, self.patch, pre_key)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._key() < other._key()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._key() == other._key()

    def __hash__(self) -> int:
        return hash(self._key())

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        return f"{base}-{self.pre}" if self.pre else base

    @property
    def tag(self) -> str:
        """Go-style tag: v3.3.9"""
        return f"v{self}"

    @property
    def is_stable(self) -> bool:
        return self.pre is None


def _pre_key(pre: str) -> tuple:
    out: list[tuple] = []
    for part in pre.split("."):
        out.append((0, int(part), "") if part.isdigit() else (1, 0, part))
    return tuple(out)


def parse(text: str | None) -> Version | None:
    """Parse a strict three-part version; None if it isn't one."""
    if not text:
        return None
    m = _STRICT.match(text.strip())
    if not m:
        return None
    return Version(int(m[1]), int(m[2]), int(m[3]), m[4])


def parse_loose(text: str | None) -> Version | None:
    """Like parse(), but also accepts two-part versions ("1.22")."""
    v = parse(text)
    if v:
        return v
    if not text:
        return None
    m = _LOOSE.match(text.strip())
    if not m:
        return None
    return Version(int(m[1]), int(m[2]), int(m[3] or 0), m[4])


def is_release_tag(text: str) -> bool:
    """True only for plain vMAJOR.MINOR.PATCH — the only shape we ever pass
    to `go install`. Anything else (pre-releases, pseudo-versions, strings
    with shell/option syntax) is rejected before it can reach a command line."""
    return bool(_GO_TAG.match(text))


def extract(text: str, regex: str | None = None) -> Version | None:
    """Pull the first version out of arbitrary tool output."""
    pattern = re.compile(regex or DEFAULT_VERSION_REGEX)
    for m in pattern.finditer(text or ""):
        v = parse(m.group(1) if m.groups() else m.group(0))
        if v:
            return v
    return None


def classify(old: Version, new: Version) -> str:
    """
    How big a step is old -> new?

      same | patch | minor | major | downgrade

    0.x modules get no stability promise from semver, so a 0.x *minor* bump is
    reported as "major" — it needs the same explicit opt-in a real major does.
    """
    if new == old:
        return "same"
    if new < old:
        return "downgrade"
    if new.major != old.major:
        return "major"
    if new.minor != old.minor:
        return "major" if old.major == 0 else "minor"
    return "patch"
