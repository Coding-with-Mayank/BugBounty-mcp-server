"""
manifest.py — load and VALIDATE config/tools.yaml.

Validation is a security boundary: the values here end up in `go install`
arguments and in filesystem paths, so every field is checked against a strict
shape before anything else sees it, and a Go module is only accepted if it
lives under the github.com/<repo> the entry claims to belong to.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import versions
from .security import NAME_RE, SecurityError
from .versions import Version

_REPO_RE = re.compile(r"^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$")
_PKG_RE = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_./-]*$|^$")
_FLAG_RE = re.compile(r"^--?[A-Za-z0-9][A-Za-z0-9_-]*$")
_ARG_RE = re.compile(r"^[A-Za-z0-9_.=-]+$")


# Second tripwire, deliberately in CODE rather than in the data file it polices:
# adding a new upstream owner means changing this set (and the test that pins
# it), which is far harder to slip past review than one more line in tools.yaml.
# It does not defend against a compromised repository — the repo is the trust
# root (see docs/UPDATING.md) — it stops accidental or partial edits.
TRUSTED_OWNERS = frozenset({"projectdiscovery", "tomnomnom", "lc", "ffuf", "OJ", "sensepost"})


class ManifestError(Exception):
    pass


@dataclass(frozen=True)
class CompatCheck:
    help_args: tuple[str, ...]
    flags: tuple[str, ...]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    purpose: str
    required: bool
    repo: str
    module: str                       # github.com/<owner>/<repo>, WITHOUT a /vN suffix
    package: str                      # sub-package holding main ("cmd/nuclei"), or ""
    tested_major: int
    min_version: Version
    max_version: Version | None
    auto_update: str                  # "safe" | "manual"
    version_args: tuple[str, ...]
    version_regex: str | None
    identity_regex: str | None
    compat: tuple[CompatCheck, ...]
    binary: str = ""
    major_in_path: bool = True        # False for modules that never adopted a /vN suffix

    def module_path(self, major: int | None = None) -> str:
        """Import path of the module for a given major (Go puts v2+ in the path)."""
        m = self.tested_major if major is None else major
        return f"{self.module}/v{m}" if (m >= 2 and self.major_in_path) else self.module

    def install_target(self, version: Version, major: int | None = None) -> str:
        """The exact `go install` argument: <module>[/vN][/pkg]@vX.Y.Z"""
        if not versions.is_release_tag(version.tag):
            raise SecurityError(f"refusing non-release version {version.tag!r}")
        m = version.major if major is None else major
        if version.major != m:
            raise SecurityError(f"{version.tag} does not belong to major v{m}")
        path = self.module_path(m)
        if self.package:
            path = f"{path}/{self.package}"
        return f"{path}@{version.tag}"

    def accepts(self, v: Version, accepted_majors: frozenset[int] = frozenset()) -> bool:
        """Is `v` inside the tested envelope (>= min, tested major, <= max)?"""
        if v < self.min_version:
            return False
        if v.major != self.tested_major and v.major not in accepted_majors:
            return False
        return not (self.max_version and v.major == self.tested_major and v > self.max_version)


@dataclass(frozen=True)
class AssetSpec:
    name: str
    purpose: str
    requires_tool: str
    repo: str
    update_args: tuple[str, ...]
    version_args: tuple[str, ...]
    version_regex: str | None = None


@dataclass(frozen=True)
class SystemTool:
    name: str
    purpose: str
    hint: str


@dataclass(frozen=True)
class Manifest:
    tools: dict[str, ToolSpec]
    assets: dict[str, AssetSpec]
    system_tools: dict[str, SystemTool]
    settings: dict[str, Any] = field(default_factory=dict)

    @property
    def required(self) -> dict[str, ToolSpec]:
        return {n: t for n, t in self.tools.items() if t.required}

    @property
    def optional(self) -> dict[str, ToolSpec]:
        return {n: t for n, t in self.tools.items() if not t.required}


def _need(d: dict, key: str, where: str, typ: type | tuple = str) -> Any:
    if key not in d:
        raise ManifestError(f"{where}: missing '{key}'")
    if not isinstance(d[key], typ):
        raise ManifestError(f"{where}: '{key}' has the wrong type")
    return d[key]


def _args(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(a, str) and _ARG_RE.match(a) for a in value):
        raise ManifestError(f"{where}: must be a list of plain argument strings")
    return tuple(value)


def _version(text: Any, where: str) -> Version:
    v = versions.parse(str(text)) if text is not None else None
    if v is None:
        raise ManifestError(f"{where}: {text!r} is not a MAJOR.MINOR.PATCH version")
    return v


def _tool(name: str, raw: dict) -> ToolSpec:
    where = f"tools.{name}"
    if not NAME_RE.match(name):
        raise ManifestError(f"{where}: unsafe tool name")
    repo = _need(raw, "repo", where)
    rm = _REPO_RE.match(repo)
    if not rm:
        raise ManifestError(f"{where}: repo must look like owner/name")
    if rm.group(1) not in TRUSTED_OWNERS:
        raise ManifestError(f"{where}: owner {rm.group(1)!r} is not in the trusted-owner allowlist "
                            "(mcp_server/toolmgr/manifest.py:TRUSTED_OWNERS)")
    module = _need(raw, "module", where)
    # Ownership validation: the module must be github.com/<this repo>, exactly.
    if module != f"github.com/{repo}":
        raise ManifestError(
            f"{where}: module {module!r} is not github.com/{repo} — "
            "refusing a manifest that points an install at a different owner"
        )
    package = raw.get("package", "")
    if not isinstance(package, str) or not _PKG_RE.match(package) or ".." in package.split("/"):
        raise ManifestError(f"{where}: unsafe package path {package!r}")
    tested_major = _need(raw, "tested_major", where, int)
    if tested_major < 0 or isinstance(tested_major, bool):
        raise ManifestError(f"{where}: tested_major must be >= 0")
    min_v = _version(_need(raw, "min_version", where, (str, int, float)), f"{where}.min_version")
    if min_v.major != tested_major:
        raise ManifestError(f"{where}: min_version {min_v} is not in tested_major {tested_major}")
    max_v = _version(raw["max_version"], f"{where}.max_version") if raw.get("max_version") else None
    auto = raw.get("auto_update", "safe")
    if auto not in ("safe", "manual"):
        raise ManifestError(f"{where}: auto_update must be 'safe' or 'manual'")
    for rx_key in ("version_regex", "identity_regex"):
        rx = raw.get(rx_key)
        if rx is not None:
            try:
                re.compile(rx)
            except re.error as exc:
                raise ManifestError(f"{where}.{rx_key}: invalid regex ({exc})") from exc
    checks = []
    for i, c in enumerate(raw.get("compat") or []):
        flags = _args(c.get("flags"), f"{where}.compat[{i}].flags")
        if not all(_FLAG_RE.match(f) for f in flags):
            raise ManifestError(f"{where}.compat[{i}].flags: entries must be flags like -x or --long")
        checks.append(CompatCheck(_args(c.get("help_args"), f"{where}.compat[{i}].help_args"), flags))
    binary = raw.get("binary") or name
    if not NAME_RE.match(binary):
        raise ManifestError(f"{where}: unsafe binary name")
    return ToolSpec(
        name=name, purpose=str(raw.get("purpose", "")), required=bool(raw.get("required", False)),
        repo=repo, module=module, package=package, tested_major=tested_major,
        min_version=min_v, max_version=max_v, auto_update=auto,
        version_args=_args(raw.get("version_args"), f"{where}.version_args"),
        version_regex=raw.get("version_regex"), identity_regex=raw.get("identity_regex"),
        compat=tuple(checks), binary=binary, major_in_path=bool(raw.get("major_in_path", True)),
    )


def parse_manifest(data: Any) -> Manifest:
    if not isinstance(data, dict):
        raise ManifestError("manifest root must be a mapping")
    if data.get("schema") != 1:
        raise ManifestError(f"unsupported manifest schema {data.get('schema')!r} (expected 1)")
    raw_tools = _need(data, "tools", "manifest", dict)
    tools = {n: _tool(n, r) for n, r in raw_tools.items() if isinstance(r, dict)}
    if len(tools) != len(raw_tools):
        raise ManifestError("every tools.<name> entry must be a mapping")
    assets = {}
    for n, r in (data.get("assets") or {}).items():
        where = f"assets.{n}"
        if not NAME_RE.match(n):
            raise ManifestError(f"{where}: unsafe asset name")
        req = _need(r, "requires_tool", where)
        if req not in tools:
            raise ManifestError(f"{where}: requires_tool {req!r} is not a declared tool")
        repo = _need(r, "repo", where)
        if not _REPO_RE.match(repo):
            raise ManifestError(f"{where}: repo must look like owner/name")
        assets[n] = AssetSpec(n, str(r.get("purpose", "")), req, repo,
                              _args(r.get("update_args"), f"{where}.update_args"),
                              _args(r.get("version_args"), f"{where}.version_args"), r.get("version_regex"))
    system = {n: SystemTool(n, str(r.get("purpose", "")), str(r.get("hint", "")))
              for n, r in (data.get("system_tools") or {}).items() if NAME_RE.match(n)}
    return Manifest(tools, assets, system, dict(data.get("settings") or {}))


def load_manifest(path: Path) -> Manifest:
    try:
        import yaml
    except ImportError as exc:
        raise ManifestError(
            "PyYAML is required to read config/tools.yaml (pip install -r requirements.txt)"
        ) from exc
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ManifestError(f"cannot read {path}: {exc}") from exc
    return parse_manifest(data)
