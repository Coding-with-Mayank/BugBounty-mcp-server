"""
detect.py — find every copy of a tool, work out what each one is, pick one.

Candidates come from three places and are never merged or overwritten:

  local   <root>/bin/tools/<tool>        installed by this project
  go      $GOBIN / $GOPATH/bin / ~/go/bin
  system  anywhere else on PATH (distro package, brew, manual copy)
  docker  /usr/local/bin inside the container image

A version is read from the binary's embedded Go build info (no execution —
required for tools like waybackurls that have no version flag and would sit
waiting on stdin) and/or from its own `--version` output. Selection prefers the
NEWEST compatible candidate, so an older project-local copy can never shadow a
newer compatible system one.
"""
from __future__ import annotations

import mmap
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from . import versions
from .layout import Layout
from .manifest import ToolSpec
from .security import RunResult, clean_env, is_unsafe_path_entry, run_argv, safe_to_execute
from .versions import Version

Runner = Callable[..., RunResult]

# Go embeds module info between these two 16-byte sentinels (runtime/debug).
_INFO_START = b"0w\xaf\x0c\x92t\x08\x02A\xe1\xc1\x07\xe6\xd6\x18\xe6"
_INFO_END = b"\xf92C1\x86\x18 r\x00\x82B\x10A\x16\xd8\xf2"
_MAGIC = b"\xff Go buildinf:"
_MAX_BINARY = 600 * 1024 * 1024


@dataclass(frozen=True)
class BuildInfo:
    path: str            # main package path
    module: str          # main module path
    version: str         # "v3.3.9", "(devel)", ...


def read_buildinfo(path: str | os.PathLike) -> BuildInfo | None:
    """Parse Go build info straight out of the file. Never executes it."""
    try:
        size = os.stat(path).st_size
        if size == 0 or size > _MAX_BINARY:
            return None
        with open(path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            if mm.find(_MAGIC) < 0:
                return None
            start = mm.find(_INFO_START)
            if start < 0:
                return None
            end = mm.find(_INFO_END, start + 16, start + 16 + 2_000_000)
            if end < 0:
                return None
            blob = mm[start + 16:end].decode("utf-8", "replace")
    except (OSError, ValueError):
        return None
    main_path = module = ver = ""
    for line in blob.splitlines():
        parts = line.split("\t")
        if parts[0] == "path" and len(parts) > 1:
            main_path = parts[1]
        elif parts[0] == "mod" and len(parts) > 2:
            module, ver = parts[1], parts[2]
    return BuildInfo(main_path, module, ver) if module or main_path else None


@dataclass
class Candidate:
    tool: str
    path: str
    source: str                       # local | go | system | docker | override
    version: Version | None = None
    identity_ok: bool = True
    works: bool = True
    error: str | None = None
    module: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        return self.works and self.identity_ok and self.version is not None

    def to_dict(self) -> dict:
        return {
            "path": self.path, "source": self.source,
            "version": str(self.version) if self.version else None,
            "identity_ok": self.identity_ok, "works": self.works, "error": self.error,
        }


def _module_matches(spec: ToolSpec, bi: BuildInfo) -> bool:
    return any(p == spec.module or p.startswith(spec.module + "/") for p in (bi.module, bi.path) if p)


def probe(spec: ToolSpec, path: str, source: str, runner: Runner = run_argv) -> Candidate:
    """Work out what the binary at `path` is. Executes it only if the manifest
    gives a version command, with stdin closed and a short timeout."""
    cand = Candidate(spec.name, path, source)
    if not os.path.isfile(path) or not os.access(path, os.X_OK):
        cand.works, cand.error = False, "not an executable file"
        return cand

    bi = read_buildinfo(path)
    bi_version = versions.parse(bi.version) if bi else None
    if bi:
        cand.module = bi.module or bi.path
    cli_text = ""
    cli_version: Version | None = None

    if spec.version_args and not safe_to_execute(path):
        cand.notes.append("not executed: running as root and this binary isn't root-owned/write-protected")
        cli_text = ""
    elif spec.version_args:
        res = runner([path, *spec.version_args], timeout=10, env=clean_env())
        cli_text = res.output
        if res.error or res.timed_out:
            cand.error = res.error or "version command timed out"
        else:
            cli_version = versions.extract(cli_text, spec.version_regex)

    # Prefer the version the binary reports about itself; fall back to the
    # embedded module version (distro builds often report "(devel)" there).
    cand.version = cli_version or (bi_version if bi_version and bi_version.is_stable else None)
    if cli_version and bi_version and bi_version.is_stable and cli_version != bi_version:
        cand.notes.append(f"build info says {bi_version}, --version says {cli_version}")

    # Identity: is this really the tool, not a same-named impostor?
    if bi:
        cand.identity_ok = _module_matches(spec, bi)
        if not cand.identity_ok:
            cand.error = f"built from {cand.module}, expected {spec.module}"
    elif spec.identity_regex:
        cand.identity_ok = bool(re.search(spec.identity_regex, cli_text, re.I))
        if not cand.identity_ok:
            cand.error = "a different program with the same name (e.g. the Python httpx CLI)"
    if cand.version is None and cand.error is None:
        cand.error = "could not determine version"
    # One rule: a candidate "works" when we could establish what version it is.
    cand.works = cand.version is not None
    return cand


def _go_bin_dirs() -> list[str]:
    dirs = []
    if os.environ.get("GOBIN"):
        dirs.append(os.environ["GOBIN"])
    for gp in (os.environ.get("GOPATH") or str(Path.home() / "go")).split(os.pathsep):
        dirs.append(os.path.join(gp, "bin"))
    return dirs


def find_candidates(spec: ToolSpec, layout: Layout, runner: Runner = run_argv,
                    path_env: str | None = None, in_docker: bool = False,
                    extra_path: str | None = None) -> list[Candidate]:
    """Every distinct binary for this tool. Same realpath = same candidate."""
    seen: dict[str, Candidate] = {}
    ours = {str(layout.root / "bin"), str(layout.root / ".venv")}

    def consider(path: str, source: str) -> None:
        if not os.path.isfile(path):
            return
        real = os.path.realpath(path)
        if real in seen:
            return
        seen[real] = probe(spec, path, source, runner)

    if extra_path and os.path.isabs(extra_path):          # a path the user pinned with `hunt config tools set`
        consider(extra_path, "override")
    consider(str(layout.tools_dir / spec.binary), "local")
    for d in _go_bin_dirs():
        if not is_unsafe_path_entry(d):
            consider(os.path.join(d, spec.binary), "go")
    for entry in (path_env if path_env is not None else os.environ.get("PATH", "")).split(os.pathsep):
        if is_unsafe_path_entry(entry) or any(entry == o or entry.startswith(o + os.sep) for o in ours):
            continue
        source = "docker" if in_docker and entry == "/usr/local/bin" else "system"
        consider(os.path.join(entry, spec.binary), source)
    return list(seen.values())


@dataclass
class Selection:
    chosen: Candidate | None
    reason: str
    candidates: list[Candidate]


_TIE_ORDER = {"system": 0, "docker": 0, "go": 1, "local": 2, "override": -1}


def select(spec: ToolSpec, candidates: list[Candidate], override: str | None = None,
           accepted_majors: frozenset[int] = frozenset()) -> Selection:
    """
    override: None/"auto" -> newest compatible; "system"|"local"|"go" -> that
    source if usable; an absolute path -> that file.
    """
    if override and override not in ("auto",):
        if os.path.isabs(override):
            for c in candidates:
                if os.path.realpath(c.path) == os.path.realpath(override) and c.usable:
                    return Selection(c, f"pinned to {override} by `hunt config tools`", candidates)
            return Selection(None, f"pinned path {override} is missing or unusable", candidates)
        pool = [c for c in candidates if c.source == override and c.usable]
        if pool:
            best = max(pool, key=lambda c: c.version)  # type: ignore[arg-type,return-value]
            return Selection(best, f"pinned to the {override} copy by `hunt config tools`", candidates)
        return Selection(None, f"you pinned the {override} copy but none is usable", candidates)

    compatible = [c for c in candidates if c.usable and spec.accepts(c.version, accepted_majors)]  # type: ignore[arg-type]
    if compatible:
        best = max(compatible, key=lambda c: (c.version, -_TIE_ORDER.get(c.source, 5)))  # type: ignore[arg-type,return-value]
        older = [c for c in compatible if c is not best and c.version < best.version]  # type: ignore[operator]
        why = "newest compatible copy"
        if older:
            why += "; ignored older: " + ", ".join(f"{c.source} {c.version}" for c in older)
        return Selection(best, why, candidates)
    usable = [c for c in candidates if c.usable]
    if usable:
        return Selection(None, "found, but outside the tested range: "
                         + ", ".join(f"{c.source} {c.version}" for c in usable), candidates)
    return Selection(None, "not installed" if not candidates else "found, but not usable", candidates)
