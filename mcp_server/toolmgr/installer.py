"""
installer.py — put a tool binary in place WITHOUT ever leaving the user worse off.

    resolve exact version
      -> `go install module@vX.Y.Z` into a private staging dir (never the live dir)
      -> validate the staged file (regular file, size, identity, version, flags)
      -> back up the working binary
      -> atomic rename over it
      -> re-verify the installed file
      -> any failure: restore the backup, report why, keep the old version

Only project-local binaries (<root>/bin/tools) are ever written. A system or
~/go/bin copy is never touched.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import detect, state, versions
from .detect import Runner
from .layout import Layout
from .manifest import ToolSpec
from .security import (
    SecurityError,
    clean_env,
    ensure_safe_dir,
    find_executable,
    redact,
    run_argv,
    safe_to_execute,
    validate_name,
)
from .versions import Version

BUILD_TIMEOUT = 1800
KEEP_BACKUPS = 3
_MAX_BIN = 600 * 1024 * 1024


@dataclass
class Result:
    tool: str
    status: str                 # installed | updated | unchanged | failed | rolled-back | planned
    old: str | None = None
    new: str | None = None
    reason: str | None = None
    path: str | None = None

    @property
    def ok(self) -> bool:
        return self.status in ("installed", "updated", "unchanged", "planned")


# ── Go toolchain ──────────────────────────────────────────────────────
def find_go() -> str | None:
    found = find_executable("go")
    if found:
        return found
    for cand in ("/usr/local/go/bin/go", "/usr/lib/go/bin/go"):
        if os.access(cand, os.X_OK):
            return cand
    return None


def go_version(go: str, runner: Runner = run_argv) -> Version | None:
    res = runner([go, "version"], timeout=20, env=clean_env())
    m = re.search(r"go(\d+\.\d+(?:\.\d+)?)", res.output or "")
    return versions.parse_loose(m.group(1)) if m else None


# ── compatibility self-test ───────────────────────────────────────────
_FLAG_BOUNDARY = r"(?<![\w-]){}(?![\w-])"


def flag_in_help(flag: str, text: str) -> bool:
    return re.search(_FLAG_BOUNDARY.format(re.escape(flag)), text) is not None


def selftest(spec: ToolSpec, path: str, runner: Runner = run_argv) -> list[str]:
    """Does this binary still accept the flags the project's handlers pass it?
    Returns problems (empty = compatible). Reads the tool's own help text; runs
    nothing that touches a network or a target."""
    problems: list[str] = []
    if spec.compat and not safe_to_execute(path):
        return ["not executed: running as root and this binary isn't root-owned/write-protected"]
    for chk in spec.compat:
        res = runner([path, *chk.help_args], timeout=15, env=clean_env())
        if res.error or res.timed_out:
            problems.append(f"`{' '.join(chk.help_args)}` failed: {res.error}")
            continue
        text = res.output
        if not text.strip():
            problems.append(f"`{' '.join(chk.help_args)}` printed nothing")
            continue
        missing = [f for f in chk.flags if not flag_in_help(f, text)]
        if missing:
            problems.append(f"no longer lists flag(s) the project uses: {', '.join(missing)}")
    return problems


def validate_binary(spec: ToolSpec, path: str, expect: Version | None, runner: Runner = run_argv,
                    run_selftest: bool = True) -> tuple[Version | None, list[str]]:
    problems: list[str] = []
    try:
        st = os.lstat(path)
    except OSError as exc:
        return None, [f"missing: {exc}"]
    if not stat.S_ISREG(st.st_mode):
        return None, ["not a regular file (symlinks are refused)"]
    if st.st_size == 0 or st.st_size > _MAX_BIN:
        return None, [f"implausible size ({st.st_size} bytes)"]
    if not st.st_mode & stat.S_IXUSR:
        return None, ["not executable"]
    cand = detect.probe(spec, path, "staging", runner)
    if not cand.identity_ok:
        problems.append(cand.error or "wrong program")
    if cand.version is None:
        problems.append(cand.error or "could not read its version")
    else:
        if expect and cand.version != expect:
            problems.append(f"reports {cand.version}, expected {expect}")
        if cand.version < spec.min_version:
            problems.append(f"{cand.version} is older than the minimum supported {spec.min_version}")
    if run_selftest and not problems:
        problems += selftest(spec, path, runner)
    return cand.version, problems


# ── backups ───────────────────────────────────────────────────────────
_BK = re.compile(r"^(?P<tool>[a-z0-9._-]+)-(?P<ver>\d+\.\d+\.\d+)$")


def list_backups(layout: Layout, tool: str) -> list[tuple[Version, Path]]:
    out = []
    if layout.backup_dir.is_dir():
        for p in layout.backup_dir.iterdir():
            m = _BK.match(p.name)
            v = versions.parse(m["ver"]) if m else None
            if m and m["tool"] == tool and v and p.is_file() and not p.is_symlink():
                out.append((v, p))
    return sorted(out, key=lambda t: t[0], reverse=True)


def _backup(layout: Layout, spec: ToolSpec, live: Path, version: Version | None) -> Path | None:
    if not live.is_file() or version is None:
        return None
    ensure_safe_dir(layout.backup_dir, private=True)
    dest = layout.backup_dir / f"{spec.name}-{version}"
    tmp = layout.backup_dir / f".{spec.name}.{os.getpid()}.tmp"
    shutil.copy2(live, tmp)
    os.chmod(tmp, 0o700)
    os.replace(tmp, dest)
    for _, old in list_backups(layout, spec.name)[KEEP_BACKUPS:]:
        old.unlink(missing_ok=True)
    return dest


def _swap_in(src: Path, live: Path, layout: Layout) -> None:
    """Atomically make `src` the live binary. Always via a temp file in the SAME
    directory so os.replace is a rename, never a copy-then-truncate."""
    fd, name = tempfile.mkstemp(dir=layout.tools_dir, prefix=".swap-")
    os.close(fd)                       # an fd left open for writing makes exec fail (ETXTBSY)
    tmp = Path(name)
    try:
        shutil.copy2(src, tmp)
        os.chmod(tmp, 0o755)
        os.replace(tmp, live)
    finally:
        tmp.unlink(missing_ok=True)


# ── build + install ───────────────────────────────────────────────────
def install_tool(layout: Layout, spec: ToolSpec, target: Version, runner: Runner = run_argv,
                 go: str | None = None, major: int | None = None, replace_existing: bool = True,
                 allow_untested: bool = False) -> Result:
    validate_name(spec.name, "tool")
    validate_name(spec.binary, "binary")
    live = layout.tools_dir / spec.binary
    old_cand = detect.probe(spec, str(live), "local", runner) if live.is_file() else None
    old_v = old_cand.version if old_cand else None
    res = Result(spec.name, "failed", str(old_v) if old_v else None, str(target))

    if old_v and old_v == target and old_cand and old_cand.usable:
        res.status, res.reason = "unchanged", "already at that version"
        return res
    if not allow_untested and not spec.accepts(target):
        res.reason = f"{target} is outside the tested range for {spec.name}"
        return res
    if live.is_file() and not replace_existing:
        res.status, res.reason = "unchanged", "already present"
        return res
    go = go or find_go()
    if not go:
        res.reason = "Go toolchain not found (install Go from https://go.dev/dl/ and retry)"
        return res
    try:
        arg = spec.install_target(target, major)
        ensure_safe_dir(layout.tools_dir)
        staging = Path(tempfile.mkdtemp(dir=ensure_safe_dir(layout.tools_dir), prefix=".staging-"))
        os.chmod(staging, 0o700)
    except (SecurityError, OSError) as exc:
        res.reason = f"cannot prepare install: {exc}"
        return res

    try:
        # Neutral cwd + scrubbed env: no stray go.mod/go.work/GOFLAGS can steer the build.
        env = clean_env({"GOBIN": str(staging), "CGO_ENABLED": os.environ.get("CGO_ENABLED", "1"),
                         "GOTOOLCHAIN": "auto", "GOWORK": "off"})
        build = runner([go, "install", arg], timeout=BUILD_TIMEOUT, env=env, cwd=str(staging))
        if not build.ok:
            tail = " ".join(build.output.strip().splitlines()[-3:]) if build.output else (build.error or "")
            res.reason = redact(f"go install failed: {tail[:300]}")
            return res
        staged = staging / spec.binary
        got_v, problems = validate_binary(spec, str(staged), target, runner)
        if problems:
            res.reason = "validation failed: " + "; ".join(problems)
            return res

        backup = _backup(layout, spec, live, old_v) if live.is_file() else None
        try:
            _swap_in(staged, live, layout)
        except OSError as exc:
            res.reason = f"could not place the new binary: {exc}"
            return res
        post_v, post_problems = validate_binary(spec, str(live), target, runner)
        if post_problems:
            if backup:
                _swap_in(backup, live, layout)
                res.status = "rolled-back"
                res.reason = f"post-install check failed ({'; '.join(post_problems)}); restored {old_v}"
            else:
                live.unlink(missing_ok=True)
                res.reason = f"post-install check failed ({'; '.join(post_problems)}); removed"
            return res
        res.status = "updated" if old_v else "installed"
        res.new, res.path = str(post_v), str(live)
        state.record_installed(layout, spec.name, str(post_v), arg, str(live),
                               go_version=str(go_version(go, runner) or ""))
        return res
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def rollback_tool(layout: Layout, spec: ToolSpec, to: Version | None = None,
                  runner: Runner = run_argv) -> Result:
    live = layout.tools_dir / spec.binary
    backups = list_backups(layout, spec.name)
    cur = detect.probe(spec, str(live), "local", runner) if live.is_file() else None
    res = Result(spec.name, "failed", str(cur.version) if cur and cur.version else None)
    pool = [(v, p) for v, p in backups if (to is None or v == to) and (not cur or v != cur.version)]
    if not pool:
        res.reason = "no matching backup" + (f" for {to}" if to else "")
        return res
    ver, path = pool[0]
    v, problems = validate_binary(spec, str(path), ver, runner, run_selftest=False)
    if problems:
        res.reason = f"backup {ver} is not usable: {'; '.join(problems)}"
        return res
    if cur and cur.version:
        _backup(layout, spec, live, cur.version)        # keep what we're leaving, so rollback is reversible
    ensure_safe_dir(layout.tools_dir)
    _swap_in(path, live, layout)
    res.status, res.new, res.path = "updated", str(ver), str(live)
    state.record_installed(layout, spec.name, str(ver), "rollback", str(live), source_note="rollback")
    return res


# ── selection links ───────────────────────────────────────────────────
def refresh_active(layout: Layout, chosen: dict[str, str | None]) -> None:
    """(Re)build <root>/bin/active/: one symlink per tool pointing at whichever
    binary was SELECTED. The launchers put this directory first on PATH, which
    is how "newest compatible copy wins" reaches the MCP server."""
    ensure_safe_dir(layout.active_dir)
    wanted = {n: p for n, p in chosen.items() if p}
    for entry in layout.active_dir.iterdir():
        if entry.name not in wanted and entry.is_symlink():
            entry.unlink()
    for name, target in wanted.items():
        validate_name(name, "tool")
        link = layout.active_dir / name
        tmp = layout.active_dir / f".{name}.{os.getpid()}"
        tmp.unlink(missing_ok=True)
        os.symlink(target, tmp)
        os.replace(tmp, link)
