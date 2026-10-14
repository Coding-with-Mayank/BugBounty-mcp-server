#!/usr/bin/env python3
"""Validate what the freshness workflow's *test* jobs produced before anything is published.

The weekly freshness workflow is split in two on purpose:

  * test jobs  — install and RUN third-party code (Go modules, PyPI packages, the tools
                 themselves). They are read-only and can publish nothing.
  * publish job — holds the only write token. It never installs or executes anything
                 from upstream; it only receives the test jobs' output as files.

Those files come from a job that ran untrusted code, so they are DATA, not instructions:
a compromised dependency could have written anything into them. This script is the
publish job's gatekeeper. It runs from the checked-out default branch (trusted code) and
refuses artifacts that are not exactly what they claim to be:

  tool-lock   a schema-1 tool-lock.json that the project's own validator accepts against
              config/tools.yaml (tool names and versions only — it cannot name a different
              module, repository or install option);
  python-lock a hash-pinned requirements.lock made ONLY of ``name==version`` + sha256 hashes
              — no URLs, VCS references, extra indexes, editable installs or pip options;
  text        free text (tool output) made safe to quote in an issue or PR body.

Usage:  ci_publish_guard.py tool-lock FILE | python-lock FILE | installed-matches FILE
                            | text FILE [--max-chars N]
        ci_publish_guard.py diff-tools OLD NEW | diff-python OLD NEW
Exit status 0 = accepted (or, for text/diff-*, printed); 1 = rejected, with the reason.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MAX_BYTES = 4 * 1024 * 1024          # a real lock is ~150 KB; anything huge is not one

_NAME = r"[A-Za-z0-9][A-Za-z0-9._-]*"
_VERSION = r"[0-9][A-Za-z0-9.!+_-]*"
# An optional PEP 508 environment marker is the only thing allowed after the version, and only
# from a small alphabet (no URLs, no paths, no pip options) — it can select a platform, never a source.
_MARKER = r"(?: ; [A-Za-z0-9_.'\"=<>!~() ]+?)?"
_REQ_LINE = re.compile(rf"^(?P<name>{_NAME})(?:\[[A-Za-z0-9,._-]+\])?==(?P<ver>{_VERSION}){_MARKER} \\$")
_REQ_LAST = re.compile(rf"^(?P<name>{_NAME})(?:\[[A-Za-z0-9,._-]+\])?==(?P<ver>{_VERSION}){_MARKER}$")
_HASH_LINE = re.compile(r"^    --hash=sha256:[0-9a-f]{64}(?: \\)?$")
_VIA_LINE = re.compile(r"^    #(?: .*)?$")        # uv's "# via ..." provenance comments (inert)


class Rejected(Exception):
    """The artifact is not acceptable. The message is safe to print."""


def _read(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise Rejected(f"{path}: not a regular file")
    if path.stat().st_size > MAX_BYTES:
        raise Rejected(f"{path}: larger than {MAX_BYTES} bytes")
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise Rejected(f"{path}: not UTF-8 text ({exc.reason})") from None


# ── tool lock ────────────────────────────────────────────────────────────────

def check_tool_lock(path: Path) -> dict[str, str]:
    """Return {tool: version}. Raises Rejected unless the project's own validator accepts it."""
    from mcp_server.toolmgr import manifest as manifest_mod
    from mcp_server.toolmgr import state

    try:
        data = json.loads(_read(path))
    except json.JSONDecodeError as exc:
        raise Rejected(f"{path}: not JSON ({exc.msg})") from None
    manifest = manifest_mod.load_manifest(ROOT / "config" / "tools.yaml")
    try:
        parsed = state.validate_lock(manifest, data)
    except Exception as exc:        # ManifestError, but never let a surprise become a publish
        raise Rejected(f"{path}: rejected by the project's lock validator: {exc}") from None
    if not parsed:
        raise Rejected(f"{path}: contains no tools")
    # validate_lock tolerates extra keys; a lock destined for the repo must not carry any.
    for tool, entry in data["tools"].items():
        extra = set(entry) - {"version", "target"}
        if extra:
            raise Rejected(f"{path}: tool {tool!r} carries unexpected keys {sorted(extra)}")
    return {t: str(v) for t, v in parsed.items()}


# ── python lock ──────────────────────────────────────────────────────────────

def check_python_lock(path: Path) -> dict[str, str]:
    """Return {package: version} for a strictly formatted, hash-pinned lock."""
    text = _read(path)
    pins: dict[str, str] = {}
    current: str | None = None
    hashes = 0
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip("\n")
        if not line.strip() or line.startswith("#"):
            continue
        if _HASH_LINE.match(line):
            if current is None:
                raise Rejected(f"{path}:{n}: hash line with no requirement above it")
            hashes += 1
            continue
        if _VIA_LINE.match(line):
            continue
        if current is not None and hashes == 0:
            raise Rejected(f"{path}: {current} has no sha256 hashes — refusing an unhashed pin")
        m = _REQ_LINE.match(line) or _REQ_LAST.match(line)
        if not m:
            raise Rejected(f"{path}:{n}: not a plain 'name==version' pin: {line[:80]!r}")
        current, hashes = m["name"].lower().replace("_", "-"), 0
        if current in pins:
            raise Rejected(f"{path}:{n}: {current} pinned twice")
        pins[current] = m["ver"]
    if current is not None and hashes == 0:
        raise Rejected(f"{path}: {current} has no sha256 hashes — refusing an unhashed pin")
    if not pins:
        raise Rejected(f"{path}: contains no pins")
    return pins


def installed_differs(pins: dict[str, str]) -> dict[str, tuple[str, str]]:
    """{package: (locked, installed)} for every pinned package present in THIS interpreter at another version.

    Run inside the venv built from the lock, after the test tooling was added: if installing
    pytest and friends silently moved a locked package, the tests did not exercise the lock.
    Packages that are not installed (platform-marker pins, e.g. pywin32 on Linux) are skipped.
    """
    from importlib import metadata

    moved = {}
    for name, want in pins.items():
        try:
            have = metadata.version(name)
        except metadata.PackageNotFoundError:
            continue
        if have != want:
            moved[name] = (want, have)
    return moved


# ── text and diffs ───────────────────────────────────────────────────────────

def safe_text(text: str, max_chars: int = 6000) -> str:
    """Make tool output safe to quote inside a fenced block in an issue or PR body.

    Defuses: fence breakouts (```), @mentions and #123 auto-links (notification spam / link
    spoofing), HTML/markdown injection via angle brackets, control characters, and size.
    """
    text = "".join(ch for ch in text if ch in "\n\t" or ch >= " " and ch != "\x7f")
    text = text.replace("`", "'").replace("<", "‹").replace(">", "›")
    text = re.sub(r"@(?=[A-Za-z0-9_-])", "@\u200b", text)
    text = re.sub(r"(?<![A-Za-z0-9])#(?=\d)", "#\u200b", text)
    if len(text) > max_chars:
        text = text[:max_chars].rstrip() + f"\n… [truncated, {len(text) - max_chars} more characters]"
    return text


def _table(rows: list[tuple[str, str, str]], head: tuple[str, str, str]) -> str:
    out = [f"| {head[0]} | {head[1]} | {head[2]} |", "|---|---|---|"]
    out += [f"| `{a}` | {b} | {c} |" for a, b, c in rows]
    return "\n".join(out) + "\n"


def diff_versions(old: dict[str, str], new: dict[str, str], head: str) -> tuple[str, bool]:
    rows = [(k, f"`{old.get(k, '-')}`", f"`{new[k]}`") for k in sorted(new) if old.get(k) != new[k]]
    return _table(rows, (head, "current", "proposed")), bool(rows)


def old_tool_versions() -> dict[str, str]:
    data = json.loads((ROOT / "config" / "tool-lock.json").read_text())
    return {t: str(e.get("version", "")) for t, e in data["tools"].items()}


def old_python_pins() -> dict[str, str]:
    return check_python_lock(ROOT / "requirements.lock")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("tool-lock", "python-lock"):
        sub.add_parser(name).add_argument("file", type=Path)
    t = sub.add_parser("text")
    t.add_argument("file", type=Path)
    t.add_argument("--max-chars", type=int, default=6000)
    sub.add_parser("installed-matches").add_argument("file", type=Path)
    for name in ("diff-tools", "diff-python"):
        sub.add_parser(name).add_argument("new", type=Path)
    a = p.parse_args(argv)
    try:
        if a.cmd == "tool-lock":
            print(f"ok: {len(check_tool_lock(a.file))} tools")
        elif a.cmd == "python-lock":
            print(f"ok: {len(check_python_lock(a.file))} pinned packages")
        elif a.cmd == "text":
            try:
                raw = a.file.read_text(encoding="utf-8", errors="replace")[: MAX_BYTES]
            except OSError:
                raw = "(no output captured)"
            print(safe_text(raw, a.max_chars))
        elif a.cmd == "installed-matches":
            pins = check_python_lock(a.file)
            moved = installed_differs(pins)
            if moved:
                raise Rejected(f"installed packages differ from the lock: {moved}")
            print(f"ok: every installed package matches its pin ({len(pins)} pins)")
        elif a.cmd == "diff-tools":
            body, changed = diff_versions(old_tool_versions(), check_tool_lock(a.new), "tool")
            print(body, end="")
            return 0 if changed else 3
        elif a.cmd == "diff-python":
            body, changed = diff_versions(old_python_pins(), check_python_lock(a.new), "package")
            print(body, end="")
            return 0 if changed else 3
    except Rejected as exc:
        print(f"REJECTED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
