"""
state.py — the records the updater keeps (all under <state_dir>, git-ignored):

  installed-tools.json   exact versions installed + which binary is selected
  update-history.json    append-only audit log (no secrets, no env, no URLs with tokens)
  tool-selection.json    per-tool system/local choice + majors the user accepted
  tool-lock.json         (config/) exact versions for reproducible installs
"""
from __future__ import annotations

import datetime as dt
import platform
import re
from pathlib import Path
from typing import Any

from . import versions
from .layout import Layout
from .manifest import Manifest, ManifestError
from .security import SecurityError, atomic_write_json, read_json, redact

HISTORY_CAP = 500


def now_iso() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def platform_tag() -> str:
    m = platform.machine().lower()
    return f"{platform.system().lower()}/{ {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(m, m) }"


# ── installed-tools.json ──────────────────────────────────────────────
def load_installed(layout: Layout) -> dict:
    d = read_json(layout.installed_file, {}) or {}
    d.setdefault("schema", 1)
    d.setdefault("tools", {})
    d.setdefault("assets", {})
    return d


def record_installed(layout: Layout, tool: str, version: str, module_target: str,
                     path: str, source_note: str = "go-install", go_version: str | None = None) -> None:
    d = load_installed(layout)
    d["generated_at"] = now_iso()
    d["platform"] = platform_tag()
    if go_version:
        d["go_version"] = go_version
    d["tools"][tool] = {"version": version, "target": module_target, "path": path,
                        "method": source_note, "installed_at": now_iso()}
    atomic_write_json(layout.installed_file, d)


def record_asset(layout: Layout, name: str, version: str | None) -> None:
    d = load_installed(layout)
    d["generated_at"] = now_iso()
    d["assets"][name] = {"version": version, "updated_at": now_iso()}
    atomic_write_json(layout.installed_file, d)


# ── update-history.json ───────────────────────────────────────────────
def log_history(layout: Layout, tool: str, old: str | None, new: str | None, status: str,
                source: str = "", reason: str | None = None, kind: str = "tool") -> None:
    d = read_json(layout.history_file, {}) or {}
    entries = d.get("entries", []) if isinstance(d, dict) else []
    entries.append({"timestamp": now_iso(), "tool": tool, "kind": kind, "old_version": old,
                    "new_version": new, "source": source, "status": status, "reason": redact(reason)})
    atomic_write_json(layout.history_file, {"schema": 1, "entries": entries[-HISTORY_CAP:]})


def load_history(layout: Layout) -> list[dict]:
    d = read_json(layout.history_file, {}) or {}
    return d.get("entries", []) if isinstance(d, dict) else []


# ── tool-selection.json ───────────────────────────────────────────────
def load_selection(layout: Layout) -> dict:
    d = read_json(layout.selection_file, {}) or {}
    return {"prefer": dict(d.get("prefer", {})), "accepted_majors": dict(d.get("accepted_majors", {}))}


def save_selection(layout: Layout, sel: dict) -> None:
    atomic_write_json(layout.selection_file, {"schema": 1, **sel})


def accepted_majors(sel: dict, tool: str) -> frozenset[int]:
    return frozenset(int(m) for m in sel.get("accepted_majors", {}).get(tool, []) if str(m).isdigit())


# ── reproducible lock ─────────────────────────────────────────────────
_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def build_lock(manifest: Manifest, installed: dict[str, str], go_version: str | None) -> dict:
    tools = {}
    for name, ver in sorted(installed.items()):
        spec = manifest.tools[name]
        v = versions.parse(ver)
        if v is None:
            continue
        tools[name] = {"version": str(v), "target": spec.install_target(v)}
    return {"schema": 1, "generated_at": now_iso(), "platform": platform_tag(),
            "go_version": go_version, "tools": tools}


def validate_lock(manifest: Manifest, data: Any) -> dict[str, versions.Version]:
    """A lock may only say 'tool X at version V'. Every target is RE-DERIVED from
    the manifest and must equal what the lock claims, so a doctored lock can't
    smuggle in a different module, owner or command-line option."""
    if not isinstance(data, dict) or data.get("schema") != 1 or not isinstance(data.get("tools"), dict):
        raise ManifestError("not a valid tool-lock.json (schema 1)")
    out: dict[str, versions.Version] = {}
    for name, ent in data["tools"].items():
        if not isinstance(name, str) or not _NAME.match(name) or name not in manifest.tools:
            raise SecurityError(f"lock names a tool the manifest doesn't know: {name!r}")
        spec = manifest.tools[name]
        v = versions.parse(str(ent.get("version", ""))) if isinstance(ent, dict) else None
        if v is None or not v.is_stable:
            raise SecurityError(f"lock: {name}: version must be a stable MAJOR.MINOR.PATCH")
        if v.major != spec.tested_major:
            raise SecurityError(f"lock: {name} {v} is outside tested major v{spec.tested_major}")
        if ent.get("target") != spec.install_target(v):
            raise SecurityError(f"lock: {name}: target does not match the manifest's module")
        out[name] = v
    return out


def load_lock(manifest: Manifest, path: Path) -> dict[str, versions.Version]:
    try:
        import json
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ManifestError(f"cannot read lock file {path}: {exc}") from exc
    return validate_lock(manifest, data)
