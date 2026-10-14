"""
capabilities.py — environment/capability diagnostics.

Single source of truth for "what's available right now", shared by:
  - the get_capabilities MCP tool (server.py)
  - the /health HTTP endpoint (server.py) — used to just build its own
    separate, shorter tool list inline; now uses this instead
  - hunt.py's `doctor` command (and its existing check_tools(), which used
    to have its own third, independently-drifting copy of the tool list)

REQUIRED tools are called directly by at least one handler in server.py
with no fallback — if one's missing, that handler simply can't run.
OPTIONAL tools either have a working fallback (gowitness -> httpx
-screenshot) or, in anew's case, aren't actually invoked by any current
handler at all despite being checked for — noted honestly below rather
than silently implying it's load-bearing.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

# Literal copy used ONLY if config/tools.yaml can't be read (e.g. PyYAML
# missing). tests/test_toolmgr_manifest.py fails if it ever drifts from the
# manifest, which is the real source of truth.
_FALLBACK_REQUIRED: dict[str, str] = {
    "subfinder":   "passive subdomain enumeration",
    "httpx":       "alive check + tech detect",
    "naabu":       "port scanner",
    "nuclei":      "vulnerability scanner",
    "ffuf":        "directory/parameter fuzzer",
    "katana":      "web crawler",
    "waybackurls": "historical URLs (Wayback Machine)",
    "gau":         "historical URLs (multiple sources)",
    "dnsx":        "DNS enumeration",
    "gobuster":    "DNS-based subdomain brute-force",
}
_FALLBACK_OPTIONAL: dict[str, str] = {
    "gowitness":         "web screenshots — falls back to httpx's built-in screenshot flag if missing",
    "anew":              "deduplication — not currently invoked by any tool handler",
    "httprobe":          "fast alive-host probing",
    "interactsh-client": "out-of-band interaction catcher (blind SSRF/XSS/RCE)",
}


def _tool_lists() -> tuple[dict[str, str], dict[str, str]]:
    """(required, optional) {name: purpose}, from config/tools.yaml."""
    try:
        from mcp_server.toolmgr.layout import REPO_ROOT
        from mcp_server.toolmgr.manifest import load_manifest
        m = load_manifest(REPO_ROOT / "config" / "tools.yaml")
        return ({n: t.purpose for n, t in m.required.items()},
                {n: t.purpose for n, t in m.optional.items()})
    except Exception:  # noqa: BLE001 — a diagnostics helper must degrade, not crash the server
        return dict(_FALLBACK_REQUIRED), dict(_FALLBACK_OPTIONAL)


REQUIRED_TOOLS, OPTIONAL_TOOLS = _tool_lists()

MIN_PYTHON = (3, 11)


def _is_projectdiscovery_httpx(path: str) -> bool:
    """
    True only if `path` is ProjectDiscovery's httpx, not the CLI the Python
    `httpx` library installs under the same name (requirements.txt pulls the
    library in, and pip drops its script on PATH — the collision the
    Dockerfile's install order exists to avoid). shutil.which() can't tell
    them apart, so doctor/get_capabilities used to report a healthy httpx
    that would then fail the first time alive_check actually ran it.
    ProjectDiscovery's prints its banner / "Current Version" on -version;
    the Python one rejects the flag as an unknown option.
    """
    try:
        proc = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    text = (proc.stdout + proc.stderr).lower()
    return "projectdiscovery" in text or "current version" in text


# Tools whose *name* is ambiguous: found-on-PATH isn't enough, identity is verified.
_IDENTITY_CHECKS = {"httpx": _is_projectdiscovery_httpx}


def _probe(tool: str) -> tuple[bool, str | None]:
    """(available, note). note explains a found-but-wrong binary."""
    path = shutil.which(tool)
    if not path:
        return False, None
    verify = _IDENTITY_CHECKS.get(tool)
    if verify and not verify(path):
        return False, (
            f"Found a different '{tool}' at {path} (not ProjectDiscovery's — likely the Python "
            "httpx library's CLI). Install the Go tool and make sure it comes first on PATH; "
            "install-native.sh's bin/ launchers handle the ordering."
        )
    return True, None


def check_go_tools() -> dict:
    required_probe = {t: _probe(t) for t in REQUIRED_TOOLS}
    optional_probe = {t: _probe(t) for t in OPTIONAL_TOOLS}

    def entry(tool: str, purpose: str, probe: tuple[bool, str | None]) -> dict:
        available, note = probe
        e: dict = {"available": available, "purpose": purpose}
        if note:
            e["note"] = note
        return e

    return {
        "required": {t: entry(t, REQUIRED_TOOLS[t], pr) for t, pr in required_probe.items()},
        "optional": {t: entry(t, OPTIONAL_TOOLS[t], pr) for t, pr in optional_probe.items()},
        "missing_required": [t for t, (ok, _) in required_probe.items() if not ok],
        "missing_optional": [t for t, (ok, _) in optional_probe.items() if not ok],
    }


def check_python() -> dict:
    ok = sys.version_info[:2] >= MIN_PYTHON
    return {
        "version": sys.version.split()[0],
        "required": f">={MIN_PYTHON[0]}.{MIN_PYTHON[1]}",
        "ok": ok,
    }


def check_wordlists(wordlists_dir: Path) -> dict:
    subdomains = wordlists_dir / "subdomains.txt"
    directories = wordlists_dir / "directories.txt"
    return {
        "dir": str(wordlists_dir),
        "subdomains_txt": subdomains.exists(),
        "directories_txt": directories.exists(),
    }


def is_running_in_docker() -> bool:
    # Standard, widely-used heuristic — the container runtime bind-mounts
    # this file into every Linux container. Not foolproof (some minimal
    # runtimes omit it) but good enough for an informational field.
    return Path("/.dockerenv").exists()


def get_capabilities(wordlists_dir: Path, mcp_tool_count: int | None = None) -> dict:
    """The full report: go_tools, python, wordlists, environment, and an
    overall status + plain-language issues list. wordlists_dir should be
    resolved relative to the caller (repo root natively, /app in Docker —
    see hunt.py's WORDLISTS_DIR for the pattern)."""
    go_tools = check_go_tools()
    python = check_python()
    wordlists = check_wordlists(wordlists_dir)

    issues: list[str] = []
    issues.extend(
        info["note"] for group in ("required", "optional")
        for info in go_tools[group].values() if info.get("note")
    )
    if not python["ok"]:
        issues.append(f"Python {python['version']} is below the required {python['required']}.")
    if go_tools["missing_required"]:
        issues.append(
            "Missing required tools: " + ", ".join(go_tools["missing_required"]) +
            ". Install them, or use the Docker image, which has all of them pre-installed."
        )
    if not wordlists["subdomains_txt"]:
        issues.append(f"subdomains.txt not found at {wordlists['dir']} — run setup.sh, or download one manually.")
    if not wordlists["directories_txt"]:
        issues.append(f"directories.txt not found at {wordlists['dir']} — run setup.sh, or download one manually.")

    result = {
        "status": "ready" if not issues else "degraded",
        "environment": "docker" if is_running_in_docker() else "native",
        "python": python,
        "go_tools": go_tools,
        "wordlists": wordlists,
        "issues": issues,
    }
    if mcp_tool_count is not None:
        result["mcp_tools"] = {"count": mcp_tool_count}
    return result
