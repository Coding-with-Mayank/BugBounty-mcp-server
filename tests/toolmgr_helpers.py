"""Shared fakes for the toolmgr tests: a synthetic manifest, a fake `go`, fake tools."""
from __future__ import annotations

import os
import stat
import textwrap
from pathlib import Path

from mcp_server.toolmgr.layout import Layout
from mcp_server.toolmgr.manifest import Manifest, parse_manifest

FAKE_MANIFEST = {
    "schema": 1,
    "tools": {
        "faketool": {
            "purpose": "fake", "required": True, "repo": "projectdiscovery/faketool",
            "module": "github.com/projectdiscovery/faketool", "package": "cmd/faketool",
            "tested_major": 2, "min_version": "2.1.0", "auto_update": "safe",
            "version_args": ["-version"], "version_regex": r"Current Version:\s*v?(\d+\.\d+\.\d+)",
            "compat": [{"help_args": ["-h"], "flags": ["-silent", "-json"]}],
        },
        "stdinonly": {
            "purpose": "reads stdin", "required": False, "repo": "projectdiscovery/stdinonly",
            "module": "github.com/projectdiscovery/stdinonly", "package": "", "tested_major": 0,
            "min_version": "0.1.0", "version_args": [],
        },
    },
    "assets": {
        "faketool-data": {"requires_tool": "faketool", "repo": "projectdiscovery/faketool-data",
                          "update_args": ["-update-data"], "version_args": ["-data-version"]},
    },
}


def parse_fake(data: dict) -> Manifest:
    """The fixtures use a real allowlisted owner, so the PRODUCTION owner check runs in every test."""
    return parse_manifest(data)


def manifest() -> Manifest:
    return parse_fake(FAKE_MANIFEST)


def fake_tool_script(version: str, flags: str = "-silent -json", broken: bool = False) -> str:
    if broken:
        return "#!/bin/sh\necho segfault >&2\nexit 139\n"
    return textwrap.dedent(f"""\
        #!/bin/sh
        case "$1" in
          -version) echo "[INF] Current Version: v{version}" ;;
          -h) echo "Usage:"; for f in {flags}; do echo "   $f   some flag"; done ;;
          *) echo ok ;;
        esac
        """)


def write_tool(path: Path, version: str, **kw) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(fake_tool_script(version, **kw))
    path.chmod(0o755)
    return path


def make_fake_go(bin_dir: Path, mode_file: Path) -> str:
    """A `go` that understands only `go install <target>` and `go version`.
    What it 'builds' is controlled by the first word in mode_file."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    go = bin_dir / "go"
    go.write_text(textwrap.dedent(f"""\
        #!/bin/sh
        PATH="/usr/bin:/bin:$PATH"
        if [ "$1" = "version" ]; then echo "go version go1.24.1 linux/amd64"; exit 0; fi
        [ "$1" = "install" ] || exit 2
        mode=$(cat "{mode_file}")
        target="$2"; ver="${{target##*@v}}"; name="${{target%@*}}"; name="${{name##*/}}"
        case "$name" in v[0-9]*) name="${{target%@*}}"; name="${{name%/*}}"; name="${{name##*/}}";; esac
        case "$mode" in
          build-fail) echo "go: module not found" >&2; exit 1 ;;
          wrong-version) ver="9.9.9" ;;
        esac
        out="$GOBIN/$name"
        {{
          echo '#!/bin/sh'
          if [ "$mode" = "broken" ]; then echo 'exit 139'; else
          echo 'case "$1" in'
          echo "  -version) echo \\"[INF] Current Version: v$ver\\" ;;"
          if [ "$mode" = "missing-flag" ]; then
            echo '  -h) echo "  -silent"; echo "  -notjson" ;;'
          else
            echo '  -h) echo "  -silent"; echo "  -json" ;;'
          fi
          echo '  *) echo ok ;;'
          echo 'esac'; fi
        }} > "$out"
        chmod 755 "$out"
        """))
    go.chmod(0o755)
    return str(go)


def layout(tmp: Path) -> Layout:
    return Layout(root=tmp / "repo", state_dir=tmp / "state")


def mode(mode_file: Path, value: str) -> None:
    mode_file.write_text(value)


__all__ = ["parse_fake", "manifest", "write_tool", "make_fake_go", "layout", "mode", "os", "stat"]
