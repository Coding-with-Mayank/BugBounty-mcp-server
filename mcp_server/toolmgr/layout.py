"""
layout.py — where everything lives on disk.

  <root>/config/tools.yaml        the manifest (committed)
  <root>/config/tool-lock.json    optional exact-version lock (committed on purpose)
  <root>/bin/tools/               project-local binaries
  <root>/bin/tools/.backup/       previous versions kept for `hunt rollback`
  <root>/bin/active/              symlinks to whichever binary is SELECTED per tool
  <state>/installed-tools.json    what is actually installed (NOT committed)
  <state>/update-history.json     audit log (NOT committed)
  <state>/cache/upstream.json     throttled upstream lookups
  <state>/tool-selection.json     user's system/local choice per tool
  <state>/auto-update.json        opt-in auto-update settings

<state> is BBMCP_STATE_DIR if set, else <root>/data (git-ignored).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path

# mcp_server/toolmgr/layout.py -> repo root (or /app in the Docker image).
REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Layout:
    root: Path = REPO_ROOT
    state_dir: Path = field(default=None)  # type: ignore[assignment]
    tools_dir: Path = field(default=None)  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.state_dir is None:
            env = os.environ.get("BBMCP_STATE_DIR")
            object.__setattr__(self, "state_dir", Path(env) if env else self.root / "data")
        if self.tools_dir is None:
            object.__setattr__(self, "tools_dir", self.root / "bin" / "tools")

    def with_tools_dir(self, path: Path) -> Layout:
        return replace(self, tools_dir=Path(path))

    @property
    def manifest(self) -> Path:
        return self.root / "config" / "tools.yaml"

    @property
    def default_lock(self) -> Path:
        return self.root / "config" / "tool-lock.json"

    @property
    def backup_dir(self) -> Path:
        return self.tools_dir / ".backup"

    @property
    def active_dir(self) -> Path:
        return self.root / "bin" / "active"

    @property
    def installed_file(self) -> Path:
        return self.state_dir / "installed-tools.json"

    @property
    def history_file(self) -> Path:
        return self.state_dir / "update-history.json"

    @property
    def cache_file(self) -> Path:
        return self.state_dir / "cache" / "upstream.json"

    @property
    def selection_file(self) -> Path:
        return self.state_dir / "tool-selection.json"

    @property
    def autoupdate_file(self) -> Path:
        return self.state_dir / "auto-update.json"

    @property
    def lock_file(self) -> Path:
        return self.state_dir / ".update.lock"
