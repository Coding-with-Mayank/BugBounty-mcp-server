"""
autoupdate.py — OPT-IN background update checks. Off unless you enable it.

What `hunt auto-update enable` creates (user level — no root, ever):

  ~/.config/systemd/user/bugbounty-mcp-update.service   runs `hunt update --auto`
  ~/.config/systemd/user/bugbounty-mcp-update.timer     once a day (+ catch-up, + jitter)
  <state>/auto-update.json                              enabled flag + interval

`--auto` is conservative: patch/minor releases of tools THIS project installed,
compatibility-tested before the swap, nothing else. Majors are never applied.

Optional APT signal (`--apt-signal`): APT can't update this project, and we
refuse to run repository code as root from an APT hook. Instead a 2-line root
hook only `touch`es a marker file; a user-level systemd .path unit notices and
starts the SAME throttled user-level check. The root-side text is printed for
you to read and install yourself — nothing here ever invokes sudo.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path

from .layout import Layout
from .security import SecurityError, atomic_write_json, read_json, run_argv

UNIT = "bugbounty-mcp-update"
APT_MARKER_DIR = "/var/lib/bugbounty-mcp"
APT_MARKER = f"{APT_MARKER_DIR}/apt-signal"
APT_CONF = "/etc/apt/apt.conf.d/99bugbounty-mcp-signal"

APT_CONF_TEXT = f"""\
// bugbounty-mcp-server: update signal. Installed by YOU, on purpose.
// Does exactly one thing: touch a marker file. No repository code runs here,
// no network is used, nothing is updated by APT itself. A user-level systemd
// unit watching the marker starts the throttled `hunt update --auto`.
DPkg::Post-Invoke {{ "test -d {APT_MARKER_DIR} && touch {APT_MARKER} || true"; }};
APT::Update::Post-Invoke-Success {{ "test -d {APT_MARKER_DIR} && touch {APT_MARKER} || true"; }};
"""


def _q(path: str) -> str:
    """Quote for a systemd unit: double %, escape quotes/backslashes."""
    if any(ch in path for ch in "\n\r\0"):
        raise SecurityError("unsafe character in path")
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'


def user_unit_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "systemd" / "user"


def render_service(root: Path) -> str:
    return f"""\
[Unit]
Description=BugBounty MCP tool update check (safe updates only)

[Service]
Type=oneshot
ExecStart={_q(str(root / "hunt"))} update --auto
Nice=10
IOSchedulingClass=idle
TimeoutStartSec=2h
NoNewPrivileges=yes
PrivateTmp=yes
LockPersonality=yes
RestrictSUIDSGID=yes
ProtectKernelTunables=yes
"""


def render_timer(interval_hours: int) -> str:
    return f"""\
[Unit]
Description=Daily BugBounty MCP tool update check

[Timer]
OnBootSec=15min
OnUnitActiveSec={int(interval_hours)}h
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
"""


def render_path_unit() -> str:
    return f"""\
[Unit]
Description=Run the BugBounty MCP update check after APT activity

[Path]
PathChanged={APT_MARKER}
Unit={UNIT}.service

[Install]
WantedBy=default.target
"""


@dataclass
class Settings:
    enabled: bool = False
    interval_hours: int = 24
    apt_signal: bool = False
    last_auto_run: float = 0.0


def load(layout: Layout) -> Settings:
    d = read_json(layout.autoupdate_file, {}) or {}
    try:
        return Settings(bool(d.get("enabled", False)), max(1, int(d.get("interval_hours", 24))),
                        bool(d.get("apt_signal", False)), float(d.get("last_auto_run", 0)))
    except (TypeError, ValueError):
        return Settings()


def save(layout: Layout, s: Settings) -> None:
    atomic_write_json(layout.autoupdate_file, {
        "schema": 1, "enabled": s.enabled, "interval_hours": s.interval_hours,
        "apt_signal": s.apt_signal, "last_auto_run": s.last_auto_run})


def due(s: Settings, now: float | None = None) -> bool:
    return (now if now is not None else time.time()) - s.last_auto_run >= s.interval_hours * 3600


def describe(root: Path, interval: int, apt_signal: bool) -> str:
    lines = [
        "Enabling automatic updates will:",
        f"  • write {user_unit_dir()}/{UNIT}.service and .timer (your user only, no root)",
        f"  • run `{root}/hunt update --auto` about every {interval}h, via systemd --user",
        "  • apply ONLY patch/minor releases of tools this project installed itself,",
        "    after each passes the compatibility self-test; a failure keeps the old version",
        "  • never apply a major release, never touch system packages, never use sudo",
        "  • log every action to data/update-history.json",
    ]
    if apt_signal:
        lines += ["  • also install a .path unit that reacts to the APT marker file (root-side text shown below)"]
    lines += ["Undo any time with: ./hunt auto-update disable"]
    return "\n".join(lines)


def systemd_available(runner=None) -> bool:
    runner = runner or run_argv
    return runner(["systemctl", "--user", "show-environment"], timeout=10).ok


def enable(layout: Layout, interval: int, apt_signal: bool, runner=None) -> list[str]:
    runner = runner or run_argv       # resolved at call time so it can be substituted
    if os.geteuid() == 0:
        raise SecurityError("auto-update is a per-user feature; run it as your normal user, not root")
    if not systemd_available(runner):
        raise SecurityError("systemd --user is not available here (macOS, containers, WSL1?). "
                            "Use cron/launchd yourself with: <repo>/hunt update --auto")
    d = user_unit_dir()
    d.mkdir(parents=True, exist_ok=True)
    written = []
    files = {f"{UNIT}.service": render_service(layout.root), f"{UNIT}.timer": render_timer(interval)}
    if apt_signal:
        files[f"{UNIT}.path"] = render_path_unit()
    for name, text in files.items():
        p = d / name
        tmp = d / f".{name}.{os.getpid()}"
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, p)
        written.append(str(p))
    for argv in (["systemctl", "--user", "daemon-reload"],
                 ["systemctl", "--user", "enable", "--now", f"{UNIT}.timer"],
                 *([["systemctl", "--user", "enable", "--now", f"{UNIT}.path"]] if apt_signal else [])):
        res = runner(argv, timeout=30)
        if not res.ok:
            raise SecurityError(f"`{' '.join(argv)}` failed: {res.output.strip()[:200]}")
    save(layout, Settings(True, interval, apt_signal, 0.0))
    return written


def disable(layout: Layout, runner=None) -> list[str]:
    runner = runner or run_argv
    removed = []
    for suffix in ("timer", "path", "service"):
        unit = f"{UNIT}.{suffix}"
        if suffix != "service":
            runner(["systemctl", "--user", "disable", "--now", unit], timeout=30)
        p = user_unit_dir() / unit
        if p.exists():
            p.unlink()
            removed.append(str(p))
    runner(["systemctl", "--user", "daemon-reload"], timeout=30)
    cur = load(layout)
    cur.enabled, cur.apt_signal = False, False
    save(layout, cur)
    return removed


def apt_instructions(install: bool = True) -> str:
    if install:
        return (
            "Root-side APT signal (optional). Read it, then run it yourself:\n\n"
            f"  sudo install -d -m 0755 {APT_MARKER_DIR}\n"
            f"  sudo tee {APT_CONF} >/dev/null <<'EOF'\n{APT_CONF_TEXT}EOF\n\n"
            "This only touches a marker file after apt runs; the repository is never executed as root."
        )
    return f"Remove the APT signal:\n\n  sudo rm -f {APT_CONF}\n  sudo rm -rf {APT_MARKER_DIR}\n"
