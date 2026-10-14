"""The hunt update/doctor/install/rollback/config/auto-update command surface."""
import json
import os

import pytest
import yaml
from toolmgr_helpers import FAKE_MANIFEST, layout, make_fake_go, mode, write_tool

from mcp_server.toolmgr import autoupdate, cli, installer, state, upstream
from mcp_server.toolmgr.security import run_argv as real_run_argv

PROXY = {"projectdiscovery/faketool/v2/@v/list": "v2.1.0\nv2.2.0\nv2.3.1", "projectdiscovery/stdinonly/@v/list": "v0.1.0"}


class FakeHttp:
    def __init__(self, routes, fail=False):
        self.routes, self.fail, self.calls = routes, fail, []

    def get(self, url):
        self.calls.append(url)
        if self.fail:
            raise upstream.UpstreamError("network error: unreachable")
        for k, v in self.routes.items():
            if k in url:
                return v.encode()
        raise upstream.UpstreamError("HTTP 404")


@pytest.fixture
def env(tmp_path, monkeypatch):
    lay = layout(tmp_path)
    (lay.root / "config").mkdir(parents=True)
    lay.manifest.write_text(yaml.safe_dump(FAKE_MANIFEST))
    mf = tmp_path / "mode"
    mode(mf, "ok")
    go = make_fake_go(tmp_path / "gobin", mf)
    monkeypatch.setattr(installer, "find_go", lambda: go)
    monkeypatch.setattr(cli, "Layout", lambda: lay)
    monkeypatch.setattr(cli, "in_docker", lambda: False)
    http = FakeHttp(dict(PROXY))
    monkeypatch.setattr(upstream, "Http", lambda **kw: http)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    for k in ("GOBIN",):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("GOPATH", str(tmp_path / "gp"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PATH", str(tmp_path / "emptybin"))
    monkeypatch.delenv("BBMCP_OFFLINE", raising=False)
    monkeypatch.setattr(cli._Out, "color", False)
    e = type("E", (), {})()
    e.lay, e.http, e.mode = lay, http, mf
    e.tool = lay.tools_dir / "faketool"
    return e


def run(capsys, *argv):
    rc = cli.main(list(argv))
    out = capsys.readouterr()
    return rc, out.out, out.err


def test_doctor_json_is_pure_json_with_legacy_free_machine_fields(env, capsys):
    write_tool(env.tool, "2.1.0")
    rc, out, _ = run(capsys, "doctor", "--json")
    data = json.loads(out)                                   # the WHOLE stdout parses: no banner, no text
    t = next(x for x in data["tools"] if x["tool"] == "faketool")
    assert (t["installed"], t["latest_compatible"], t["status"]) == ("2.1.0", "2.3.1", "UPDATE")
    assert {"python_env", "go", "path_problems", "assets", "status"} <= set(data)


def test_doctor_table_has_the_requested_columns(env, capsys):
    write_tool(env.tool, "2.3.1")
    _, out, _ = run(capsys, "doctor")
    assert "Tool" in out and "Installed" in out and "Latest" in out and "Status" in out
    line = next(ln for ln in out.splitlines() if ln.startswith("faketool"))
    assert "2.3.1" in line and "OK" in line


def test_doctor_strict_fails_when_required_tool_missing_but_default_does_not(env, capsys):
    assert run(capsys, "doctor", "--offline")[0] == 0
    assert run(capsys, "doctor", "--offline", "--strict")[0] == 1


def test_doctor_selftest_catches_a_flag_regression(env, capsys):
    write_tool(env.tool, "2.3.1", flags="-silent")           # lost -json
    rc, out, _ = run(capsys, "doctor", "--offline", "--selftest", "--strict")
    assert rc == 1 and "-json" in out


def test_update_check_changes_nothing_and_can_signal_ci(env, capsys):
    write_tool(env.tool, "2.1.0")
    before = env.tool.read_bytes()
    assert run(capsys, "update", "--check")[0] == 0
    rc, out, _ = run(capsys, "update", "--check", "--fail-on-outdated")
    assert rc == cli.EXIT_OUTDATED and "UPDATE" in out
    assert env.tool.read_bytes() == before and state.load_history(env.lay) == []


def test_update_dry_run_modifies_nothing(env, capsys):
    write_tool(env.tool, "2.1.0")
    before = env.tool.read_bytes()
    rc, out, _ = run(capsys, "update", "--dry-run")
    assert rc == 0 and "Dry run" in out
    assert env.tool.read_bytes() == before
    assert not env.lay.history_file.exists() and not env.lay.backup_dir.exists()


def test_update_without_confirmation_or_tty_refuses(env, capsys, monkeypatch):
    write_tool(env.tool, "2.1.0")
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    rc, _, err = run(capsys, "update", "--no-templates")
    assert rc == cli.EXIT_USAGE and "--yes" in err
    assert "2.1.0" in env.tool.read_text()


def test_update_yes_applies_and_reports_like_the_spec(env, capsys):
    write_tool(env.tool, "2.1.0")
    rc, out, _ = run(capsys, "update", "--yes", "--no-templates")
    assert rc == 0
    line = next(ln for ln in out.splitlines() if ln.startswith("faketool") and "UPDATED" in ln)
    assert "2.1.0" in line and "2.3.1" in line
    assert state.load_history(env.lay)[-1]["new_version"] == "2.3.1"
    assert (env.lay.active_dir / "faketool").exists()


def test_update_failure_is_reported_and_old_version_survives(env, capsys):
    write_tool(env.tool, "2.1.0")
    mode(env.mode, "missing-flag")
    rc, out, _ = run(capsys, "update", "--yes", "--no-templates")
    assert rc == 1 and "FAILED" in out and "still in place" in out
    assert "2.1.0" in env.tool.read_text()


def test_update_when_offline_keeps_everything(env, capsys):
    write_tool(env.tool, "2.1.0")
    env.http.fail = True
    rc, out, _ = run(capsys, "update", "--yes", "--no-templates")
    assert rc == 0 and "Update check failed" in out and "Nothing was changed" in out
    assert "2.1.0" in env.tool.read_text()


def test_update_major_is_reported_with_the_exact_command(env, capsys):
    env.http.routes["projectdiscovery/faketool/v3/@v/list"] = "v3.0.0"
    write_tool(env.tool, "2.3.1")
    _, out, _ = run(capsys, "update", "--check")
    assert "Major update detected" in out and "./hunt update --major" in out
    assert "2.3.1" in env.tool.read_text()


def test_update_refuses_to_run_as_root(env, capsys, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    write_tool(env.tool, "2.1.0")
    rc, _, err = run(capsys, "update", "--yes")
    assert rc == 1 and "refusing to run as root" in err
    assert run(capsys, "update", "--check")[0] == 0, "read-only commands stay available to root"


def test_install_picks_latest_and_install_with_lock_reproduces(env, capsys, tmp_path):
    rc, out, _ = run(capsys, "install", "--tool", "faketool")
    assert rc == 0 and "2.3.1" in out
    lockfile = tmp_path / "lock.json"
    write_tool(env.tool, "2.2.0")
    run(capsys, "snapshot", "--output", str(lockfile))
    env.tool.unlink()
    rc, out, _ = run(capsys, "install", "--lock", str(lockfile))
    assert rc == 0 and "2.2.0" in out and "2.3.1" not in out.split("faketool")[1].split("\n")[0]


def test_install_without_go_explains_what_to_do(env, capsys, monkeypatch):
    monkeypatch.setattr(installer, "find_go", lambda: None)
    rc, out, _ = run(capsys, "install")
    assert rc == 1 and "Go toolchain not found" in out


def test_install_reports_failed_required_tool_and_strict_fails(env, capsys):
    mode(env.mode, "build-fail")
    assert run(capsys, "install", "--tool", "faketool")[0] == 0         # installer scripts tolerate it
    rc, out, _ = run(capsys, "install", "--tool", "faketool", "--strict")
    assert rc == 1 and "Required tool(s) not installed" in out


def test_rollback_command(env, capsys):
    write_tool(env.tool, "2.1.0")
    run(capsys, "update", "--yes", "--no-templates")
    rc, out, _ = run(capsys, "rollback", "faketool", "--yes")
    assert rc == 0 and "2.1.0" in out and "UPDATED" in out
    assert state.load_history(env.lay)[-1]["source"] == "rollback"
    assert run(capsys, "rollback", "nosuchtool", "--yes")[0] == cli.EXIT_USAGE


def test_config_tools_shows_every_copy_and_pin_works(env, capsys, tmp_path, monkeypatch):
    sysdir = tmp_path / "sys"
    write_tool(sysdir / "faketool", "2.1.0")
    write_tool(env.tool, "2.3.1")
    monkeypatch.setenv("PATH", str(sysdir))
    _, out, _ = run(capsys, "config", "tools")
    row = next(ln for ln in out.splitlines() if ln.startswith("faketool"))
    assert "local 2.3.1" in row and "system 2.1.0" in row
    run(capsys, "config", "tools", "set", "faketool", "system")
    _, out, _ = run(capsys, "config", "tools")
    assert "system 2.1.0" in next(ln for ln in out.splitlines() if ln.startswith("faketool"))
    assert run(capsys, "config", "tools", "set", "faketool", "bogus")[0] == cli.EXIT_USAGE


def test_verify_is_a_strict_gate(env, capsys):
    assert run(capsys, "verify")[0] == 1
    write_tool(env.tool, "2.3.1")
    assert run(capsys, "verify")[0] == 0
    write_tool(env.tool, "2.3.1", flags="-silent")
    assert run(capsys, "verify")[0] == 1


# ── auto-update: opt-in, throttled, never root ────────────────────────
def test_auto_run_does_nothing_unless_enabled(env, capsys):
    write_tool(env.tool, "2.1.0")
    rc, out, _ = run(capsys, "update", "--auto")
    assert rc == 0 and "not enabled" in out and "2.1.0" in env.tool.read_text()
    assert env.http.calls == [], "a disabled auto-update must not even touch the network"


def test_auto_run_applies_safe_updates_and_then_throttles(env, capsys):
    write_tool(env.tool, "2.1.0")
    autoupdate.save(env.lay, autoupdate.Settings(enabled=True, interval_hours=24))
    rc, out, _ = run(capsys, "update", "--auto")
    assert rc == 0 and "2.3.1" in env.tool.read_text()
    calls = len(env.http.calls)
    rc, out, _ = run(capsys, "update", "--auto")
    assert "throttled" in out and len(env.http.calls) == calls


def test_auto_run_never_applies_majors(env, capsys):
    env.http.routes["projectdiscovery/faketool/v3/@v/list"] = "v3.0.0"
    write_tool(env.tool, "2.3.1")
    autoupdate.save(env.lay, autoupdate.Settings(enabled=True))
    run(capsys, "update", "--auto", "--major")
    assert "2.3.1" in env.tool.read_text()


def test_auto_run_refuses_root(env, capsys, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    autoupdate.save(env.lay, autoupdate.Settings(enabled=True))
    assert run(capsys, "update", "--auto")[0] == 1


def test_auto_update_enable_describes_before_acting_and_needs_consent(env, capsys, monkeypatch):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    rc, out, _ = run(capsys, "auto-update", "enable")
    assert "never apply a major" in out and "Not enabled" in out
    assert not autoupdate.load(env.lay).enabled


def test_auto_update_enable_and_disable_lifecycle(env, capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    calls = []
    def fake_run(argv, timeout=15, env=None, cwd=None):
        calls.append(list(argv))
        return real_run_argv(["/bin/true"])
    monkeypatch.setattr(autoupdate, "run_argv", fake_run)
    monkeypatch.setattr(autoupdate, "systemd_available", lambda runner=None: True)
    rc, out, err = run(capsys, "auto-update", "enable", "--yes", "--apt-signal")
    assert rc == 0 and autoupdate.load(env.lay).enabled, err
    units = tmp_path / "xdg" / "systemd" / "user"
    assert {p.name for p in units.iterdir()} == {"bugbounty-mcp-update.service", "bugbounty-mcp-update.timer",
                                                 "bugbounty-mcp-update.path"}
    assert "sudo tee /etc/apt/apt.conf.d/99bugbounty-mcp-signal" in out
    assert not any(c[0] == "sudo" for c in calls), "must never invoke sudo itself"
    rc, out, _ = run(capsys, "auto-update", "disable")
    assert not autoupdate.load(env.lay).enabled and not list(units.iterdir())
    assert "sudo rm -f /etc/apt/apt.conf.d/99bugbounty-mcp-signal" in out


def test_generated_units_and_apt_hook_are_inert_by_design():
    svc = autoupdate.render_service(__import__("pathlib").Path("/opt/my repo"))
    assert 'ExecStart="/opt/my repo/hunt" update --auto' in svc and "NoNewPrivileges=yes" in svc
    assert "sudo" not in svc
    hook = autoupdate.APT_CONF_TEXT
    code = "\n".join(ln for ln in hook.splitlines() if not ln.startswith("//"))     # what apt actually executes
    assert code.count("touch /var/lib/bugbounty-mcp/apt-signal") == 2
    for forbidden in ("hunt", "curl", "wget", "git", "python", "bash", "sh -c", "http"):
        assert forbidden not in code, f"the root hook must not reference {forbidden!r}"
    with pytest.raises(autoupdate.SecurityError):
        autoupdate._q("/bad\npath")


def test_total_outage_is_explained_once_not_once_per_tool(env, capsys):
    write_tool(env.tool, "2.1.0")
    env.http.fail = True
    rc, out, _ = run(capsys, "update", "--check")
    assert rc == 0
    assert out.count("Update check failed") == 1 and "network error: unreachable" in out
    row = next(ln for ln in out.splitlines() if ln.startswith("faketool"))
    assert "2.1.0" in row and "UNCHECKED" in row
    assert "BLOCKED" not in out, "an outage is not a per-tool block"


def test_partial_outage_names_the_cause_once_and_leaves_those_tools_alone(env, capsys):
    write_tool(env.tool, "2.1.0")
    before = env.tool.read_bytes()
    env.http.routes = {"projectdiscovery/stdinonly/@v/list": "v0.1.0"}      # faketool's lookup 404s; stdinonly's works
    rc, out, _ = run(capsys, "update", "--yes", "--no-templates")
    assert rc == 0
    assert "Could not check 1 tool(s)" in out and out.count("could not check upstream") == 1
    assert env.tool.read_bytes() == before


def test_piping_into_head_is_not_a_traceback(tmp_path):
    import subprocess
    import sys
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    env = {**os.environ, "BBMCP_OFFLINE": "1", "BBMCP_STATE_DIR": str(tmp_path)}
    proc = subprocess.Popen([sys.executable, "-m", "mcp_server.toolmgr", "doctor", "--json"], cwd=root, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.stdout.read(1)
    proc.stdout.close()                                   # the reader goes away mid-output
    err = proc.stderr.read().decode()
    assert proc.wait(timeout=30) == 0 and "Traceback" not in err, err
