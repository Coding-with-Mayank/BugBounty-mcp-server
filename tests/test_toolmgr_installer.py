"""Installer: staging, validation, backup, atomic swap, rollback."""
import os
import stat

import pytest
from toolmgr_helpers import layout, make_fake_go, manifest, mode, write_tool

from mcp_server.toolmgr import detect, installer, state, versions
from mcp_server.toolmgr.security import run_argv

V = versions.parse


@pytest.fixture
def env(tmp_path):
    lay = layout(tmp_path)
    mf = tmp_path / "mode"
    mode(mf, "ok")
    go = make_fake_go(tmp_path / "gobin", mf)
    return lay, manifest().tools["faketool"], go, mf


def _installed_version(lay, spec):
    return detect.probe(spec, str(lay.tools_dir / spec.binary), "local").version


def test_fresh_install_places_a_verified_binary_and_records_it(env):
    lay, spec, go, _ = env
    r = installer.install_tool(lay, spec, V("2.5.0"), go=go)
    assert r.status == "installed" and r.new == "2.5.0", r.reason
    assert _installed_version(lay, spec) == V("2.5.0")
    rec = state.load_installed(lay)["tools"]["faketool"]
    assert rec["version"] == "2.5.0" and rec["target"] == "github.com/projectdiscovery/faketool/v2/cmd/faketool@v2.5.0"
    assert not [p for p in lay.tools_dir.iterdir() if p.name.startswith(".staging")], "staging dir leaked"


def test_update_keeps_a_backup_of_the_previous_version(env):
    lay, spec, go, _ = env
    write_tool(lay.tools_dir / "faketool", "2.1.0")
    r = installer.install_tool(lay, spec, V("2.6.0"), go=go)
    assert r.status == "updated" and (r.old, r.new) == ("2.1.0", "2.6.0")
    assert [str(v) for v, _ in installer.list_backups(lay, "faketool")] == ["2.1.0"]


@pytest.mark.parametrize("bad_mode,fragment", [
    ("missing-flag", "no longer lists flag"),
    ("wrong-version", "reports 9.9.9"),
    ("broken", "could not"),
    ("build-fail", "go install failed"),
])
def test_failed_validation_keeps_the_working_version(env, bad_mode, fragment):
    lay, spec, go, mf = env
    write_tool(lay.tools_dir / "faketool", "2.1.0")
    before = (lay.tools_dir / "faketool").read_bytes()
    mode(mf, bad_mode)
    r = installer.install_tool(lay, spec, V("2.6.0"), go=go)
    assert r.status == "failed" and fragment in (r.reason or ""), r.reason
    assert (lay.tools_dir / "faketool").read_bytes() == before, "working binary was modified"
    assert _installed_version(lay, spec) == V("2.1.0")
    assert not installer.list_backups(lay, "faketool"), "no swap happened, so no backup needed"


def test_failed_fresh_install_leaves_nothing_behind(env):
    lay, spec, go, mf = env
    mode(mf, "missing-flag")
    r = installer.install_tool(lay, spec, V("2.6.0"), go=go)
    assert r.status == "failed"
    assert not (lay.tools_dir / "faketool").exists()


def test_post_install_failure_restores_the_backup(env, monkeypatch):
    lay, spec, go, _ = env
    write_tool(lay.tools_dir / "faketool", "2.1.0")
    real = installer.validate_binary
    calls = {"n": 0}

    def flaky(spec_, path, expect, runner=run_argv, run_selftest=True):
        calls["n"] += 1
        if path.endswith("/faketool") and ".staging" not in path:      # the post-swap check
            return None, ["simulated post-install failure"]
        return real(spec_, path, expect, runner, run_selftest)

    monkeypatch.setattr(installer, "validate_binary", flaky)
    r = installer.install_tool(lay, spec, V("2.6.0"), go=go)
    assert r.status == "rolled-back" and "restored 2.1.0" in r.reason
    monkeypatch.undo()
    assert _installed_version(lay, spec) == V("2.1.0")


def test_same_version_is_a_noop(env):
    lay, spec, go, _ = env
    write_tool(lay.tools_dir / "faketool", "2.6.0")
    assert installer.install_tool(lay, spec, V("2.6.0"), go=go).status == "unchanged"


def test_refuses_versions_outside_the_tested_range(env):
    lay, spec, go, _ = env
    assert "outside the tested range" in installer.install_tool(lay, spec, V("3.0.0"), go=go).reason
    assert "outside the tested range" in installer.install_tool(lay, spec, V("2.0.5"), go=go).reason


def test_missing_go_is_reported_not_crashed(env, monkeypatch):
    lay, spec, _, _ = env
    monkeypatch.setattr(installer, "find_go", lambda: None)
    r = installer.install_tool(lay, spec, V("2.6.0"))
    assert r.status == "failed" and "Go toolchain not found" in r.reason


def test_rollback_restores_previous_and_is_itself_reversible(env):
    lay, spec, go, _ = env
    write_tool(lay.tools_dir / "faketool", "2.1.0")
    installer.install_tool(lay, spec, V("2.6.0"), go=go)
    r = installer.rollback_tool(lay, spec)
    assert r.status == "updated" and r.new == "2.1.0"
    assert _installed_version(lay, spec) == V("2.1.0")
    assert "2.6.0" in [str(v) for v, _ in installer.list_backups(lay, "faketool")], "rollback must be undoable"
    assert installer.rollback_tool(lay, spec, to=V("2.6.0")).new == "2.6.0"


def test_rollback_with_no_backup_fails_cleanly(env):
    lay, spec, _, _ = env
    assert "no matching backup" in installer.rollback_tool(lay, spec).reason


def test_backups_are_pruned(env):
    lay, spec, go, _ = env
    write_tool(lay.tools_dir / "faketool", "2.1.0")
    for minor in range(2, 8):
        assert installer.install_tool(lay, spec, V(f"2.{minor}.0"), go=go).ok
    assert len(installer.list_backups(lay, "faketool")) == installer.KEEP_BACKUPS


def test_staging_and_backup_dirs_are_private(env):
    lay, spec, go, _ = env
    write_tool(lay.tools_dir / "faketool", "2.1.0")
    installer.install_tool(lay, spec, V("2.6.0"), go=go)
    assert stat.S_IMODE(os.stat(lay.backup_dir).st_mode) == 0o700


def test_symlinked_tools_dir_is_refused(env, tmp_path):
    lay, spec, go, _ = env
    real = tmp_path / "elsewhere"
    real.mkdir()
    lay.tools_dir.parent.mkdir(parents=True)
    os.symlink(real, lay.tools_dir)
    r = installer.install_tool(lay, spec, V("2.6.0"), go=go)
    assert r.status == "failed" and "symlink" in r.reason
    assert not any(real.iterdir())


def test_flag_matching_is_exact(env):
    assert installer.flag_in_help("-json", "  -json   output")
    assert not installer.flag_in_help("-json", "  -jsonl  output")
    assert not installer.flag_in_help("-d", "  --depth")
    assert installer.flag_in_help("-d", "  -d, -domain string")


def test_active_links_follow_selection_and_drop_stale(env, tmp_path):
    lay, spec, *_ = env
    a = write_tool(tmp_path / "a" / "faketool", "2.5.0")
    installer.refresh_active(lay, {"faketool": str(a), "gone": None})
    assert (lay.active_dir / "faketool").resolve() == a.resolve()
    installer.refresh_active(lay, {"faketool": None})
    assert not (lay.active_dir / "faketool").exists()
