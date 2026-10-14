"""Update policy and orchestration, driven by a fake upstream and a fake `go`."""
import json

import pytest
from toolmgr_helpers import layout, make_fake_go, manifest, mode, write_tool

from mcp_server.toolmgr import installer, ops, state, upstream, versions
from mcp_server.toolmgr.manifest import ManifestError
from mcp_server.toolmgr.security import SecurityError

V = versions.parse


class FakeHttp:
    """Stands in for proxy.golang.org / api.github.com."""
    def __init__(self, routes=None, fail=False):
        self.routes, self.fail, self.calls = routes or {}, fail, []

    def get(self, url):
        self.calls.append(url)
        if self.fail:
            raise upstream.UpstreamError("network error: unreachable")
        for key, body in self.routes.items():
            if key in url:
                return body.encode()
        raise upstream.UpstreamError("HTTP 404")


PROXY = {
    "projectdiscovery/faketool/v2/@v/list": "v2.0.5\nv2.1.0\nv2.2.0\nv2.3.1\nv2.4.0-rc1",
    "projectdiscovery/stdinonly/@v/list": "v0.1.0\nv0.1.1",
}


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch, tmp_path):
    monkeypatch.delenv("GOBIN", raising=False)
    monkeypatch.setenv("GOPATH", str(tmp_path / "gopath"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("BBMCP_STATE_DIR", str(tmp_path / "state"))


@pytest.fixture
def ctx(tmp_path):
    mf = tmp_path / "mode"
    mode(mf, "ok")
    go = make_fake_go(tmp_path / "gobin", mf)
    sysdir = tmp_path / "sysbin"
    sysdir.mkdir()
    c = ops.Context(layout(tmp_path), manifest(), FakeHttp(dict(PROXY)), go=go, path_env=str(sysdir))
    c.sysdir, c.modefile = sysdir, mf          # handy handles for tests
    return c


def status_of(ctx, tool="faketool"):
    return ops.collect(ctx, [tool])[0]


# ── Scenario A: fresh install resolves the newest COMPATIBLE release now ──
def test_fresh_install_picks_newest_stable_in_tested_major(ctx):
    res = ops.install_all(ctx, ["faketool"])
    assert res[0].status == "installed" and res[0].new == "2.3.1", res[0].reason     # not rc1, not v3


def test_install_is_exact_when_a_newer_major_exists_upstream(ctx):
    ctx.http.routes["projectdiscovery/faketool/v3/@v/list"] = "v3.0.0\nv3.1.0"
    lt = upstream.latest_for(ctx.manifest.tools["faketool"], ctx.http)
    assert lt.version == V("2.3.1") and lt.newer_major == V("3.1.0")
    assert ops.install_all(ctx, ["faketool"])[0].new == "2.3.1"


# ── Scenario B/E: patch+minor auto, major reported not applied ────────
def test_update_applies_minor_and_keeps_backup(ctx):
    write_tool(ctx.layout.tools_dir / "faketool", "2.1.0")
    plan = ops.make_plan(ops.collect(ctx, ["faketool"]))
    assert (plan[0].action, plan[0].kind, plan[0].target) == ("update", "minor", "2.3.1")
    res = ops.apply_plan(ctx, plan)
    assert res[0].status == "updated"
    assert state.load_history(ctx.layout)[-1]["status"] == "success"


def test_major_is_reported_and_not_installed_by_default(ctx):
    ctx.http.routes["projectdiscovery/faketool/v3/@v/list"] = "v3.0.0"
    write_tool(ctx.layout.tools_dir / "faketool", "2.3.1")
    ts = status_of(ctx)
    assert ts.status == "MAJOR" and "--major" in ts.detail
    plan = ops.make_plan([ts])
    assert plan[0].action == "skip" and "major v3.x available" in plan[0].note
    assert ops.apply_plan(ctx, plan) == []


def test_major_flag_plans_the_new_major_and_remembers_acceptance(ctx):
    ctx.http.routes["projectdiscovery/faketool/v3/@v/list"] = "v3.0.0"
    write_tool(ctx.layout.tools_dir / "faketool", "2.3.1")
    plan = ops.make_plan([status_of(ctx)], major=True)
    assert (plan[0].action, plan[0].kind, plan[0].target, plan[0].major) == ("update", "major", "3.0.0", 3)
    res = ops.apply_plan(ctx, plan)
    assert res[0].status == "updated", res[0].reason
    assert state.accepted_majors(state.load_selection(ctx.layout), "faketool") == frozenset({3})
    assert status_of(ctx).selection.chosen.version == V("3.0.0"), "accepted major must stay selected"


def test_zero_x_minor_counts_as_major(ctx):
    spec = ctx.manifest.tools["stdinonly"]
    assert versions.classify(V("0.1.1"), V("0.2.0")) == "major"
    assert spec.accepts(V("0.1.5"))


def test_never_downgrades(ctx):
    write_tool(ctx.layout.tools_dir / "faketool", "2.9.0")
    ts = status_of(ctx)
    assert ts.status == "OK"
    assert ops.make_plan([ts])[0].action == "skip"


# ── Scenario D: offline / upstream down ───────────────────────────────
def test_upstream_failure_changes_nothing(ctx):
    write_tool(ctx.layout.tools_dir / "faketool", "2.1.0")
    before = (ctx.layout.tools_dir / "faketool").read_bytes()
    ctx.http = FakeHttp(fail=True)
    ts = status_of(ctx)
    assert ts.status == "UNKNOWN"
    plan = ops.make_plan([ts])
    assert plan[0].action == "skip" and "upstream unavailable" in plan[0].reason
    ops.apply_plan(ctx, plan)
    assert (ctx.layout.tools_dir / "faketool").read_bytes() == before


def test_offline_flag_never_touches_the_network(ctx):
    ctx.offline = True
    ctx.http = FakeHttp(dict(PROXY))
    write_tool(ctx.layout.tools_dir / "faketool", "2.1.0")
    status_of(ctx)
    assert ctx.http.calls == []


def test_cache_throttles_lookups(ctx):
    status_of(ctx)
    n = len(ctx.http.calls)
    assert n > 0
    status_of(ctx)
    assert len(ctx.http.calls) == n, "second check within the interval must come from cache"
    ctx.refresh = True
    status_of(ctx)
    assert len(ctx.http.calls) > n


def test_offline_falls_back_to_a_stale_cache_and_says_so(ctx):
    status_of(ctx)
    ctx.offline = True
    ts = status_of(ctx)
    assert ts.latest.version == V("2.3.1") and "offline" in (ts.latest.error or "")


def test_missing_tool_and_failed_install_are_reported(ctx):
    mode(ctx.modefile, "build-fail")
    res = ops.install_all(ctx, ["faketool"])
    assert res[0].status == "failed" and not (ctx.layout.tools_dir / "faketool").exists()


# ── Section 17: system vs project-local ───────────────────────────────
def test_newer_system_copy_beats_older_local_and_no_duplicate_is_installed(ctx):
    write_tool(ctx.sysdir / "faketool", "2.3.1")
    write_tool(ctx.layout.tools_dir / "faketool", "2.1.0")
    ts = status_of(ctx)
    assert ts.selection.chosen.source == "system" and ts.installed == V("2.3.1")
    assert "ignored older: local 2.1.0" in ts.selection.reason
    res = ops.install_all(ctx, ["faketool"])
    assert res[0].status == "unchanged" and "existing system copy" in res[0].reason
    assert "2.1.0" in (ctx.layout.tools_dir / "faketool").read_text(), "the local copy must not have been replaced"


def test_older_system_copy_is_never_modified_and_a_local_copy_is_added(ctx):
    sysbin = write_tool(ctx.sysdir / "faketool", "2.1.0")
    before = sysbin.read_bytes()
    res = ops.apply_plan(ctx, ops.make_plan(ops.collect(ctx, ["faketool"])))
    assert res[0].status == "installed"
    assert sysbin.read_bytes() == before
    ts = status_of(ctx)
    assert ts.selection.chosen.source == "local" and ts.installed == V("2.3.1")


def test_user_pin_to_system_is_honoured(ctx):
    write_tool(ctx.sysdir / "faketool", "2.1.0")
    write_tool(ctx.layout.tools_dir / "faketool", "2.3.1")
    sel = state.load_selection(ctx.layout)
    sel["prefer"]["faketool"] = "system"
    state.save_selection(ctx.layout, sel)
    assert status_of(ctx).selection.chosen.source == "system"


def test_refresh_selection_links_the_chosen_binary(ctx):
    sysbin = write_tool(ctx.sysdir / "faketool", "2.3.1")
    write_tool(ctx.layout.tools_dir / "faketool", "2.1.0")
    chosen = ops.refresh_selection(ctx)
    assert (ctx.layout.active_dir / "faketool").resolve() == sysbin.resolve()
    assert chosen["faketool"] == str(sysbin)


def test_update_never_installs_an_optional_tool_you_did_not_ask_for(ctx):
    plan = ops.make_plan(ops.collect(ctx, ["stdinonly"]))
    assert plan[0].action == "skip" and "hunt install --tool stdinonly" in plan[0].reason
    assert ops.make_plan(ops.collect(ctx, ["stdinonly"]), explicit=frozenset({"stdinonly"}))[0].action == "install"
    # ...but a REQUIRED tool that is missing is repaired by a plain update
    assert ops.make_plan(ops.collect(ctx, ["faketool"]))[0].action == "install"


# ── auto mode ─────────────────────────────────────────────────────────
def test_auto_mode_only_touches_tools_this_project_installed(ctx):
    write_tool(ctx.sysdir / "faketool", "2.1.0")                      # system only, no local copy
    plan = ops.make_plan(ops.collect(ctx, ["faketool"]), auto=True)
    assert plan[0].action == "skip"
    write_tool(ctx.layout.tools_dir / "faketool", "2.1.0")
    assert ops.make_plan(ops.collect(ctx, ["faketool"]), auto=True)[0].action == "update"


def test_auto_mode_never_does_major(ctx):
    ctx.http.routes["projectdiscovery/faketool/v3/@v/list"] = "v3.0.0"
    write_tool(ctx.layout.tools_dir / "faketool", "2.3.1")
    plan = ops.make_plan(ops.collect(ctx, ["faketool"]), major=True, auto=True)
    assert plan[0].action == "skip"


# ── broken / incompatible installs ────────────────────────────────────
def test_broken_binary_is_reported_broken_and_repaired_by_install(ctx):
    write_tool(ctx.layout.tools_dir / "faketool", "2.1.0", broken=True)
    assert status_of(ctx).status == "BROKEN"
    assert ops.apply_plan(ctx, ops.make_plan(ops.collect(ctx, ["faketool"])))[0].status == "installed"
    assert status_of(ctx).status == "OK"


def test_too_old_install_is_incompatible(ctx):
    write_tool(ctx.layout.tools_dir / "faketool", "2.0.5")
    assert status_of(ctx).status == "INCOMPATIBLE"


def test_untested_major_install_is_flagged_not_selected(ctx):
    write_tool(ctx.layout.tools_dir / "faketool", "3.1.0")
    assert status_of(ctx).status == "UNTESTED"


# ── upgrade FROM the versions this repo used to ship, then roll back ──
def test_upgrade_from_legacy_pin_then_rollback(ctx):
    write_tool(ctx.layout.tools_dir / "faketool", "2.1.0")           # == manifest min / the old pin
    assert ops.apply_plan(ctx, ops.make_plan(ops.collect(ctx, ["faketool"])))[0].new == "2.3.1"
    spec = ctx.manifest.tools["faketool"]
    assert installer.rollback_tool(ctx.layout, spec).new == "2.1.0"
    assert status_of(ctx).installed == V("2.1.0")


def test_failed_update_keeps_old_and_logs_failure(ctx):
    write_tool(ctx.layout.tools_dir / "faketool", "2.1.0")
    mode(ctx.modefile, "missing-flag")
    res = ops.apply_plan(ctx, ops.make_plan(ops.collect(ctx, ["faketool"])))
    assert res[0].status == "failed"
    assert status_of(ctx).installed == V("2.1.0")
    last = state.load_history(ctx.layout)[-1]
    assert last["status"] == "failure" and "flag" in last["reason"] and last["old_version"] == "2.1.0"


# ── Scenario H: lock / snapshot ───────────────────────────────────────
def test_snapshot_then_install_from_lock_reproduces_versions(ctx, tmp_path):
    write_tool(ctx.layout.tools_dir / "faketool", "2.2.0")
    lock = ops.snapshot(ctx)
    assert lock["tools"]["faketool"] == {
        "version": "2.2.0", "target": "github.com/projectdiscovery/faketool/v2/cmd/faketool@v2.2.0"}
    p = tmp_path / "lock.json"
    p.write_text(json.dumps(lock))
    (ctx.layout.tools_dir / "faketool").unlink()
    res = ops.install_all(ctx, lock=state.load_lock(ctx.manifest, p))
    assert res[0].status == "installed" and res[0].new == "2.2.0"       # NOT 2.3.1
    assert state.load_selection(ctx.layout)["prefer"]["faketool"] == "local"


@pytest.mark.parametrize("mutate", [
    lambda d: d["tools"]["faketool"].update(target="github.com/evil/faketool/v2/cmd/faketool@v2.2.0"),
    lambda d: d["tools"]["faketool"].update(version="2.2.0-rc1"),
    lambda d: d["tools"]["faketool"].update(version="3.0.0", target="github.com/projectdiscovery/faketool/v3/cmd/faketool@v3.0.0"),
    lambda d: d["tools"].update({"../../evil": {"version": "1.0.0", "target": "x"}}),
    lambda d: d["tools"].update({"unknowntool": {"version": "1.0.0", "target": "x"}}),
    lambda d: d.update(schema=2),
])
def test_tampered_lock_is_rejected(ctx, mutate):
    lock = {"schema": 1, "tools": {"faketool": {
        "version": "2.2.0", "target": "github.com/projectdiscovery/faketool/v2/cmd/faketool@v2.2.0"}}}
    mutate(lock)
    with pytest.raises((SecurityError, ManifestError)):
        state.validate_lock(ctx.manifest, lock)


# ── assets (nuclei-templates-style) are separate from the engine ──────
@pytest.fixture
def asset_ctx(ctx, tmp_path):
    data = tmp_path / "data-version"
    data.write_text("v1.0.0")
    exe = ctx.layout.tools_dir / "faketool"
    exe.parent.mkdir(parents=True)
    exe.write_text(f"""#!/bin/sh
case "$1" in
  -version) echo "[INF] Current Version: v2.3.1" ;;
  -h) echo " -silent -json" ;;
  -data-version) echo "[INF] data version: $(cat {data})" ;;
  -update-data) echo v1.1.0 > {data}; echo updated ;;
esac
""")
    exe.chmod(0o755)
    ctx.http.routes["projectdiscovery/faketool-data/releases"] = json.dumps(
        [{"tag_name": "v1.1.0"}, {"tag_name": "v1.0.0"}, {"tag_name": "v1.2.0-beta", "prerelease": True}])
    ctx.manifest.assets["faketool-data"] = type(ctx.manifest.assets["faketool-data"])(
        "faketool-data", "", "faketool", "projectdiscovery/faketool-data", ("-update-data",), ("-data-version",),
        r"data version:\s*v?(\d+\.\d+\.\d+)")
    return ctx


def test_asset_status_reports_engine_and_data_separately(asset_ctx):
    s = ops.asset_status(asset_ctx, "faketool-data")
    assert (s["status"], s["installed"], s["latest_compatible"]) == ("UPDATE", "1.0.0", "1.1.0")   # prerelease ignored
    assert status_of(asset_ctx).status == "OK", "the engine is fine while the data is stale"


def test_asset_dry_run_changes_nothing(asset_ctx, tmp_path):
    r = ops.update_asset(asset_ctx, "faketool-data", dry_run=True)
    assert r.status == "planned" and (tmp_path / "data-version").read_text() == "v1.0.0"
    assert state.load_history(asset_ctx.layout) == []


def test_asset_update_runs_the_tools_own_updater_and_logs_it(asset_ctx, tmp_path):
    r = ops.update_asset(asset_ctx, "faketool-data")
    assert (r.status, r.old, r.new) == ("updated", "1.0.0", "1.1.0")
    h = state.load_history(asset_ctx.layout)[-1]
    assert h["kind"] == "asset" and h["tool"] == "faketool-data" and h["status"] == "success"
    assert ops.asset_status(asset_ctx, "faketool-data")["status"] == "OK"


def test_asset_without_its_tool_is_missing(ctx):
    s = ops.asset_status(ctx, "faketool-data")
    assert s["status"] == "MISSING"
    assert "not installed" in ops.update_asset(ctx, "faketool-data").reason
