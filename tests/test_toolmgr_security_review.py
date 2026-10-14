"""
Findings from the security review of the updater, each written as the ATTACK.

  command injection · path traversal · malicious release metadata · compromised
  download URLs · unsafe archive extraction · symlink attacks · running
  downloaded code as root · env-var injection · PATH hijack · repo compromise ·
  unsafe temp files · TOCTOU · privilege escalation
"""
import json
import os
from pathlib import Path

import pytest
from toolmgr_helpers import layout, make_fake_go, manifest, mode, write_tool

from mcp_server.toolmgr import detect, installer, ops, security, state, upstream, versions
from mcp_server.toolmgr.security import SecurityError

V = versions.parse
SPEC = manifest().tools["faketool"]


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.delenv("GOBIN", raising=False)
    monkeypatch.setenv("GOPATH", str(tmp_path / "gp"))
    mf = tmp_path / "mode"
    mode(mf, "ok")
    return layout(tmp_path), make_fake_go(tmp_path / "gobin", mf), mf


# ── running downloaded/untrusted code as root ─────────────────────────
def test_root_never_executes_a_user_writable_binary_while_probing(tmp_path, monkeypatch):
    marker = tmp_path / "pwned-as-root"
    exe = tmp_path / "faketool"
    exe.write_text(f"#!/bin/sh\ntouch {marker}\necho 'Current Version: v2.3.1'\n")
    exe.chmod(0o755)
    os.chown(exe, 1000, 1000)                              # owned by an unprivileged user
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    cand = detect.probe(SPEC, str(exe), "local")
    assert not marker.exists(), "root executed a binary a normal user can modify"
    assert not cand.usable and any("not executed" in n for n in cand.notes)


def test_root_still_runs_root_owned_write_protected_binaries(tmp_path, monkeypatch):
    exe = write_tool(tmp_path / "faketool", "2.3.1")
    os.chown(exe, 0, 0)
    exe.chmod(0o755)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert detect.probe(SPEC, str(exe), "system").version == V("2.3.1")
    exe.chmod(0o775)                                       # now group-writable -> refused
    assert not security.safe_to_execute(str(exe))


# ── symlink attacks ───────────────────────────────────────────────────
def test_a_symlinked_live_binary_never_modifies_what_it_points_to(env, tmp_path):
    lay, go, _ = env
    system_bin = write_tool(tmp_path / "usr-bin" / "faketool", "2.1.0")
    before = system_bin.read_bytes()
    lay.tools_dir.mkdir(parents=True)
    os.symlink(system_bin, lay.tools_dir / "faketool")     # bin/tools/faketool -> a "system" file
    r = installer.install_tool(lay, SPEC, V("2.5.0"), go=go)
    assert r.status in ("updated", "installed"), r.reason
    assert system_bin.read_bytes() == before, "update wrote THROUGH a symlink into another file"
    assert not (lay.tools_dir / "faketool").is_symlink()


def test_a_planted_lock_symlink_is_not_followed(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep me")
    lock = tmp_path / "state" / ".update.lock"
    lock.parent.mkdir()
    os.symlink(victim, lock)
    with pytest.raises(OSError), security.exclusive_lock(lock):      # O_NOFOLLOW -> ELOOP
        pass
    assert victim.read_text() == "keep me"


def test_state_dir_with_loose_permissions_is_tightened(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    d.chmod(0o777)
    security.ensure_safe_dir(d)
    assert not d.stat().st_mode & 0o022


def test_a_symlinked_state_dir_is_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    os.symlink(real, tmp_path / "data")
    with pytest.raises(SecurityError, match="symlink"):
        security.ensure_safe_dir(tmp_path / "data")


# ── command injection / path traversal / malicious metadata ───────────
@pytest.mark.parametrize("evil", [
    "v2.3.1; touch /tmp/pwned", "v2.3.1 --flag", "$(id)", "v2.3.1\nv9.9.9", "-fno-x", "v2.3.1@v9.9.9", "../../x"])
def test_hostile_version_strings_never_reach_a_command_line(evil):
    assert versions.parse(evil) is None
    assert not versions.is_release_tag(evil)


def test_install_target_is_built_only_from_validated_parts(env):
    lay, go, _ = env
    seen = []
    def spy(argv, **kw):
        seen.append(list(argv))
        return security.run_argv(argv, **kw)
    installer.install_tool(lay, SPEC, V("2.5.0"), runner=spy, go=go)
    build = next(a for a in seen if a[1:2] == ["install"])
    assert build == [go, "install", "github.com/projectdiscovery/faketool/v2/cmd/faketool@v2.5.0"]
    assert all(isinstance(x, str) for a in seen for x in a)


@pytest.mark.parametrize("name", ["../etc/passwd", "a/b", "A", "-rf", "", "x" * 80, "a b", "a;b", ".hidden"])
def test_unsafe_tool_names_are_rejected_everywhere(name):
    with pytest.raises(SecurityError):
        security.validate_name(name)


def test_hostile_lock_cannot_smuggle_a_path_or_module(tmp_path):
    m = manifest()
    for bad in ({"../../evil": {"version": "1.0.0", "target": "x"}},
                {"faketool": {"version": "2.2.0", "target": "github.com/evil/x/v2@v2.2.0"}},
                {"faketool": {"version": "2.2.0; id", "target": "x"}}):
        with pytest.raises((SecurityError, Exception)):
            state.validate_lock(m, {"schema": 1, "tools": bad})


def test_a_json_bomb_from_upstream_is_a_clean_error_not_a_crash():
    class H:
        def get(self, url):
            return b"[" * 200_000 + b"]" * 200_000
    with pytest.raises(upstream.UpstreamError, match="bad JSON"):
        upstream.github_versions(H(), "projectdiscovery/faketool")


def test_a_compromised_upstream_serving_garbage_cannot_downgrade_or_crash(env):
    lay, go, _ = env
    class H:
        def get(self, url):
            return b"v0.0.1\nv1.0.0\nnot-a-version\n\x00\xff\n"
    write_tool(lay.tools_dir / "faketool", "2.3.1")
    ctx = ops.Context(lay, manifest(), H(), go=go, path_env="")
    ts = ops.collect(ctx, ["faketool"])[0]
    plan = ops.make_plan([ts])
    assert plan[0].action == "skip"
    assert (lay.tools_dir / "faketool").read_text().count("2.3.1") >= 1


# ── env-var injection / credentials ───────────────────────────────────
@pytest.mark.parametrize("var,val", [
    ("GOFLAGS", "-insecure"), ("GOINSECURE", "*"), ("GONOSUMDB", "*"), ("GONOSUMCHECK", "1"),
    ("GOPRIVATE", "*"), ("LD_PRELOAD", "/tmp/x.so"), ("DYLD_INSERT_LIBRARIES", "/tmp/x"),
    ("CGO_CFLAGS", "-I/tmp"), ("CGO_LDFLAGS", "-L/tmp"), ("BASH_ENV", "/tmp/x"), ("PYTHONPATH", "/tmp")])
def test_dangerous_environment_never_reaches_a_build(var, val, monkeypatch):
    monkeypatch.setenv(var, val)
    assert var not in security.clean_env()


def test_gosumdb_off_is_dropped_but_a_real_checksum_db_is_kept(monkeypatch):
    monkeypatch.setenv("GOSUMDB", "off")
    assert "GOSUMDB" not in security.clean_env()
    monkeypatch.setenv("GOSUMDB", "sum.golang.org")
    assert security.clean_env()["GOSUMDB"] == "sum.golang.org"


@pytest.mark.parametrize("raw,expect_absent", [
    ("Get https://user:s3cretpass@proxy.corp/x: dial tcp", "s3cretpass"),
    ("token ghp_" + "a" * 36 + " leaked", "ghp_" + "a" * 20),
    ("github_pat_" + "B" * 30, "B" * 20)])
def test_credentials_are_redacted_before_they_reach_logs_or_history(raw, expect_absent, env):
    assert expect_absent not in security.redact(raw)
    lay, *_ = env
    state.log_history(lay, "faketool", "1.0.0", None, "failure", "x", raw)
    assert expect_absent not in lay.history_file.read_text()


def test_failed_build_output_is_redacted_in_the_reported_reason(env, tmp_path):
    lay, go, _ = env
    def noisy(argv, **kw):
        if argv[1:2] == ["install"]:
            return security.RunResult(1, "Get https://bob:hunter2@goproxy.corp/x: 407")
        return security.run_argv(argv, **kw)
    r = installer.install_tool(lay, SPEC, V("2.5.0"), runner=noisy, go=go)
    assert r.status == "failed" and "hunter2" not in r.reason


def test_the_history_log_holds_no_environment_or_secrets(env):
    lay, go, _ = env
    os.environ["GITHUB_TOKEN"] = "ghp_" + "z" * 36
    try:
        ctx = ops.Context(lay, manifest(), None, go=go, path_env="")
        installer.install_tool(lay, SPEC, V("2.5.0"), go=go)
        state.log_history(lay, "faketool", None, "2.5.0", "success", "test")
        blob = lay.history_file.read_text() + lay.installed_file.read_text()
        assert "ghp_" not in blob and "GITHUB_TOKEN" not in blob
        assert ctx is not None
    finally:
        del os.environ["GITHUB_TOKEN"]


# ── PATH hijack ───────────────────────────────────────────────────────
def test_go_is_never_resolved_through_a_world_writable_or_relative_path(tmp_path):
    evil = tmp_path / "evil"
    write_tool(evil / "go", "1.0.0")
    evil.chmod(0o777)
    assert security.find_executable("go", f"{evil}:.::relative") is None


def test_bin_active_is_not_writable_by_others_after_use(env, tmp_path):
    lay, *_ = env
    a = write_tool(tmp_path / "a" / "faketool", "2.5.0")
    installer.refresh_active(lay, {"faketool": str(a)})
    assert not lay.active_dir.stat().st_mode & 0o022


# ── TOCTOU: the check must cover what is ACTUALLY installed ───────────
def test_the_binary_that_ends_up_installed_is_the_one_that_was_checked(env, monkeypatch):
    lay, go, _ = env
    write_tool(lay.tools_dir / "faketool", "2.1.0")
    real_swap = installer._swap_in
    def tampering_swap(src, live, layout_):
        real_swap(src, live, layout_)
        live.write_text("#!/bin/sh\necho 'Current Version: v2.5.0'\ncase \"$1\" in -h) echo '-silent' ;; esac\n")  # lost -json
        live.chmod(0o755)
    monkeypatch.setattr(installer, "_swap_in", tampering_swap)
    r = installer.install_tool(lay, SPEC, V("2.5.0"), go=go)
    assert r.status != "updated", "a binary changed between validation and use was accepted"


def test_concurrent_updates_cannot_interleave(tmp_path):
    lay = layout(tmp_path)
    with security.exclusive_lock(lay.lock_file), pytest.raises(SecurityError, match="already running"), \
            security.exclusive_lock(lay.lock_file):
        pytest.fail("two updaters held the lock at once")


# ── privilege escalation / auto-update surface ────────────────────────
def test_mutating_commands_refuse_root_unless_explicitly_allowed(monkeypatch):
    from mcp_server.toolmgr import cli
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    args = cli.build_parser().parse_args(["update", "--yes"])
    with pytest.raises(SecurityError, match="refusing to run as root"):
        cli._guard_root(args)
    args = cli.build_parser().parse_args(["install", "--allow-root"])
    cli._guard_root(args)          # the Docker build opts in explicitly


def test_the_apt_hook_text_is_static_and_contains_no_repo_paths_or_variables():
    from mcp_server.toolmgr import autoupdate
    code = "\n".join(ln for ln in autoupdate.APT_CONF_TEXT.splitlines() if not ln.startswith("//"))
    assert "$" not in code and "`" not in code and str(Path(__file__).resolve().parent.parent) not in code
    assert autoupdate.APT_CONF_TEXT.encode("ascii", "ignore").decode() == autoupdate.APT_CONF_TEXT


def test_no_downloaded_archive_is_ever_extracted():
    # The updater builds from the Go module proxy; it downloads no archives, so
    # there is no zip-slip / tar-symlink surface. Guard that this stays true.
    src = "".join(p.read_text() for p in Path(upstream.__file__).parent.glob("*.py"))
    for risky in ("tarfile", "zipfile", "extractall", "shutil.unpack_archive", "os.system", "shell=True", "curl "):
        assert risky not in src, f"toolmgr gained a risky primitive: {risky}"


def test_auto_run_cannot_be_triggered_into_a_major_by_any_flag_combination(env):
    lay, go, _ = env
    class H:
        def get(self, url):
            if "faketool/v2/@v/list" in url:
                return b"v2.3.1"
            if "faketool/v3/@v/list" in url:
                return b"v3.0.0"
            raise upstream.UpstreamError("HTTP 404")
    write_tool(lay.tools_dir / "faketool", "2.3.1")
    ctx = ops.Context(lay, manifest(), H(), go=go, path_env="")
    plan = ops.make_plan(ops.collect(ctx, ["faketool"]), major=True, auto=True)
    assert [p.action for p in plan] == ["skip"]
    assert json.dumps([p.to_dict() for p in plan])


def test_pinning_an_arbitrary_absolute_path_works_and_is_identity_checked(env, tmp_path):
    lay, go, _ = env
    custom = write_tool(tmp_path / "opt" / "faketool", "2.4.0")
    write_tool(lay.tools_dir / "faketool", "2.1.0")
    sel = state.load_selection(lay)
    sel["prefer"]["faketool"] = str(custom)
    state.save_selection(lay, sel)
    ctx = ops.Context(lay, manifest(), None, go=go, path_env="")
    ts = ops.collect(ctx, ["faketool"], with_latest=False)[0]
    assert ts.selection.chosen.path == str(custom) and ts.selection.chosen.source == "override"


def test_a_build_that_produces_a_symlink_instead_of_a_binary_is_refused(tmp_path):
    # A hostile/buggy build step leaving staging/<tool> -> /bin/sh must never be installed.
    staged = tmp_path / "faketool"
    os.symlink("/bin/sh", staged)
    ver, problems = installer.validate_binary(SPEC, str(staged), V("2.5.0"))
    assert ver is None and any("symlink" in p for p in problems)


@pytest.mark.parametrize("make,fragment", [
    (lambda p: p.write_text("") or p.chmod(0o755), "implausible size"),
    (lambda p: p.write_text("#!/bin/sh\n") or p.chmod(0o644), "not executable"),
])
def test_empty_or_non_executable_build_output_is_refused(tmp_path, make, fragment):
    f = tmp_path / "faketool"
    make(f)
    _, problems = installer.validate_binary(SPEC, str(f), V("2.5.0"))
    assert any(fragment in p for p in problems)


def test_root_does_not_run_the_compat_selftest_on_a_user_writable_binary(tmp_path, monkeypatch):
    marker = tmp_path / "pwned-as-root"
    exe = tmp_path / "faketool"
    exe.write_text(f"#!/bin/sh\ntouch {marker}\n")
    exe.chmod(0o755)
    os.chown(exe, 1000, 1000)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    problems = installer.selftest(SPEC, str(exe))
    assert not marker.exists() and problems and "not executed" in problems[0]


def test_a_timeout_kills_the_whole_process_tree_not_just_the_child():
    # Regression: subprocess.run killed only `sh`; its `sleep` child lived on
    # (and a timed-out `go install` would have left compilers running).
    import subprocess
    marker = "37.123"                                         # unique, so pgrep can't match anything else
    r = security.run_argv(["sh", "-c", f"sleep {marker} & wait"], timeout=0.4)
    assert r.timed_out
    import time
    time.sleep(0.3)
    left = subprocess.run(["pgrep", "-f", f"sleep {marker}"], capture_output=True, text=True).stdout.strip()
    assert not left, f"orphaned descendant survived the timeout: pid {left}"


def test_runaway_output_is_truncated_not_buffered_in_memory():
    r = security.run_argv(["sh", "-c", "yes x | head -c 50000000"], timeout=20)
    assert r.ok and len(r.output) == security._MAX_OUTPUT


def test_children_get_a_closed_stdin_and_their_own_session():
    r = security.run_argv(["sh", "-c", "cat; echo sid=$(ps -o sid= -p $$ | tr -d ' ') me=$$"], timeout=5)
    assert r.ok and "sid=" in r.output
    sid = r.output.split("sid=")[1].split()[0]
    assert sid != str(os.getsid(0)), "child shares our session; killpg on it could hit us"
