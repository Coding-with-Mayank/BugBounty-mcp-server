"""
Tests for mcp_server.server — focused on this upgrade pass's fixes:

  1. Scope enforcement is actually wired into every active-scanning handler
     (regression test for the gap where crawl/tech_detect/nuclei_scan/
     dir_fuzz/xss_scan/sqli_scan/cors_check sent traffic with zero
     authorization check).
  2. Flag-injection / domain-format validation rejects hostile input
     before it reaches a subprocess argv.
  3. The shared targets_tempfile() helper always cleans up, including
     when the caller raises.

run_cmd is monkeypatched everywhere so these tests need none of the
underlying Go security tools (subfinder, nuclei, naabu, ...) installed —
and, crucially, so a test asserting "out-of-scope targets never reach
run_cmd" can prove that by making run_cmd raise if it's called at all.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

from mcp_server import server


def _no_call_allowed(*_a, **_kw):
    raise AssertionError("run_cmd was called — an out-of-scope target reached the subprocess layer")


def _set_scope(monkeypatch, allowed: list[str], blocked: list[str] | None = None):
    """scope_list / blocked_list are read-only pydantic properties derived
    from allowed_scope / blocked_targets — patch the raw fields instead."""
    monkeypatch.setattr(server.settings, "allowed_scope", ",".join(allowed))
    if blocked is not None:
        monkeypatch.setattr(server.settings, "blocked_targets", ",".join(blocked))


async def _fake_resolver_harmless(host: str, timeout: float) -> list[str]:
    """Default test resolver: every hostname 'resolves' to a fixed TEST-NET-3
    address (RFC 5737, reserved for documentation — never realistically on
    anyone's BLOCKED_TARGETS list), so resolution-aware scope checks behave
    deterministically without touching live DNS."""
    return ["203.0.113.10"]


@pytest.fixture(autouse=True)
def _no_live_dns(monkeypatch):
    """Every test gets the harmless fake resolver by default. Tests that
    care about resolution behavior override server.dns_resolver themselves."""
    monkeypatch.setattr(server, "dns_resolver", _fake_resolver_harmless)


@pytest.fixture(autouse=True)
def _reset_scope(monkeypatch):
    """Default every test to open mode unless it opts into a specific scope."""
    _set_scope(monkeypatch, [], blocked=[])


@pytest.mark.asyncio
class TestRunCmdCancellation:
    """
    run_cmd's CancelledError handling — verified against a REAL subprocess
    (not mocked), since the point is proving the OS process actually dies,
    not just that a coroutine returns. asyncio.CancelledError is a
    BaseException, not an Exception, so this needs its own except clause;
    the bug this guards against is a scanner left running in the
    background after the caller thinks they cancelled it.
    """

    async def test_cancelling_the_task_kills_the_child_process(self):
        task = asyncio.create_task(server.run_cmd(["sleep", "30"], timeout=60))
        await asyncio.sleep(0.2)  # let the subprocess actually spawn

        # Get the PID before cancelling, from the still-running process list.
        import subprocess as sp
        pgrep_before = sp.run(["pgrep", "-f", "sleep 30"], capture_output=True, text=True)
        assert pgrep_before.stdout.strip(), "the sleep subprocess should be running before cancel"

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        await asyncio.sleep(0.3)  # give the OS a moment to reap the killed process
        pgrep_after = sp.run(["pgrep", "-f", "sleep 30"], capture_output=True, text=True)
        assert not pgrep_after.stdout.strip(), (
            "sleep subprocess is still running after cancellation - run_cmd leaked it"
        )


class TestWordlistDefaultsAreNotDockerOnly:
    """Regression test: subdomain_brute/dir_fuzz used to default to
    /app/wordlists/... , which only exists inside the Docker image and
    silently breaks native execution. WORDLISTS_DIR must resolve relative
    to server.py's own location instead."""

    def test_wordlists_dir_is_not_hardcoded_to_app(self):
        assert str(server.WORDLISTS_DIR) != "/app/wordlists"

    def test_wordlists_dir_resolves_relative_to_repo_root(self):
        # server.py lives at <repo>/mcp_server/server.py
        expected = Path(server.__file__).resolve().parent.parent / "wordlists"
        assert expected == server.WORDLISTS_DIR


class TestFlagInjectionGuard:
    @pytest.mark.parametrize("value", ["-oJ", "--resolver-list", "-x"])
    def test_rejects_leading_dash(self, value):
        assert server.reject_flag_injection(value) is not None

    @pytest.mark.parametrize("value", ["example.com", "10.0.0.1", "https://example.com/path"])
    def test_allows_normal_values(self, value):
        assert server.reject_flag_injection(value) is None


class TestDomainValidation:
    @pytest.mark.parametrize("value", ["example.com", "sub.example.co.uk", "a-b.example.com"])
    def test_valid_domains_accepted(self, value):
        assert server.is_valid_domain(value) is True

    @pytest.mark.parametrize("value", ["-oJ", "not a domain", "10.0.0.1", "", "example..com"])
    def test_invalid_domains_rejected(self, value):
        assert server.is_valid_domain(value) is False


class TestTargetsTempfile:
    def test_writes_all_targets_and_cleans_up(self):
        targets = ["a.example.com", "b.example.com"]
        captured_path = None
        with server.targets_tempfile(targets) as path:
            captured_path = path
            assert Path(path).read_text() == "a.example.com\nb.example.com"
        assert not Path(captured_path).exists()

    def test_cleans_up_even_when_caller_raises(self):
        captured_path = None
        with pytest.raises(RuntimeError), server.targets_tempfile(["x.example.com"]) as path:
            captured_path = path
            raise RuntimeError("simulated failure mid-scan")
        assert not Path(captured_path).exists()


@pytest.mark.asyncio
class TestScopeCheckHelpers:
    async def test_scope_check_none_when_allowed(self, monkeypatch):
        _set_scope(monkeypatch, ["example.com"])
        assert await server._scope_check("example.com") is None

    async def test_scope_check_returns_error_when_denied(self, monkeypatch):
        _set_scope(monkeypatch, ["example.com"])
        err = await server._scope_check("evil.com")
        assert err is not None
        assert err["error"] == "target_out_of_scope"

    async def test_filter_in_scope_splits_allowed_and_blocked(self, monkeypatch):
        _set_scope(monkeypatch, ["example.com"])
        allowed, blocked = await server._filter_in_scope(["a.example.com", "evil.com"])
        # a.example.com is not *.example.com or an exact match -> also blocked
        assert allowed == []
        assert len(blocked) == 2

    async def test_filter_in_scope_wildcard(self, monkeypatch):
        _set_scope(monkeypatch, ["*.example.com"])
        allowed, blocked = await server._filter_in_scope(["a.example.com", "evil.com"])
        assert allowed == ["a.example.com"]
        assert [b["target"] for b in blocked] == ["evil.com"]


@pytest.mark.asyncio
class TestDnsRebindingProtection:
    """
    Coverage for the actual point of this pass: a hostname that matches
    ALLOWED_SCOPE can still resolve to something on BLOCKED_TARGETS right
    now (stale record, or an active DNS-rebinding attempt). The hostname
    check alone (what existed before) can't catch that.
    """

    async def test_denies_when_resolved_ip_is_blocked(self, monkeypatch):
        _set_scope(monkeypatch, ["evil-but-in-scope.com"], blocked=["169.254.169.254"])

        async def resolves_to_metadata_ip(host, timeout):
            return ["169.254.169.254"]

        monkeypatch.setattr(server, "dns_resolver", resolves_to_metadata_ip)
        err = await server._scope_check("evil-but-in-scope.com")
        assert err is not None
        assert err["error"] == "target_out_of_scope"
        assert "169.254.169.254" in err["reason"]

    async def test_allows_when_resolved_ip_is_clean(self, monkeypatch):
        _set_scope(monkeypatch, ["example.com"], blocked=["169.254.169.254"])

        async def resolves_clean(host, timeout):
            return ["93.184.216.34"]

        monkeypatch.setattr(server, "dns_resolver", resolves_clean)
        assert await server._scope_check("example.com") is None

    async def test_resolution_failure_does_not_block_the_scan(self, monkeypatch):
        _set_scope(monkeypatch, ["example.com"])

        async def flaky_resolver(host, timeout):
            raise OSError("DNS server unreachable")

        monkeypatch.setattr(server, "dns_resolver", flaky_resolver)
        # Should NOT be denied just because resolution failed transiently.
        assert await server._scope_check("example.com") is None

    async def test_bare_ip_target_never_triggers_resolution(self, monkeypatch):
        _set_scope(monkeypatch, ["10.0.0.5"])

        async def must_not_be_called(host, timeout):
            raise AssertionError("resolver called for a bare-IP target - nothing to resolve")

        monkeypatch.setattr(server, "dns_resolver", must_not_be_called)
        assert await server._scope_check("10.0.0.5") is None

    async def test_out_of_scope_hostname_never_triggers_resolution(self, monkeypatch):
        # Already denied on the hostname alone - no reason to spend a DNS
        # round trip finding that out a second way.
        _set_scope(monkeypatch, ["example.com"])

        async def must_not_be_called(host, timeout):
            raise AssertionError("resolver called for an already-out-of-scope hostname")

        monkeypatch.setattr(server, "dns_resolver", must_not_be_called)
        err = await server._scope_check("evil.com")
        assert err is not None

    async def test_filter_in_scope_resolves_concurrently_and_blocks_rebound_target(self, monkeypatch):
        _set_scope(monkeypatch, ["good.example.com", "bad.example.com"], blocked=["169.254.169.254"])

        async def per_host_resolver(host, timeout):
            return ["169.254.169.254"] if host == "bad.example.com" else ["93.184.216.34"]

        monkeypatch.setattr(server, "dns_resolver", per_host_resolver)
        allowed, blocked = await server._filter_in_scope(["good.example.com", "bad.example.com"])
        assert allowed == ["good.example.com"]
        assert blocked[0]["target"] == "bad.example.com"
        assert "169.254.169.254" in blocked[0]["reason"]

    async def test_check_scope_tool_surfaces_resolved_ips(self, monkeypatch):
        _set_scope(monkeypatch, ["example.com"])

        async def resolver(host, timeout):
            return ["93.184.216.34"]

        monkeypatch.setattr(server, "dns_resolver", resolver)
        res = await server._check_scope({"target": "example.com"})
        assert res["allowed"] is True
        assert res["resolved_ips"] == ["93.184.216.34"]


@pytest.mark.asyncio
class TestHandlerScopeEnforcement:
    """
    Regression tests for the core bug this pass fixed: these handlers used
    to call run_cmd unconditionally, with no scope check at all. Each test
    puts the target out of scope and asserts run_cmd is never reached.
    """

    async def test_port_scan_blocks_out_of_scope(self, monkeypatch):
        _set_scope(monkeypatch, ["example.com"])
        monkeypatch.setattr(server, "run_cmd", _no_call_allowed)
        res = await server._port_scan({"target": "evil.com"})
        assert res["error"] == "target_out_of_scope"

    async def test_dns_enum_blocks_out_of_scope(self, monkeypatch):
        _set_scope(monkeypatch, ["example.com"])
        monkeypatch.setattr(server, "run_cmd", _no_call_allowed)
        res = await server._dns_enum({"domain": "evil.com"})
        assert res["error"] == "target_out_of_scope"

    async def test_crawl_blocks_out_of_scope(self, monkeypatch):
        # crawl had NO scope check at all before this pass.
        _set_scope(monkeypatch, ["example.com"])
        monkeypatch.setattr(server, "run_cmd", _no_call_allowed)
        res = await server._crawl({"url": "https://evil.com/"})
        assert res["error"] == "target_out_of_scope"

    async def test_tech_detect_blocks_out_of_scope(self, monkeypatch):
        # tech_detect had NO scope check at all before this pass.
        _set_scope(monkeypatch, ["example.com"])
        monkeypatch.setattr(server, "run_cmd", _no_call_allowed)
        res = await server._tech_detect({"targets": ["https://evil.com/"]})
        assert "error" in res
        assert res["scope_blocked"][0]["target"] == "https://evil.com/"

    async def test_nuclei_scan_blocks_out_of_scope(self, monkeypatch):
        # nuclei_scan had NO scope check at all before this pass.
        _set_scope(monkeypatch, ["example.com"])
        monkeypatch.setattr(server, "run_cmd", _no_call_allowed)
        res = await server._nuclei_scan({"targets": ["https://evil.com/"]})
        assert "error" in res

    async def test_dir_fuzz_blocks_out_of_scope(self, monkeypatch, tmp_path):
        # dir_fuzz had NO scope check at all before this pass.
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("admin\n")
        _set_scope(monkeypatch, ["example.com"])
        monkeypatch.setattr(server, "run_cmd", _no_call_allowed)
        res = await server._dir_fuzz({"url": "https://evil.com/", "wordlist": str(wordlist)})
        assert res["error"] == "target_out_of_scope"

    async def test_xss_scan_blocks_out_of_scope(self, monkeypatch):
        # xss/sqli/cors all route through _nuclei_targeted, which had NO
        # scope check at all before this pass.
        _set_scope(monkeypatch, ["example.com"])
        monkeypatch.setattr(server, "run_cmd", _no_call_allowed)
        res = await server._xss_scan({"targets": ["https://evil.com/"]})
        assert "error" in res

    async def test_alive_check_partial_scope_only_scans_allowed(self, monkeypatch):
        _set_scope(monkeypatch, ["good.example.com"])
        seen_cmds = []
        written_contents = []

        async def fake_run_cmd(cmd, **kw):
            seen_cmds.append(cmd)
            # Read the temp file's content now — targets_tempfile() deletes
            # it as soon as this handler returns.
            written_contents.append(Path(cmd[cmd.index("-l") + 1]).read_text())
            return "", "", 0

        monkeypatch.setattr(server, "run_cmd", fake_run_cmd)
        res = await server._alive_check({"targets": ["good.example.com", "evil.com"]})

        assert res["data"]["scope_blocked"] == [
            {"target": "evil.com", "reason": res["data"]["scope_blocked"][0]["reason"]}
        ]
        # Only the in-scope target's file should ever reach httpx.
        assert len(seen_cmds) == 1
        assert "evil.com" not in written_contents[0]
        assert "good.example.com" in written_contents[0]


@pytest.mark.asyncio
class TestHandlerHappyPath:
    """Sanity checks that in-scope calls still work end-to-end against a mocked run_cmd."""

    async def test_subdomain_enum_rejects_bad_domain(self):
        res = await server._subdomain_enum({"domain": "-oJ"})
        assert "error" in res

    async def test_subdomain_enum_happy_path(self, monkeypatch):
        async def fake_run_cmd(cmd, **kw):
            return "a.example.com\nb.example.com\n", "", 0

        monkeypatch.setattr(server, "run_cmd", fake_run_cmd)
        res = await server._subdomain_enum({"domain": "example.com"})
        assert res["data"]["count"] == 2

    async def test_check_scope_tool_reports_reason(self, monkeypatch):
        _set_scope(monkeypatch, ["example.com"])
        res = await server._check_scope({"target": "evil.com"})
        assert res["allowed"] is False
        assert "evil.com" in res["reason"] or "not in ALLOWED_SCOPE" in res["reason"]

    async def test_get_capabilities_handler_returns_full_report(self):
        res = await server._get_capabilities({})
        assert res["status"] in ("ready", "degraded")
        assert "go_tools" in res
        assert "python" in res
        assert res["mcp_tools"]["count"] == len(server.TOOLS)

    async def test_get_capabilities_registered_in_tools_and_handlers(self):
        assert "get_capabilities" in server.TOOL_HANDLERS
        assert any(t.name == "get_capabilities" for t in server.TOOLS)

    async def test_get_capabilities_reachable_via_call_tool_dispatch(self):
        results = await server.call_tool("get_capabilities", {})
        payload = json.loads(results[0].text)
        assert payload["status"] in ("ready", "degraded")

    async def test_nuclei_scan_happy_path_in_scope(self, monkeypatch):
        _set_scope(monkeypatch, ["example.com"])

        async def fake_run_cmd(cmd, **kw):
            finding = {"template-id": "t1", "info": {"name": "n", "severity": "high"}}
            return json.dumps(finding) + "\n", "", 0

        monkeypatch.setattr(server, "run_cmd", fake_run_cmd)
        res = await server._nuclei_scan({"targets": ["https://example.com/"]})
        assert res["data"]["total"] == 1

    async def test_strict_scope_setting_denies_on_resolution_failure(self, monkeypatch):
        _set_scope(monkeypatch, ["example.com"])
        monkeypatch.setattr(server.settings, "strict_scope", True)

        async def failing_resolver(host, timeout):
            raise OSError("simulated DNS failure")

        monkeypatch.setattr(server, "dns_resolver", failing_resolver)
        err = await server._scope_check("example.com")
        assert err is not None
        assert err["error"] == "target_out_of_scope"

    async def test_strict_scope_off_by_default_allows_on_resolution_failure(self, monkeypatch):
        _set_scope(monkeypatch, ["example.com"])
        # strict_scope left at its default (False)

        async def failing_resolver(host, timeout):
            raise OSError("simulated DNS failure")

        monkeypatch.setattr(server, "dns_resolver", failing_resolver)
        assert await server._scope_check("example.com") is None


@pytest.mark.asyncio
class TestTaskManagementWiring:
    """
    server._start_task/_get_task_status/_get_task_results/_cancel_task are
    thin wrappers around the shared server.task_manager instance, which is
    built from the SAME server.TOOL_HANDLERS dispatch table call_tool()
    uses. These confirm that wiring end-to-end — not TaskManager's own
    lifecycle logic, which test_tasks.py already covers against a fully
    isolated instance.
    """

    async def test_start_task_rejects_unknown_tool(self):
        res = await server._start_task({"tool": "not_a_real_tool", "args": {}})
        assert "error" in res

    async def test_start_task_requires_tool_name(self):
        res = await server._start_task({"args": {}})
        assert "error" in res

    async def test_start_task_refuses_to_start_itself(self):
        res = await server._start_task({"tool": "start_task", "args": {}})
        assert "error" in res

    async def test_start_task_runs_a_real_registered_handler(self, monkeypatch):
        _set_scope(monkeypatch, ["example.com"])
        res = await server._start_task({"tool": "check_scope", "args": {"target": "example.com"}})
        assert "task_id" in res
        task_id = res["task_id"]

        await asyncio.sleep(0.2)
        results = await server._get_task_results({"task_id": task_id})
        assert results["status"] == "completed"
        assert results["result"]["allowed"] is True

    async def test_get_task_status_and_results_require_task_id(self):
        assert "error" in await server._get_task_status({})
        assert "error" in await server._get_task_results({})
        assert "error" in await server._cancel_task({})

    async def test_get_task_status_unknown_id(self):
        res = await server._get_task_status({"task_id": "task_doesnotexist"})
        assert "error" in res

    async def test_list_tasks_finds_a_task_started_via_start_task(self, monkeypatch):
        _set_scope(monkeypatch, ["example.com"])
        res = await server._start_task({"tool": "check_scope", "args": {"target": "example.com"}})
        task_id = res["task_id"]
        await asyncio.sleep(0.2)

        listing = await server._list_tasks({})
        assert listing["count"] >= 1
        assert any(t["task_id"] == task_id for t in listing["tasks"])

        filtered = await server._list_tasks({"tool": "check_scope"})
        assert all(t["tool"] == "check_scope" for t in filtered["tasks"])

        done = await server._list_tasks({"status": "completed"})
        assert any(t["task_id"] == task_id for t in done["tasks"])


@pytest.mark.asyncio
class TestTaskManagerRealSubprocess:
    """
    The test that matters most for this feature: cancel_task, going
    through the real server.task_manager (not an isolated TaskManager),
    must actually kill the underlying OS process — not just mark the task
    'cancelled' while a scanner keeps running in the background.
    """

    async def test_cancel_task_kills_the_real_subprocess(self, monkeypatch):
        async def sleep_tool(args: dict) -> dict:
            # Exercises the real run_cmd (with its CancelledError fix),
            # not a mock — the whole point is proving the OS process dies.
            stdout, stderr, rc = await server.run_cmd(["sleep", "30"], timeout=60)
            return {"stdout": stdout, "stderr": stderr, "rc": rc}

        monkeypatch.setitem(server.TOOL_HANDLERS, "test_sleep_tool", sleep_tool)

        start_res = await server._start_task({"tool": "test_sleep_tool", "args": {}})
        task_id = start_res["task_id"]
        await asyncio.sleep(0.3)  # let the subprocess actually spawn

        import subprocess as sp
        pgrep_before = sp.run(["pgrep", "-f", "sleep 30"], capture_output=True, text=True)
        assert pgrep_before.stdout.strip(), "the sleep subprocess should be running before cancel"

        cancel_res = await server._cancel_task({"task_id": task_id})
        assert cancel_res["status"] == "cancelled"

        await asyncio.sleep(0.3)  # give the OS a moment to reap it
        pgrep_after = sp.run(["pgrep", "-f", "sleep 30"], capture_output=True, text=True)
        assert not pgrep_after.stdout.strip(), (
            "sleep subprocess is still running after cancel_task - it leaked through the task manager"
        )

    async def test_hard_timeout_also_kills_the_real_subprocess(self, monkeypatch):
        async def sleep_tool(args: dict) -> dict:
            stdout, stderr, rc = await server.run_cmd(["sleep", "30"], timeout=60)
            return {"stdout": stdout, "stderr": stderr, "rc": rc}

        monkeypatch.setitem(server.TOOL_HANDLERS, "test_sleep_tool_2", sleep_tool)

        start_res = await server._start_task(
            {"tool": "test_sleep_tool_2", "args": {}, "hard_timeout_seconds": 0.5}
        )
        task_id = start_res["task_id"]
        await asyncio.sleep(1.0)  # past the 0.5s hard timeout

        status = await server._get_task_status({"task_id": task_id})
        assert status["status"] == "timed_out"

        import subprocess as sp
        pgrep_after = sp.run(["pgrep", "-f", "sleep 30"], capture_output=True, text=True)
        assert not pgrep_after.stdout.strip(), (
            "sleep subprocess is still running after hitting the hard timeout"
        )

    async def test_cancelled_real_handler_returns_partial_subdomains_via_mcp_tools(self, monkeypatch, tmp_path):
        """End to end through the MCP surface: the real subdomain_enum
        handler runs a (fake) subfinder that has already printed some
        results when the task is cancelled. get_task_results must hand them
        back, labelled as unprocessed partial output."""
        fake = tmp_path / "subfinder"
        fake.write_text("#!/bin/sh\necho a.example.com\necho b.example.com\nexec sleep 30\n")
        fake.chmod(0o755)
        monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")

        start_res = await server._start_task({"tool": "subdomain_enum", "args": {"domain": "example.com"}})
        task_id = start_res["task_id"]
        await asyncio.sleep(0.6)
        await server._cancel_task({"task_id": task_id})

        status = await server._get_task_status({"task_id": task_id})
        assert status["status"] == "cancelled"
        assert status["partial_results_available"] is True

        res = await server._get_task_results({"task_id": task_id})
        assert res["result"]["partial"] is True
        assert res["result"]["captured"][0]["cmd"][0] == "subfinder"
        assert res["result"]["captured"][0]["stdout"] == "a.example.com\nb.example.com\n"


@pytest.mark.asyncio
class TestSmartHuntEndToEnd:
    """Smart Hunt exercised through the real MCP tool handlers (not an
    isolated engine instance) — the same path an actual client goes through:
    smart_hunt_start -> run the real subdomain_enum handler against a fake
    subfinder -> smart_hunt_next -> expect alive_check recommended next,
    with the flagged subdomain prioritised."""

    async def test_full_loop_through_real_handlers(self, monkeypatch, tmp_path):
        fake = tmp_path / "subfinder"
        fake.write_text("#!/bin/sh\necho a.example.com\necho admin.example.com\necho b.example.com\n")
        fake.chmod(0o755)
        monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
        _set_scope(monkeypatch, ["*.example.com"])

        start = await server._smart_hunt_start({"target": "example.com"})
        assert start["recommendation"]["tool"] == "subdomain_enum"

        sub_result = await server._subdomain_enum({"domain": "example.com"})
        assert sorted(sub_result["data"]["subdomains"]) == ["a.example.com", "admin.example.com", "b.example.com"]

        nxt = await server._smart_hunt_next({
            "session_id": start["session_id"], "tool": "subdomain_enum", "result": sub_result,
        })
        assert nxt["recorded"]["learned"] == 3
        assert nxt["recommendation"]["tool"] == "alive_check"
        targets = nxt["recommendation"]["args"]["targets"]
        assert targets[0] == "https://admin.example.com"  # flagged host goes first

        status = await server._smart_hunt_status({"session_id": start["session_id"]})
        assert status["high_value"]["suspicious_subdomains"][0]["subdomain"] == "admin.example.com"

        closed = await server._smart_hunt_close({"session_id": start["session_id"]})
        assert closed["status"] == "closed"

    async def test_refuses_to_start_without_allowed_scope(self, monkeypatch):
        _set_scope(monkeypatch, [])
        res = await server._smart_hunt_start({"target": "example.com"})
        assert "error" in res and "open mode" in res["error"]

    async def test_smart_hunt_tools_are_registered(self):
        names = {t.name for t in server.TOOLS}
        assert {"smart_hunt_start", "smart_hunt_next", "smart_hunt_status", "smart_hunt_close"} <= names
        for name in ("smart_hunt_start", "smart_hunt_next", "smart_hunt_status", "smart_hunt_close"):
            assert name in server.TOOL_HANDLERS


class TestVersionConsistency:
    """mcp_server.__version__ is the single source of truth for the version
    string (pyproject.toml, hunt.py's banner, and the health endpoint all
    derive from it) — this used to be four independently hand-edited copies
    that silently drifted apart. Guards against that regressing."""

    def test_version_matches_pyproject(self):
        import tomllib

        from mcp_server import __version__
        pyproject = tomllib.loads(Path("pyproject.toml").read_text())
        assert pyproject["project"]["version"] == __version__

    def test_hunt_py_banner_shows_the_current_version(self, capsys):
        import hunt
        from mcp_server import __version__
        hunt.banner()
        assert f"v{__version__}" in capsys.readouterr().out

    def test_health_app_version_matches(self):
        """Both FastAPI version fields reference the shared constant rather
        than their own hardcoded string literal."""
        import inspect

        from mcp_server.server import _start_health_server
        src = inspect.getsource(_start_health_server)
        assert 'version=__version__' in src
        assert '"version": __version__' in src
