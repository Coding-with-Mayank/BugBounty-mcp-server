"""
hunt.py scope enforcement + shared-core wiring.

hunt.py used to have no scope enforcement at all — only server.py's
handlers checked ALLOWED_SCOPE/BLOCKED_TARGETS. These mirror
tests/test_server.py::TestHandlerScopeEnforcement: put the target out of
scope, make hunt.run() raise if it's ever reached, and assert it wasn't.
"""
from __future__ import annotations

import functools
import subprocess
import sys
from pathlib import Path

import pytest

import hunt
from mcp_server import core

HUNT_PY = Path(__file__).resolve().parent.parent / "hunt.py"


async def _harmless_resolver(host: str, timeout: float) -> list[str]:
    return ["93.184.216.34"]


@pytest.fixture(autouse=True)
def _scope_and_dns(monkeypatch):
    # No live DNS in tests, same rule as test_server.py.
    monkeypatch.setattr(
        hunt, "resolve_and_check",
        functools.partial(hunt.resolve_and_check, resolver=_harmless_resolver),
    )
    monkeypatch.setattr(hunt.settings, "allowed_scope", "example.com,*.example.com")
    monkeypatch.setattr(hunt.settings, "blocked_targets", "169.254.169.254,10.0.0.0/8")
    monkeypatch.setattr(hunt.settings, "strict_scope", False)


async def _no_call_allowed(*a, **kw):
    raise AssertionError("hunt.run was called — an out-of-scope target reached the subprocess layer")


class TestScopeHelpers:
    async def test_in_scope_target_allowed(self):
        assert await hunt.scope_allows("example.com") is True

    async def test_out_of_scope_target_denied_and_explained(self, capsys):
        assert await hunt.scope_allows("evil.com") is False
        assert "Out of scope" in capsys.readouterr().out

    async def test_blocked_range_denied_even_if_hostname_in_scope(self, monkeypatch):
        async def rebinds_to_metadata(host, timeout):
            return ["169.254.169.254"]

        monkeypatch.setattr(
            hunt, "resolve_and_check",
            functools.partial(hunt.resolve_and_check.func, resolver=rebinds_to_metadata),
        )
        assert await hunt.scope_allows("api.example.com") is False

    async def test_filter_in_scope_drops_only_the_bad_ones(self):
        kept = await hunt.filter_in_scope(["https://a.example.com", "https://evil.com", "example.com"])
        assert kept == ["https://a.example.com", "example.com"]


class TestActiveCommandsRefuseOutOfScope:
    async def test_scan_blocks_out_of_scope(self, monkeypatch):
        monkeypatch.setattr(hunt, "run", _no_call_allowed)
        await hunt.cmd_scan("https://evil.com")

    async def test_fuzz_blocks_out_of_scope(self, monkeypatch):
        monkeypatch.setattr(hunt, "run", _no_call_allowed)
        await hunt.cmd_fuzz("https://evil.com/FUZZ", wordlist=__file__)

    async def test_full_blocks_out_of_scope_before_any_stage_runs(self, monkeypatch):
        monkeypatch.setattr(hunt, "run", _no_call_allowed)
        await hunt.cmd_full("evil.com")

    async def test_screenshot_blocks_out_of_scope(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(hunt.shutil, "which", lambda name: "/usr/bin/" + name)
        monkeypatch.setattr(hunt, "run", _no_call_allowed)
        await hunt.cmd_screenshot("evil.com")

    async def test_alive_drops_out_of_scope_hosts_from_the_probe_list(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        listing = tmp_path / "subs.txt"
        listing.write_text("a.example.com\nevil.com\n")
        seen: dict = {}

        async def fake_run(cmd, timeout=120):
            if cmd[0] == "httpx":
                seen["targets"] = Path(cmd[cmd.index("-l") + 1]).read_text().splitlines()
            return "", ""

        monkeypatch.setattr(hunt, "run", fake_run)
        await hunt.cmd_alive("example.com", list_file=str(listing))
        assert seen["targets"] == ["https://a.example.com"]

    async def test_alive_with_everything_out_of_scope_never_runs_httpx(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        listing = tmp_path / "subs.txt"
        listing.write_text("evil.com\n")
        monkeypatch.setattr(hunt, "run", _no_call_allowed)
        await hunt.cmd_alive("example.com", list_file=str(listing))


class TestInScopeStillRuns:
    async def test_scan_in_scope_reaches_nuclei(self, monkeypatch):
        calls = []

        async def fake_run(cmd, timeout=120):
            calls.append(cmd)
            return "", ""

        monkeypatch.setattr(hunt, "run", fake_run)
        await hunt.cmd_scan("https://api.example.com")
        assert calls and calls[0][0] == "nuclei"

    async def test_passive_commands_are_not_scope_gated(self, monkeypatch, tmp_path):
        """recon/wayback/cert never contact the target, so — consistent with
        server.py's own exemption list — they run even for a target outside
        ALLOWED_SCOPE."""
        monkeypatch.chdir(tmp_path)
        calls = []

        async def fake_run(cmd, timeout=120):
            calls.append(cmd[0])
            return "", ""

        monkeypatch.setattr(hunt, "run", fake_run)
        await hunt.cmd_wayback("evil.com")
        assert "waybackurls" in calls


class TestSharedCore:
    def test_hunt_uses_the_shared_runner_not_its_own_copy(self):
        assert hunt.run_cmd is core.run_cmd

    async def test_run_adapter_delegates_to_core_run_cmd(self, monkeypatch):
        async def fake_core(cmd, timeout=120, stdin=None):
            return "out", "err", 0

        monkeypatch.setattr(hunt, "run_cmd", fake_core)
        assert await hunt.run(["whatever"]) == ("out", "err")


class TestCliArgvValidation:
    def _run(self, *args):
        return subprocess.run([sys.executable, str(HUNT_PY), *args], capture_output=True, text=True, timeout=15)

    def test_flag_like_target_is_rejected(self):
        res = self._run("recon", "-oJ")
        assert "looks like a CLI flag" in res.stdout

    def test_invalid_domain_is_rejected_for_domain_commands(self):
        res = self._run("recon", "not a domain")
        assert "not a valid domain" in res.stdout
