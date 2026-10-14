"""
core.py — the runner and validation helpers shared by server.py and hunt.py.

run_cmd tests use real `sh` subprocesses rather than mocks: the properties
that matter (partial output survives a kill, the child really dies, pipes
don't deadlock) only exist at the OS level.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from mcp_server import core
from mcp_server.core import (
    capture_partial_results,
    is_valid_domain,
    lines,
    reject_flag_injection,
    run_cmd,
    sanitize,
    targets_tempfile,
)


def sh(script: str) -> list[str]:
    return ["sh", "-c", script]


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


async def _wait_dead(pid: int, seconds: float = 3.0) -> bool:
    for _ in range(int(seconds / 0.05)):
        if not _alive(pid):
            return True
        await asyncio.sleep(0.05)
    return False


@pytest.mark.asyncio
class TestRunCmdBasics:
    async def test_returns_stdout_stderr_and_returncode(self):
        out, err, rc = await run_cmd(sh("echo hi; echo oops >&2; exit 3"))
        assert (out, err, rc) == ("hi\n", "oops\n", 3)

    async def test_missing_binary_returns_127_with_actionable_message(self):
        out, err, rc = await run_cmd(["definitely-not-a-real-binary-xyz"])
        assert rc == 127 and out == ""
        assert "install-native.sh" in err and "doctor" in err

    async def test_stdin_is_fed_to_the_process(self):
        out, _, rc = await run_cmd(["cat"], stdin="hello\nworld\n")
        assert (out, rc) == ("hello\nworld\n", 0)

    async def test_large_output_does_not_deadlock(self):
        out, _, rc = await run_cmd(sh("yes abcdefghij | head -n 300000"), timeout=30)
        assert rc == 0 and out.count("\n") == 300000

    async def test_single_very_long_line_is_returned_intact(self):
        """readline() would raise LimitOverrunError here (minified JSON from
        httpx/katana can be huge); chunked reads must not."""
        out, _, rc = await run_cmd(sh("head -c 1500000 /dev/zero | tr '\\0' 'a'; echo"), timeout=30)
        assert rc == 0 and len(out) == 1_500_001

    async def test_stdin_and_big_output_together_do_not_deadlock(self):
        out, _, rc = await run_cmd(sh("yes line | head -n 200000; cat >/dev/null"), timeout=30, stdin="x\n" * 100000)
        assert rc == 0 and out.count("\n") == 200000


@pytest.mark.asyncio
class TestRunCmdOwnTimeout:
    async def test_timeout_returns_partial_stdout_not_nothing(self):
        out, err, rc = await run_cmd(sh("echo one; echo two; exec sleep 30"), timeout=1)
        assert out == "one\ntwo\n"
        assert rc == -1 and "timed out after 1s" in err

    async def test_timeout_drops_a_trailing_line_fragment(self):
        """A process killed mid-write leaves half a line (half a JSON
        object, for nuclei -jsonl). Only whole lines are returned."""
        out, _, rc = await run_cmd(sh("echo complete; printf '{\"half\": '; exec sleep 30"), timeout=1)
        assert out == "complete\n"
        assert rc == -1

    async def test_timeout_actually_kills_the_child(self, tmp_path):
        pidfile = tmp_path / "pid"
        await run_cmd(sh(f"echo $$ > {pidfile}; exec sleep 30"), timeout=1)
        assert await _wait_dead(int(pidfile.read_text()))


@pytest.mark.asyncio
class TestCancellation:
    async def test_cancellation_propagates_and_kills_the_child(self, tmp_path):
        pidfile = tmp_path / "pid"
        task = asyncio.create_task(run_cmd(sh(f"echo $$ > {pidfile}; exec sleep 30"), timeout=60))
        await asyncio.sleep(0.4)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert await _wait_dead(int(pidfile.read_text()))

    async def test_cancelled_call_records_partial_output_in_the_sink(self):
        async def work():
            with capture_partial_results() as sink:
                try:
                    await run_cmd(sh("echo found-1; echo found-2; printf frag; exec sleep 30"), timeout=60)
                finally:
                    captured.extend(sink)

        captured: list[dict] = []
        task = asyncio.create_task(work())
        await asyncio.sleep(0.5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert len(captured) == 1
        entry = captured[0]
        assert entry["stdout"] == "found-1\nfound-2\n"  # fragment dropped
        assert "cancelled" in entry["note"]
        assert entry["cmd"][0] == "sh"

    async def test_sink_collects_completed_calls_plus_the_interrupted_one(self):
        """Multi-stage handlers (full_recon etc.) finish some commands before
        being stopped; those results must survive too."""
        captured: list[dict] = []

        async def work():
            with capture_partial_results() as sink:
                try:
                    await run_cmd(sh("echo stage1-done"))
                    await run_cmd(sh("echo stage2-partial; exec sleep 30"), timeout=60)
                finally:
                    captured.extend(sink)

        task = asyncio.create_task(work())
        await asyncio.sleep(0.6)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert [e["stdout"] for e in captured] == ["stage1-done\n", "stage2-partial\n"]
        assert captured[0]["returncode"] == 0
        assert captured[1]["returncode"] == -1


@pytest.mark.asyncio
class TestCaptureScope:
    async def test_nothing_is_recorded_outside_a_capture_scope(self):
        assert core._partial_sink.get() is None
        await run_cmd(sh("echo x"))  # must simply work, with no sink

    async def test_capture_scope_resets_afterwards(self):
        with capture_partial_results() as sink:
            await run_cmd(sh("echo x"))
        assert len(sink) == 1
        assert core._partial_sink.get() is None

    async def test_concurrent_tasks_do_not_see_each_others_output(self):
        async def worker(tag: str) -> list[dict]:
            with capture_partial_results() as sink:
                await run_cmd(sh(f"sleep 0.1; echo {tag}"))
                return list(sink)

        a, b = await asyncio.gather(worker("alpha"), worker("beta"))
        assert [e["stdout"] for e in a] == ["alpha\n"]
        assert [e["stdout"] for e in b] == ["beta\n"]

    async def test_captured_output_is_size_capped_and_flagged(self, monkeypatch):
        monkeypatch.setattr(core, "_MAX_CAPTURED_CHARS", 100)
        with capture_partial_results() as sink:
            out, _, _ = await run_cmd(sh("yes abcdefghij | head -n 1000"))
        assert len(out) == 11_000  # the real return value is never truncated
        assert len(sink[0]["stdout"]) == 100 and sink[0]["truncated"] is True

    async def test_missing_binary_is_recorded_too(self):
        with capture_partial_results() as sink:
            await run_cmd(["definitely-not-a-real-binary-xyz"])
        assert sink[0]["returncode"] == 127


class TestValidation:
    @pytest.mark.parametrize("d", ["example.com", "a.b.example.co.uk", "x-y.example.org"])
    def test_valid_domains(self, d):
        assert is_valid_domain(d)

    @pytest.mark.parametrize("d", ["", "localhost", "-bad.com", "a b.com", "exa_mple.com", "http://x.com", "x..com"])
    def test_invalid_domains(self, d):
        assert not is_valid_domain(d)

    def test_sanitize_strips_shell_metacharacters(self):
        assert sanitize("ex;am|ple`$(x)`.com ") == "examplex.com"

    def test_reject_flag_injection(self):
        assert reject_flag_injection("example.com") is None
        assert "flag" in reject_flag_injection("-oJ")
        assert "flag" in reject_flag_injection("  --resolver-list")

    def test_lines_strips_and_drops_blanks(self):
        assert lines(" a \n\n b\n   \n") == ["a", "b"]

    def test_targets_tempfile_writes_one_per_line_and_cleans_up(self):
        with targets_tempfile(["a.com", "b.com"]) as path:
            assert Path(path).read_text() == "a.com\nb.com"
        assert not Path(path).exists()

    def test_targets_tempfile_cleans_up_even_when_the_body_raises(self):
        with pytest.raises(RuntimeError), targets_tempfile(["a.com"]) as path:
            raise RuntimeError("boom")
        assert not Path(path).exists()
