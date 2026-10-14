"""
Tests for mcp_server.tasks.TaskManager — background task lifecycle for
long-running tool calls (start_task/get_task_status/get_task_results/
cancel_task).

Uses fake async handlers throughout (no real tools, no server.py
dependency — TaskManager takes get_handler as a plain injected lookup).
Real-subprocess cancellation (proving the underlying OS process actually
dies, not just that the coroutine returns) is covered in
test_server.py::TestTaskManagerRealSubprocess, going through the full
server.py wiring — that's the one that matters most; these are about the
lifecycle/bookkeeping logic in isolation.
"""
from __future__ import annotations

import asyncio

import pytest

from mcp_server.tasks import TaskManager


async def _instant(args: dict) -> dict:
    return {"ok": True, "echo": args}


async def _sleeper(seconds: float):
    async def _handler(args: dict) -> dict:
        await asyncio.sleep(seconds)
        return {"ok": True, "slept": seconds}
    return _handler


async def _always_fails(args: dict) -> dict:
    raise ValueError("simulated handler failure")


def _manager(handlers: dict, **kw) -> TaskManager:
    return TaskManager(get_handler=handlers.get, **kw)


@pytest.mark.asyncio
class TestBasicLifecycle:
    async def test_unknown_tool_returns_error_without_creating_a_task(self):
        tm = _manager({})
        res = await tm.start("nope", {})
        assert "error" in res
        assert "Unknown tool" in res["error"]

    async def test_start_returns_task_id_immediately(self):
        tm = _manager({"fast": _instant})
        res = await tm.start("fast", {"x": 1})
        assert "task_id" in res
        assert res["tool"] == "fast"
        assert res["status"] in ("queued", "running")

    async def test_task_completes_and_results_are_retrievable(self):
        tm = _manager({"fast": _instant})
        res = await tm.start("fast", {"x": 1})
        task_id = res["task_id"]
        await asyncio.sleep(0.05)  # let the scheduled task actually run

        status = tm.status(task_id)
        assert status["status"] == "completed"

        results = tm.results(task_id)
        assert results["status"] == "completed"
        assert results["result"] == {"ok": True, "echo": {"x": 1}}
        assert results["error"] is None

    async def test_failed_handler_marks_task_failed_with_error(self):
        tm = _manager({"broken": _always_fails})
        res = await tm.start("broken", {})
        await asyncio.sleep(0.05)

        results = tm.results(res["task_id"])
        assert results["status"] == "failed"
        assert "simulated handler failure" in results["error"]

    async def test_unknown_task_id_returns_error_not_exception(self):
        tm = _manager({})
        assert "error" in tm.status("task_doesnotexist")
        assert "error" in tm.results("task_doesnotexist")

    async def test_task_ids_are_unique(self):
        tm = _manager({"fast": _instant}, max_concurrent=50)
        ids = {(await tm.start("fast", {}))["task_id"] for _ in range(20)}
        assert len(ids) == 20


@pytest.mark.asyncio
class TestSoftTimeout:
    async def test_soft_timeout_not_flagged_before_threshold(self):
        handler = await _sleeper(2)
        tm = _manager({"slow": handler})
        res = await tm.start("slow", {}, soft_timeout=60)
        status = tm.status(res["task_id"])
        assert status.get("soft_timeout_exceeded") is not True
        await tm.cancel(res["task_id"])  # cleanup

    async def test_soft_timeout_flagged_once_exceeded(self):
        handler = await _sleeper(1.0)
        tm = _manager({"slow": handler})
        res = await tm.start("slow", {}, soft_timeout=0.1)
        await asyncio.sleep(0.3)
        status = tm.status(res["task_id"])
        assert status["soft_timeout_exceeded"] is True
        assert status["options"] == ["continue", "cancel"]
        await tm.cancel(res["task_id"])  # cleanup

    async def test_soft_timeout_is_advisory_only_task_keeps_running(self):
        """Crossing the soft threshold must NOT stop the task."""
        handler = await _sleeper(0.4)
        tm = _manager({"slow": handler})
        res = await tm.start("slow", {}, soft_timeout=0.05)
        await asyncio.sleep(0.2)
        assert tm.status(res["task_id"])["status"] == "running"  # still going
        await asyncio.sleep(0.4)
        assert tm.status(res["task_id"])["status"] == "completed"  # finished on its own


@pytest.mark.asyncio
class TestHardTimeout:
    async def test_hard_timeout_marks_task_timed_out(self):
        handler = await _sleeper(5)
        tm = _manager({"slow": handler})
        res = await tm.start("slow", {}, hard_timeout=0.2)
        await asyncio.sleep(0.5)
        results = tm.results(res["task_id"])
        assert results["status"] == "timed_out"
        assert "hard timeout" in results["error"]

    async def test_task_completing_before_hard_timeout_is_unaffected(self):
        handler = await _sleeper(0.1)
        tm = _manager({"fast_enough": handler})
        res = await tm.start("fast_enough", {}, hard_timeout=5)
        await asyncio.sleep(0.3)
        assert tm.status(res["task_id"])["status"] == "completed"


@pytest.mark.asyncio
class TestCancellation:
    async def test_cancel_running_task_marks_cancelled(self):
        handler = await _sleeper(10)
        tm = _manager({"slow": handler})
        res = await tm.start("slow", {})
        await asyncio.sleep(0.1)
        cancel_res = await tm.cancel(res["task_id"])
        assert cancel_res["status"] == "cancelled"

    async def test_cancel_already_finished_task_is_graceful(self):
        tm = _manager({"fast": _instant})
        res = await tm.start("fast", {})
        await asyncio.sleep(0.1)
        assert tm.status(res["task_id"])["status"] == "completed"

        cancel_res = await tm.cancel(res["task_id"])
        assert cancel_res["status"] == "completed"  # unchanged
        assert "already" in cancel_res["message"]

    async def test_cancel_unknown_task_id_returns_error(self):
        tm = _manager({})
        res = await tm.cancel("task_doesnotexist")
        assert "error" in res

    async def test_cancel_before_task_ever_runs_still_finalizes_to_cancelled(self):
        """Regression test: cancelling a task with no intervening `await`
        between start() and cancel() used to leave it stuck at QUEUED
        forever (_run()'s own except-clause never got a chance to execute),
        even though the underlying asyncio.Task was already dead and would
        never produce a result."""
        handler = await _sleeper(5)
        tm = _manager({"slow": handler})
        res = await tm.start("slow", {})
        cancel_res = await tm.cancel(res["task_id"])  # no sleep() in between
        assert cancel_res["status"] == "cancelled"

        status = tm.status(res["task_id"])
        assert status["status"] == "cancelled"
        results = tm.results(res["task_id"])
        assert results["status"] == "cancelled"
        assert results["error"] is not None


@pytest.mark.asyncio
class TestConcurrencyLimit:
    async def test_rejects_new_task_once_at_max_concurrent(self):
        handler = await _sleeper(5)
        tm = _manager({"slow": handler}, max_concurrent=2)
        r1 = await tm.start("slow", {})
        r2 = await tm.start("slow", {})
        assert "task_id" in r1
        assert "task_id" in r2

        r3 = await tm.start("slow", {})
        assert "error" in r3
        assert "Too many tasks" in r3["error"]

        # cleanup
        await tm.cancel(r1["task_id"])
        await tm.cancel(r2["task_id"])

    async def test_slot_frees_up_after_a_task_finishes(self):
        tm = _manager({"fast": _instant}, max_concurrent=1)
        r1 = await tm.start("fast", {})
        await asyncio.sleep(0.1)  # let it finish
        assert tm.status(r1["task_id"])["status"] == "completed"

        r2 = await tm.start("fast", {})
        assert "task_id" in r2  # slot was freed


@pytest.mark.asyncio
class TestEviction:
    async def test_old_finished_tasks_evicted_beyond_max_tracked(self):
        tm = _manager({"fast": _instant}, max_tracked=5)
        ids = []
        for _ in range(10):
            r = await tm.start("fast", {})
            ids.append(r["task_id"])
            await asyncio.sleep(0.02)  # let each finish before starting the next

        assert len(tm._tasks) <= 5
        # the earliest-created tasks should be the ones evicted
        assert ids[0] not in tm._tasks
        assert ids[-1] in tm._tasks

    async def test_running_tasks_are_never_evicted(self):
        handler = await _sleeper(5)
        tm = _manager({"slow": handler, "fast": _instant}, max_tracked=2)
        slow_res = await tm.start("slow", {})  # stays running throughout
        for _ in range(5):
            await tm.start("fast", {})
            await asyncio.sleep(0.02)

        assert slow_res["task_id"] in tm._tasks
        await tm.cancel(slow_res["task_id"])  # cleanup


@pytest.mark.asyncio
class TestListTasks:
    async def test_list_tasks_empty(self):
        tm = _manager({})
        res = tm.list_tasks()
        assert res == {"count": 0, "running_count": 0, "max_concurrent": 10, "tasks": []}

    async def test_list_tasks_returns_newest_first(self):
        tm = _manager({"fast": _instant})
        ids = []
        for _ in range(3):
            r = await tm.start("fast", {})
            ids.append(r["task_id"])
            await asyncio.sleep(0.02)

        res = tm.list_tasks()
        assert res["count"] == 3
        assert [t["task_id"] for t in res["tasks"]] == list(reversed(ids))

    async def test_list_tasks_filters_by_status(self):
        handler = await _sleeper(5)
        tm = _manager({"slow": handler, "fast": _instant})
        slow_res = await tm.start("slow", {})
        await tm.start("fast", {})
        await asyncio.sleep(0.05)

        running = tm.list_tasks(status="running")
        assert running["count"] == 1
        assert running["tasks"][0]["task_id"] == slow_res["task_id"]

        completed = tm.list_tasks(status="completed")
        assert completed["count"] == 1
        assert completed["tasks"][0]["tool"] == "fast"

        await tm.cancel(slow_res["task_id"])  # cleanup

    async def test_list_tasks_filters_by_tool(self):
        tm = _manager({"a": _instant, "b": _instant})
        await tm.start("a", {})
        await tm.start("b", {})
        await asyncio.sleep(0.05)

        res = tm.list_tasks(tool="a")
        assert res["count"] == 1
        assert res["tasks"][0]["tool"] == "a"

    async def test_list_tasks_unknown_status_returns_error(self):
        tm = _manager({})
        res = tm.list_tasks(status="not_a_real_status")
        assert "error" in res

    async def test_list_tasks_reports_running_count_and_max_concurrent(self):
        handler = await _sleeper(5)
        tm = _manager({"slow": handler}, max_concurrent=7)
        r1 = await tm.start("slow", {})
        r2 = await tm.start("slow", {})

        res = tm.list_tasks()
        assert res["running_count"] == 2
        assert res["max_concurrent"] == 7

        await tm.cancel(r1["task_id"])
        await tm.cancel(r2["task_id"])


# ── Partial-result preservation ──────────────────────────────────────────────
from mcp_server.core import run_cmd  # noqa: E402


def _sh(script: str) -> list[str]:
    return ["sh", "-c", script]


async def _two_stage_handler(args: dict) -> dict:
    """Stand-in for a multi-stage handler (full_recon-style): one command
    finishes, the next runs long and emits output as it goes."""
    await run_cmd(_sh("echo subdomain-a; echo subdomain-b"))
    await run_cmd(_sh("echo finding-1; echo finding-2; printf half-line; exec sleep 30"), timeout=60)
    return {"never": "reached"}


@pytest.mark.asyncio
class TestPartialResultPreservation:
    async def test_cancelled_task_returns_what_it_gathered(self):
        tm = _manager({"recon": _two_stage_handler})
        res = await tm.start("recon", {})
        await asyncio.sleep(0.8)
        await tm.cancel(res["task_id"])

        out = tm.results(res["task_id"])
        assert out["status"] == "cancelled"
        assert out["result"]["partial"] is True
        assert out["result"]["commands_captured"] == 2
        stdouts = [c["stdout"] for c in out["result"]["captured"]]
        assert stdouts == ["subdomain-a\nsubdomain-b\n", "finding-1\nfinding-2\n"]  # fragment dropped
        assert "NOT a processed result" in out["result"]["note"]

    async def test_hard_timeout_also_preserves_partial_output(self):
        tm = _manager({"recon": _two_stage_handler})
        res = await tm.start("recon", {}, hard_timeout=1.0)
        await asyncio.sleep(2.0)

        out = tm.results(res["task_id"])
        assert out["status"] == "timed_out"
        assert out["result"]["partial"] is True
        assert out["result"]["captured"][-1]["stdout"] == "finding-1\nfinding-2\n"

    async def test_status_flags_that_partial_results_exist(self):
        tm = _manager({"recon": _two_stage_handler})
        res = await tm.start("recon", {})
        await asyncio.sleep(0.8)
        assert "partial_results_available" not in tm.status(res["task_id"])  # still running
        await tm.cancel(res["task_id"])
        assert tm.status(res["task_id"])["partial_results_available"] is True

    async def test_failed_task_keeps_what_ran_before_the_failure(self):
        async def fails_after_work(args):
            await run_cmd(_sh("echo got-this-far"))
            raise RuntimeError("parser exploded")

        tm = _manager({"x": fails_after_work})
        res = await tm.start("x", {})
        await asyncio.sleep(0.4)
        out = tm.results(res["task_id"])
        assert out["status"] == "failed" and "parser exploded" in out["error"]
        assert out["result"]["captured"][0]["stdout"] == "got-this-far\n"

    async def test_task_with_no_subprocess_output_keeps_result_none(self):
        """No behaviour change for handlers that never ran a command."""
        handler = await _sleeper(5)
        tm = _manager({"slow": handler})
        res = await tm.start("slow", {})
        await asyncio.sleep(0.1)
        await tm.cancel(res["task_id"])
        assert tm.results(res["task_id"])["result"] is None
        assert "partial_results_available" not in tm.status(res["task_id"])

    async def test_completed_task_result_is_untouched(self):
        async def ok(args):
            await run_cmd(_sh("echo hi"))
            return {"findings": [1, 2, 3]}

        tm = _manager({"ok": ok})
        res = await tm.start("ok", {})
        await asyncio.sleep(0.4)
        out = tm.results(res["task_id"])
        assert out["status"] == "completed"
        assert out["result"] == {"findings": [1, 2, 3]}

    async def test_a_completed_result_containing_a_partial_key_is_not_misreported(self):
        async def odd(args):
            return {"partial": True, "from": "the handler's own data"}

        tm = _manager({"odd": odd})
        res = await tm.start("odd", {})
        await asyncio.sleep(0.2)
        assert "partial_results_available" not in tm.status(res["task_id"])

    async def test_concurrent_tasks_capture_independently(self):
        async def tagged(args):
            await run_cmd(_sh(f"echo {args['tag']}; exec sleep 30"), timeout=60)

        tm = _manager({"t": tagged})
        a = await tm.start("t", {"tag": "AAA"})
        b = await tm.start("t", {"tag": "BBB"})
        await asyncio.sleep(0.6)
        await tm.cancel(a["task_id"])
        await tm.cancel(b["task_id"])
        assert tm.results(a["task_id"])["result"]["captured"][0]["stdout"] == "AAA\n"
        assert tm.results(b["task_id"])["result"]["captured"][0]["stdout"] == "BBB\n"
