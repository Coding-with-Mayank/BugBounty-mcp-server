"""
persistence.py (JsonStore) and TaskManager's use of it.

The claims being tested are the "safe" ones: atomic writes, no traversal via
IDs, corrupt files can't block startup, a broken disk can't fail a scan, and
a restart reports interrupted work honestly instead of pretending to resume.
"""
from __future__ import annotations

import asyncio
import json
import os
import stat
import time

import pytest

from mcp_server import persistence
from mcp_server.core import run_cmd
from mcp_server.persistence import JsonStore
from mcp_server.tasks import TaskManager, TaskStatus


def _sh(script: str) -> list[str]:
    return ["sh", "-c", script]


class TestJsonStore:
    def test_save_and_load_roundtrip(self, tmp_path):
        store = JsonStore(tmp_path / "s")
        assert store.save("rec_1", {"a": 1, "nested": {"b": [1, 2]}}) is True
        assert store.load("rec_1") == {"a": 1, "nested": {"b": [1, 2]}}

    def test_load_missing_returns_none(self, tmp_path):
        assert JsonStore(tmp_path).load("nope") is None

    def test_overwrite_replaces_the_record(self, tmp_path):
        store = JsonStore(tmp_path)
        store.save("r", {"v": 1})
        store.save("r", {"v": 2})
        assert store.load("r") == {"v": 2}

    def test_files_are_owner_only(self, tmp_path):
        store = JsonStore(tmp_path / "s")
        store.save("r", {"secret": "recon data"})
        file_mode = stat.S_IMODE((tmp_path / "s" / "r.json").stat().st_mode)
        dir_mode = stat.S_IMODE((tmp_path / "s").stat().st_mode)
        assert file_mode == 0o600
        assert dir_mode == 0o700

    def test_non_json_serialisable_values_do_not_crash_the_save(self, tmp_path):
        store = JsonStore(tmp_path)
        assert store.save("r", {"when": {1, 2}, "obj": object()}) is True  # default=str
        assert store.load("r") is not None

    @pytest.mark.parametrize("bad", ["../escape", "a/b", "", "x" * 65, "has space", "..", "a.b", "nul\x00"])
    def test_unsafe_ids_are_rejected_everywhere(self, tmp_path, bad):
        store = JsonStore(tmp_path / "s")
        assert store.save(bad, {"x": 1}) is False
        assert store.load(bad) is None
        assert store.delete(bad) is False
        assert not (tmp_path / "escape.json").exists()

    def test_failed_write_leaves_the_previous_record_intact_and_no_temp_files(self, tmp_path, monkeypatch):
        store = JsonStore(tmp_path)
        store.save("r", {"v": "old"})

        def boom(src, dst):
            raise OSError("disk exploded")

        monkeypatch.setattr(persistence.os, "replace", boom)
        assert store.save("r", {"v": "new"}) is False
        monkeypatch.undo()

        assert store.load("r") == {"v": "old"}
        assert list(tmp_path.glob(".*.tmp")) == []

    def test_unwritable_location_never_raises(self, tmp_path):
        blocker = tmp_path / "file"
        blocker.write_text("i am a file, not a directory")
        store = JsonStore(blocker / "sub")
        assert store.save("r", {"x": 1}) is False  # logged, not raised
        assert store.load_all() == []

    def test_corrupt_file_is_quarantined_and_skipped(self, tmp_path):
        store = JsonStore(tmp_path)
        store.save("good", {"ok": True})
        (tmp_path / "bad.json").write_text("{ this is not json")
        assert store.load_all() == [{"ok": True}]
        assert (tmp_path / "bad.json.corrupt").exists()
        assert not (tmp_path / "bad.json").exists()

    def test_non_object_json_is_treated_as_corrupt(self, tmp_path):
        (tmp_path / "list.json").write_text("[1, 2, 3]")
        assert JsonStore(tmp_path).load("list") is None

    def test_oversized_record_becomes_a_small_stub(self, tmp_path, monkeypatch):
        monkeypatch.setattr(persistence, "MAX_RECORD_BYTES", 500)
        store = JsonStore(tmp_path)
        store.save("r", {"id": "r", "status": "completed", "result": "x" * 5000})
        rec = store.load("r")
        assert rec["truncated"] is True and "result" not in rec
        assert rec["status"] == "completed"

    def test_load_all_is_oldest_first(self, tmp_path):
        store = JsonStore(tmp_path)
        for i, name in enumerate(["c", "a", "b"]):
            store.save(name, {"n": name})
            os.utime(tmp_path / f"{name}.json", (1000 + i, 1000 + i))
        assert [r["n"] for r in store.load_all()] == ["c", "a", "b"]

    def test_prune_removes_the_oldest(self, tmp_path):
        store = JsonStore(tmp_path)
        for i in range(5):
            store.save(f"r{i}", {"i": i})
            os.utime(tmp_path / f"r{i}.json", (1000 + i, 1000 + i))
        assert store.prune(keep=2) == 3
        assert store.ids() == ["r3", "r4"]

    def test_cleanup_removes_interrupted_write_leftovers(self, tmp_path):
        (tmp_path / ".r.abc.tmp").write_text("partial")
        JsonStore(tmp_path).save("keep", {"x": 1})
        assert JsonStore(tmp_path).cleanup_temp_files() == 1
        assert JsonStore(tmp_path).ids() == ["keep"]

    def test_delete(self, tmp_path):
        store = JsonStore(tmp_path)
        store.save("r", {"x": 1})
        assert store.delete("r") is True
        assert store.load("r") is None
        assert store.delete("r") is True  # idempotent


async def _instant(args):
    return {"ok": True, "findings": [1, 2]}


@pytest.mark.asyncio
class TestTaskManagerPersistence:
    def _tm(self, tmp_path, handlers, **kw):
        return TaskManager(get_handler=handlers.get, store=JsonStore(tmp_path / "tasks"), **kw)

    async def test_task_lifecycle_is_written_to_disk(self, tmp_path):
        tm = self._tm(tmp_path, {"fast": _instant})
        res = await tm.start("fast", {"domain": "example.com"})
        await asyncio.sleep(0.1)

        rec = json.loads((tmp_path / "tasks" / f"{res['task_id']}.json").read_text())
        assert rec["status"] == "completed"
        assert rec["tool"] == "fast"
        assert rec["result"] == {"ok": True, "findings": [1, 2]}
        assert rec["finished_wall"] is not None

    async def test_history_survives_a_restart(self, tmp_path):
        tm1 = self._tm(tmp_path, {"fast": _instant})
        res = await tm1.start("fast", {})
        await asyncio.sleep(0.1)

        tm2 = self._tm(tmp_path, {"fast": _instant})  # "new process", same data dir
        info = tm2.load_persisted()
        assert info == {"persistence": "enabled", "restored": 1, "interrupted": 0}

        out = tm2.results(res["task_id"])
        assert out["status"] == "completed"
        assert out["result"] == {"ok": True, "findings": [1, 2]}
        assert out["restored_from_previous_session"] is True
        assert tm2.list_tasks()["count"] == 1

    async def test_task_running_when_the_process_died_is_reported_as_interrupted(self, tmp_path):
        store = JsonStore(tmp_path / "tasks")
        now = time.time()
        store.save("task_crashed01", {
            "schema": 1, "id": "task_crashed01", "tool": "nuclei_scan", "args": {"target": "x.example.com"},
            "status": "running", "created_wall": now - 120, "started_wall": now - 118,
            "finished_wall": None, "updated_wall": now - 100, "soft_timeout": 60, "hard_timeout": 900,
            "result": None, "error": None,
        })
        tm = self._tm(tmp_path, {})
        info = tm.load_persisted()
        assert info["interrupted"] == 1

        out = tm.results("task_crashed01")
        assert out["status"] == "interrupted"
        assert "did not survive" in out["error"]
        assert tm.status("task_crashed01")["elapsed_seconds"] == pytest.approx(18, abs=2)
        # and it's persisted as interrupted, so the next restart doesn't re-flag it as running
        assert store.load("task_crashed01")["status"] == "interrupted"

    async def test_interrupted_tasks_do_not_count_toward_the_concurrency_limit(self, tmp_path):
        store = JsonStore(tmp_path / "tasks")
        for i in range(3):
            store.save(f"task_c{i}", {"id": f"task_c{i}", "tool": "t", "status": "running",
                                       "created_wall": time.time(), "args": {}})
        tm = self._tm(tmp_path, {"fast": _instant}, max_concurrent=1)
        tm.load_persisted()
        res = await tm.start("fast", {})
        assert "error" not in res

    async def test_partial_results_are_persisted_and_restored(self, tmp_path):
        async def long_scan(args):
            await run_cmd(_sh("echo hit-1; echo hit-2; exec sleep 30"), timeout=60)

        tm1 = self._tm(tmp_path, {"scan": long_scan})
        res = await tm1.start("scan", {})
        await asyncio.sleep(0.6)
        await tm1.cancel(res["task_id"])

        tm2 = self._tm(tmp_path, {"scan": long_scan})
        tm2.load_persisted()
        out = tm2.results(res["task_id"])
        assert out["status"] == "cancelled"
        assert out["result"]["captured"][0]["stdout"] == "hit-1\nhit-2\n"
        assert tm2.status(res["task_id"])["partial_results_available"] is True

    async def test_shutdown_cancels_active_tasks_and_preserves_their_output(self, tmp_path):
        async def long_scan(args):
            await run_cmd(_sh("echo progress; exec sleep 30"), timeout=60)

        tm1 = self._tm(tmp_path, {"scan": long_scan})
        r1 = await tm1.start("scan", {})
        r2 = await tm1.start("scan", {})
        await asyncio.sleep(0.6)

        assert await tm1.shutdown() == 2

        tm2 = self._tm(tmp_path, {"scan": long_scan})
        info = tm2.load_persisted()
        assert info["interrupted"] == 0  # a graceful stop is not a crash
        for r in (r1, r2):
            out = tm2.results(r["task_id"])
            assert out["status"] == "cancelled"
            assert "shut down" in out["error"]
            assert out["result"]["captured"][0]["stdout"] == "progress\n"

    async def test_shutdown_with_nothing_running_is_a_noop(self, tmp_path):
        tm = self._tm(tmp_path, {"fast": _instant})
        await tm.start("fast", {})
        await asyncio.sleep(0.1)
        assert await tm.shutdown() == 0

    async def test_credentials_in_task_args_are_redacted_on_disk(self, tmp_path):
        tm = self._tm(tmp_path, {"fast": _instant})
        res = await tm.start("fast", {"domain": "example.com", "shodan_api_key": "SUPERSECRET",
                                      "headers": {"Authorization": "Bearer abc", "X-Trace": "1"}})
        await asyncio.sleep(0.1)
        raw = (tmp_path / "tasks" / f"{res['task_id']}.json").read_text()
        assert "SUPERSECRET" not in raw and "Bearer abc" not in raw
        rec = json.loads(raw)
        assert rec["args"]["domain"] == "example.com"
        assert rec["args"]["headers"]["X-Trace"] == "1"

    async def test_evicted_tasks_are_deleted_from_disk_too(self, tmp_path):
        tm = self._tm(tmp_path, {"fast": _instant}, max_tracked=2)
        ids = []
        for _ in range(5):
            ids.append((await tm.start("fast", {}))["task_id"])
            await asyncio.sleep(0.03)
        await asyncio.sleep(0.1)
        on_disk = set(JsonStore(tmp_path / "tasks").ids())
        assert on_disk == set(tm._tasks)
        assert len(on_disk) <= 3

    async def test_malformed_records_are_skipped_without_crashing_startup(self, tmp_path):
        d = tmp_path / "tasks"
        d.mkdir()
        (d / "task_missingfields.json").write_text(json.dumps({"id": "task_missingfields"}))
        (d / "task_badstatus.json").write_text(json.dumps({"id": "task_badstatus", "tool": "t", "status": "wat"}))
        (d / "task_garbage.json").write_text("not json")
        JsonStore(d).save("task_fine", {"id": "task_fine", "tool": "t", "status": "completed",
                                        "created_wall": time.time(), "args": {}})
        tm = self._tm(tmp_path, {})
        assert tm.load_persisted()["restored"] == 1
        assert tm.status("task_fine")["status"] == "completed"

    async def test_a_broken_disk_never_fails_the_task(self, tmp_path):
        blocker = tmp_path / "blocked"
        blocker.write_text("a file where the directory should be")
        tm = TaskManager(get_handler={"fast": _instant}.get, store=JsonStore(blocker / "tasks"))
        res = await tm.start("fast", {})
        await asyncio.sleep(0.1)
        assert tm.results(res["task_id"])["status"] == "completed"

    async def test_no_store_means_no_files_and_old_behaviour(self, tmp_path):
        tm = TaskManager(get_handler={"fast": _instant}.get)
        res = await tm.start("fast", {})
        await asyncio.sleep(0.1)
        assert tm.results(res["task_id"])["status"] == "completed"
        assert tm.load_persisted() == {"persistence": "disabled", "restored": 0, "interrupted": 0}

    async def test_load_persisted_does_not_clobber_live_tasks(self, tmp_path):
        tm = self._tm(tmp_path, {"fast": _instant})
        res = await tm.start("fast", {})
        await asyncio.sleep(0.1)
        before = tm._tasks[res["task_id"]]
        tm.load_persisted()
        assert tm._tasks[res["task_id"]] is before
        assert before.restored is False

    async def test_restored_tasks_sort_before_new_ones_in_list_tasks(self, tmp_path):
        tm1 = self._tm(tmp_path, {"fast": _instant})
        old = (await tm1.start("fast", {}))["task_id"]
        await asyncio.sleep(0.1)

        tm2 = self._tm(tmp_path, {"fast": _instant})
        tm2.load_persisted()
        new = (await tm2.start("fast", {}))["task_id"]
        listing = [t["task_id"] for t in tm2.list_tasks()["tasks"]]
        assert listing == [new, old]  # newest first, across the restart boundary

    async def test_cancel_before_start_is_persisted_as_cancelled(self, tmp_path):
        async def slow(args):
            await asyncio.sleep(5)

        tm = self._tm(tmp_path, {"slow": slow})
        res = await tm.start("slow", {})
        await tm.cancel(res["task_id"])  # no await in between: the race fixed in step 1
        rec = JsonStore(tmp_path / "tasks").load(res["task_id"])
        assert rec["status"] == TaskStatus.CANCELLED.value


@pytest.mark.asyncio
class TestRealCrashRecovery:
    async def test_sigkilled_process_leaves_an_interrupted_task_not_a_phantom_running_one(self, tmp_path):
        """Not simulated: spawn a real process that starts a task, SIGKILL it
        mid-run (no chance to clean up or shut down gracefully), then restore
        from the same directory in this process."""
        import signal
        import subprocess
        import sys
        import textwrap
        from pathlib import Path

        repo = Path(__file__).resolve().parent.parent
        child_code = textwrap.dedent(f"""
            import asyncio
            from mcp_server.persistence import JsonStore
            from mcp_server.tasks import TaskManager

            async def long(args):
                await asyncio.sleep(60)

            async def main():
                tm = TaskManager(get_handler={{"long": long}}.get, store=JsonStore({str(tmp_path / "tasks")!r}))
                await tm.start("long", {{"target": "example.com"}})
                print("started", flush=True)
                await asyncio.sleep(60)

            asyncio.run(main())
        """)
        proc = subprocess.Popen(
            [sys.executable, "-c", child_code], cwd=repo, env={**os.environ, "PYTHONPATH": str(repo)},
            stdout=subprocess.PIPE, text=True,
        )
        try:
            assert proc.stdout.readline().strip() == "started"
            await asyncio.sleep(0.3)
            proc.send_signal(signal.SIGKILL)
            proc.wait(timeout=10)
        finally:
            if proc.poll() is None:
                proc.kill()

        tm = TaskManager(get_handler={}.get, store=JsonStore(tmp_path / "tasks"))
        info = tm.load_persisted()
        assert info["restored"] == 1 and info["interrupted"] == 1
        task = tm.list_tasks()["tasks"][0]
        assert task["status"] == "interrupted"
        assert tm.list_tasks()["running_count"] == 0
