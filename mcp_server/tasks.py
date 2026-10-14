"""
tasks.py — background task lifecycle for long-running tool calls.

nuclei_scan/dir_fuzz/full_recon/port_scan can run for minutes. Calling
them directly (as every existing tool call does) blocks the MCP request
until they finish, with no visibility into progress and no way to cancel
a runaway scan mid-flight. start_task wraps any registered tool call in a
cancellable background asyncio.Task; get_task_status/get_task_results poll
it; cancel_task stops it.

This reuses the exact same handler functions every direct tool call already
uses — the SAME dispatch table server.py's call_tool() has. Nothing about
how any existing tool validates its input, checks scope, or executes
changes because of this module. start_task is purely an additional way to
invoke the same handlers asynchronously.

Task state is in-memory only and lost on restart — there's no persistence
layer in this project. See CHANGELOG.md for why that's a deliberate scope
boundary for now, not an oversight.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .core import capture_partial_results
from .persistence import JsonStore, valid_id

logger = logging.getLogger(__name__)


class TaskStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    # Only ever assigned when restoring history after a restart: the task was
    # queued/running when the previous server process died, and its
    # subprocess died with it. Can't be resumed — reported honestly as such.
    INTERRUPTED = "interrupted"


TERMINAL_STATUSES = frozenset({
    TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED, TaskStatus.TIMED_OUT,
    TaskStatus.INTERRUPTED,
})

_SENSITIVE_KEY = re.compile(r"(key|token|secret|passw|auth|cookie|bearer)", re.IGNORECASE)


def _redact(value: Any) -> Any:
    """Task args are saved to disk as history. Anything that looks like a
    credential is masked first — a task's *record* shouldn't become a place
    API keys or session cookies get copied to."""
    if isinstance(value, dict):
        return {
            k: ("***redacted***" if _SENSITIVE_KEY.search(str(k)) else _redact(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value

DEFAULT_SOFT_TIMEOUT = 60.0
DEFAULT_HARD_TIMEOUT = 900.0


@dataclass
class _Task:
    id: str
    tool: str
    args: dict
    status: TaskStatus = TaskStatus.QUEUED
    created_at: float = field(default_factory=time.monotonic)
    started_at: float | None = None
    finished_at: float | None = None
    soft_timeout: float = DEFAULT_SOFT_TIMEOUT
    hard_timeout: float = DEFAULT_HARD_TIMEOUT
    result: Any = None
    error: str | None = None
    asyncio_task: asyncio.Task | None = field(default=None, repr=False)
    # Wall-clock mirrors of the monotonic timestamps above. monotonic() is
    # meaningless across processes, so these are what survive a restart.
    created_wall: float = field(default_factory=time.time)
    started_wall: float | None = None
    finished_wall: float | None = None
    restored: bool = False

    def to_record(self) -> dict:
        return {
            "schema": 1,
            "id": self.id,
            "tool": self.tool,
            "args": _redact(self.args),
            "status": self.status.value,
            "created_wall": self.created_wall,
            "started_wall": self.started_wall,
            "finished_wall": self.finished_wall,
            "updated_wall": time.time(),
            "soft_timeout": self.soft_timeout,
            "hard_timeout": self.hard_timeout,
            "result": self.result,
            "error": self.error,
        }

    @classmethod
    def from_record(cls, rec: dict) -> _Task | None:
        """Rebuild a task from disk; None if the record is malformed (a
        hand-edited or truncated file must not crash startup)."""
        try:
            task_id, tool = rec["id"], rec["tool"]
            if not (isinstance(task_id, str) and valid_id(task_id) and isinstance(tool, str)):
                return None
            status = TaskStatus(rec["status"])
            created_wall = float(rec.get("created_wall") or time.time())
            started_wall = rec.get("started_wall")
            finished_wall = rec.get("finished_wall")
            # Map wall-clock onto this process's monotonic clock so elapsed
            # times and newest-first ordering stay coherent with new tasks.
            now_mono, now_wall = time.monotonic(), time.time()

            def mono(wall: float | None) -> float | None:
                return None if wall is None else now_mono - (now_wall - float(wall))

            args = rec.get("args")
            return cls(
                id=task_id,
                tool=tool,
                args=args if isinstance(args, dict) else {},
                status=status,
                created_at=mono(created_wall) or now_mono,
                started_at=mono(started_wall),
                finished_at=mono(finished_wall),
                soft_timeout=float(rec.get("soft_timeout", DEFAULT_SOFT_TIMEOUT)),
                hard_timeout=float(rec.get("hard_timeout", DEFAULT_HARD_TIMEOUT)),
                result=rec.get("result"),
                error=rec.get("error"),
                created_wall=created_wall,
                started_wall=started_wall,
                finished_wall=finished_wall,
                restored=True,
            )
        except (KeyError, ValueError, TypeError):
            return None

    def elapsed_seconds(self) -> float:
        start = self.started_at or self.created_at
        end = self.finished_at or time.monotonic()
        return round(end - start, 1)

    def soft_timeout_exceeded(self) -> bool:
        return self.status == TaskStatus.RUNNING and self.elapsed_seconds() >= self.soft_timeout

    def status_dict(self) -> dict:
        d: dict[str, Any] = {
            "task_id": self.id,
            "tool": self.tool,
            "status": self.status.value,
            "elapsed_seconds": self.elapsed_seconds(),
            "soft_timeout_seconds": self.soft_timeout,
            "hard_timeout_seconds": self.hard_timeout,
        }
        if self.soft_timeout_exceeded():
            d["soft_timeout_exceeded"] = True
            d["message"] = (
                f"Still running after {self.elapsed_seconds():.0f}s "
                f"(soft threshold: {self.soft_timeout:.0f}s). It's still active — "
                "this is advisory, not a pause: keep polling get_task_status to "
                "wait, or call cancel_task to stop it."
            )
            d["options"] = ["continue", "cancel"]
        if self.has_partial_results:
            d["partial_results_available"] = True
        if self.restored:
            d["restored_from_previous_session"] = True
        return d

    @property
    def has_partial_results(self) -> bool:
        # Status check so a handler that legitimately returns a "partial"
        # key in a *completed* result is never mistaken for an interrupted run.
        return (
            self.status in (
                TaskStatus.TIMED_OUT, TaskStatus.CANCELLED, TaskStatus.FAILED, TaskStatus.INTERRUPTED,
            )
            and isinstance(self.result, dict)
            and bool(self.result.get("partial"))
        )

    def results_dict(self) -> dict:
        d = self.status_dict()
        d["result"] = self.result
        d["error"] = self.error
        return d


def _partial_result(captured: list[dict], reason: str) -> dict | None:
    """Shape what was captured from an interrupted task. None when nothing
    was captured (a handler that never ran a subprocess), so tasks that
    stopped before producing anything keep result=None exactly as before."""
    if not captured:
        return None
    return {
        "partial": True,
        "note": (
            f"Task stopped ({reason}) before finishing. Below is the raw output of each "
            "command it ran, in order — the last one may be incomplete (whole lines only). "
            "This is NOT a processed result: findings were not parsed, deduplicated or "
            "scope-filtered the way a completed run's would be."
        ),
        "commands_captured": len(captured),
        "captured": list(captured),
    }


Handler = Callable[[dict], Awaitable[dict]]
HandlerLookup = Callable[[str], Handler | None]


class TaskManager:
    """
    tool -> handler lookup is injected (get_handler) rather than imported,
    so this module has no dependency on server.py — server.py depends on
    this module, not the other way around.
    """

    def __init__(
        self,
        get_handler: HandlerLookup,
        max_concurrent: int = 10,
        max_tracked: int = 200,
        store: JsonStore | None = None,
    ):
        self._tasks: dict[str, _Task] = {}
        self._get_handler = get_handler
        self.max_concurrent = max_concurrent
        self.max_tracked = max_tracked
        # Optional. None = purely in-memory, exactly the pre-persistence
        # behaviour (and what every test that doesn't opt in gets).
        self._store = store

    def _persist(self, task: _Task) -> None:
        """Best-effort: a disk problem must never fail or stall a scan."""
        if self._store is None:
            return
        try:
            self._store.save(task.id, task.to_record())
        except Exception:  # noqa: BLE001 — persistence is never allowed to break a task
            logger.exception("could not persist task %s", task.id)

    def load_persisted(self) -> dict:
        """Restore task history from the store (call once at startup, before
        serving). Tasks that were queued/running when the previous process
        died are marked INTERRUPTED — their subprocesses died with it, and
        the original result (if any) was never produced. This restores
        *history and results*; it does not and cannot resume work."""
        if self._store is None:
            return {"persistence": "disabled", "restored": 0, "interrupted": 0}
        self._store.cleanup_temp_files()
        restored = interrupted = 0
        for rec in self._store.load_all():
            task = _Task.from_record(rec)
            if task is None or task.id in self._tasks:
                continue
            if task.status in (TaskStatus.QUEUED, TaskStatus.RUNNING):
                task.status = TaskStatus.INTERRUPTED
                task.error = (
                    "The server stopped or restarted while this task was still running; its "
                    "process did not survive. Nothing was recovered — re-run it if you still need it."
                )
                last_seen = float(rec.get("updated_wall") or time.time())
                task.finished_wall = last_seen
                task.finished_at = time.monotonic() - (time.time() - last_seen)
                self._persist(task)
                interrupted += 1
            self._tasks[task.id] = task
            restored += 1
        self._evict_old_finished()
        self._store.prune(self.max_tracked)
        return {"persistence": "enabled", "restored": restored, "interrupted": interrupted}

    async def shutdown(self, reason: str = "The server shut down while this task was running.") -> int:
        """Cancel everything still active, so each task's partial output is
        captured and persisted instead of vanishing with the process.
        Returns how many tasks were stopped."""
        active = [t for t in self._tasks.values() if t.status in (TaskStatus.QUEUED, TaskStatus.RUNNING)]
        await asyncio.gather(*(self.cancel(t.id) for t in active), return_exceptions=True)
        for t in active:
            if t.status == TaskStatus.CANCELLED:
                t.error = reason
                self._persist(t)
        return len(active)

    def _running_count(self) -> int:
        return sum(
            1 for t in self._tasks.values()
            if t.status in (TaskStatus.QUEUED, TaskStatus.RUNNING)
        )

    def _evict_old_finished(self) -> None:
        """Keep memory bounded: drop the oldest *finished* tasks once
        max_tracked is exceeded. Never evicts a queued/running task."""
        if len(self._tasks) <= self.max_tracked:
            return
        finished = sorted(
            (t for t in self._tasks.values() if t.status in TERMINAL_STATUSES),
            key=lambda t: t.finished_at or 0,
        )
        while len(self._tasks) > self.max_tracked and finished:
            evicted = finished.pop(0)
            self._tasks.pop(evicted.id, None)
            if self._store is not None:
                self._store.delete(evicted.id)

    async def start(
        self,
        tool: str,
        args: dict,
        soft_timeout: float | None = None,
        hard_timeout: float | None = None,
    ) -> dict:
        handler = self._get_handler(tool)
        if handler is None:
            return {"error": f"Unknown tool '{tool}' — not in the tool registry."}

        if self._running_count() >= self.max_concurrent:
            return {
                "error": (
                    f"Too many tasks already running ({self.max_concurrent} max). "
                    "Wait for one to finish, or cancel one with cancel_task."
                )
            }

        task_id = "task_" + uuid.uuid4().hex[:10]
        task = _Task(
            id=task_id,
            tool=tool,
            args=args,
            soft_timeout=soft_timeout if soft_timeout is not None else DEFAULT_SOFT_TIMEOUT,
            hard_timeout=hard_timeout if hard_timeout is not None else DEFAULT_HARD_TIMEOUT,
        )
        self._tasks[task_id] = task
        self._evict_old_finished()
        self._persist(task)

        async def _run() -> None:
            task.status = TaskStatus.RUNNING
            task.started_at = time.monotonic()
            task.started_wall = time.time()
            self._persist(task)
            # Everything run_cmd() produces inside this block — every command
            # a multi-stage handler already finished, plus the in-flight one's
            # output up to the moment it was stopped — lands in `partial`,
            # which survives the CancelledError unwinding the stack. That's
            # what lets a cancelled / hard-timed-out task return the recon or
            # scan output gathered so far instead of nothing.
            with capture_partial_results() as partial:
                try:
                    task.result = await asyncio.wait_for(handler(args), timeout=task.hard_timeout)
                    task.status = TaskStatus.COMPLETED
                except TimeoutError:
                    # asyncio.wait_for cancels the inner call internally on
                    # timeout, which propagates a CancelledError down through
                    # run_cmd (killing any child process) before this is raised.
                    task.status = TaskStatus.TIMED_OUT
                    task.error = f"Hit the hard timeout ({task.hard_timeout:.0f}s) and was force-stopped."
                    task.result = _partial_result(partial, "hard timeout")
                except asyncio.CancelledError:
                    # External cancel_task() call, not the hard timeout above.
                    task.status = TaskStatus.CANCELLED
                    task.error = "Cancelled."
                    task.result = _partial_result(partial, "cancelled")
                    raise  # never swallow cancellation
                except Exception as exc:
                    task.status = TaskStatus.FAILED
                    task.error = str(exc)
                    task.result = _partial_result(partial, "failed")
                finally:
                    task.finished_at = time.monotonic()
                    task.finished_wall = time.time()
                    self._persist(task)

        task.asyncio_task = asyncio.create_task(_run())
        return task.status_dict()

    def status(self, task_id: str) -> dict:
        task = self._tasks.get(task_id)
        if task is None:
            return {"error": f"No task with id '{task_id}'."}
        return task.status_dict()

    def results(self, task_id: str) -> dict:
        task = self._tasks.get(task_id)
        if task is None:
            return {"error": f"No task with id '{task_id}'."}
        return task.results_dict()

    async def cancel(self, task_id: str) -> dict:
        task = self._tasks.get(task_id)
        if task is None:
            return {"error": f"No task with id '{task_id}'."}
        if task.status in TERMINAL_STATUSES:
            d = task.status_dict()
            d["message"] = f"Task already {task.status.value}; nothing to cancel."
            return d
        if task.asyncio_task is not None:
            task.asyncio_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task.asyncio_task
            # Edge case: if the task was still QUEUED (asyncio hadn't given
            # _run() its first scheduling turn yet), cancelling it means the
            # coroutine raises CancelledError at entry without executing a
            # single line of _run()'s body — including its own except
            # asyncio.CancelledError clause. Without this, the task would
            # stay QUEUED forever: it'll never run, but also never reports
            # as finished. Finalize it here instead, since this is the one
            # place that reliably knows the underlying asyncio.Task is dead.
            if task.status not in TERMINAL_STATUSES:
                task.status = TaskStatus.CANCELLED
                task.error = "Cancelled before it started running."
                task.finished_at = time.monotonic()
                task.finished_wall = time.time()
                self._persist(task)
        return task.status_dict()

    def list_tasks(self, status: str | None = None, tool: str | None = None) -> dict:
        """Enumerate tracked tasks (newest first), optionally filtered by
        status and/or tool name. Without this, an agent that loses track of
        a task_id — or wants to see everything currently running before
        starting more work — has no way to find it again; get_task_status/
        get_task_results both require already knowing the id."""
        status_filter: TaskStatus | None = None
        if status is not None:
            try:
                status_filter = TaskStatus(status)
            except ValueError:
                valid = ", ".join(s.value for s in TaskStatus)
                return {"error": f"Unknown status '{status}'. Valid values: {valid}."}

        tasks = sorted(self._tasks.values(), key=lambda t: t.created_at, reverse=True)
        if status_filter is not None:
            tasks = [t for t in tasks if t.status == status_filter]
        if tool is not None:
            tasks = [t for t in tasks if t.tool == tool]

        return {
            "count": len(tasks),
            "running_count": self._running_count(),
            "max_concurrent": self.max_concurrent,
            "tasks": [t.status_dict() for t in tasks],
        }
