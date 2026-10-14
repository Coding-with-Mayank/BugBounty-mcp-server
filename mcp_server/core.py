"""
core.py — the shared foundation between server.py (MCP) and hunt.py (CLI).

Before this module existed, hunt.py had its own independent subprocess
runner (no cancellation handling, no flag-injection guard) and no scope
enforcement at all — only server.py's handlers checked ALLOWED_SCOPE/
BLOCKED_TARGETS before sending traffic anywhere. capabilities.py was
already shared (both surfaces import it); this does the same for the
pieces AGENTS.md flagged as still duplicated: the subprocess runner and
the input-validation helpers that keep argv-injection out of every tool
call built from user-controlled strings.

Dependency direction is one-way and stays that way: core.py knows nothing
about server.py, hunt.py, tasks.py, or the MCP protocol — it's imported
BY all three, never the reverse. That's what makes it a shared core
rather than just another thing server.py happens to own.

run_cmd() here is behaviourally identical to the one server.py used to
define inline (same timeout handling, same CancelledError-safe kill-on-
cancel — see the comment on that clause below, it matters) plus one
addition: incremental output capture via capture_partial_results(), used
by tasks.py so a cancelled/timed-out background task can still return
whatever was gathered before it was stopped, instead of nothing.
"""
from __future__ import annotations

import asyncio
import contextlib
import contextvars
import re
import shutil
import tempfile
from pathlib import Path

# ── Partial-result capture (used by tasks.py — see capture_partial_results) ──
# A ContextVar rather than a parameter threaded through run_cmd()'s ~20
# call sites across server.py's handlers: contextvars are copied into each
# new asyncio.Task at creation and mutations stay isolated to that task's
# context, which is exactly the isolation a per-background-task capture
# sink needs, without changing a single handler's signature. None means
# "nobody's listening" — a normal direct/synchronous call (or hunt.py,
# which never opens a capture scope) pays no bookkeeping cost at all.
_partial_sink: contextvars.ContextVar[list[dict] | None] = contextvars.ContextVar(
    "bugbounty_partial_sink", default=None
)

# Cap how much of any single run_cmd() call's output gets captured into
# the partial-result sink — nuclei/ffuf/katana output can be large, and
# this is an in-memory safety net, not a replacement for the real result.
_MAX_CAPTURED_CHARS = 20_000


def _record_partial(cmd: list[str], stdout: str, stderr: str, returncode: int, note: str | None = None) -> None:
    sink = _partial_sink.get()
    if sink is None:
        return
    truncated = len(stdout) > _MAX_CAPTURED_CHARS or len(stderr) > _MAX_CAPTURED_CHARS
    entry = {
        "cmd": cmd,
        "stdout": stdout[-_MAX_CAPTURED_CHARS:],
        "stderr": stderr[-_MAX_CAPTURED_CHARS:],
        "returncode": returncode,
        "truncated": truncated,
    }
    if note:
        entry["note"] = note
    sink.append(entry)


@contextlib.contextmanager
def capture_partial_results():
    """
    While this context is active, every run_cmd() call made within it (or
    anything it awaits, including across multiple sequential calls in the
    same handler — e.g. full_recon's several stages) appends a record of
    what it captured to the yielded list — on normal completion, on
    run_cmd's own internal timeout, AND on cancellation, where run_cmd
    must still re-raise CancelledError rather than return (it's a
    BaseException; swallowing it would leave the orphaned subprocess
    problem this whole mechanism exists to avoid elsewhere). The caller
    reads the list from the `finally`/except side, after the exception has
    already propagated through — that's the whole point: the list is a
    side channel that survives the stack unwind a direct return value
    couldn't.
    """
    sink: list[dict] = []
    token = _partial_sink.set(sink)
    try:
        yield sink
    finally:
        _partial_sink.reset(token)


# ── Subprocess execution ─────────────────────────────────────────────────────

_READ_CHUNK = 64 * 1024
# After killing a process, give its pipe readers this long to drain what the
# OS already buffered, so "partial" output isn't missing the last few KB.
_DRAIN_GRACE_SECONDS = 1.0


async def _drain(stream: asyncio.StreamReader | None, buf: list[bytes]) -> None:
    """Read a pipe to EOF into `buf` as data arrives (not at the end), so a
    cancel/timeout can still see everything produced so far. Chunked reads
    rather than readline(): a single very long line (minified JSON from
    httpx/katana) would raise LimitOverrunError on readline()."""
    if stream is None:
        return
    while True:
        chunk = await stream.read(_READ_CHUNK)
        if not chunk:
            return
        buf.append(chunk)


def _decode(buf: list[bytes], *, complete_lines_only: bool) -> str:
    text = b"".join(buf).decode("utf-8", errors="replace")
    if complete_lines_only and text and not text.endswith("\n"):
        # The process was killed mid-write: the final line is a fragment
        # (e.g. half a nuclei JSON object). Handlers parse these streams
        # line by line, so dropping the fragment is what makes the partial
        # result safe to hand back as if it were real output.
        text = text[: text.rfind("\n") + 1]
    return text


async def _stop(proc: asyncio.subprocess.Process | None, readers: list[asyncio.Task]) -> None:
    """Kill the child, let its readers drain what's already in the pipes,
    then cancel whatever is still hanging (e.g. a grandchild holding the
    pipe open)."""
    if proc is not None:
        with contextlib.suppress(Exception):
            proc.kill()
    if readers:
        with contextlib.suppress(Exception):
            await asyncio.wait(readers, timeout=_DRAIN_GRACE_SECONDS)
    for t in readers:
        if not t.done():
            t.cancel()


async def run_cmd(
    cmd: list[str],
    timeout: int = 120,
    stdin: str | None = None,
) -> tuple[str, str, int]:
    """
    Run a CLI command async. Returns (stdout, stderr, returncode).
    Never raises for ordinary failures — those go into stderr with a
    non-zero/sentinel returncode. The one thing this DOES let through is
    asyncio.CancelledError (see the clause below) — that's deliberate, not
    an oversight.

    Output is read incrementally while the process runs. On this call's own
    timeout the stdout captured so far (complete lines only) is returned
    instead of being discarded; on cancellation it can't be returned —
    CancelledError must propagate — so it is recorded into the active
    capture_partial_results() sink, if any (see tasks.py).
    """
    binary = cmd[0]
    if not shutil.which(binary):
        msg = (
            f"Tool '{binary}' not found in PATH.\n"
            f"Fix: run ./install-native.sh (native install), or rebuild the Docker "
            f"image with `docker-compose build --no-cache`.\n"
            f"Check what's missing with: python hunt.py doctor"
        )
        _record_partial(cmd, "", msg, 127)
        return "", msg, 127

    proc: asyncio.subprocess.Process | None = None
    out_buf: list[bytes] = []
    err_buf: list[bytes] = []
    readers: list[asyncio.Task] = []
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if stdin else None,
        )
        # Readers first, THEN feed stdin: a tool that emits lots of output
        # before it has consumed all its input would otherwise deadlock
        # against a full pipe nobody is reading.
        readers = [
            asyncio.create_task(_drain(proc.stdout, out_buf)),
            asyncio.create_task(_drain(proc.stderr, err_buf)),
        ]
        if stdin and proc.stdin is not None:
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                proc.stdin.write(stdin.encode())
                await proc.stdin.drain()
            with contextlib.suppress(Exception):
                proc.stdin.close()

        async def _finish() -> None:
            await proc.wait()  # type: ignore[union-attr]
            await asyncio.wait(readers)  # asyncio.wait, not gather: cancelling us must not cancel the readers

        await asyncio.wait_for(_finish(), timeout=timeout)
        out = _decode(out_buf, complete_lines_only=False)
        err = _decode(err_buf, complete_lines_only=False)
        rc = proc.returncode or 0
        _record_partial(cmd, out, err, rc)
        return out, err, rc
    except TimeoutError:
        await _stop(proc, readers)
        if proc is not None:
            with contextlib.suppress(Exception):
                await proc.wait()
        out = _decode(out_buf, complete_lines_only=True)
        msg = f"Command timed out after {timeout}s. Try increasing timeout or reducing scope."
        err = _decode(err_buf, complete_lines_only=True)
        _record_partial(cmd, out, err + msg, -1, note="hit run_cmd's own timeout")
        return out, (err + "\n" + msg).strip(), -1
    except asyncio.CancelledError:
        # CancelledError is a BaseException, not an Exception — the
        # handlers around it never catch it. Without this clause, cancelling
        # the asyncio.Task this coroutine runs in (cancel_task, or
        # TaskManager's hard timeout via asyncio.wait_for) would leave the
        # child process (nuclei/naabu/ffuf/...) running in the background,
        # orphaned, still hitting the target. Don't remove this if you're
        # touching run_cmd.
        if proc is not None:
            with contextlib.suppress(Exception):
                proc.kill()
            # Reap it before we re-raise. CancelledError has already been
            # delivered at this point, so this await runs normally — it
            # isn't itself re-cancelled. Skipping it leaves the Process
            # object to be garbage-collected later (possibly after the
            # event loop that owns its pipe transport has closed), which
            # logs a spurious "Exception ignored ... Event loop is closed".
            with contextlib.suppress(Exception):
                await proc.wait()
        for t in readers:
            if not t.done():
                t.cancel()
        _record_partial(
            cmd,
            _decode(out_buf, complete_lines_only=True),
            _decode(err_buf, complete_lines_only=True),
            -1,
            note="cancelled before the command finished; output is what was produced up to that point",
        )
        raise  # never swallow cancellation
    except Exception as exc:
        await _stop(proc, readers)
        _record_partial(cmd, _decode(out_buf, complete_lines_only=True), str(exc), -1)
        return _decode(out_buf, complete_lines_only=True), str(exc), -1


# ── Validation / safety helpers ──────────────────────────────────────────────

def lines(output: str) -> list[str]:
    return [ln.strip() for ln in output.splitlines() if ln.strip()]


def is_valid_domain(domain: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain.strip()))


def sanitize(s: str) -> str:
    """Remove shell-injection characters from user input.

    Commands are run via create_subprocess_exec (no shell), so this isn't
    guarding against shell metacharacter injection in the traditional sense —
    it's a defense-in-depth pass so junk like backticks/pipes never reach a
    tool's argv. Flag injection (a value starting with '-') is a separate
    risk and is handled by reject_flag_injection() below.
    """
    return re.sub(r"[;&|`$(){}]", "", s).strip()


def reject_flag_injection(value: str) -> str | None:
    """
    Return an error message if `value` would be parsed as a CLI flag by the
    downstream tool instead of as data — e.g. a "domain" of "-oJ" or
    "--resolver-list" getting passed straight into naabu/subfinder/nuclei's
    argv. Every user-controlled value that becomes a positional CLI argument
    should be checked with this before being placed in a cmd list.
    Returns None when the value is safe.
    """
    v = value.strip()
    if v.startswith("-"):
        return (
            f"'{value}' looks like a CLI flag, not a target "
            "(values starting with '-' are rejected to prevent argument injection)."
        )
    return None


@contextlib.contextmanager
def targets_tempfile(targets: list[str]):
    """
    Write `targets` (one per line) to a temp file for tools that take -l/-f,
    yielding the path. Guarantees cleanup even if the caller raises — the
    old inline tempfile.NamedTemporaryFile(...) pattern this replaced leaked
    the file on any exception between creation and the manual unlink().
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        path = f.name
    try:
        yield path
    finally:
        Path(path).unlink(missing_ok=True)
