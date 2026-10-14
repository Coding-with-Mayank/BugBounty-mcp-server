"""Small helpers every command-line entry point shares.

The one thing that lives here today: surviving a closed output pipe.

    ./hunt doctor --json | head -1

``head`` exits after one line; the next write to our stdout fails with EPIPE.
That is a normal way for a pipeline to end, not an error, so it must produce no
traceback and a clean exit status.

Why a plain ``try/except BrokenPipeError`` around the command is NOT enough
---------------------------------------------------------------------------
When stdout is a pipe Python block-buffers it (8 KiB). A command whose output
is smaller than that never fails inside ``print()`` at all: the failing write
happens later, in the flush that the interpreter performs while shutting down —
after every ``except`` in our code has already been left. The result is
``Exception ignored in: <_io.TextIOWrapper name='<stdout>'> BrokenPipeError``
on stderr and exit status 120. It is also timing dependent (it only happens
when the reader leaves *before* that final flush), which is why a handler that
"worked" could still fail intermittently in CI. ``sys.exit(main())`` placed
outside the guard has the same hole.

The documented recipe (https://docs.python.org/3/library/signal.html#note-on-sigpipe)
is therefore to flush *inside* the try block, and on failure point the file
descriptor at /dev/null so the interpreter's own final flush has nowhere left to
fail. :func:`run_cli` does exactly that for every entry point.
"""
from __future__ import annotations

import contextlib
import os
import sys
from collections.abc import Callable

EXIT_OK = 0


def _quiet(stream) -> None:
    """Point a stream's file descriptor at /dev/null so a later flush cannot fail."""
    with contextlib.suppress(OSError, ValueError, AttributeError):
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, stream.fileno())
        finally:
            os.close(devnull)


def _flush_all() -> None:
    """Flush both streams NOW, while we are still inside the caller's try block.

    stderr is flushed on its own so a vanished *stdout* reader doesn't also silence
    diagnostics; only a stream that is itself broken gets redirected.
    """
    try:
        sys.stderr.flush()
    except BrokenPipeError:
        _quiet(sys.stderr)
    except ValueError:                  # already closed: nothing to flush
        pass
    sys.stdout.flush()


def _exit_code(value: object) -> int:
    """What ``sys.exit(value)`` would turn into, as an int (and print a str message)."""
    if value is None:
        return EXIT_OK
    if isinstance(value, int):
        return value
    print(value, file=sys.stderr)
    return 1


def run_cli(main: Callable[[], int | None]) -> int:
    """Run ``main`` and return its exit status, treating a vanished reader as success.

    ``main`` may return a status, return ``None``, or call ``sys.exit`` — all three
    behave exactly as before. Only a broken pipe is intercepted.
    """
    try:
        try:
            status = _exit_code(main())
        except SystemExit as exc:
            status = _exit_code(exc.code)
        _flush_all()                    # the write that actually fails for short output
        return status
    except BrokenPipeError:
        _quiet(sys.stdout)
        return EXIT_OK


def main_guard(main: Callable[[], int | None]) -> None:
    """``if __name__ == "__main__": main_guard(main)`` — run, flush safely, exit."""
    sys.exit(run_cli(main))
