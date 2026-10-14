"""`hunt ... | head` must end quietly: no traceback, no 'Exception ignored', exit 0.

The bug these pin down: output smaller than the 8 KiB stdio buffer is only
written by the interpreter's *exit-time* flush, which ran after every
``except BrokenPipeError`` in the program had been left (exit status 120 plus an
"Exception ignored" message). It depended on whether the reader left before or
after that flush, so it showed up as an intermittent CI failure.

Every subprocess test strips PYTHONUNBUFFERED (and friends): an unbuffered stdout
fails inside ``print()`` instead, which hides this class of bug entirely.
"""
from __future__ import annotations

import contextlib
import io
import os
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_server.cliutil import run_cli

ROOT = Path(__file__).resolve().parent.parent


# ── run_cli itself ────────────────────────────────────────────────────────────

@pytest.fixture
def dead_pipe_stdout(monkeypatch):
    """A throwaway sys.stdout whose reader has already gone away.

    run_cli redirects a broken stream's file descriptor to /dev/null; doing that to the
    real (pytest-captured) stdout would corrupt the capture, so tests never use it.
    """
    r, w = os.pipe()
    os.close(r)
    stream = io.TextIOWrapper(os.fdopen(w, "wb"), write_through=False)
    monkeypatch.setattr(sys, "stdout", stream)
    yield stream
    with contextlib.suppress(OSError, ValueError):
        stream.close()


def test_status_passthrough():
    assert run_cli(lambda: 0) == 0
    assert run_cli(lambda: 7) == 7
    assert run_cli(lambda: None) == 0


def test_system_exit_is_returned_not_raised():
    def boom():
        raise SystemExit(3)
    assert run_cli(boom) == 3
    assert run_cli(lambda: (_ for _ in ()).throw(SystemExit())) == 0


def test_system_exit_with_message_goes_to_stderr(capsys):
    def boom():
        raise SystemExit("bad things")
    assert run_cli(boom) == 1
    assert "bad things" in capsys.readouterr().err


def test_other_exceptions_are_not_swallowed():
    def boom():
        raise RuntimeError("real bug")
    with pytest.raises(RuntimeError, match="real bug"):
        run_cli(boom)


def test_broken_pipe_raised_by_the_command_is_success(monkeypatch):
    """A command that fails inside print(): success, and stdout (only) is neutralised.

    The fd redirect is recorded rather than performed: dup2-ing over a descriptor while
    pytest's own fd-capture is active corrupts the capture. The real redirect is covered
    by the final-flush test below and by the subprocess tests.
    """
    from mcp_server import cliutil
    silenced = []
    monkeypatch.setattr(cliutil, "_quiet", silenced.append)

    def boom():
        raise BrokenPipeError(32, "Broken pipe")

    assert run_cli(boom) == 0
    assert silenced == [sys.stdout]


def test_broken_pipe_on_the_final_flush_is_success(dead_pipe_stdout):
    """The actual regression: print() succeeds (buffered); only the flush fails."""
    def main():
        print("short output, never flushed by print()")
        return 0

    assert run_cli(main) == 0
    # The fd now points at /dev/null, so the interpreter's own final flush is harmless.
    dead_pipe_stdout.flush()


# ── the real entry points, as separate processes ─────────────────────────────

def _env(tmp_path: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
    env.update(BBMCP_OFFLINE="1", BBMCP_STATE_DIR=str(tmp_path))
    return env


COMMANDS = {
    "toolmgr doctor --json": ["-m", "mcp_server.toolmgr", "doctor", "--json"],
    "toolmgr --help": ["-m", "mcp_server.toolmgr", "--help"],
    "hunt.py doctor --json": ["hunt.py", "doctor", "--json"],
    "hunt.py doctor": ["hunt.py", "doctor", "--offline"],
    "hunt.py help": ["hunt.py", "help"],
    "hunt.py update --check": ["hunt.py", "update", "--check"],
}


@pytest.mark.parametrize("reader", ["leaves-before-any-output", "leaves-after-first-chunk"])
@pytest.mark.parametrize("name", list(COMMANDS))
def test_closed_reader_is_not_an_error(name, reader, tmp_path):
    proc = subprocess.Popen([sys.executable, *COMMANDS[name]], cwd=ROOT, env=_env(tmp_path),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.stdout is not None and proc.stderr is not None
    if reader == "leaves-after-first-chunk":
        proc.stdout.read(1)
    proc.stdout.close()
    err = proc.stderr.read().decode()
    rc = proc.wait(timeout=60)
    assert rc == 0, f"exit status {rc}: {err}"
    assert "Traceback" not in err and "Exception ignored" not in err and "BrokenPipe" not in err, err


def test_normal_output_is_unchanged(tmp_path):
    """The wrapper must be invisible when nothing goes wrong."""
    done = subprocess.run([sys.executable, "-m", "mcp_server.toolmgr", "doctor", "--json"], cwd=ROOT,
                          env=_env(tmp_path), capture_output=True, text=True, timeout=60)
    assert done.returncode in (0, 1, 10), done.stderr
    import json
    json.loads(done.stdout)                      # still ONE JSON document, nothing else on stdout
