"""
security.py — the small set of primitives the updater leans on.

The updater downloads and executes code, so everything that touches the
filesystem, a subprocess or the environment goes through here where it can be
reviewed (and tested) in one place.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import signal
import stat
import subprocess
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

try:  # fcntl is POSIX-only; native install already requires Linux/macOS.
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_MAX_OUTPUT = 64 * 1024

# Variables that change what `go` builds/trusts or what a loader injects into
# a child process. A stray value in the caller's environment (or one planted
# by a service unit) must not be able to disable checksum verification or
# preload code into the build. GOPROXY and a non-"off" GOSUMDB are still honoured.
_SCRUB_EXACT = {
    "GOFLAGS", "GOINSECURE", "GONOSUMDB", "GONOSUMCHECK", "GONOPROXY", "GOPRIVATE",
    "GOEXPERIMENT", "GOWORK", "GOTOOLCHAIN", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
    "PYTHONSTARTUP", "PYTHONPATH", "BASH_ENV", "ENV", "IFS",
}
_SCRUB_PREFIX = ("DYLD_", "CGO_")


class SecurityError(Exception):
    """A check that must fail closed."""


_CRED_RE = re.compile(r"(://[^/\s:@]+:)[^@\s/]+@")
_TOKEN_RE = re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")


def redact(text: str | None) -> str | None:
    """Strip credentials from text bound for logs/history/terminal: URL
    userinfo (https://user:pass@host) and GitHub token shapes."""
    if not text:
        return text
    return _TOKEN_RE.sub("***", _CRED_RE.sub(r"\1***@", text))


def safe_to_execute(path: str) -> bool:
    """
    Running as root, only execute binaries root owns and nobody else can write.
    Otherwise `sudo hunt doctor` would run whatever is in a user-writable
    bin/tools as root — a privilege-escalation path. Non-root: always fine
    (it's the user's own binary run as the user).
    """
    if os.geteuid() != 0:
        return True
    try:
        st = os.stat(path)
    except OSError:
        return False
    return st.st_uid == 0 and not st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)


def validate_name(name: str, what: str = "name") -> str:
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise SecurityError(f"unsafe {what}: {name!r}")
    return name


def clean_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """A scrubbed copy of os.environ for child processes."""
    env = {
        k: v for k, v in os.environ.items()
        if k not in _SCRUB_EXACT and not k.startswith(_SCRUB_PREFIX)
    }
    if env.get("GOSUMDB", "").lower() == "off":
        env.pop("GOSUMDB")
    if extra:
        env.update(extra)
    return env


def is_unsafe_path_entry(entry: str) -> bool:
    """Relative/empty PATH entries ('.', '') and world-writable directories are
    classic PATH-hijack vectors; we never resolve tools through them."""
    if not entry or not os.path.isabs(entry):
        return True
    try:
        st = os.stat(entry)
    except OSError:
        return False  # nonexistent: harmless
    return bool(st.st_mode & stat.S_IWOTH)


def find_executable(name: str, path: str | None = None) -> str | None:
    """shutil.which() minus the unsafe PATH entries."""
    search = path if path is not None else os.environ.get("PATH", "")
    for entry in search.split(os.pathsep):
        if is_unsafe_path_entry(entry):
            continue
        cand = os.path.join(entry, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def path_problems(path: str | None = None) -> list[str]:
    out = []
    for entry in (path if path is not None else os.environ.get("PATH", "")).split(os.pathsep):
        if not entry:
            out.append("PATH contains an empty entry (means the current directory)")
        elif not os.path.isabs(entry):
            out.append(f"PATH contains a relative entry: {entry!r}")
        elif os.path.isdir(entry) and is_unsafe_path_entry(entry):
            out.append(f"PATH entry {entry} is world-writable")
    return list(dict.fromkeys(out))


def ensure_safe_dir(path: Path, private: bool = False) -> Path:
    """
    mkdir -p for a directory we will later put executables or state in.
    Refuses a symlink or a directory owned by someone else, and strips
    group/other WRITE (a directory others can write to lets them swap a
    binary between our check and our use). private=True also strips all
    group/other access — used for staging and backup directories.
    """
    if path.is_symlink():
        raise SecurityError(f"{path} is a symlink; refusing to use it")
    path.mkdir(parents=True, exist_ok=True, mode=0o700 if private else 0o755)
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode):
        raise SecurityError(f"{path} is not a directory")
    if st.st_uid not in (os.geteuid(), 0):
        raise SecurityError(f"{path} is owned by another user")
    wanted = 0o700 if private else (st.st_mode & 0o7777) & ~(stat.S_IWGRP | stat.S_IWOTH)
    if (st.st_mode & 0o7777) != wanted:
        os.chmod(path, wanted)
    return path


def atomic_write_json(path: Path, obj: Any, mode: int = 0o600) -> None:
    """Write JSON via a same-directory temp file + rename; never a torn file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2, sort_keys=True, default=str)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


@contextlib.contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    """Cross-process lock so two updaters (cron + a human) can't interleave."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)   # a planted symlink must not redirect us
    try:
        if fcntl is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise SecurityError(
                    "another hunt update/install is already running (lock held on "
                    f"{path.name}); wait for it to finish"
                ) from exc
        yield
    finally:
        with contextlib.suppress(OSError):
            os.close(fd)


class RunResult:
    __slots__ = ("rc", "output", "timed_out", "error")

    def __init__(self, rc: int, output: str, timed_out: bool = False, error: str | None = None):
        self.rc, self.output, self.timed_out, self.error = rc, output, timed_out, error

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out and self.error is None


def _kill_group(proc: subprocess.Popen) -> None:
    """Kill the child AND everything it started (go -> compiler/linker, sh -> sleep)."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        with contextlib.suppress(OSError):
            proc.kill()


def run_argv(
    argv: Sequence[str],
    timeout: float = 15,
    env: Mapping[str, str] | None = None,
    cwd: str | None = None,
) -> RunResult:
    """
    The only way this package spawns a process: an argv list (never a shell),
    stdin closed, a hard timeout, a scrubbed environment, bounded output.

    The child runs in its OWN process group and a timeout kills the whole
    group — `subprocess.run` would kill only the direct child and leak its
    descendants (a timed-out `go install` would leave compilers running).
    Output goes to an unlinked temp file, not a pipe, so a runaway binary
    can't exhaust memory; only the first 64 KiB is kept.
    """
    with tempfile.TemporaryFile() as sink:
        try:
            proc = subprocess.Popen(
                list(argv), stdin=subprocess.DEVNULL, stdout=sink, stderr=subprocess.STDOUT,
                env=dict(env) if env is not None else clean_env(), cwd=cwd, start_new_session=True,
            )
        except OSError as exc:
            return RunResult(-1, "", error=f"{type(exc).__name__}: {exc}")
        timed_out = False
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_group(proc)
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=5)
        except BaseException:
            _kill_group(proc)
            raise
        sink.seek(0)
        out = sink.read(_MAX_OUTPUT).decode("utf-8", "replace")
    if timed_out:
        return RunResult(-1, out, timed_out=True, error=f"timed out after {timeout:g}s")
    return RunResult(proc.returncode, out)
