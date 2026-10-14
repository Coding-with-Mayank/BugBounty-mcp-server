"""
persistence.py — small, dependency-free JSON file store.

Used for task history (tasks.py) and Smart Hunt investigation sessions
(smart_hunt.py). Deliberately NOT a database:

  * No new infrastructure. requirements.txt/config.py carry Mongo and Redis
    settings, but nothing in the code ever used them — and a native install
    (install-native.sh) shouldn't need a database server just to remember
    what a scan found. One JSON file per record under DATA_DIR works the
    same in Docker (the data volume) and natively.
  * Safe by construction (see the guarantees below), because this sits under
    code that runs long scans: persistence must never be the reason a task
    fails, and a crash mid-write must never destroy an existing record.

Guarantees:
  - Atomic writes: data goes to a temp file in the same directory, is
    fsync'd, then os.replace()d into place. A reader (or a crash) sees
    either the complete old record or the complete new one, never half.
  - Owner-only permissions (0600 files, 0700 directory): records contain
    recon results and discovered endpoints for programs the user is testing.
  - IDs become filenames, so they're validated against a strict pattern —
    a hostile or corrupted ID can't traverse out of the store directory.
  - Corrupt files don't take the store down: they're moved aside to
    `<name>.corrupt` and skipped, so one bad record never blocks startup.
  - Every public method swallows and logs OS/JSON errors instead of raising
    (returns False/None/empty). Callers treat persistence as best-effort.
  - Oversized records are replaced with a small stub rather than written.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
MAX_RECORD_BYTES = 5 * 1024 * 1024


def valid_id(record_id: str) -> bool:
    return bool(_ID_RE.match(record_id))


class JsonStore:
    """One JSON file per record, `<dir>/<id>.json`."""

    def __init__(self, directory: str | Path, max_records: int = 1000):
        self.dir = Path(directory)
        self.max_records = max_records

    # ── internals ───────────────────────────────────────────────────────────

    def _path(self, record_id: str) -> Path | None:
        if not valid_id(record_id):
            logger.warning("persistence: refusing unsafe record id %r", record_id)
            return None
        return self.dir / f"{record_id}.json"

    def _ensure_dir(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(self.dir, 0o700)

    # ── public API ──────────────────────────────────────────────────────────

    def save(self, record_id: str, record: dict[str, Any]) -> bool:
        """Atomically write a record. True on success, False (logged) on any failure."""
        path = self._path(record_id)
        if path is None:
            return False
        tmp_name: str | None = None
        try:
            self._ensure_dir()
            payload = json.dumps(record, default=str, ensure_ascii=False, indent=1)
            if len(payload.encode("utf-8")) > MAX_RECORD_BYTES:
                payload = json.dumps(self._stub(record), default=str, indent=1)
            fd, tmp_name = tempfile.mkstemp(dir=self.dir, prefix=f".{record_id}.", suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as f:  # mkstemp creates it 0600
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_name, path)
            tmp_name = None
            return True
        except (OSError, TypeError, ValueError) as exc:
            logger.warning("persistence: could not save %s: %s", record_id, exc)
            return False
        finally:
            if tmp_name:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_name)

    @staticmethod
    def _stub(record: dict[str, Any]) -> dict[str, Any]:
        """Keep the record's small fields, drop the oversized payload."""
        stub = {k: v for k, v in record.items() if k not in ("result", "findings", "history")}
        stub["truncated"] = True
        stub["truncated_note"] = (
            f"Record exceeded {MAX_RECORD_BYTES // (1024 * 1024)} MB and was not persisted in full."
        )
        return stub

    def load(self, record_id: str) -> dict[str, Any] | None:
        path = self._path(record_id)
        if path is None or not path.exists():
            return None
        return self._read(path)

    def load_all(self) -> list[dict[str, Any]]:
        """Every readable record, oldest file first. Corrupt files are
        quarantined and skipped."""
        if not self.dir.is_dir():
            return []
        records: list[tuple[float, dict[str, Any]]] = []
        for path in self.dir.glob("*.json"):
            if not valid_id(path.stem):
                continue
            rec = self._read(path)
            if rec is not None:
                with contextlib.suppress(OSError):
                    records.append((path.stat().st_mtime, rec))
        records.sort(key=lambda pair: pair[0])
        return [rec for _, rec in records]

    def delete(self, record_id: str) -> bool:
        path = self._path(record_id)
        if path is None:
            return False
        try:
            path.unlink(missing_ok=True)
            return True
        except OSError as exc:
            logger.warning("persistence: could not delete %s: %s", record_id, exc)
            return False

    def ids(self) -> list[str]:
        if not self.dir.is_dir():
            return []
        return sorted(p.stem for p in self.dir.glob("*.json") if valid_id(p.stem))

    def prune(self, keep: int | None = None) -> int:
        """Delete the oldest records beyond `keep` (default max_records)."""
        keep = self.max_records if keep is None else keep
        if not self.dir.is_dir():
            return 0
        try:
            files = sorted(
                (p for p in self.dir.glob("*.json") if valid_id(p.stem)),
                key=lambda p: p.stat().st_mtime,
            )
        except OSError:
            return 0
        removed = 0
        for path in files[: max(0, len(files) - keep)]:
            with contextlib.suppress(OSError):
                path.unlink()
                removed += 1
        return removed

    def cleanup_temp_files(self) -> int:
        """Remove `.tmp` leftovers from a write interrupted by a crash."""
        if not self.dir.is_dir():
            return 0
        removed = 0
        for path in self.dir.glob(".*.tmp"):
            with contextlib.suppress(OSError):
                path.unlink()
                removed += 1
        return removed

    def _read(self, path: Path) -> dict[str, Any] | None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("record is not a JSON object")
            return data
        except (OSError, ValueError) as exc:
            logger.warning("persistence: %s is unreadable (%s); moving aside", path.name, exc)
            with contextlib.suppress(OSError):
                os.replace(path, path.with_suffix(".json.corrupt"))
            return None
