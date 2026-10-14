"""
Real subprocess-level tests for hunt.py's CLI entry points.

Unlike the rest of the suite (which imports mcp_server and calls handler
functions directly), these actually invoke `python hunt.py ...` as a
subprocess — the only way to catch dispatch/signature mismatches between
main()'s argv parsing and a command handler's actual signature. This is
exactly the class of bug that a plain `import hunt` can't catch: hunt.py
imported fine and every function was individually well-formed, but
main()'s dispatch called cmd_doctor(target, **kwargs) with a positional
arg it doesn't accept, and cmd_doctor itself had a leftover
`return available` from a previous version referencing an undefined name
— both only surfaced by actually running it.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HUNT_PY = Path(__file__).resolve().parent.parent / "hunt.py"


def _run_hunt(*args: str, timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HUNT_PY), *args],
        capture_output=True, text=True, timeout=timeout,
    )


class TestDoctorCommand:
    def test_doctor_runs_without_crashing(self):
        result = _run_hunt("doctor")
        assert result.returncode == 0, result.stderr
        assert "Traceback" not in result.stderr

    def test_doctor_reports_environment_and_tools(self):
        result = _run_hunt("doctor")
        assert "Environment" in result.stdout
        assert "Required tools" in result.stdout
        assert "Wordlists" in result.stdout

    def test_doctor_does_not_require_a_target(self):
        # Unlike every other command, `doctor` with zero extra args must
        # NOT hit main()'s "Target required" path.
        result = _run_hunt("doctor")
        assert "Target required" not in result.stdout

    def test_doctor_json_flag_produces_valid_json(self):
        result = _run_hunt("doctor", "--json")
        assert result.returncode == 0, result.stderr
        # --json is machine-readable: the WHOLE of stdout is one JSON document
        # (no banner, no human report in front of it). It used to print the
        # human report first and the JSON after, which no parser could take.
        payload = json.loads(result.stdout)
        assert payload["status"] in ("ready", "degraded")
        assert "go_tools" in payload                      # legacy keys are still present...
        assert {"tools", "assets", "python_env", "path_problems"} <= set(payload)   # ...plus the version data

    def test_doctor_json_reports_version_fields_per_tool(self):
        payload = json.loads(_run_hunt("doctor", "--json").stdout)
        nuclei = next(t for t in payload["tools"] if t["tool"] == "nuclei")
        assert {"installed", "latest_compatible", "status", "source", "path"} <= set(nuclei)

    def test_doctor_human_output_has_the_version_table(self):
        out = _run_hunt("doctor").stdout
        assert "Installed" in out and "Latest" in out and "Status" in out

    def test_doctor_appears_in_command_list(self):
        result = _run_hunt()  # no args -> usage()
        assert "doctor" in result.stdout


class TestExistingCommandsStillDispatchCorrectly:
    """Regression guard: doctor's special-cased dispatch in main() must not
    break the target-required path every other command relies on."""

    def test_target_requiring_command_without_target_shows_clear_error(self):
        result = _run_hunt("recon")
        assert "Target required" in result.stdout

    def test_unknown_command_shows_usage(self):
        result = _run_hunt("not-a-real-command")
        assert "Unknown command" in result.stdout

    def test_no_args_shows_usage_without_crashing(self):
        result = _run_hunt()
        assert result.returncode == 0
        assert "Traceback" not in result.stderr
