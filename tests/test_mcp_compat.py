"""MCP SDK 1.x/2.x compatibility: unit checks + a LIVE stdio session."""
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from mcp_server import mcp_compat

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}


@pytest.mark.parametrize("field", ["inputSchema", "input_schema"])
def test_validation_reads_the_schema_under_either_sdk_field_name(field):
    # SDK 1.x names the field inputSchema, 2.x input_schema. Reading only one
    # of them crashed every tools/call on the other SDK.
    tool = SimpleNamespace(name="t", **{field: SCHEMA})
    assert mcp_compat._validation_error([tool], "t", {}) .startswith("Input validation error")
    assert mcp_compat._validation_error([tool], "t", {"domain": "example.com"}) is None
    assert mcp_compat._validation_error([tool], "unknown", {}) is None


def test_sdk_major_is_detected():
    assert mcp_compat.MCP_MAJOR in (1, 2)


def test_live_stdio_session_works_on_the_installed_sdk(tmp_path):
    env = {"DATA_DIR": str(tmp_path / "d"), "LOG_FILE": str(tmp_path / "d" / "s.log"),
           "BBMCP_STATE_DIR": str(tmp_path / "s"), "PATH": "/usr/bin:/bin"}
    (tmp_path / "d").mkdir()
    res = subprocess.run([sys.executable, str(ROOT / "scripts" / "mcp_smoke.py")], cwd=ROOT, env=env,
                         capture_output=True, text=True, timeout=120)
    assert res.returncode == 0, res.stdout + res.stderr
    out = json.loads(res.stdout.split("MCP smoke test")[0])
    assert out["tool_count"] >= 30 and out["validates_input"] and out["capabilities_ok"]
