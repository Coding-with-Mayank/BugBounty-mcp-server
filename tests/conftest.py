"""
Shared pytest fixtures / setup.

config.py's Settings default to /app/logs, /app/reports, etc. — correct
inside the Docker image, but not writable (or present) on a bare CI runner
or a contributor's machine running `pytest` outside the container. This
must run before ANYTHING imports mcp_server.config (which happens as soon
as mcp_server.server or mcp_server.config is imported, since the module
calls `settings.ensure_dirs()` at import time), so it's set here in
conftest.py rather than in a fixture — pytest loads conftest.py before
collecting/importing test modules.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# toolmgr tests share small fakes that live next to the tests.
sys.path.insert(0, str(Path(__file__).parent))

_TEST_STATE_DIR = tempfile.mkdtemp(prefix="bbmcp-test-")

os.environ.setdefault("LOG_FILE", os.path.join(_TEST_STATE_DIR, "logs", "mcp_server.log"))
os.environ.setdefault("REPORTS_DIR", os.path.join(_TEST_STATE_DIR, "reports"))
os.environ.setdefault("SCREENSHOTS_DIR", os.path.join(_TEST_STATE_DIR, "screenshots"))
os.environ.setdefault("DATA_DIR", os.path.join(_TEST_STATE_DIR, "data"))
# Keep tests deterministic regardless of whatever the developer's real
# .env (if any) sets — tests that care about scope pass explicit lists.
os.environ.setdefault("ALLOWED_SCOPE", "")
# Tests must never touch the network or write into the real checkout's data/:
# hunt.py is spawned as a subprocess by some tests and inherits these.
os.environ.setdefault("BBMCP_OFFLINE", "1")
os.environ.setdefault("BBMCP_STATE_DIR", os.path.join(_TEST_STATE_DIR, "toolmgr-state"))
