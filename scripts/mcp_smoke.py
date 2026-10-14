#!/usr/bin/env python3
"""
mcp_smoke.py — start the MCP server over stdio and talk real JSON-RPC to it.

Proves, without any security tool installed, that the server:
  1. starts and completes the MCP initialize handshake,
  2. lists its tools,
  3. executes a tool call end-to-end,
  4. still validates arguments against each tool's inputSchema.

Used by the test-suite, CI, and the Docker validation step.

    python scripts/mcp_smoke.py                       # native
    python scripts/mcp_smoke.py -- docker run -i --rm IMAGE python -m mcp_server
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading

PROTOCOL = "2024-11-05"


class Session:
    def __init__(self, argv: list[str], timeout: float = 60):
        env = {**os.environ, "BBMCP_OFFLINE": "1"}
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, env=env)
        self.timeout, self._id = timeout, 0
        self.stderr: list[str] = []
        threading.Thread(target=lambda: self.stderr.extend(self.p.stderr or []), daemon=True).start()

    def send(self, obj: dict) -> None:
        assert self.p.stdin
        self.p.stdin.write(json.dumps(obj) + "\n")
        self.p.stdin.flush()

    def call(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        self.send({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}})
        assert self.p.stdout
        result: list[dict] = []

        def read() -> None:
            while True:
                line = self.p.stdout.readline()  # type: ignore[union-attr]
                if not line:
                    return
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue
                if msg.get("id") == self._id:
                    result.append(msg)
                    return

        t = threading.Thread(target=read, daemon=True)
        t.start()
        t.join(self.timeout)
        if not result:
            raise TimeoutError(f"no response to {method}; stderr tail: {''.join(self.stderr[-5:])}")
        return result[0]

    def close(self) -> None:
        try:
            self.p.stdin.close()  # type: ignore[union-attr]
            self.p.wait(timeout=10)
        except Exception:  # noqa: BLE001
            self.p.kill()


def run(argv: list[str]) -> dict:
    s = Session(argv)
    out: dict = {}
    try:
        init = s.call("initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
                                     "clientInfo": {"name": "smoke", "version": "1"}})
        out["server"] = init["result"]["serverInfo"]["name"]
        s.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools = s.call("tools/list")["result"]["tools"]
        out["tool_count"] = len(tools)
        out["has_get_capabilities"] = any(t["name"] == "get_capabilities" for t in tools)
        res = s.call("tools/call", {"name": "get_capabilities", "arguments": {}})["result"]
        out["capabilities_ok"] = not res.get("isError") and "status" in json.loads(res["content"][0]["text"])
        bad = s.call("tools/call", {"name": "subdomain_enum", "arguments": {}})   # required `domain` missing
        r = bad.get("result", {})
        out["validates_input"] = bool(r.get("isError")) or "error" in bad
    finally:
        s.close()
    return out


def main() -> int:
    argv = sys.argv[sys.argv.index("--") + 1:] if "--" in sys.argv else [sys.executable, "-m", "mcp_server"]
    out = run(argv)
    print(json.dumps(out, indent=2))
    ok = (out.get("tool_count", 0) > 0 and out.get("has_get_capabilities") and out.get("capabilities_ok")
          and out.get("validates_input"))
    print("MCP smoke test:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
