"""pyenv.py — Python environment + MCP SDK status for `hunt doctor`."""
from __future__ import annotations

import re
import sys
from importlib import metadata
from pathlib import Path

from . import versions

MIN_PYTHON = (3, 11)
_REQ = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*(\[[^\]]*\])?\s*([<>=!~][^;#]*)?")
_SPEC = re.compile(r"^(>=|<=|==|!=|>|<)\s*([0-9][0-9A-Za-z.]*)$")


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _satisfies(installed: versions.Version, spec_text: str) -> bool | None:
    """None = couldn't evaluate (unknown operator/version) — treated as OK."""
    for part in (p.strip() for p in spec_text.split(",") if p.strip()):
        m = _SPEC.match(part)
        bound = versions.parse_loose(m[2]) if m else None
        if not m or bound is None:
            return None
        op = m[1]
        if not {">=": installed >= bound, "<=": installed <= bound, "==": installed == bound,
                "!=": installed != bound, ">": installed > bound, "<": installed < bound}[op]:
            return False
    return True


def requirements_status(req_file: Path) -> list[dict]:
    out: list[dict] = []
    try:
        lines = req_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return out
    for line in lines:
        if not line.strip() or line.lstrip().startswith(("#", "-")):
            continue
        m = _REQ.match(line)
        if not m:
            continue
        name, spec = m[1], (m[3] or "").strip()
        try:
            raw = metadata.version(name)
        except metadata.PackageNotFoundError:
            out.append({"package": _norm(name), "required": spec or "any", "installed": None, "status": "MISSING"})
            continue
        v = versions.parse_loose(raw)
        ok = _satisfies(v, spec) if (v and spec) else True
        out.append({"package": _norm(name), "required": spec or "any", "installed": raw,
                    "status": "OK" if ok in (True, None) else "OUT-OF-RANGE"})
    return out


def mcp_status() -> dict:
    try:
        raw = metadata.version("mcp")
    except metadata.PackageNotFoundError:
        return {"installed": None, "api": None, "status": "MISSING"}
    v = versions.parse_loose(raw)
    api = "2.x" if v and v.major >= 2 else "1.x"
    return {"installed": raw, "api": api, "status": "OK",
            "note": f"server registers handlers through the {api} API"}


def python_report(root: Path) -> dict:
    in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    reqs = requirements_status(root / "requirements.txt")
    pyok = sys.version_info >= MIN_PYTHON
    issues = []
    if not pyok:
        issues.append(f"Python {'.'.join(map(str, MIN_PYTHON))}+ required")
    issues += [f"{r['package']}: {r['status'].lower()} (needs {r['required']})" for r in reqs if r["status"] != "OK"]
    return {"version": ".".join(map(str, sys.version_info[:3])), "ok": pyok, "in_virtualenv": in_venv,
            "executable": sys.executable, "requirements": reqs, "mcp": mcp_status(), "issues": issues}
