#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════
Advanced Bug Bounty MCP Server — server.py
Compatible with: Claude Desktop · Claude CLI · Gemini CLI · any MCP client

Tools exposed:
  Recon:     subdomain_enum, subdomain_brute, alive_check, port_scan,
             dns_enum, screenshot, crawl, wayback, tech_detect, full_recon
  Scanning:  nuclei_scan, dir_fuzz, xss_scan, sqli_scan, cors_check
  Intel:     whois_lookup, cert_search, shodan_search
  Analysis:  analyze_findings, get_next_steps, generate_report
  Utility:   list_tools, check_scope, explain_finding
═══════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import shutil
import signal
import threading
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server

from . import __version__
from .capabilities import get_capabilities
from .config import settings
from .core import (
    is_valid_domain,
    lines,
    reject_flag_injection,
    run_cmd,
    sanitize,
    targets_tempfile,
)
from .guidance import GuidanceEngine
from .mcp_compat import register_tools
from .persistence import JsonStore
from .scope import OutOfScopeError, default_resolve
from .scope import resolve_and_check as resolve_scope
from .smart_hunt import SmartHuntEngine
from .tasks import TaskManager

# Re-exported so `server.run_cmd`/`server.is_valid_domain`/etc. keep working
# for existing call sites and tests (several monkeypatch server.run_cmd and
# server.dns_resolver directly) — these now live in core.py, shared with
# hunt.py, but every handler below still calls them as plain module-level
# names, which is what monkeypatch.setattr(server, "run_cmd", fake) patches.
__all__ = [
    "is_valid_domain",
    "lines",
    "reject_flag_injection",
    "run_cmd",
    "sanitize",
    "targets_tempfile",
]

# repo-root/wordlists in a native checkout; /app/wordlists inside Docker
# (the Dockerfile does `COPY . /app/`, preserving this same relative
# layout — server.py lives at mcp_server/server.py either way, so going up
# two levels reaches the repo root/image root in both cases). Same fix as
# hunt.py's WORDLISTS_DIR, for the same reason: the old hardcoded
# /app/wordlists/... defaults below only worked inside Docker.
WORDLISTS_DIR = Path(__file__).resolve().parent.parent / "wordlists"

# ── Setup ─────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.FileHandler(settings.log_file),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("bugbounty.server")

server = Server("bugbounty-mcp-server")
guide = GuidanceEngine()


# ── Scope enforcement ────────────────────────────────────────────────────────
# Applied to every tool that sends traffic directly at the target (active
# recon and scanning). Passive OSINT tools that only query third parties —
# subfinder's passive sources, crt.sh, Wayback/gau, WHOIS, Shodan — never
# touch the target itself, so they're intentionally exempt.
#
# Both helpers resolve the hostname and check what it currently points at,
# not just the hostname string — an ALLOWED_SCOPE match doesn't save a
# target whose DNS record currently resolves into BLOCKED_TARGETS (DNS
# rebinding, or a stale/misconfigured record). See scope.resolve_and_check.
#
# dns_resolver is a module attribute (not a hardcoded default) so tests can
# swap it for a fake — same pattern as run_cmd — instead of hitting live DNS.
dns_resolver = default_resolve


async def _scope_check(target: str) -> dict | None:
    """Return an error dict if `target` is out of scope, else None."""
    decision = await resolve_scope(
        target, scope_list=settings.scope_list, blocked_list=settings.blocked_list,
        resolver=dns_resolver, strict=settings.strict_scope,
    )
    if not decision.allowed:
        return OutOfScopeError(target, decision).as_dict()
    return None


async def _filter_in_scope(targets: list[str]) -> tuple[list[str], list[dict]]:
    """Split targets into (allowed, blocked_info) without failing the whole call."""
    decisions = await asyncio.gather(*(
        resolve_scope(
            t, scope_list=settings.scope_list, blocked_list=settings.blocked_list,
            resolver=dns_resolver, strict=settings.strict_scope,
        )
        for t in targets
    ))

    allowed: list[str] = []
    blocked: list[dict] = []
    for t, decision in zip(targets, decisions, strict=True):
        if decision.allowed:
            allowed.append(t)
        else:
            blocked.append({"target": t, "reason": decision.reason})
    return allowed, blocked


def result(
    tool: str,
    target: str,
    data: Any,
    guidance_ctx: dict | None = None,
) -> dict:
    """Wrap tool output with metadata + guidance."""
    guidance_ctx = guidance_ctx or {}
    guidance_ctx.update({"tool": tool, "target": target, "data": data})
    return {
        "tool": tool,
        "target": target,
        "timestamp": datetime.now(UTC).isoformat(),
        "data": data,
        "guidance": guide.generate(guidance_ctx),
    }


# ── Tool Schemas ──────────────────────────────────────────────────────────────

TOOLS: list[types.Tool] = [
    # ── Recon ────────────────────────────────────────────────────────────────
    types.Tool(
        name="subdomain_enum",
        description=(
            "Passively enumerate subdomains using subfinder (uses public APIs, crt.sh, etc). "
            "Returns subdomains + smart guidance on suspicious patterns and next steps."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain, e.g. example.com"},
                "timeout": {"type": "integer", "description": "Scan timeout seconds (default 60)"},
            },
            "required": ["domain"],
        },
    ),
    types.Tool(
        name="subdomain_brute",
        description=(
            "Actively brute-force subdomains using a wordlist (ffuf + DNS). "
            "More aggressive than passive enum — use only on targets you have permission to test."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "wordlist": {
                    "type": "string",
                    "description": "Path to wordlist (default: <repo>/wordlists/subdomains.txt)",
                },
                "threads": {"type": "integer", "description": "Concurrent threads (default 50)"},
            },
            "required": ["domain"],
        },
    ),
    types.Tool(
        name="alive_check",
        description=(
            "Probe a list of hosts/URLs with httpx. Returns status codes, titles, "
            "web servers, and detected technologies. Identifies interesting endpoints."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "URLs or domains to probe",
                },
                "timeout": {"type": "integer", "description": "Per-request timeout (default 10)"},
            },
            "required": ["targets"],
        },
    ),
    types.Tool(
        name="port_scan",
        description=(
            "Fast TCP port scan using naabu. Discovers open services. "
            "Returns port list with service guesses and investigation hints."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP address or hostname"},
                "ports": {
                    "type": "string",
                    "description": "Port range (default: top-100). Examples: '80,443,8080', '1-1000', 'top-1000'",
                },
                "timeout": {"type": "integer"},
            },
            "required": ["target"],
        },
    ),
    types.Tool(
        name="dns_enum",
        description="Enumerate DNS records (A, MX, NS, TXT, CNAME, SOA) for a domain using dnsx.",
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
            },
            "required": ["domain"],
        },
    ),
    types.Tool(
        name="screenshot",
        description=(
            "Take screenshots of web targets using gowitness. "
            "Screenshots saved to the configured screenshots directory (SCREENSHOTS_DIR). Returns file paths + interesting observations."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of URLs to screenshot",
                },
                "timeout": {"type": "integer", "description": "Per-page timeout (default 15)"},
            },
            "required": ["targets"],
        },
    ),
    types.Tool(
        name="crawl",
        description=(
            "Crawl a website with katana to discover URLs, forms, JS files, and API endpoints. "
            "Great for finding hidden functionality."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Starting URL"},
                "depth": {"type": "integer", "description": "Crawl depth (default 3)"},
                "timeout": {"type": "integer"},
            },
            "required": ["url"],
        },
    ),
    types.Tool(
        name="wayback",
        description=(
            "Retrieve historical URLs from Wayback Machine + gau. "
            "Useful for finding old endpoints, backup files, and forgotten parameters."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
            },
            "required": ["domain"],
        },
    ),
    types.Tool(
        name="tech_detect",
        description=(
            "Detect web technologies (frameworks, CDNs, CMS, servers) using httpx. "
            "Returns technology stack with known vulnerability hints."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "targets": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["targets"],
        },
    ),
    types.Tool(
        name="full_recon",
        description=(
            "Run a complete automated recon pipeline on a domain: "
            "subdomain_enum → alive_check → port_scan → tech_detect → screenshot. "
            "Best starting point for a new target."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "screenshot": {"type": "boolean", "description": "Take screenshots (default true)"},
            },
            "required": ["domain"],
        },
    ),
    # ── Scanning ─────────────────────────────────────────────────────────────
    types.Tool(
        name="nuclei_scan",
        description=(
            "Run Nuclei vulnerability scanner with 10,000+ templates. "
            "Filter by severity. Returns findings with CVSSv3 scores and remediation guidance."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "targets": {"type": "array", "items": {"type": "string"}},
                "severity": {
                    "type": "string",
                    "description": "Comma-separated severities: info,low,medium,high,critical (default: medium,high,critical)",
                },
                "templates": {
                    "type": "string",
                    "description": "Template tag or path (e.g. 'cve', 'misconfig', 'xss'). Blank = all.",
                },
                "timeout": {"type": "integer"},
            },
            "required": ["targets"],
        },
    ),
    types.Tool(
        name="dir_fuzz",
        description=(
            "Directory and file fuzzing with ffuf. Finds hidden paths, backup files, admin panels. "
            "Returns discovered paths with response analysis."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL. FUZZ keyword optional (inserted at end if absent).",
                },
                "wordlist": {
                    "type": "string",
                    "description": "Wordlist path (default: <repo>/wordlists/directories.txt)",
                },
                "extensions": {
                    "type": "string",
                    "description": "File extensions to try, e.g. 'php,asp,bak,old'",
                },
                "threads": {"type": "integer"},
                "timeout": {"type": "integer"},
            },
            "required": ["url"],
        },
    ),
    types.Tool(
        name="xss_scan",
        description=(
            "Targeted XSS scanning using Nuclei XSS templates. "
            "Returns potential XSS vectors with PoC details and manual verification steps."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "targets": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["targets"],
        },
    ),
    types.Tool(
        name="sqli_scan",
        description=(
            "SQL injection scanning using Nuclei SQLi templates. "
            "Returns potential injection points with evidence and manual testing steps."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "targets": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["targets"],
        },
    ),
    types.Tool(
        name="cors_check",
        description=(
            "Check for CORS misconfigurations. "
            "Returns misconfigured endpoints with exploitation steps."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "targets": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["targets"],
        },
    ),
    # ── Intelligence ──────────────────────────────────────────────────────────
    types.Tool(
        name="whois_lookup",
        description="Retrieve WHOIS data for a domain or IP. Useful for identifying organization, registrar, and contact info.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain or IP address"},
            },
            "required": ["target"],
        },
    ),
    types.Tool(
        name="cert_search",
        description=(
            "Search certificate transparency logs (crt.sh) for a domain. "
            "Often reveals subdomains that passive tools miss."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
            },
            "required": ["domain"],
        },
    ),
    types.Tool(
        name="shodan_search",
        description=(
            "Query Shodan for internet-exposed services. "
            "Requires SHODAN_API_KEY in .env. Returns open ports, banners, CVEs."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Shodan query e.g. 'hostname:example.com'"},
            },
            "required": ["query"],
        },
    ),
    # ── Analysis ──────────────────────────────────────────────────────────────
    types.Tool(
        name="analyze_findings",
        description=(
            "Analyze a collection of raw findings and get prioritized report: "
            "what's critical, what needs manual verification, and a full attack chain suggestion."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "findings": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "List of finding objects from other tool calls",
                },
                "target": {"type": "string"},
            },
            "required": ["findings"],
        },
    ),
    types.Tool(
        name="explain_finding",
        description=(
            "Explain what a specific finding means, its severity, how to manually verify it, "
            "and how to write it up for a bug bounty report."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "finding": {
                    "type": "object",
                    "description": "A single finding object (from nuclei_scan, xss_scan, etc.)",
                },
            },
            "required": ["finding"],
        },
    ),
    types.Tool(
        name="generate_report",
        description="Generate a professional Markdown bug bounty report from collected findings.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "findings": {"type": "array", "items": {"type": "object"}},
                "program_name": {"type": "string"},
            },
            "required": ["target", "findings"],
        },
    ),
    # ── Utility ──────────────────────────────────────────────────────────────
    types.Tool(
        name="check_scope",
        description=(
            "Check whether a target is allowed under ALLOWED_SCOPE / BLOCKED_TARGETS "
            "before scanning it. Every active-scanning tool enforces this automatically — "
            "use this to check ahead of time or to debug why a scan was rejected."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain, host, IP, or URL to check"},
            },
            "required": ["target"],
        },
    ),
    types.Tool(
        name="get_capabilities",
        description=(
            "Check the environment before relying on it: which external tools "
            "(subfinder, nuclei, naabu, ...) are actually installed and on PATH, "
            "Python version, whether the subdomain/directory wordlists are present, "
            "and whether this is running natively or in Docker. Use this instead of "
            "guessing why a tool call failed, or before starting an investigation to "
            "know what's actually available."
        ),
        inputSchema={"type": "object", "properties": {}},
    ),
    # ── Task Management ──────────────────────────────────────────────────────
    # For long-running tools (nuclei_scan, dir_fuzz, full_recon, port_scan can
    # run for minutes) — runs any tool above in the background instead of
    # blocking the call until it finishes. Every tool works fine called
    # directly too; this is an additional option, not a requirement.
    types.Tool(
        name="start_task",
        description=(
            "Run any tool in the background instead of blocking until it finishes. "
            "Returns a task_id immediately — poll it with get_task_status, fetch the "
            "result with get_task_results once complete, or stop it with cancel_task. "
            "Best for potentially slow tools: nuclei_scan, dir_fuzz, full_recon, "
            "port_scan, screenshot/crawl with many targets."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "tool": {"type": "string", "description": "Name of an existing tool, e.g. 'nuclei_scan'"},
                "args": {"type": "object", "description": "The arguments you'd normally pass to that tool"},
                "soft_timeout_seconds": {
                    "type": "number",
                    "description": "When get_task_status starts flagging this as slow (default 60s). Advisory only — doesn't stop anything.",
                },
                "hard_timeout_seconds": {
                    "type": "number",
                    "description": "Force-cancel ceiling (default 900s). The subprocess is killed and the task marked timed_out.",
                },
            },
            "required": ["tool", "args"],
        },
    ),
    types.Tool(
        name="get_task_status",
        description=(
            "Check a background task's status: queued/running/completed/failed/"
            "cancelled/timed_out, plus elapsed time. If it's been running past its "
            "soft timeout, the response flags that and suggests continuing to wait "
            "or calling cancel_task — it's informational, not a real pause."
        ),
        inputSchema={
            "type": "object",
            "properties": {"task_id": {"type": "string"}},
            "required": ["task_id"],
        },
    ),
    types.Tool(
        name="get_task_results",
        description=(
            "Get a background task's current result. If still running, returns the "
            "status with result: null rather than an error — check the status field."
        ),
        inputSchema={
            "type": "object",
            "properties": {"task_id": {"type": "string"}},
            "required": ["task_id"],
        },
    ),
    types.Tool(
        name="cancel_task",
        description=(
            "Stop a running background task. Kills the underlying process (if any) "
            "rather than leaving it running in the background, and marks the task "
            "cancelled. Safe to call on an already-finished task — just reports that "
            "there was nothing to cancel."
        ),
        inputSchema={
            "type": "object",
            "properties": {"task_id": {"type": "string"}},
            "required": ["task_id"],
        },
    ),
    types.Tool(
        name="list_tasks",
        description=(
            "List background tasks without needing to already know a task_id — "
            "everything currently queued/running, plus recent finished ones (subject "
            "to max_tracked_tasks). Use this to find a task you lost track of, see "
            "what's still running before starting more work, or review what a "
            "session has done so far. Optionally filter by status and/or tool name."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "description": "Optional: queued, running, completed, failed, cancelled, timed_out, or interrupted.",
                },
                "tool": {"type": "string", "description": "Optional: only tasks for this tool name."},
            },
        },
    ),
    # ── Smart Hunt ───────────────────────────────────────────────────────────
    # Decision support on top of everything above, not a separate agent: it
    # never calls a tool itself. It tracks what a hunt has found and
    # recommends the single best next MCP tool call — you run that tool
    # (directly, or via start_task/get_task_results for the slow ones), then
    # report back with smart_hunt_next so it can recommend the next step.
    types.Tool(
        name="smart_hunt_start",
        description=(
            "Start an AI-guided recon/scan workflow for a domain: Smart Hunt tracks what's been found "
            "and recommends one next tool call at a time, instead of you deciding the whole plan upfront. "
            "Returns a session_id plus the first recommendation. Requires an explicit ALLOWED_SCOPE "
            "(refuses to start in open mode) — see check_scope."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain to investigate, e.g. example.com"},
                "depth": {
                    "type": "string",
                    "description": "light (passive + alive only), standard (default), or deep (adds brute-force, fuzzing, XSS/SQLi probes).",
                },
                "max_steps": {"type": "integer", "description": "Step budget before Smart Hunt forces a wrap-up (default 40)."},
            },
            "required": ["target"],
        },
    ),
    types.Tool(
        name="smart_hunt_next",
        description=(
            "Report a tool's outcome to a Smart Hunt session and get the next recommendation. Pass "
            "EITHER task_id (for a tool you ran via start_task — Smart Hunt reads its result itself; if "
            "it's still running you'll be told to poll and retry) OR tool + result (for a tool you called "
            "directly). Call with neither to just get the current recommendation again. Returns "
            "done: true with a wrap-up summary once nothing useful is left to recommend."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "task_id": {"type": "string", "description": "A task_id from start_task, for the tool that was just run."},
                "tool": {"type": "string", "description": "Alternative to task_id: the tool you called directly."},
                "result": {"type": "object", "description": "That tool's full return value (required with 'tool')."},
            },
            "required": ["session_id"],
        },
    ),
    types.Tool(
        name="smart_hunt_status",
        description=(
            "Get a Smart Hunt session's full state: everything discovered so far (subdomains, alive "
            "hosts, findings by severity, flagged high-value hosts), which tools have run, and the "
            "pending recommendation. Omit session_id to list all sessions instead."
        ),
        inputSchema={"type": "object", "properties": {"session_id": {"type": "string"}}},
    ),
    types.Tool(
        name="smart_hunt_close",
        description="Stop a Smart Hunt session (e.g. you're switching targets or done for now). Keeps its history; just stops recommending further steps.",
        inputSchema={"type": "object", "properties": {"session_id": {"type": "string"}}, "required": ["session_id"]},
    ),
]


# ── Tool Registration ─────────────────────────────────────────────────────────

async def list_tools() -> list[types.Tool]:
    return TOOLS


async def call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    args = arguments or {}
    handler = TOOL_HANDLERS.get(name)
    if not handler:
        res = {"error": f"Unknown tool '{name}'", "available": list(TOOL_HANDLERS.keys())}
        return [types.TextContent(type="text", text=json.dumps(res, indent=2))]

    try:
        res = await handler(args)
        return [types.TextContent(type="text", text=json.dumps(res, indent=2, default=str))]
    except Exception as exc:
        logger.exception(f"Tool '{name}' raised unhandled exception")
        err = {
            "error": str(exc),
            "tool": name,
            "guidance": guide.generate({"tool": name, "error": str(exc)}),
        }
        return [types.TextContent(type="text", text=json.dumps(err, indent=2))]


# Registered through the compat shim so the same code runs on MCP SDK 1.x
# (decorator API) and 2.x (add_request_handler) — see mcp_compat.py.
register_tools(server, list_tools, call_tool, TOOLS)


# ── Recon Handlers ────────────────────────────────────────────────────────────

async def _subdomain_enum(args: dict) -> dict:
    domain = sanitize(args.get("domain", ""))
    if not domain:
        return {"error": "domain is required"}
    if not is_valid_domain(domain):
        return {"error": f"'{domain}' doesn't look like a valid domain (expected e.g. 'example.com')."}
    timeout = int(args.get("timeout", 60))

    stdout, stderr, rc = await run_cmd(
        ["subfinder", "-d", domain, "-silent", "-all", "-recursive"],
        timeout=timeout,
    )

    subs = sorted(set(lines(stdout)))
    suspicious = guide.flag_suspicious_subdomains(subs)

    return result(
        "subdomain_enum", domain,
        {"count": len(subs), "subdomains": subs, "suspicious": suspicious},
        {"found": len(subs), "stderr": stderr},
    )


async def _subdomain_brute(args: dict) -> dict:
    """
    DNS-based subdomain brute-force using gobuster dns.
    Resolves each candidate via DNS — catches subdomains regardless of
    whether they serve HTTP/HTTPS, unlike HTTP-based approaches.
    """
    domain = sanitize(args.get("domain", ""))
    wordlist = args.get("wordlist", str(WORDLISTS_DIR / "subdomains.txt"))
    threads = int(args.get("threads", 50))

    if not domain:
        return {"error": "domain is required"}
    if not is_valid_domain(domain):
        return {"error": f"'{domain}' doesn't look like a valid domain (expected e.g. 'example.com')."}
    if (err := await _scope_check(domain)) is not None:
        return err

    if not Path(wordlist).exists():
        return {
            "error": f"Wordlist not found: {wordlist}",
            "guidance": {
                "next_steps": [
                    "Run setup.sh — it downloads wordlists automatically",
                    f"Or manually: wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt -O {WORDLISTS_DIR / 'subdomains.txt'}",
                ]
            },
        }

    # gobuster dns — resolves each candidate subdomain via DNS.
    # Much more accurate than HTTP-based ffuf for subdomain discovery.
    stdout, stderr, rc = await run_cmd(
        [
            "gobuster", "dns",
            "-d", domain,
            "-w", wordlist,
            "-t", str(threads),
            "--no-color",
            "-q",                # quiet: only show found subdomains
        ],
        timeout=300,
    )

    # gobuster dns output format: "Found: sub.domain.com"
    found = []
    for line in lines(stdout):
        line = line.strip()
        if line.startswith("Found:"):
            sub = line.replace("Found:", "").strip()
            if sub:
                found.append(sub)
        elif domain in line and not line.startswith("["):
            # fallback: grab any line containing the domain
            found.append(line.strip())

    found = sorted(set(found))
    suspicious = guide.flag_suspicious_subdomains(found)

    return result(
        "subdomain_brute", domain,
        {"count": len(found), "subdomains": found, "suspicious": suspicious},
        {"found": len(found)},
    )


async def _alive_check(args: dict) -> dict:
    targets = args.get("targets", [])
    timeout_s = int(args.get("timeout", 10))
    if not targets:
        return {"error": "targets list is required"}

    targets, scope_blocked = await _filter_in_scope(targets)
    if not targets:
        return {"error": "All targets are out of scope.", "scope_blocked": scope_blocked}

    with targets_tempfile(targets) as tmp:
        stdout, stderr, rc = await run_cmd(
            [
                "httpx", "-l", tmp,
                "-silent",
                "-status-code", "-title", "-tech-detect",
                "-web-server", "-content-length",
                "-follow-redirects",
                "-timeout", str(timeout_s),
                "-json",
            ],
            timeout=120,
        )

    alive = []
    interesting = []
    for line in lines(stdout):
        try:
            obj = json.loads(line)
            alive.append(obj)
            if _is_interesting(obj):
                interesting.append(obj)
        except json.JSONDecodeError:
            pass

    return result(
        "alive_check", str(targets[:3]) + "...",
        {"count": len(alive), "hosts": alive, "interesting": interesting, "scope_blocked": scope_blocked},
        {"alive_count": len(alive), "interesting_count": len(interesting)},
    )


def _is_interesting(httpx_obj: dict) -> bool:
    title = (httpx_obj.get("title") or "").lower()
    interesting_keywords = [
        "admin", "dashboard", "login", "portal", "manager", "console",
        "swagger", "api", "phpmyadmin", "jenkins", "grafana", "kibana",
        "test", "staging", "dev", "debug", "error", "exception",
    ]
    return any(kw in title for kw in interesting_keywords)


async def _port_scan(args: dict) -> dict:
    target = sanitize(args.get("target", ""))
    ports = args.get("ports", "")
    timeout = int(args.get("timeout", 120))

    if not target:
        return {"error": "target is required"}
    if (err := reject_flag_injection(target)) is not None:
        return {"error": err}
    if (scope_err := await _scope_check(target)) is not None:
        return scope_err

    cmd = ["naabu", "-host", target, "-silent", "-json"]
    if ports and ports != "top-100":
        if ports.startswith("top-"):
            cmd += ["-top-ports", ports[4:]]
        else:
            cmd += ["-p", ports]
    else:
        cmd += ["-top-ports", "100"]

    stdout, stderr, rc = await run_cmd(cmd, timeout=timeout)

    open_ports = []
    for line in lines(stdout):
        try:
            obj = json.loads(line)
            open_ports.append({"port": obj.get("port"), "protocol": obj.get("protocol", "tcp")})
        except json.JSONDecodeError:
            pass

    return result(
        "port_scan", target,
        {"count": len(open_ports), "ports": open_ports},
        {"ports": [p["port"] for p in open_ports]},
    )


async def _dns_enum(args: dict) -> dict:
    domain = sanitize(args.get("domain", ""))
    if not domain:
        return {"error": "domain is required"}
    if not is_valid_domain(domain):
        return {"error": f"'{domain}' doesn't look like a valid domain (expected e.g. 'example.com')."}
    if (err := await _scope_check(domain)) is not None:
        return err

    stdout, stderr, rc = await run_cmd(
        ["dnsx", "-d", domain, "-silent", "-json", "-resp",
         "-a", "-mx", "-ns", "-txt", "-cname", "-soa"],
        timeout=60,
    )

    records: dict[str, list] = {}
    for line in lines(stdout):
        try:
            obj = json.loads(line)
            rtype = obj.get("type", "unknown").upper()
            records.setdefault(rtype, []).append(obj.get("value", obj.get("resp")))
        except json.JSONDecodeError:
            pass

    return result(
        "dns_enum", domain,
        {"records": records},
        {"record_types": list(records.keys())},
    )


async def _screenshot(args: dict) -> dict:
    targets = args.get("targets", [])
    timeout_s = int(args.get("timeout", 15))
    if not targets:
        return {"error": "targets required"}

    targets, scope_blocked = await _filter_in_scope(targets)
    if not targets:
        return {"error": "All targets are out of scope.", "scope_blocked": scope_blocked}

    out_dir = Path(settings.screenshots_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    screenshots: list[dict[str, Any]] = []
    with targets_tempfile(targets) as tmp:
        # Try gowitness first, fall back to httpx screenshot
        if shutil.which("gowitness"):
            _, stderr, rc = await run_cmd(
                [
                    "gowitness", "file",
                    "-f", tmp,
                    "--screenshot-path", str(out_dir),
                    "--timeout", str(timeout_s),
                    "--disable-db",
                ],
                timeout=timeout_s * len(targets) + 30,
            )
            for t in targets:
                # gowitness names files by URL slug
                slug = re.sub(r"[^a-zA-Z0-9._-]", "_", t.replace("://", "_"))
                candidates = list(out_dir.glob(f"*{slug[:30]}*"))
                if candidates:
                    screenshots.append({"url": t, "file": str(candidates[0])})
                else:
                    screenshots.append({"url": t, "file": None, "note": "screenshot may not have rendered"})
        else:
            # Fallback: httpx with screenshot flag (needs Chrome)
            _, stderr, rc = await run_cmd(
                ["httpx", "-l", tmp, "-screenshot", "-srd", str(out_dir), "-silent"],
                timeout=timeout_s * len(targets) + 30,
            )
            for f2 in out_dir.iterdir():
                if f2.suffix == ".png":
                    screenshots.append({"file": str(f2)})

    return result(
        "screenshot", str(targets[:3]),
        {"screenshots": screenshots, "output_dir": str(out_dir), "scope_blocked": scope_blocked},
        {"count": len(screenshots)},
    )


async def _crawl(args: dict) -> dict:
    url = args.get("url", "")
    depth = int(args.get("depth", 3))
    timeout = int(args.get("timeout", 120))

    if not url:
        return {"error": "url is required"}
    if (err := reject_flag_injection(url)) is not None:
        return {"error": err}
    if (scope_err := await _scope_check(url)) is not None:
        return scope_err

    stdout, stderr, rc = await run_cmd(
        ["katana", "-u", url, "-d", str(depth), "-silent",
         "-jc", "-fx", "-kf", "all"],
        timeout=timeout,
    )

    urls_found = lines(stdout)
    js_files = [u for u in urls_found if u.endswith(".js")]
    api_paths = [u for u in urls_found if "/api/" in u or "/v1/" in u or "/v2/" in u]
    interesting = [u for u in urls_found if any(kw in u for kw in
        ["admin", "config", "backup", "secret", ".env", "swagger", "upload", "debug"])]

    return result(
        "crawl", url,
        {
            "total_urls": len(urls_found),
            "all_urls": urls_found[:200],  # cap output
            "js_files": js_files,
            "api_paths": api_paths,
            "interesting": interesting,
        },
        {"total": len(urls_found), "interesting_count": len(interesting)},
    )


async def _wayback(args: dict) -> dict:
    domain = sanitize(args.get("domain", ""))
    if not domain:
        return {"error": "domain is required"}
    if not is_valid_domain(domain):
        return {"error": f"'{domain}' doesn't look like a valid domain (expected e.g. 'example.com')."}

    # Run waybackurls and gau in parallel
    wb_task = run_cmd(["waybackurls", domain], timeout=90)
    gau_task = run_cmd(["gau", "--subs", domain], timeout=90)
    (wb_out, _, _), (gau_out, _, _) = await asyncio.gather(wb_task, gau_task)

    all_urls = sorted(set(lines(wb_out) + lines(gau_out)))
    interesting = [u for u in all_urls if any(ext in u for ext in
        [".bak", ".old", ".zip", ".tar", ".sql", ".log", ".env", ".config",
         "backup", "debug", "secret", "password", "token", "key", "admin"])]

    return result(
        "wayback", domain,
        {
            "total": len(all_urls),
            "urls": all_urls[:300],
            "interesting": interesting,
        },
        {"total": len(all_urls), "interesting": len(interesting)},
    )


async def _tech_detect(args: dict) -> dict:
    targets = args.get("targets", [])
    if not targets:
        return {"error": "targets required"}

    targets, scope_blocked = await _filter_in_scope(targets)
    if not targets:
        return {"error": "All targets are out of scope.", "scope_blocked": scope_blocked}

    with targets_tempfile(targets) as tmp:
        stdout, stderr, rc = await run_cmd(
            ["httpx", "-l", tmp, "-silent", "-tech-detect", "-json", "-timeout", "10"],
            timeout=120,
        )

    tech_map = {}
    for line in lines(stdout):
        try:
            obj = json.loads(line)
            url = obj.get("url", obj.get("input"))
            techs = obj.get("technologies", obj.get("tech", []))
            if url and techs:
                tech_map[url] = techs
        except json.JSONDecodeError:
            pass

    return result(
        "tech_detect", str(targets[:3]),
        {"technology_map": tech_map, "scope_blocked": scope_blocked},
        {"tech_map": tech_map},
    )


async def _full_recon(args: dict) -> dict:
    domain = sanitize(args.get("domain", ""))
    do_screenshots = args.get("screenshot", True)
    if not domain:
        return {"error": "domain required"}

    pipeline = {}

    # Step 1: Subdomain enum
    pipeline["subdomains"] = await _subdomain_enum({"domain": domain})
    subs = pipeline["subdomains"].get("data", {}).get("subdomains", [])

    # Step 2: Alive check
    if subs:
        https_subs = [f"https://{s}" for s in subs[:100]]  # cap at 100 for speed
        pipeline["alive"] = await _alive_check({"targets": https_subs})
        alive_hosts = [h.get("url") for h in pipeline["alive"].get("data", {}).get("hosts", []) if h.get("url")]
    else:
        alive_hosts = [f"https://{domain}"]

    # Step 3: Port scan on main domain
    pipeline["ports"] = await _port_scan({"target": domain})

    # Step 4: Tech detect on alive hosts
    if alive_hosts:
        pipeline["tech"] = await _tech_detect({"targets": alive_hosts[:20]})

    # Step 5: Screenshots
    if do_screenshots and alive_hosts:
        pipeline["screenshots"] = await _screenshot({"targets": alive_hosts[:15], "timeout": 10})

    return {
        "tool": "full_recon",
        "target": domain,
        "timestamp": datetime.now(UTC).isoformat(),
        "pipeline": pipeline,
        "guidance": guide.generate({
            "tool": "full_recon",
            "target": domain,
            "subdomains": len(subs),
            "alive": len(alive_hosts),
        }),
    }


# ── Scanning Handlers ─────────────────────────────────────────────────────────

async def _nuclei_scan(args: dict) -> dict:
    targets = args.get("targets", [])
    severity = args.get("severity", "medium,high,critical")
    templates = args.get("templates", "")
    timeout = int(args.get("timeout", 300))

    if not targets:
        return {"error": "targets required"}

    targets, scope_blocked = await _filter_in_scope(targets)
    if not targets:
        return {"error": "All targets are out of scope.", "scope_blocked": scope_blocked}

    cmd_tail = ["-severity", severity, "-silent", "-json", "-rate-limit", "50", "-bulk-size", "25"]
    if templates:
        cmd_tail += ["-tags", templates]

    with targets_tempfile(targets) as tmp:
        stdout, stderr, rc = await run_cmd(["nuclei", "-l", tmp, *cmd_tail], timeout=timeout)

    findings = []
    for line in lines(stdout):
        try:
            obj = json.loads(line)
            findings.append({
                "template_id": obj.get("template-id"),
                "name": obj.get("info", {}).get("name"),
                "severity": obj.get("info", {}).get("severity"),
                "cvss": obj.get("info", {}).get("classification", {}).get("cvss-score"),
                "url": obj.get("matched-at", obj.get("host")),
                "description": obj.get("info", {}).get("description"),
                "reference": obj.get("info", {}).get("reference", []),
                "matcher_name": obj.get("matcher-name"),
                "extracted_results": obj.get("extracted-results", []),
            })
        except json.JSONDecodeError:
            pass

    by_severity: dict[str, list] = {}
    for f3 in findings:
        sev = f3.get("severity", "unknown")
        by_severity.setdefault(sev, []).append(f3)

    return result(
        "nuclei_scan", str(targets[:3]),
        {
            "total": len(findings),
            "by_severity": by_severity,
            "findings": findings,
            "scope_blocked": scope_blocked,
        },
        {"total": len(findings), "severities": {k: len(v) for k, v in by_severity.items()}},
    )


async def _dir_fuzz(args: dict) -> dict:
    url = args.get("url", "")
    wordlist = args.get("wordlist", str(WORDLISTS_DIR / "directories.txt"))
    extensions = args.get("extensions", "")
    threads = int(args.get("threads", 50))
    timeout = int(args.get("timeout", 180))

    if not url:
        return {"error": "url is required"}
    if (err := reject_flag_injection(url)) is not None:
        return {"error": err}
    if (scope_err := await _scope_check(url)) is not None:
        return scope_err

    if not Path(wordlist).exists():
        return {
            "error": f"Wordlist missing: {wordlist}",
            "guidance": {"next_steps": [
                "Run setup.sh to download wordlists automatically",
                f"Or: wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -O {WORDLISTS_DIR / 'directories.txt'}"
            ]}
        }

    fuzz_url = url if "FUZZ" in url else url.rstrip("/") + "/FUZZ"
    cmd = [
        "ffuf", "-u", fuzz_url,
        "-w", wordlist,
        "-t", str(threads),
        "-mc", "200,201,204,301,302,307,401,403,405",
        "-ac",  # auto-calibrate to filter false positives
        "-json",
    ]
    if extensions:
        cmd += ["-e", "." + extensions.replace(",", ",.")]

    stdout, stderr, rc = await run_cmd(cmd, timeout=timeout)

    results_list = []
    try:
        data = json.loads(stdout)
        results_list = data.get("results", [])
    except json.JSONDecodeError:
        for line in lines(stdout):
            with contextlib.suppress(Exception):
                results_list.append(json.loads(line))

    filtered = [
        {
            "url": r.get("url"),
            "status": r.get("status"),
            "length": r.get("length"),
            "words": r.get("words"),
            "lines": r.get("lines"),
        }
        for r in results_list
    ]

    return result(
        "dir_fuzz", url,
        {"count": len(filtered), "paths": filtered},
        {"found": len(filtered)},
    )


async def _nuclei_targeted(target_tag: str, args: dict) -> dict:
    targets = args.get("targets", [])
    if not targets:
        return {"error": "targets required"}

    targets, scope_blocked = await _filter_in_scope(targets)
    if not targets:
        return {"error": "All targets are out of scope.", "scope_blocked": scope_blocked}

    with targets_tempfile(targets) as tmp:
        stdout, stderr, rc = await run_cmd(
            ["nuclei", "-l", tmp, "-tags", target_tag, "-silent", "-json", "-rate-limit", "30"],
            timeout=180,
        )

    findings = []
    for line in lines(stdout):
        with contextlib.suppress(Exception):
            findings.append(json.loads(line))

    return result(
        f"{target_tag}_scan", str(targets[:3]),
        {"count": len(findings), "findings": findings, "scope_blocked": scope_blocked},
        {"count": len(findings), "tag": target_tag},
    )


async def _xss_scan(args: dict) -> dict:
    return await _nuclei_targeted("xss", args)


async def _sqli_scan(args: dict) -> dict:
    return await _nuclei_targeted("sqli", args)


async def _cors_check(args: dict) -> dict:
    return await _nuclei_targeted("cors", args)


# ── Intelligence Handlers ─────────────────────────────────────────────────────

async def _whois_lookup(args: dict) -> dict:
    target = sanitize(args.get("target", ""))
    if not target:
        return {"error": "target is required"}
    if (err := reject_flag_injection(target)) is not None:
        return {"error": err}
    stdout, stderr, rc = await run_cmd(["whois", target], timeout=30)
    return result(
        "whois_lookup", target,
        {"raw": stdout, "error": stderr if rc != 0 else None},
        {},
    )


async def _cert_search(args: dict) -> dict:
    domain = sanitize(args.get("domain", ""))
    if not domain:
        return {"error": "domain is required"}
    if not is_valid_domain(domain):
        return {"error": f"'{domain}' doesn't look like a valid domain (expected e.g. 'example.com')."}
    import httpx as _httpx
    try:
        async with _httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"https://crt.sh/?q=%.{domain}&output=json"
            )
            data = resp.json()
    except Exception as e:
        return {"error": str(e), "guidance": guide.generate({"tool": "cert_search", "error": str(e)})}

    names = sorted(set(
        entry.get("name_value", "").replace("*.", "")
        for entry in data
        if entry.get("name_value")
    ))
    unique_domains = [n for n in names if domain in n and "\n" not in n]

    return result(
        "cert_search", domain,
        {"count": len(unique_domains), "domains": unique_domains},
        {"found": len(unique_domains)},
    )


async def _shodan_search(args: dict) -> dict:
    query = args.get("query", "")
    api_key = settings.shodan_api_key
    if not api_key:
        return {
            "error": "SHODAN_API_KEY not set",
            "guidance": {
                "manual_alternative": [
                    f"Visit https://www.shodan.io/search?query={query}",
                    "Create a free account at shodan.io for API access",
                    "Add SHODAN_API_KEY=your_key to .env and restart",
                ]
            },
        }

    import httpx as _httpx
    try:
        async with _httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                "https://api.shodan.io/shodan/host/search",
                params={"key": api_key, "query": query, "minify": True},
            )
            data = resp.json()
    except Exception as e:
        return {"error": str(e)}

    return result(
        "shodan_search", query,
        {
            "total": data.get("total", 0),
            "matches": data.get("matches", [])[:20],
        },
        {"total": data.get("total", 0)},
    )


# ── Analysis Handlers ─────────────────────────────────────────────────────────

async def _analyze_findings(args: dict) -> dict:
    findings = args.get("findings", [])
    target = args.get("target", "unknown")

    analysis = guide.analyze_collection(findings, target)
    return {
        "tool": "analyze_findings",
        "target": target,
        "timestamp": datetime.now(UTC).isoformat(),
        "analysis": analysis,
    }


async def _explain_finding(args: dict) -> dict:
    finding = args.get("finding", {})
    explanation = guide.explain(finding)
    return {
        "tool": "explain_finding",
        "finding": finding,
        "explanation": explanation,
    }


async def _generate_report(args: dict) -> dict:
    target = args.get("target", "unknown")
    findings = args.get("findings", [])
    program = args.get("program_name", "Bug Bounty Program")

    report = guide.render_report(target, findings, program)
    # `target` is caller-supplied and ends up in a filename: slug it so a
    # value like "../../x" can't walk out of the reports directory.
    safe_target = re.sub(r"[^a-zA-Z0-9._-]", "_", target)
    report_path = Path(settings.reports_dir) / f"report_{safe_target}_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report)

    return {
        "tool": "generate_report",
        "report_path": str(report_path),
        "report": report,
    }


# ── Utility Handlers ──────────────────────────────────────────────────────────

async def _check_scope(args: dict) -> dict:
    target = args.get("target", "")
    if not target:
        return {"error": "target is required"}

    decision = await resolve_scope(
        target, scope_list=settings.scope_list, blocked_list=settings.blocked_list,
        resolver=dns_resolver, strict=settings.strict_scope,
    )
    resp = {
        "tool": "check_scope",
        "target": target,
        "allowed": decision.allowed,
        "reason": decision.reason,
        "allowed_scope": settings.scope_list or "(empty — open mode)",
    }
    if decision.resolved_ips:
        resp["resolved_ips"] = list(decision.resolved_ips)
    if decision.resolution_warning:
        resp["resolution_warning"] = decision.resolution_warning
    return resp


async def _get_capabilities(args: dict) -> dict:
    return get_capabilities(WORDLISTS_DIR, mcp_tool_count=len(TOOLS))


# ── Tool Dispatch ─────────────────────────────────────────────────────────────
# Single source of truth for "tool name -> handler function", shared by
# call_tool() (direct/synchronous calls) and the task manager (start_task's
# background calls) — the same handler runs either way, with the same
# validation, scope checks, and execution. Defined here, after every
# handler above, since it references all of them by name.

TOOL_HANDLERS: dict[str, Callable[[dict], Awaitable[dict]]] = {
    "subdomain_enum":   _subdomain_enum,
    "subdomain_brute":  _subdomain_brute,
    "alive_check":      _alive_check,
    "port_scan":        _port_scan,
    "dns_enum":         _dns_enum,
    "screenshot":       _screenshot,
    "crawl":            _crawl,
    "wayback":          _wayback,
    "tech_detect":      _tech_detect,
    "full_recon":       _full_recon,
    "nuclei_scan":      _nuclei_scan,
    "dir_fuzz":         _dir_fuzz,
    "xss_scan":         _xss_scan,
    "sqli_scan":        _sqli_scan,
    "cors_check":       _cors_check,
    "whois_lookup":     _whois_lookup,
    "cert_search":      _cert_search,
    "shodan_search":    _shodan_search,
    "analyze_findings": _analyze_findings,
    "explain_finding":  _explain_finding,
    "generate_report":  _generate_report,
    "check_scope":      _check_scope,
    "get_capabilities": _get_capabilities,
}

task_store = (
    JsonStore(Path(settings.data_dir) / "tasks", max_records=settings.max_tracked_tasks)
    if settings.persist_tasks else None
)
task_manager = TaskManager(get_handler=TOOL_HANDLERS.get, max_concurrent=settings.max_concurrent_tasks,
                            max_tracked=settings.max_tracked_tasks, store=task_store)


def _task_lookup(task_id: str) -> dict | None:
    """Status+result shape Smart Hunt needs, or None if unknown — used
    instead of handing Smart Hunt the TaskManager itself, so it can only
    ever read task outcomes, never start/cancel tasks on its own."""
    res = task_manager.results(task_id)
    return None if "error" in res and "task_id" not in res else res


async def _smart_hunt_scope_check(target: str):
    decision = await resolve_scope(
        target, scope_list=settings.scope_list, blocked_list=settings.blocked_list,
        resolver=dns_resolver, strict=settings.strict_scope,
    )
    return decision


smart_hunt = SmartHuntEngine(
    store=JsonStore(Path(settings.data_dir) / "hunts") if settings.smart_hunt_enabled else None,
    scope_lists=lambda: (settings.scope_list, settings.blocked_list),
    scope_check=_smart_hunt_scope_check,
    task_lookup=_task_lookup,
    require_explicit_scope=settings.smart_hunt_require_scope,
)


async def _start_task(args: dict) -> dict:
    tool = args.get("tool", "")
    tool_args = args.get("args", {})
    if not tool:
        return {"error": "'tool' is required — the name of an existing tool to run in the background, e.g. 'nuclei_scan'."}
    if tool == "start_task":
        return {"error": "start_task can't start another start_task."}
    return await task_manager.start(
        tool, tool_args,
        soft_timeout=args.get("soft_timeout_seconds"),
        hard_timeout=args.get("hard_timeout_seconds"),
    )


async def _get_task_status(args: dict) -> dict:
    task_id = args.get("task_id", "")
    if not task_id:
        return {"error": "task_id is required"}
    return task_manager.status(task_id)


async def _get_task_results(args: dict) -> dict:
    task_id = args.get("task_id", "")
    if not task_id:
        return {"error": "task_id is required"}
    return task_manager.results(task_id)


async def _cancel_task(args: dict) -> dict:
    task_id = args.get("task_id", "")
    if not task_id:
        return {"error": "task_id is required"}
    return await task_manager.cancel(task_id)


async def _list_tasks(args: dict) -> dict:
    return task_manager.list_tasks(status=args.get("status"), tool=args.get("tool"))


TOOL_HANDLERS["start_task"] = _start_task
TOOL_HANDLERS["get_task_status"] = _get_task_status
TOOL_HANDLERS["get_task_results"] = _get_task_results
TOOL_HANDLERS["cancel_task"] = _cancel_task
TOOL_HANDLERS["list_tasks"] = _list_tasks


# ── Smart Hunt handlers ────────────────────────────────────────────────────────

async def _smart_hunt_start(args: dict) -> dict:
    target = args.get("target", "")
    depth = args.get("depth", "standard")
    max_steps = args.get("max_steps")
    return await smart_hunt.start(target, depth=depth, max_steps=max_steps)


async def _smart_hunt_next(args: dict) -> dict:
    session_id = args.get("session_id", "")
    if not session_id:
        return {"error": "session_id is required"}
    return await smart_hunt.next(
        session_id,
        task_id=args.get("task_id"),
        tool=args.get("tool"),
        result=args.get("result"),
    )


async def _smart_hunt_status(args: dict) -> dict:
    return smart_hunt.status(args.get("session_id"))


async def _smart_hunt_close(args: dict) -> dict:
    session_id = args.get("session_id", "")
    if not session_id:
        return {"error": "session_id is required"}
    return smart_hunt.close(session_id)


TOOL_HANDLERS["smart_hunt_start"] = _smart_hunt_start
TOOL_HANDLERS["smart_hunt_next"] = _smart_hunt_next
TOOL_HANDLERS["smart_hunt_status"] = _smart_hunt_status
TOOL_HANDLERS["smart_hunt_close"] = _smart_hunt_close


# ── Health API (127.0.0.1:8080 by default) ───────────────────────────────────
# Runs in a background daemon thread. It is unauthenticated and /capabilities describes
# the host (installed tools and versions, paths), so it is reachable from THIS machine
# only unless you opt in: HEALTH_HOST=0.0.0.0 (what the Docker image sets *inside* the
# container so a loopback-only port mapping can reach it) and HEALTH_PORT.

def _health_bind(env: Mapping[str, str] | None = None) -> tuple[str, int]:
    """(host, port) for the health API. Invalid values fall back to the safe defaults."""
    env = os.environ if env is None else env
    host = (env.get("HEALTH_HOST") or "").strip() or "127.0.0.1"
    try:
        port = int(env.get("HEALTH_PORT") or 8080)
    except ValueError:
        port = 8080
    return host, port if 0 < port < 65536 else 8080

# Provides container health, tool availability, and basic stats.

def _start_health_server() -> None:
    """Start a minimal FastAPI server (see _health_bind) in a background thread."""
    try:
        import uvicorn
        from fastapi import FastAPI
        from fastapi.responses import JSONResponse

        health_app = FastAPI(title="Bug Bounty MCP", version=__version__, docs_url=None)
        _start_time = datetime.now(UTC)

        @health_app.get("/health")
        def health():
            # Uses the same capabilities.check_go_tools() as the get_capabilities
            # MCP tool and hunt.py's doctor command — one source of truth for
            # "what tools exist and are they installed", not three separately
            # drifting copies. Only REQUIRED tools affect "degraded" status —
            # previously this also counted gowitness/anew (both optional: one
            # has a working fallback, the other isn't invoked by any handler
            # at all), which meant a missing never-used tool could mark the
            # whole service degraded.
            go_tools = get_capabilities(WORDLISTS_DIR).get("go_tools", {})
            missing = go_tools.get("missing_required", [])
            total_checked = len(go_tools.get("required", {})) + len(go_tools.get("optional", {}))
            available = total_checked - len(missing) - len(go_tools.get("missing_optional", []))
            return JSONResponse({
                "status": "ok" if not missing else "degraded",
                "version": __version__,
                "uptime_seconds": int((datetime.now(UTC) - _start_time).total_seconds()),
                "mcp_tools": len(TOOLS),
                "go_tools": {
                    "available": available,
                    "total": total_checked,
                    "missing": missing,
                },
            })

        @health_app.get("/capabilities")
        def capabilities():
            """Full environment/capability report — same data as the
            get_capabilities MCP tool, over HTTP for anything polling the
            container directly rather than through MCP."""
            return JSONResponse(get_capabilities(WORDLISTS_DIR, mcp_tool_count=len(TOOLS)))

        @health_app.get("/tools")
        def list_mcp_tools():
            return JSONResponse({
                "count": len(TOOLS),
                "tools": [{"name": t.name, "description": (t.description or "")[:80]} for t in TOOLS],
            })

        host, port = _health_bind()
        uvicorn.run(health_app, host=host, port=port, log_level="error", access_log=False)
    except Exception as exc:
        # Health server is non-critical — MCP stdio still works without it
        logger.warning(f"Health server failed to start: {exc}")


# ── Entry point ───────────────────────────────────────────────────────────────

async def main() -> None:
    logger.info("BugBounty-mcp-server v%s — Claude · Gemini · any MCP client", __version__)

    # Restore task history from the previous run (no-op if persistence is off).
    restored = task_manager.load_persisted()
    if restored.get("restored"):
        logger.info(
            "Restored %d task(s) from disk (%d were interrupted by the previous shutdown).",
            restored["restored"], restored["interrupted"],
        )
    n_hunts = smart_hunt.load_persisted()
    if n_hunts:
        logger.info("Restored %d Smart Hunt session(s) from disk.", n_hunts)

    # Start health/status API on :8080 in background (non-blocking)
    health_thread = threading.Thread(target=_start_health_server, daemon=True)
    health_thread.start()
    logger.info("Health API starting on http://%s:%d/health", *_health_bind())

    # SIGTERM (e.g. `docker stop`, a client killing the process) should shut
    # down the same graceful way stdin EOF and Ctrl-C do, so running tasks
    # are cancelled and their partial output is saved rather than lost.
    main_task = asyncio.current_task()
    with contextlib.suppress(NotImplementedError, RuntimeError):  # not available on Windows
        asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, lambda: main_task and main_task.cancel())

    # Run MCP protocol on stdio (this is the main loop)
    try:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )
    finally:
        stopped = await task_manager.shutdown()
        if stopped:
            logger.info("Shutdown: stopped %d running task(s); partial output preserved.", stopped)


if __name__ == "__main__":
    asyncio.run(main())
