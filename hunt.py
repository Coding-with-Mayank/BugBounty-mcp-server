#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
  hunt.py — Manual Bug Bounty CLI
  Works standalone: no Docker, no MCP client needed.
  Just run: python hunt.py <command> [options]

  Usage examples:
    python hunt.py recon example.com
    python hunt.py scan example.com --severity high,critical
    python hunt.py fuzz https://example.com/FUZZ
    python hunt.py full example.com
    python hunt.py cert example.com
    python hunt.py wayback example.com
    python hunt.py screenshot https://example.com
═══════════════════════════════════════════════════════════════
"""
from __future__ import annotations

import asyncio
import json
import shutil
import sys
from collections.abc import Callable, Coroutine
from datetime import datetime
from pathlib import Path
from typing import Any

# repo-root/wordlists in a native checkout; /app/wordlists inside Docker
# (the Dockerfile does `COPY . /app/`, preserving this same relative
# layout) — resolving relative to this file's own location means one path
# is correct in both, instead of hardcoding the Docker-only /app/... path.
WORDLISTS_DIR = Path(__file__).resolve().parent / "wordlists"

# mcp_server is a package right next to this script (both live at the repo
# root) — this is the same shared-core sharing already done for tool
# dispatch (server.py's TOOL_HANDLERS) applied to diagnostics: one
# definition of "what tools are needed and are they installed", not a
# separately-maintained copy per interface.
from mcp_server import __version__, capabilities
from mcp_server.config import settings
from mcp_server.core import is_valid_domain, reject_flag_injection, run_cmd, targets_tempfile
from mcp_server.scope import resolve_and_check

try:
    from rich.console import Console
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None


# ── Colours for non-rich fallback ────────────────────────────────────────────

def c(text: str, color: str) -> str:
    colors = {"red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
              "blue": "\033[94m", "cyan": "\033[96m", "bold": "\033[1m", "reset": "\033[0m"}
    return f"{colors.get(color, '')}{text}{colors['reset']}"


def banner():
    print(c(f"""
  ██████╗ ██╗   ██╗ ██████╗     ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
  ██╔══██╗██║   ██║██╔════╝     ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝
  ██████╔╝██║   ██║██║  ███╗    ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝
  ██╔══██╗██║   ██║██║   ██║    ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝
  ██████╔╝╚██████╔╝╚██████╔╝    ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║
  ╚═════╝  ╚═════╝  ╚═════╝     ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝
  Manual Bug Bounty CLI — v{__version__}
  ⚠️  Only test targets you have explicit permission to test.
""", "cyan"))


def check_tools():
    """Check which tools are available and warn about missing ones."""
    go_tools = capabilities.check_go_tools()
    missing_required = go_tools["missing_required"]
    total = len(go_tools["required"]) + len(go_tools["optional"])
    available_count = total - len(missing_required) - len(go_tools["missing_optional"])

    if missing_required:
        print(c(f"\n⚠  Missing required tools ({len(missing_required)}):", "yellow"))
        for t in missing_required:
            print(c(f"   ✗ {t:<15}", "red") + f"  ({go_tools['required'][t]['purpose']})")
        print(c("\n  → Quickest fix: use Docker instead:", "yellow"))
        print(c("    docker-compose up -d\n    docker exec -it bugbounty-mcp bash\n", "cyan"))
    else:
        print(c(f"\n✓  All {available_count}/{total} tools available\n", "green"))


def _toolmgr_doctor(offline: bool, refresh: bool, selftest: bool) -> dict | None:
    """Version/health data from the tool manager, or None if it can't run
    (e.g. config/tools.yaml unreadable) — doctor then falls back to the
    plain availability report instead of failing."""
    try:
        from mcp_server.toolmgr import cli as tm
        args = tm.build_parser().parse_args(
            ["doctor", *(["--offline"] if offline else []), *(["--refresh"] if refresh else [])])
        return tm.doctor_data(tm.make_context(args), selftest=selftest)
    except Exception as exc:  # noqa: BLE001 — diagnostics must never crash the diagnostic
        return {"error": f"{type(exc).__name__}: {exc}"}


async def cmd_doctor(**kwargs):
    """Full environment diagnostic — Python version, all tools (required
    and optional) with installed/latest versions, wordlists, and whether this
    is running natively or in Docker. Same underlying availability check as
    the get_capabilities MCP tool and the /capabilities HTTP endpoint, plus
    the tool manager's version/compatibility view (see config/tools.yaml)."""
    report = capabilities.get_capabilities(WORDLISTS_DIR)
    tm = _toolmgr_doctor(bool(kwargs.get("offline")), bool(kwargs.get("refresh")), bool(kwargs.get("selftest")))
    tm_ok = tm is not None and "error" not in tm
    tm_data: dict = tm if (tm is not None and tm_ok) else {}
    if tm_ok:
        known = " ".join(report["issues"])
        extra = [i for i in tm_data["toolmgr_issues"] if i.split(":")[0] not in known]
        report["issues"] = report["issues"] + extra
        if extra:
            report["status"] = "degraded"
        report.update({k: tm_data[k] for k in ("tools", "assets", "python_env", "path_problems", "go", "update_check")})
    elif tm:
        report["toolmgr_error"] = tm["error"]

    if kwargs.get("json_output"):
        print(json.dumps(report, indent=2))     # JSON only: safe to pipe straight into jq / a parser
        return

    from mcp_server.toolmgr import cli as tmcli
    print(c("\nEnvironment", "cyan"))
    print(f"  Mode:    {report['environment']}")
    py = report["python"]
    mark = "✓" if py["ok"] else "✗"
    color = "green" if py["ok"] else "red"
    print(c(f"  {mark} Python {py['version']}", color) + f"  (need {py['required']})")

    if tm_ok:
        print(c("\nRequired tools", "cyan"))
        tmcli.print_tools_table(tm_data, only_required=True)
        print(c("\nOptional tools", "cyan"))
        tmcli.print_tools_table(tm_data, only_required=False)
    else:
        print(c("\nRequired tools", "cyan"))
        for tool, info in report["go_tools"]["required"].items():
            mark, color = ("✓", "green") if info["available"] else ("✗", "red")
            print(c(f"  {mark} {tool:<14}", color) + f"  {info['purpose']}")
        print(c("\nOptional tools", "cyan"))
        for tool, info in report["go_tools"]["optional"].items():
            mark, color = ("✓", "green") if info["available"] else ("○", "yellow")
            print(c(f"  {mark} {tool:<14}", color) + f"  {info['purpose']}")
        if tm:
            print(c(f"  (version table unavailable: {tm['error']})", "yellow"))

    print(c("\nWordlists", "cyan"))
    wl = report["wordlists"]
    for name, key in [("subdomains.txt", "subdomains_txt"), ("directories.txt", "directories_txt")]:
        mark, color = ("✓", "green") if wl[key] else ("✗", "red")
        print(c(f"  {mark} {name}", color))
    print(f"    ({wl['dir']})")

    if tm_ok:
        tmcli.print_doctor_extras(tm_data)

    print()
    if report["status"] == "ready":
        print(c("✓  Environment is ready.\n", "green"))
    else:
        print(c("⚠  Environment is degraded:", "yellow"))
        for issue in report["issues"]:
            print(c(f"   • {issue}", "yellow"))
        print()
    if kwargs.get("strict") and report["status"] != "ready":
        sys.exit(1)


async def run(cmd: list[str], timeout: int = 120) -> tuple[str, str]:
    """Run command, return (stdout, stderr).

    Thin adapter over the shared core.run_cmd — the same runner the MCP
    server uses (argv list, never a shell, always a timeout, child process
    killed on cancel). hunt.py used to carry its own separate copy.
    """
    out, err, _rc = await run_cmd(cmd, timeout=timeout)
    return out, err


# ── Scope enforcement ─────────────────────────────────────────────────────────
# Same policy as server.py (see AGENTS.md "Security boundaries"): anything
# that sends traffic AT the target is checked against ALLOWED_SCOPE/
# BLOCKED_TARGETS (including what the hostname currently resolves to);
# passive third-party lookups (recon, wayback, cert) never touch the target
# and are exempt. Reads the same .env / env vars as the MCP server, so one
# scope config governs both interfaces.

async def scope_allows(target: str) -> bool:
    """Print why and return False if `target` is out of scope."""
    decision = await resolve_and_check(
        target, scope_list=settings.scope_list, blocked_list=settings.blocked_list,
        strict=settings.strict_scope,
    )
    if not decision.allowed:
        print(c(f"\n  ✗ Out of scope: {target}", "red"))
        print(c(f"    {decision.reason}", "yellow"))
        print(c("    Add it to ALLOWED_SCOPE in .env only if you are authorized to test it.\n", "yellow"))
        return False
    if decision.resolution_warning:
        print(c(f"  ⚠ {decision.resolution_warning}", "yellow"))
    return True


async def filter_in_scope(targets: list[str]) -> list[str]:
    """Keep only in-scope targets, reporting what was dropped."""
    decisions = await asyncio.gather(*(
        resolve_and_check(
            t, scope_list=settings.scope_list, blocked_list=settings.blocked_list,
            strict=settings.strict_scope,
        )
        for t in targets
    ))
    kept = [t for t, d in zip(targets, decisions, strict=True) if d.allowed]
    dropped = len(targets) - len(kept)
    if dropped:
        print(c(f"  ⚠ Dropped {dropped} out-of-scope target(s) before scanning.", "yellow"))
    return kept


def save_output(name: str, data: str | dict, target: str) -> Path:
    """Save output to ./output/<target>/ directory."""
    out_dir = Path(f"output/{target.replace('/', '_')}")
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%H%M%S")
    fpath = out_dir / f"{name}_{ts}.{'json' if isinstance(data, dict) else 'txt'}"
    content = json.dumps(data, indent=2) if isinstance(data, dict) else data
    fpath.write_text(content)
    return fpath


# ── Commands ──────────────────────────────────────────────────────────────────

async def cmd_recon(domain: str, **kwargs):
    """Passive subdomain recon with subfinder + cert transparency."""
    print(c(f"\n[*] Subdomain Enum: {domain}", "cyan"))

    # subfinder
    out, err = await run(["subfinder", "-d", domain, "-silent", "-all"], timeout=60)
    subs_subfinder = [ln.strip() for ln in out.splitlines() if ln.strip()]

    # crt.sh
    crt_subs = []
    try:
        import json as _json
        import urllib.request
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        with urllib.request.urlopen(url, timeout=10) as r:
            data = _json.loads(r.read())
            for entry in data:
                val = entry.get("name_value", "")
                for v in val.splitlines():
                    v = v.strip().lstrip("*.")
                    if domain in v and v not in crt_subs:
                        crt_subs.append(v)
    except Exception as e:
        print(c(f"  crt.sh failed: {e}", "yellow"))

    all_subs = sorted(set(subs_subfinder + crt_subs))
    print(c(f"\n  Found {len(all_subs)} unique subdomains", "green"))
    print(c(f"  subfinder: {len(subs_subfinder)}  crt.sh: {len(crt_subs)}", "blue"))

    # Flag suspicious ones
    suspicious_prefixes = ["dev", "staging", "admin", "api", "internal", "test", "jenkins",
                           "gitlab", "grafana", "kibana", "elastic", "backup", "old", "vpn"]
    suspicious = [s for s in all_subs if any(s.startswith(p + ".") for p in suspicious_prefixes)]

    if suspicious:
        print(c(f"\n  🚨 Suspicious subdomains ({len(suspicious)}):", "red"))
        for s in suspicious:
            print(c(f"    ★ {s}", "yellow"))

    print(c("\n  All subdomains:", "blue"))
    for s in all_subs:
        print(f"    {s}")

    saved = save_output("subdomains", "\n".join(all_subs), domain)
    print(c(f"\n  Saved → {saved}", "green"))

    print(c("\n  Next steps:", "cyan"))
    print("    python hunt.py alive " + domain + " --list " + str(saved))
    print("    python hunt.py cert " + domain)
    print(f"    Check: https://www.virustotal.com/gui/domain/{domain}/relations")


async def cmd_alive(domain: str, list_file: str | None = None, **kwargs):
    """Check which subdomains are alive using httpx."""
    print(c(f"\n[*] Alive Check: {domain}", "cyan"))

    if list_file and Path(list_file).exists():
        print(c(f"  Using list: {list_file}", "blue"))
        raw = [ln.strip() for ln in Path(list_file).read_text().splitlines() if ln.strip()]
        targets = [t if "://" in t else f"https://{t}" for t in raw]
    else:
        # Quick subfinder first
        out, _ = await run(["subfinder", "-d", domain, "-silent"], timeout=45)
        subs = [ln.strip() for ln in out.splitlines() if ln.strip()]
        if not subs:
            print(c("  No subdomains found. Try: python hunt.py recon " + domain, "yellow"))
            return
        targets = [f"https://{s}" for s in subs]

    # httpx sends real requests to every host: scope-check each one.
    targets = await filter_in_scope(targets)
    if not targets:
        print(c("  Nothing in scope to probe.", "yellow"))
        return

    with targets_tempfile(targets) as targets_file:
        out, err = await run(
            ["httpx", "-l", targets_file, "-silent", "-status-code",
             "-title", "-tech-detect", "-web-server", "-timeout", "10"],
            timeout=120,
        )

    lines = [ln for ln in out.splitlines() if ln.strip()]
    print(c(f"\n  Alive hosts ({len(lines)}):\n", "green"))

    for line in lines:
        color = "red" if "[200]" in line else "yellow" if "[30" in line else "blue"
        print(c(f"    {line}", color))

    saved = save_output("alive", "\n".join(lines), domain)
    print(c(f"\n  Saved → {saved}", "green"))
    print(c("\n  Next steps:", "cyan"))
    print(f"    python hunt.py scan {domain}")
    print(f"    python hunt.py fuzz https://{domain}/FUZZ")
    print(f"    python hunt.py screenshot {domain} --list {saved}")


async def cmd_scan(target: str, severity: str = "medium,high,critical", **kwargs):
    """Nuclei vulnerability scan."""
    if not await scope_allows(target):
        return
    print(c(f"\n[*] Nuclei Scan: {target} (severity: {severity})", "cyan"))
    print(c("  This may take several minutes...\n", "yellow"))

    out, err = await run(
        ["nuclei", "-u", target, "-severity", severity,
         "-silent", "-rate-limit", "30", "-bulk-size", "20"],
        timeout=300,
    )

    findings = [ln for ln in out.splitlines() if ln.strip()]
    if not findings:
        print(c("  No findings from Nuclei.", "yellow"))
        print(c("\n  This doesn't mean no vulnerabilities exist!", "yellow"))
        print(c("  Nuclei only covers known patterns. Manual testing is essential.\n", "yellow"))
        print(c("  Manual checks to do:", "cyan"))
        manual_checks = [
            "IDOR: change IDs in requests (user_id=1 → user_id=2)",
            "Auth bypass: remove cookies/JWT and retry privileged requests",
            "Mass assignment: add 'role:admin' to JSON body in profile update",
            "Race condition: send 10 simultaneous requests to checkout endpoint",
            "SSRF: modify URL parameters to point to http://169.254.169.254",
            "Open redirect: append ?redirect=https://evil.com to login page",
            "Rate limit: send 50 login requests in 10 seconds",
        ]
        for m in manual_checks:
            print(c(f"    → {m}", "blue"))
        return

    print(c(f"  Found {len(findings)} issues:\n", "red"))
    for finding in findings:
        severity_color = "red" if "[critical]" in finding or "[high]" in finding else "yellow"
        print(c(f"    {finding}", severity_color))

    saved = save_output("nuclei", "\n".join(findings), target)
    print(c(f"\n  Saved → {saved}", "green"))
    print(c("\n  ⚠  Always verify findings manually before reporting!", "yellow"))
    print(c("  Use Burp Suite to capture request/response as evidence.", "cyan"))


async def cmd_fuzz(url: str, wordlist: str | None = None, extensions: str = "", **kwargs):
    """Directory fuzzing with ffuf."""
    if not await scope_allows(url.replace("FUZZ", "")):
        return
    default_wordlists = [
        str(WORDLISTS_DIR / "directories.txt"),
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        str(Path.home() / "wordlists/common.txt"),
    ]
    wl = wordlist
    if not wl:
        for w in default_wordlists:
            if Path(w).exists():
                wl = w
                break
    if not wl:
        print(c("  No wordlist found. Download one:", "red"))
        print(c("  wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt", "cyan"))
        print(c(f"  -O {WORDLISTS_DIR / 'directories.txt'}", "cyan"))
        return

    fuzz_url = url if "FUZZ" in url else url.rstrip("/") + "/FUZZ"
    print(c(f"\n[*] Dir Fuzz: {fuzz_url}", "cyan"))
    print(c(f"  Wordlist: {wl}\n", "blue"))

    cmd = ["ffuf", "-u", fuzz_url, "-w", wl, "-t", "50",
           "-mc", "200,201,204,301,302,307,401,403", "-ac", "-c"]
    if extensions:
        cmd += ["-e", "." + extensions.replace(",", ",.")]

    out, err = await run(cmd, timeout=180)
    if out.strip():
        print(out)
        saved = save_output("fuzz", out, url.split("//")[-1].split("/")[0])
        print(c(f"\n  Saved → {saved}", "green"))
    else:
        print(c("  No paths found.\n", "yellow"))
        print(c("  Tips:", "cyan"))
        print("    → Try a larger wordlist: SecLists/Discovery/Web-Content/raft-large-directories.txt")
        print("    → Try with extensions: python hunt.py fuzz URL --ext php,asp,bak")
        print("    → Target may have WAF — try slower: add -rate 10 to ffuf")


async def cmd_wayback(domain: str, **kwargs):
    """Get historical URLs from Wayback Machine + gau."""
    print(c(f"\n[*] Historical URLs: {domain}", "cyan"))

    wb_task = run(["waybackurls", domain], timeout=90)
    gau_task = run(["gau", "--subs", domain], timeout=90)
    (wb_out, _), (gau_out, _) = await asyncio.gather(wb_task, gau_task)

    all_urls = sorted(set(
        ln.strip() for ln in (wb_out + "\n" + gau_out).splitlines()
        if ln.strip()
    ))

    interesting_kw = [".bak", ".old", ".zip", ".sql", ".env", ".log", ".config",
                      "backup", "admin", "secret", "password", "token", "key", "debug"]
    interesting = [u for u in all_urls if any(kw in u.lower() for kw in interesting_kw)]

    print(c(f"\n  Total URLs: {len(all_urls)}", "green"))
    if interesting:
        print(c(f"  🚨 Interesting URLs ({len(interesting)}):", "red"))
        for u in interesting[:30]:
            print(c(f"    ★ {u}", "yellow"))

    saved = save_output("wayback", "\n".join(all_urls), domain)
    print(c(f"\n  Saved → {saved}", "green"))

    print(c("\n  Manual analysis tips:", "cyan"))
    print("    Extract params: grep '?' " + str(saved) + " | sed 's/=.*/=FUZZ/' | sort -u > params.txt")
    print("    Find JS files: grep '\\.js$' " + str(saved))
    print("    Dead endpoints: cat " + str(saved) + " | httprobe")


async def cmd_cert(domain: str, **kwargs):
    """Search certificate transparency for subdomains."""
    print(c(f"\n[*] Certificate Transparency: {domain}", "cyan"))
    try:
        import json as _json
        import urllib.request
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        with urllib.request.urlopen(url, timeout=15) as r:
            data = _json.loads(r.read())
        names = sorted(set(
            v.strip().lstrip("*.")
            for entry in data
            for v in entry.get("name_value", "").splitlines()
            if domain in v
        ))
        print(c(f"\n  Found {len(names)} domains in CT logs:\n", "green"))
        for n in names:
            print(f"    {n}")
        saved = save_output("cert", "\n".join(names), domain)
        print(c(f"\n  Saved → {saved}", "green"))
    except Exception as e:
        print(c(f"  Error: {e}", "red"))
        print(c(f"  Manual: https://crt.sh/?q=%.{domain}", "cyan"))


async def cmd_screenshot(target: str, list_file: str | None = None, **kwargs):
    """Take screenshots of web targets."""
    print(c(f"\n[*] Screenshots: {target}", "cyan"))
    out_dir = Path(f"output/{target.replace('/', '_')}/screenshots")
    out_dir.mkdir(parents=True, exist_ok=True)

    if not shutil.which("gowitness"):
        print(c("  gowitness not found. Alternatives:", "yellow"))
        print(c("  → Run ./install-native.sh (installs it), or use the Docker image", "cyan"))
        print(c("  → Install: ./hunt install --tool gowitness   (resolves the right version for you)", "cyan"))
        print(c("  → Or use: httpx -screenshot flag inside the container", "cyan"))
        return

    # gowitness loads every page in a real browser: scope-check first.
    if list_file and Path(list_file).exists():
        raw = [ln.strip() for ln in Path(list_file).read_text().splitlines() if ln.strip()]
        urls = await filter_in_scope([t if "://" in t else f"https://{t}" for t in raw])
        if not urls:
            print(c("  Nothing in scope to screenshot.", "yellow"))
            return
        with targets_tempfile(urls) as tmp:
            cmd = ["gowitness", "file", "-f", tmp, "--screenshot-path", str(out_dir), "--disable-db"]
            out, err = await run(cmd, timeout=120)
    else:
        if not await scope_allows(target):
            return
        url = f"https://{target}" if "://" not in target else target
        cmd = ["gowitness", "single", "-u", url, "--screenshot-path", str(out_dir), "--disable-db"]
        out, err = await run(cmd, timeout=120)

    screenshots = list(out_dir.glob("*.png"))
    print(c(f"\n  {len(screenshots)} screenshots saved to {out_dir}", "green"))
    if screenshots:
        for s in screenshots[:5]:
            print(f"    {s}")


async def cmd_full(domain: str, **kwargs):
    """Run the full recon pipeline."""
    print(c(f"\n[*] Full Recon Pipeline: {domain}", "cyan"))
    print(c("  Steps: recon → alive → port scan → nuclei scan\n", "blue"))

    # Fail fast: if the apex itself is out of scope, don't even start the
    # (passive) recon stage just to have every active stage refuse later.
    if not await scope_allows(domain):
        return

    await cmd_recon(domain)

    sub_file = sorted(Path(f"output/{domain}").glob("subdomains_*.txt"))
    if sub_file:
        await cmd_alive(domain, list_file=str(sub_file[-1]))

    print(c(f"\n[*] Port Scan: {domain}", "cyan"))
    out, _ = await run(["naabu", "-host", domain, "-silent", "-top-ports", "100"], timeout=120)
    if out.strip():
        print(out)
        save_output("ports", out, domain)
    else:
        print(c("  No open ports found (top 100).", "yellow"))

    await cmd_scan(domain)

    print(c(f"\n\n{'═'*60}", "cyan"))
    print(c(f"  Full recon complete for {domain}", "bold"))
    print(c(f"  Results saved to: output/{domain}/", "green"))
    print(c("  Next: manual testing of discovered endpoints", "cyan"))
    print(c(f"{'═'*60}\n", "cyan"))


# ── CLI Entry Point ───────────────────────────────────────────────────────────

## Each handler takes a different argument shape (cmd_doctor takes only a
## json_output kwarg; everything else takes a positional target plus
## command-specific **kwargs) — there's no single signature that describes
## all of them soundly, so this is deliberately typed as Any-in/Any-out
## rather than left for mypy to infer (which fails: "Cannot call function
## of unknown type" at both dispatch sites in main()). The real safety net
## for argument shape is the explicit per-command handling in main() below,
## not the type checker.
CommandHandler = Callable[..., Coroutine[Any, Any, None]]
COMMANDS: dict[str, tuple[CommandHandler, str]] = {
    "recon":      (cmd_recon,      "Passive subdomain enum (subfinder + crt.sh)"),
    "alive":      (cmd_alive,      "Check which hosts are alive (httpx)"),
    "scan":       (cmd_scan,       "Nuclei vulnerability scan"),
    "fuzz":       (cmd_fuzz,       "Directory fuzzing (ffuf)"),
    "wayback":    (cmd_wayback,    "Historical URLs (waybackurls + gau)"),
    "cert":       (cmd_cert,       "Certificate transparency search"),
    "screenshot": (cmd_screenshot, "Web screenshots (gowitness)"),
    "full":       (cmd_full,       "Full recon pipeline"),
    "doctor":     (cmd_doctor,     "Check environment: Python, tools, wordlists"),
}


MAINTENANCE_COMMANDS: dict[str, str] = {
    "doctor":              "Versions + health of every tool (--json, --offline, --selftest, --strict)",
    "update":              "Update tools: patch/minor automatically (--check, --dry-run, --yes, --major)",
    "install":             "Install tools (newest compatible, or --lock FILE for exact versions)",
    "rollback <tool>":     "Restore the previous version of a tool",
    "snapshot":            "Record installed versions to config/tool-lock.json",
    "config tools":        "See / choose which copy (system, local, go) of each tool is used",
    "auto-update enable":  "Opt in to safe background updates (systemd user timer)",
    "verify":              "Strict health gate (used by Docker builds and CI)",
}
# Handled by mcp_server.toolmgr (doctor is handled here, with the legacy report).
TOOLMGR_COMMANDS = frozenset({"update", "install", "rollback", "snapshot", "config", "auto-update", "verify"})


def usage():
    banner()
    check_tools()
    print(c("  Commands:\n", "bold"))
    for name, (_, desc) in COMMANDS.items():
        print(f"    {c(f'hunt.py {name:<12}', 'cyan')} {desc}")
    print(c("\n  Tool maintenance (versions are resolved at install time — see config/tools.yaml):\n", "bold"))
    for name, desc in MAINTENANCE_COMMANDS.items():
        print(f"    {c(f'hunt {name:<18}', 'cyan')} {desc}")
    print(c("\n  Examples:\n", "bold"))
    print("    python hunt.py full example.com")
    print("    python hunt.py recon example.com")
    print("    python hunt.py scan https://example.com --severity high,critical")
    print("    python hunt.py fuzz https://example.com/FUZZ --ext php,asp,bak")
    print("    python hunt.py alive example.com --list subdomains.txt")
    print(c("\n  ⚠️  Only test targets you have written permission to test.\n", "red"))


def main():
    args = sys.argv[1:]
    if args and args[0] in TOOLMGR_COMMANDS:
        from mcp_server.toolmgr.cli import main as toolmgr_main
        sys.exit(toolmgr_main(args))
    if not (args and args[0] == "doctor" and "--json" in args):
        banner()                       # `doctor --json` must emit JSON and nothing else
    if not args or args[0] in ("-h", "--help", "help"):
        usage()
        return

    command = args[0]
    if command not in COMMANDS:
        print(c(f"Unknown command: {command}", "red"))
        usage()
        return

    # doctor is an environment check, not a target scan — it takes no
    # target at all, unlike every other command here.
    if command == "doctor":
        rest = args[1:]
        handler, _ = COMMANDS[command]
        asyncio.run(handler(
            json_output="--json" in rest, offline="--offline" in rest, refresh="--refresh" in rest,
            selftest="--selftest" in rest, strict="--strict" in rest,
        ))
        return

    # Parse positional target + kwargs
    target = args[1] if len(args) > 1 else None
    if not target:
        print(c(f"Target required: python hunt.py {command} <target>", "red"))
        return

    # Same argv-injection guard the MCP server applies: a "target" that
    # starts with '-' would be parsed as a flag by the downstream Go tool.
    flag_error = reject_flag_injection(target)
    if flag_error:
        print(c(flag_error, "red"))
        return
    if command in ("recon", "alive", "cert", "wayback", "full") and not is_valid_domain(target):
        print(c(f"'{target}' is not a valid domain name.", "red"))
        return

    # Parse --flag value pairs
    kwargs: dict = {}
    i = 2
    while i < len(args):
        if args[i].startswith("--") and i + 1 < len(args):
            key = args[i][2:].replace("-", "_")
            kwargs[key] = args[i + 1]
            i += 2
        else:
            i += 1

    handler, _ = COMMANDS[command]
    asyncio.run(handler(target, **kwargs))


if __name__ == "__main__":
    # run_cli handles `hunt ... | head`: a vanished reader is not an error, and the
    # interpreter's exit-time flush must not be left to fail either (see cliutil).
    # It also covers the toolmgr commands, which leave through sys.exit().
    from mcp_server.cliutil import main_guard
    main_guard(main)
