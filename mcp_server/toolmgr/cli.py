"""
cli.py — `hunt doctor|update|install|rollback|snapshot|config|auto-update|verify`

Also runnable directly:  python -m mcp_server.toolmgr <command> ...
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from . import autoupdate, installer, ops, pyenv, state, upstream, versions
from .layout import Layout
from .manifest import ManifestError, load_manifest
from .security import SecurityError, atomic_write_json, ensure_safe_dir, exclusive_lock, path_problems

EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_OUTDATED = 0, 1, 2, 10
_BAD = {"MISSING", "BROKEN", "INCOMPATIBLE", "UNTESTED"}


def in_docker() -> bool:
    if os.environ.get("BBMCP_DOCKER") == "1" or Path("/.dockerenv").exists():
        return True
    try:
        txt = Path("/proc/1/cgroup").read_text()
        return any(k in txt for k in ("docker", "containerd", "kubepods"))
    except OSError:
        return False


class _Out:
    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    _C = {"red": "31", "green": "32", "yellow": "33", "cyan": "36", "dim": "2", "bold": "1"}

    @classmethod
    def c(cls, text: str, name: str) -> str:
        return f"\033[{cls._C[name]}m{text}\033[0m" if cls.color else text


def _status_color(status: str) -> str:
    return {"OK": "green", "UPDATE": "yellow", "MAJOR": "yellow", "MANUAL": "yellow", "UNKNOWN": "dim",
            "UPDATED": "green", "UNCHECKED": "dim", "INSTALLED": "green", "FAILED": "red", "ROLLED-BACK": "red"}.get(status, "red")


def table(headers: Sequence[str], rows: Sequence[Sequence[str]], status_col: int | None = None) -> str:
    widths = [max(len(str(x)) for x in col) for col in zip(headers, *rows, strict=True)] if rows else [len(h) for h in headers]
    def fmt(r: Sequence[str], colour: bool) -> str:
        cells = []
        for i, (cell, w) in enumerate(zip(r, widths, strict=True)):
            text = str(cell).ljust(w)
            cells.append(_Out.c(text, _status_color(str(cell))) if colour and i == status_col else text)
        return "  ".join(cells).rstrip()
    out = [fmt(headers, False), "-" * (sum(widths) + 2 * (len(widths) - 1))]
    out += [fmt(r, True) for r in rows]
    return "\n".join(out)


# ── context ───────────────────────────────────────────────────────────
def make_context(args: argparse.Namespace, layout: Layout | None = None, http=None) -> ops.Context:
    layout = layout or Layout()
    if getattr(args, "dest", None):
        layout = layout.with_tools_dir(Path(args.dest))
    manifest = load_manifest(layout.manifest)
    timeout = float(manifest.settings.get("network_timeout_seconds", 8))
    offline = bool(getattr(args, "offline", False) or os.environ.get("BBMCP_OFFLINE") == "1")
    return ops.Context(
        layout=layout, manifest=manifest,
        http=http or upstream.Http(timeout=min(timeout, 5) if args.command == "doctor" else timeout, offline=offline),
        in_docker=in_docker(), offline=offline, refresh=bool(getattr(args, "refresh", False)),
    )


def _prepare_state(ctx: ops.Context) -> None:
    """Mutating commands only: make sure the state dir is ours and not writable by others."""
    ensure_safe_dir(ctx.layout.state_dir)


def _guard_root(args: argparse.Namespace) -> None:
    if os.geteuid() == 0 and not getattr(args, "allow_root", False):
        raise SecurityError("refusing to run as root: this writes into the repository and builds code "
                            "downloaded from the internet. Run as your normal user "
                            "(or pass --allow-root if that is genuinely what you want, e.g. in a Docker build).")


# ── doctor ────────────────────────────────────────────────────────────
def doctor_data(ctx: ops.Context, selftest: bool = False) -> dict:
    statuses = ops.collect(ctx)
    tools = [s.to_dict() for s in statuses]
    issues: list[str] = []
    for s, d in zip(statuses, tools, strict=True):
        if selftest and s.selection.chosen:
            probs = installer.selftest(s.spec, s.selection.chosen.path, ctx.runner)
            d["selftest"] = probs or "ok"
            if probs:
                d["status"] = "INCOMPATIBLE"
                s.status = "INCOMPATIBLE"
                issues.append(f"{s.spec.name}: {'; '.join(probs)}")
        if s.status in _BAD and s.spec.required:
            issues.append(f"{s.spec.name}: {s.status.lower()} — {s.detail or s.selection.reason}")
    assets = [a for a in (ops.asset_status(ctx, n) for n in ctx.manifest.assets) if a]
    py = pyenv.python_report(ctx.layout.root)
    issues += py["issues"]
    pp = path_problems()
    go = installer.find_go()
    gv = installer.go_version(go, ctx.runner) if go else None
    min_go = versions.parse_loose(str(ctx.manifest.settings.get("min_go_version", "1.21")))
    go_info = {"path": go, "version": str(gv) if gv else None,
               "ok": bool(go and gv and min_go and gv >= min_go)}
    return {"tools": tools, "assets": assets, "python_env": py, "path_problems": pp, "go": go_info,
            "update_check": {"offline": ctx.offline, "interval_hours": ctx.cache.ttl / 3600},  # type: ignore[union-attr]
            "toolmgr_issues": issues}


def print_tools_table(data: dict, only_required: bool | None = None) -> None:
    rows = []
    for t in data["tools"]:
        if only_required is not None and t["required"] != only_required:
            continue
        status = t["status"]
        note = f" (v{t['newer_major_available'].split('.')[0]}.x exists)" if t.get("newer_major_available") else ""
        rows.append((t["tool"], t["installed"] or "-", (t["latest_compatible"] or "?") + note, status, t["source"] or "-"))
    print(table(["Tool", "Installed", "Latest", "Status", "Source"], rows, status_col=3))


def print_doctor_extras(data: dict) -> None:
    if data["assets"]:
        print(_Out.c("\nTemplates / data (versioned separately from the engine)", "cyan"))
        print(table(["Asset", "Installed", "Latest", "Status"],
                    [(a["tool"], a["installed"] or "-", a["latest_compatible"] or "?", a["status"]) for a in data["assets"]],
                    status_col=3))
    g = data["go"]
    print(_Out.c("\nGo toolchain (used to build tools)", "cyan"))
    print(f"  {'✓' if g['ok'] else '✗'} {g['version'] or 'not found'}  {g['path'] or ''}")
    py = data["python_env"]
    print(_Out.c("\nPython / MCP dependencies", "cyan"))
    print(f"  {'✓' if py['in_virtualenv'] else '○'} virtualenv: {'yes' if py['in_virtualenv'] else 'no (using the system Python)'}")
    m = py["mcp"]
    print(f"  {'✓' if m['status'] == 'OK' else '✗'} mcp SDK {m['installed'] or 'missing'} (API {m.get('api') or '?'})")
    bad = [r for r in py["requirements"] if r["status"] != "OK"]
    for r in bad:
        print(_Out.c(f"  ✗ {r['package']}: {r['status'].lower()} (needs {r['required']}, has {r['installed']})", "red"))
    if not bad:
        print(f"  ✓ {len(py['requirements'])} requirements satisfied")
    if data["path_problems"]:
        print(_Out.c("\nPATH problems", "yellow"))
        for p in data["path_problems"]:
            print(_Out.c(f"  ⚠ {p}", "yellow"))
    stale = [t for t in data["tools"] if t["status"] in ("UPDATE", "MANUAL", "MAJOR")]
    if stale:
        print(_Out.c("\nUpdates available — run `./hunt update --check` for details", "yellow"))
    if data["update_check"]["offline"]:
        print(_Out.c("\n(offline mode: latest versions come from cache, if any)", "dim"))


def cmd_doctor(args: argparse.Namespace) -> int:
    ctx = make_context(args)
    data = doctor_data(ctx, selftest=args.selftest)
    degraded = bool(data["toolmgr_issues"])
    data["status"] = "degraded" if degraded else "ready"
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(_Out.c("\nBugBounty MCP — tools\n", "bold"))
        print_tools_table(data)
        print_doctor_extras(data)
        print()
        print(_Out.c("⚠  Environment is degraded:", "yellow") if degraded else _Out.c("✓  Environment is ready.", "green"))
        for i in data["toolmgr_issues"]:
            print(_Out.c(f"   • {i}", "yellow"))
    return EXIT_FAIL if (degraded and args.strict) else EXIT_OK


# ── update ────────────────────────────────────────────────────────────
def _mark_auto_run(layout: Layout) -> None:
    s = autoupdate.load(layout)
    s.last_auto_run = time.time()
    autoupdate.save(layout, s)


def _confirm(prompt: str) -> bool:
    try:
        return input(f"{prompt} [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


def _plan_rows(plan: list[ops.PlanItem], results: dict[str, installer.Result] | None = None) -> list[tuple[str, ...]]:
    rows: list[tuple[str, ...]] = []
    for p in plan:
        r = (results or {}).get(p.tool)
        if r:
            label = {"updated": "UPDATED", "installed": "INSTALLED", "unchanged": "UNCHANGED",
                     "failed": "FAILED", "rolled-back": "ROLLED-BACK", "planned": "WOULD " + p.action.upper()}[r.status]
        else:
            label = {"install": "INSTALL", "update": "UPDATE", "skip": "OK" if p.reason == "up to date" else "SKIPPED",
                     "blocked": "BLOCKED"}[p.action]
        note = p.reason if label not in ("OK", "UPDATED", "INSTALLED") else ""
        if note.startswith("upstream unavailable"):
            note = "could not check upstream (see below)"
        rows.append((p.tool, p.installed or "-", "->", p.target or "?", label, note))
    return rows


# What `update` manages — and, just as important, what it does not. Printed at the top of every run
# and in --help so nobody believes a green `hunt update` also patched Python packages or the OS.
UPDATE_SCOPE_LINE = ("Updates: the security tools this project installs, and Nuclei templates (separately from the engine). "
                     "Not touched: Python dependencies, the project's own source, OS packages, Docker images.")
UPDATE_SCOPE_HELP = """\
What this updates:
  * the security tools this project installed (subfinder, httpx, nuclei, ...): patch/minor
    releases automatically, majors only with --major, never a downgrade, every new binary
    self-tested before it replaces the working one (`hunt rollback TOOL` undoes it)
  * Nuclei templates — updated by nuclei itself, separately from the nuclei engine

What it does NOT touch (each has its own command; see docs/UPDATING.md):
  * Python dependencies    pip install -U -r requirements.txt   (or --require-hashes -r requirements.lock)
  * the project's source   git pull
  * operating-system pkgs  sudo apt update && sudo apt upgrade
  * Docker images          make refresh-tools
"""


def cmd_update(args: argparse.Namespace) -> int:
    if args.disable_auto:
        return _auto_disable(args)
    layout = Layout()
    if args.auto:
        s = autoupdate.load(layout)
        if os.geteuid() == 0:
            print("auto-update refuses to run as root.", file=sys.stderr)
            return EXIT_FAIL
        if not s.enabled:
            print("Automatic updates are not enabled (./hunt auto-update enable). Nothing to do.")
            return EXIT_OK
        if not autoupdate.due(s):
            print("Last automatic check is recent; skipping (throttled).")
            return EXIT_OK
        args.yes, args.major = True, False
    if not (args.check or args.dry_run):
        _guard_root(args)
    ctx = make_context(args, layout)
    if not (args.check or args.dry_run):
        _prepare_state(ctx)
    names = args.tool or None
    docker = ctx.in_docker
    if args.templates_only:
        with exclusive_lock(ctx.layout.lock_file):
            res = ops.update_asset(ctx, dry_run=args.dry_run or args.check)
        print(f"nuclei templates: {res.old or '?'} -> {res.new or '?'}  {res.status.upper()}"
              + (f"  ({res.reason})" if res.reason else ""))
        return EXIT_OK if res.ok else EXIT_FAIL
    print(_Out.c("\nBugBounty MCP Tool Update\n", "bold"))
    print(_Out.c(UPDATE_SCOPE_LINE, "dim") + "\n")
    statuses = ops.collect(ctx, names)
    plan = ops.make_plan(statuses, major=args.major, auto=args.auto, explicit=frozenset(names or ()))
    tpl = None if (args.no_templates or names) else ops.asset_status(ctx)

    errs = {s.spec.name: s.latest.error for s in statuses if s.latest and s.latest.error and not s.latest.version}
    if statuses and len(errs) == len(statuses):
        # Every lookup failed (offline, firewall, upstream down): say it ONCE and
        # show what is installed — not N copies of the same error.
        unique = list(dict.fromkeys(errs.values()))
        # the circuit-breaker's generic text is a symptom; show the root cause if there is one
        reasons = [r for r in unique if "looks unavailable" not in r] or unique
        if reasons[0] == "offline":
            # Offline was asked for (flag or BBMCP_OFFLINE): that is a mode, not a failure.
            print(_Out.c("Offline — upstream was not checked; every existing tool is kept as it is.", "yellow"))
            print("  Nothing was changed. Run again without --offline to look for updates.\n")
        else:
            print(_Out.c("Update check failed — keeping every existing tool as it is.", "yellow"))
            print(_Out.c(f"  reason: {reasons[0]}", "dim"))
            print("  Nothing was changed. Retry later, or use --offline to skip the check.\n")
        print(table(["Tool", "Installed", "Status"],
                    [(s.spec.name, str(s.installed) if s.installed else "-",
                      "UNCHECKED" if s.installed else "NOT INSTALLED") for s in statuses]))
        return EXIT_OK
    print(table(["Tool", "Installed", "", "Target", "Status", "Note"], _plan_rows(plan), status_col=4))
    for p in plan:
        if p.note:
            print(_Out.c(f"  {p.tool}: {p.note}", "dim"))
    if errs:
        distinct = [e for e in dict.fromkeys(errs.values()) if "looks unavailable" not in e] or list(errs.values())[:1]
        print(_Out.c(f"\nCould not check {len(errs)} tool(s); they were left untouched. Cause:", "yellow"))
        for cause in distinct[:3]:
            print(_Out.c(f"  • {cause}", "dim"))
    if tpl:
        print(f"\nnuclei templates: {tpl['installed'] or '?'} -> {tpl['latest_compatible'] or '?'}  {tpl['status']}")
    blocked_major = [p for p in plan if "needs --major" in p.reason or "major v" in p.note]
    if blocked_major and not args.major:
        print(_Out.c("\nMajor update detected — NOT applied automatically (major-version compatibility "
                     "needs validation). Run `./hunt update --major` to try it; the compatibility "
                     "self-test still runs and a failure keeps the current version.", "yellow"))

    actionable = [p for p in plan if p.action in ("install", "update")]
    tpl_due = bool(tpl and tpl["status"] == "UPDATE")
    if args.check or args.dry_run:
        if args.dry_run:
            ops.apply_plan(ctx, plan, dry_run=True)
            print(_Out.c("\nDry run: nothing was modified.", "dim"))
        if args.check and args.fail_on_outdated and (actionable or tpl_due):
            return EXIT_OUTDATED
        return EXIT_OK
    if docker:
        if actionable:
            print(_Out.c("\nRunning inside a Docker image: tool binaries are part of the image and are not "
                         "modified in place. Rebuild to get the versions above:\n"
                         "    docker compose build --pull --build-arg TOOLS_REFRESH=$(date +%s)", "yellow"))
        actionable = []
    if not actionable and not tpl_due:
        print(_Out.c("\nNothing to update.", "green"))
        if args.auto:
            _mark_auto_run(layout)
        return EXIT_OK
    if not args.yes:
        if not sys.stdin.isatty():
            print("\nNot applying changes: no terminal to confirm on. Re-run with --yes.", file=sys.stderr)
            return EXIT_USAGE
        if not _confirm(f"\nApply {len(actionable)} change(s)" + (" + templates" if tpl_due else "") + "?"):
            print("Aborted; nothing changed.")
            return EXIT_OK

    with exclusive_lock(ctx.layout.lock_file):
        results = ops.apply_plan(ctx, actionable and plan)
        by_tool = {r.tool: r for r in results}
        tres = ops.update_asset(ctx) if tpl_due and not args.offline else None
        if not docker:
            ops.refresh_selection(ctx)
    print()
    print(table(["Tool", "Installed", "", "Target", "Status", "Note"], _plan_rows(plan, by_tool), status_col=4))
    failed = [r for r in results if not r.ok]
    for r in failed:
        print(_Out.c(f"  ✗ {r.tool}: {r.reason}", "red"))
        if r.status == "failed":
            print(_Out.c(f"    the previously working version ({r.old or 'none'}) is still in place", "dim"))
    if tres:
        print(f"\nnuclei templates: {tres.old or '?'} -> {tres.new or '?'}  {tres.status.upper()}"
              + (f"  ({tres.reason})" if tres.reason else ""))
        failed += [] if tres.ok else [tres]
    if args.auto:
        _mark_auto_run(layout)
    print(_Out.c("\nHistory: data/update-history.json", "dim"))
    return EXIT_FAIL if failed else EXIT_OK


# ── install / rollback / snapshot ─────────────────────────────────────
def cmd_install(args: argparse.Namespace) -> int:
    if not args.dry_run:
        _guard_root(args)
    ctx = make_context(args)
    if not args.dry_run:
        _prepare_state(ctx)
    lock = state.load_lock(ctx.manifest, Path(args.lock)) if args.lock else None
    names = args.tool or None
    if args.dry_run:
        statuses = ops.collect(ctx, names)
        for s in statuses:
            target = lock[s.spec.name] if lock and s.spec.name in lock else (s.latest.version if s.latest else None)
            ch = s.selection.chosen
            have = f"{s.installed} ({ch.source})" if (s.installed and ch) else "not installed"
            why = (s.latest.error if s.latest else None) or "?"
            print(f"  {s.spec.name:<18} have: {have:<28} would install: {target or f'cannot resolve ({why})'}")
        print("\nDry run: nothing was modified.")
        return EXIT_OK
    if not installer.find_go():
        print(_Out.c("Go toolchain not found — cannot build the security tools. Install Go from "
                     "https://go.dev/dl/ (or `apt install golang-go` / `brew install go`) and re-run.", "red"))
        return EXIT_FAIL
    with exclusive_lock(ctx.layout.lock_file):
        results = ops.install_all(ctx, names, lock)
        if not args.dest and not ctx.in_docker:
            ops.refresh_selection(ctx)
    req = ctx.manifest.required
    rows, bad_required = [], []
    for r in results:
        rows.append((r.tool, r.status.upper(), r.new or r.old or "-", (r.reason or r.path or "")[:90]))
        if not r.ok and r.tool in req:
            bad_required.append(r.tool)
    print(table(["Tool", "Result", "Version", "Detail"], rows, status_col=1))
    if bad_required:
        print(_Out.c(f"\nRequired tool(s) not installed: {', '.join(bad_required)}. "
                     "Run `./hunt doctor` for details.", "yellow"))
    print(_Out.c(f"\nExact versions recorded in {ctx.layout.installed_file}", "dim"))
    return EXIT_FAIL if (bad_required and args.strict) else EXIT_OK


def cmd_rollback(args: argparse.Namespace) -> int:
    _guard_root(args)
    ctx = make_context(args)
    _prepare_state(ctx)
    spec = ctx.manifest.tools.get(args.tool)
    if not spec:
        print(f"Unknown tool {args.tool!r}. Known: {', '.join(ctx.manifest.tools)}", file=sys.stderr)
        return EXIT_USAGE
    backups = installer.list_backups(ctx.layout, spec.name)
    if not backups:
        print(f"No backups of {spec.name} (backups are made automatically when an update replaces it).")
        return EXIT_FAIL
    to = versions.parse(args.to) if args.to else None
    print(f"Backups of {spec.name}: " + ", ".join(str(v) for v, _ in backups))
    if not args.yes and sys.stdin.isatty() and not _confirm(f"Roll {spec.name} back to {to or backups[0][0]}?"):
        return EXIT_OK
    with exclusive_lock(ctx.layout.lock_file):
        res = installer.rollback_tool(ctx.layout, spec, to, ctx.runner)
        if res.ok:
            ops.refresh_selection(ctx)
    state.log_history(ctx.layout, spec.name, res.old, res.new, "success" if res.ok else "failure", "rollback", res.reason)
    print(f"{spec.name}: {res.old or '?'} -> {res.new or '?'}  {res.status.upper()}" + (f"  ({res.reason})" if res.reason else ""))
    return EXIT_OK if res.ok else EXIT_FAIL


def cmd_snapshot(args: argparse.Namespace) -> int:
    ctx = make_context(args)
    lock = ops.snapshot(ctx)
    if args.stdout:
        print(json.dumps(lock, indent=2))
        return EXIT_OK
    out = Path(args.output) if args.output else ctx.layout.default_lock
    atomic_write_json(out, lock, mode=0o644)
    print(f"Wrote {out} ({len(lock['tools'])} tools). Reproduce with: ./hunt install --lock {out}")
    return EXIT_OK


# ── config tools ──────────────────────────────────────────────────────
def cmd_config(args: argparse.Namespace) -> int:
    ctx = make_context(args)
    sel = state.load_selection(ctx.layout)
    if args.action == "set":
        if args.tool not in ctx.manifest.tools:
            print(f"Unknown tool {args.tool!r}", file=sys.stderr)
            return EXIT_USAGE
        v = args.value
        if v not in ("auto", "system", "local", "go") and not (os.path.isabs(v) and os.path.isfile(v)):
            print("value must be auto | system | local | go | /absolute/path/to/binary", file=sys.stderr)
            return EXIT_USAGE
        sel["prefer"][args.tool] = v
        state.save_selection(ctx.layout, sel)
    elif args.action == "reset":
        for t in ([args.tool] if args.tool else list(sel["prefer"])):
            sel["prefer"].pop(t, None)
        state.save_selection(ctx.layout, sel)
    statuses = ops.collect(ctx, with_latest=False)
    if args.action in ("set", "reset", "refresh") and not ctx.in_docker:
        ops.refresh_selection(ctx)
        statuses = ops.collect(ctx, with_latest=False)
    if args.json:
        print(json.dumps([s.to_dict() for s in statuses], indent=2))
        return EXIT_OK
    rows = []
    for s in statuses:
        ch = s.selection.chosen
        rows.append((s.spec.name, f"{ch.source} {ch.version}" if ch else "-",
                     sel["prefer"].get(s.spec.name, "auto"),
                     "; ".join(f"{c.source} {c.version or '?'}" for c in s.selection.candidates) or "none found"))
    print(table(["Tool", "Selected", "Preference", "All copies found"], rows))
    print("\nSelection = the newest compatible copy unless you pin one: ./hunt config tools set <tool> system|local|go|auto")
    return EXIT_OK


# ── auto-update ───────────────────────────────────────────────────────
def _auto_disable(args: argparse.Namespace) -> int:
    layout = Layout()
    removed = autoupdate.disable(layout)
    print("Automatic updates disabled." + (f" Removed: {', '.join(removed)}" if removed else ""))
    print(autoupdate.apt_instructions(install=False) if autoupdate.load(layout).apt_signal or removed else "")
    return EXIT_OK


def cmd_autoupdate(args: argparse.Namespace) -> int:
    layout = Layout()
    if args.action == "status":
        s = autoupdate.load(layout)
        print(f"enabled: {s.enabled}   interval: {s.interval_hours}h   apt-signal: {s.apt_signal}")
        return EXIT_OK
    if args.action == "disable":
        return _auto_disable(args)
    print(autoupdate.describe(layout.root, args.interval, args.apt_signal))
    if not args.yes and not (sys.stdin.isatty() and _confirm("\nEnable?")):
        print("Not enabled.")
        return EXIT_OK
    written = autoupdate.enable(layout, args.interval, args.apt_signal)
    print("Enabled. Wrote:\n  " + "\n  ".join(written))
    if args.apt_signal:
        print("\n" + autoupdate.apt_instructions())
    return EXIT_OK


# ── verify (Docker / CI health gate) ──────────────────────────────────
def cmd_verify(args: argparse.Namespace) -> int:
    ctx = make_context(args)
    ctx.offline = True
    rows, fatal = [], []
    for s in ops.collect(ctx, with_latest=False):
        ch = s.selection.chosen
        probs = installer.selftest(s.spec, ch.path, ctx.runner) if ch else []
        ok = bool(ch) and not probs
        rows.append((s.spec.name, str(ch.version) if ch else "-", "OK" if ok else s.status if not ch else "INCOMPATIBLE",
                     ch.path if ch else (s.detail or s.selection.reason), "; ".join(probs)))
        if not ok and (s.spec.required or args.all):
            fatal.append(s.spec.name)
    print(table(["Tool", "Version", "Status", "Path", "Problems"], rows, status_col=2))
    if fatal:
        print(_Out.c(f"\nverify FAILED: {', '.join(fatal)}", "red"))
        return EXIT_FAIL
    print(_Out.c("\nverify passed: every required tool is present, compatible and runs.", "green"))
    return EXIT_OK


# ── parser ────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hunt", description="Tool/dependency management")
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("doctor", help="versions, health and compatibility of every tool")
    d.add_argument("--json", action="store_true", help="machine-readable output (JSON only)")
    d.add_argument("--offline", action="store_true", help="never touch the network (cached latest only)")
    d.add_argument("--refresh", action="store_true", help="ignore the cache and re-check upstream")
    d.add_argument("--selftest", action="store_true", help="also run each tool's compatibility self-test")
    d.add_argument("--strict", action="store_true", help="exit 1 if anything required is wrong")
    d.set_defaults(fn=cmd_doctor)

    u = sub.add_parser("update", help="update tools (patch/minor automatically; majors only with --major)",
                       description="Update the security tools (and Nuclei templates).", epilog=UPDATE_SCOPE_HELP,
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    u.add_argument("--check", action="store_true", help="report what is available; change nothing")
    u.add_argument("--dry-run", action="store_true", help="show exactly what would happen; change nothing")
    u.add_argument("--yes", "-y", action="store_true", help="don't ask for confirmation")
    u.add_argument("--major", action="store_true", help="also try major / untested releases (still self-tested)")
    u.add_argument("--offline", action="store_true", help="don't use the network (changes nothing)")
    u.add_argument("--refresh", action="store_true", help="ignore the cache and re-check upstream")
    u.add_argument("--tool", action="append", metavar="NAME", help="only this tool (repeatable)")
    u.add_argument("--no-templates", action="store_true", help="skip the nuclei-templates update")
    u.add_argument("--templates-only", action="store_true", help="only update nuclei templates (not the tools)")
    u.add_argument("--auto", action="store_true", help=argparse.SUPPRESS)
    u.add_argument("--fail-on-outdated", action="store_true", help="with --check: exit 10 if updates exist (CI)")
    u.add_argument("--disable-auto", action="store_true", help="turn automatic updating off")
    u.add_argument("--allow-root", action="store_true", help=argparse.SUPPRESS)
    u.set_defaults(fn=cmd_update)

    i = sub.add_parser("install", help="install tools: newest compatible, or exact versions from a lock")
    i.add_argument("--lock", metavar="FILE", help="install exactly these versions (see `hunt snapshot`)")
    i.add_argument("--tool", action="append", metavar="NAME")
    i.add_argument("--dest", metavar="DIR", help="install into DIR instead of bin/tools (Docker build)")
    i.add_argument("--dry-run", action="store_true")
    i.add_argument("--offline", action="store_true")
    i.add_argument("--strict", action="store_true", help="exit 1 if a required tool could not be installed")
    i.add_argument("--allow-root", action="store_true", help=argparse.SUPPRESS)
    i.set_defaults(fn=cmd_install, refresh=True)

    r = sub.add_parser("rollback", help="restore the previous version of a tool")
    r.add_argument("tool")
    r.add_argument("--to", metavar="VERSION")
    r.add_argument("--yes", "-y", action="store_true")
    r.add_argument("--allow-root", action="store_true", help=argparse.SUPPRESS)
    r.set_defaults(fn=cmd_rollback)

    s = sub.add_parser("snapshot", help="record installed versions to config/tool-lock.json")
    s.add_argument("--output", metavar="FILE")
    s.add_argument("--stdout", action="store_true")
    s.set_defaults(fn=cmd_snapshot)

    c = sub.add_parser("config", help="choose which copy (system/local/go) of a tool is used")
    c.add_argument("what", choices=["tools"])
    c.add_argument("action", nargs="?", choices=["show", "set", "reset", "refresh"], default="show")
    c.add_argument("tool", nargs="?")
    c.add_argument("value", nargs="?")
    c.add_argument("--json", action="store_true")
    c.set_defaults(fn=cmd_config)

    a = sub.add_parser("auto-update", help="opt-in background update checks (systemd user timer)")
    a.add_argument("action", choices=["enable", "disable", "status"])
    a.add_argument("--interval", type=int, default=24, metavar="HOURS")
    a.add_argument("--apt-signal", action="store_true", help="also react to APT activity (root-side step is printed, never run)")
    a.add_argument("--yes", "-y", action="store_true")
    a.set_defaults(fn=cmd_autoupdate)

    v = sub.add_parser("verify", help="strict health gate for Docker builds and CI")
    v.add_argument("--all", action="store_true", help="optional tools must pass too")
    v.set_defaults(fn=cmd_verify)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (SecurityError, ManifestError) as exc:
        print(_Out.c(f"error: {exc}", "red"), file=sys.stderr)
        return EXIT_FAIL
    except BrokenPipeError:
        # `hunt doctor | head`: the reader left; that's not an error. Point stdout
        # at /dev/null so the interpreter's exit-time flush doesn't traceback either.
        with contextlib.suppress(OSError, ValueError):
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return EXIT_OK
    except KeyboardInterrupt:
        print("\ninterrupted — nothing is left half-installed (staging is cleaned up).", file=sys.stderr)
        return 130
