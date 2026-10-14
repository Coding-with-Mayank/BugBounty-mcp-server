"""
ops.py — orchestration: statuses, update plans, applying them, lock/snapshot.

Update policy (see config/tools.yaml for the per-tool knobs):

  patch   applied (when the tool's auto_update is 'safe', or you ran it by hand)
  minor   applied — but ONLY after the staged build passes the compatibility
          self-test; a failure keeps the old binary
  major   never applied unless `--major`; reported instead. 0.x minors count as major.
  never a downgrade; never touches a system / ~/go/bin copy
"""
from __future__ import annotations

import os
import re
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import detect, installer, state, upstream, versions
from .detect import Candidate, Runner, Selection
from .layout import Layout
from .manifest import AssetSpec, Manifest, ToolSpec
from .security import clean_env, redact, run_argv
from .upstream import Cache, Latest
from .versions import Version


@dataclass
class Context:
    layout: Layout
    manifest: Manifest
    http: Any
    runner: Runner = run_argv
    cache: Cache | None = None
    in_docker: bool = False
    offline: bool = False
    refresh: bool = False
    go: str | None = None
    path_env: str | None = None

    def __post_init__(self) -> None:
        if self.cache is None:
            hrs = float(self.manifest.settings.get("check_interval_hours", 24))
            self.cache = Cache(self.layout.cache_file, hrs)


@dataclass
class ToolStatus:
    spec: ToolSpec
    selection: Selection
    latest: Latest | None
    status: str
    detail: str = ""

    @property
    def installed(self) -> Version | None:
        return self.selection.chosen.version if self.selection.chosen else None

    @property
    def local(self) -> Candidate | None:
        return next((c for c in self.selection.candidates if c.source == "local" and c.usable), None)

    def to_dict(self) -> dict:
        ch = self.selection.chosen
        lt = self.latest
        return {
            "tool": self.spec.name, "required": self.spec.required, "status": self.status,
            "installed": str(self.installed) if self.installed else None,
            "latest_compatible": str(lt.version) if lt and lt.version else None,
            "newer_major_available": str(lt.newer_major) if lt and lt.newer_major else None,
            "tested_major": self.spec.tested_major, "min_version": str(self.spec.min_version),
            "source": ch.source if ch else None, "path": ch.path if ch else None,
            "selection_reason": self.selection.reason, "detail": self.detail,
            "candidates": [c.to_dict() for c in self.selection.candidates],
            "latest_source": lt.source if lt else None,
            "latest_error": lt.error if lt and lt.error else None,
        }


# ── gathering ─────────────────────────────────────────────────────────
def _select(ctx: Context, spec: ToolSpec, sel_state: dict) -> Selection:
    pref = sel_state["prefer"].get(spec.name)
    cands = detect.find_candidates(spec, ctx.layout, ctx.runner, ctx.path_env, ctx.in_docker,
                                   extra_path=pref if (pref and os.path.isabs(pref)) else None)
    return detect.select(spec, cands, pref, state.accepted_majors(sel_state, spec.name))


def _latest(ctx: Context, spec: ToolSpec) -> Latest:
    if ctx.offline:
        e = ctx.cache.get(f"latest:{spec.name}", allow_stale=True)  # type: ignore[union-attr]
        if e and not e.get("error"):
            lt = upstream._from_cache(e)
            lt.error = "offline — showing cached answer"
            return lt
        return Latest(None, None, None, "none", "offline")
    return upstream.latest_cached(spec, ctx.http, ctx.cache, ctx.refresh)  # type: ignore[arg-type]


def _status(spec: ToolSpec, sel: Selection, lt: Latest | None, accepted: frozenset[int]) -> tuple[str, str]:
    if sel.chosen is None:
        usable = [c for c in sel.candidates if c.usable]
        if not sel.candidates:
            return "MISSING", "not installed"
        if usable:
            old = [c for c in usable if c.version < spec.min_version]  # type: ignore[operator]
            if old and len(old) == len(usable):
                return "INCOMPATIBLE", f"older than the minimum supported {spec.min_version}"
            return "UNTESTED", "version is outside the range this project was tested with"
        bad = next((c for c in sel.candidates if not c.identity_ok), None)
        if bad:
            return "BROKEN", bad.error or "wrong program"
        return "BROKEN", next((c.error for c in sel.candidates if c.error), "does not run")
    v = sel.chosen.version
    if lt is None or lt.version is None:
        return "UNKNOWN", (lt.error if lt and lt.error else "latest version not checked")
    if v >= lt.version:  # type: ignore[operator]
        if lt.newer_major:
            return "MAJOR", f"v{lt.newer_major.major}.x exists; needs `hunt update --major`"
        return "OK", ""
    kind = versions.classify(v, lt.version)  # type: ignore[arg-type]
    if kind in ("patch", "minor"):
        return "UPDATE", f"{kind} update available"
    return "MANUAL", f"{kind}-level jump; needs `hunt update --major`"


def collect(ctx: Context, names: Iterable[str] | None = None, with_latest: bool = True) -> list[ToolStatus]:
    sel_state = state.load_selection(ctx.layout)
    specs = [s for n, s in ctx.manifest.tools.items() if names is None or n in set(names)]
    sels = {s.name: _select(ctx, s, sel_state) for s in specs}
    latest: dict[str, Latest | None] = {s.name: None for s in specs}
    if with_latest:
        with ThreadPoolExecutor(max_workers=6) as pool:
            for s, lt in zip(specs, pool.map(lambda sp: _latest(ctx, sp), specs), strict=True):
                latest[s.name] = lt
        ctx.cache.save()  # type: ignore[union-attr]
    out = []
    for s in specs:
        st, detail = _status(s, sels[s.name], latest[s.name], state.accepted_majors(sel_state, s.name))
        out.append(ToolStatus(s, sels[s.name], latest[s.name], st, detail))
    return out


# ── planning ──────────────────────────────────────────────────────────
@dataclass
class PlanItem:
    tool: str
    action: str                 # install | update | skip | blocked
    kind: str                   # install | patch | minor | major | none
    installed: str | None
    target: str | None
    reason: str = ""
    note: str = ""              # e.g. "system copy left untouched"
    major: int | None = None
    spec: ToolSpec | None = field(default=None, repr=False)

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in ("tool", "action", "kind", "installed", "target", "reason", "note")}


def make_plan(statuses: list[ToolStatus], *, major: bool = False, auto: bool = False,
              explicit: frozenset[str] = frozenset()) -> list[PlanItem]:
    """explicit = tools the user named with --tool (the only way `update` installs an optional tool)."""
    plan: list[PlanItem] = []
    for ts in statuses:
        spec, lt, best = ts.spec, ts.latest, ts.selection.chosen
        inst = str(best.version) if best else None
        item = PlanItem(spec.name, "skip", "none", inst, None, spec=spec)
        if auto and (not ts.local or spec.auto_update != "safe"):
            item.reason = ("auto-update only touches tools already installed by this project"
                           if not ts.local else "tool is set to manual updates")
            plan.append(item)
            continue
        if lt is None or lt.version is None:
            item.action = "blocked" if best is None else "skip"
            item.reason = f"upstream unavailable ({lt.error if lt else 'not checked'}); keeping current"
            plan.append(item)
            continue
        item.target = str(lt.version)
        if best is None and not spec.required and spec.name not in explicit and not ts.selection.candidates:
            item.reason = f"optional, not installed (add it with: hunt install --tool {spec.name})"
            plan.append(item)
            continue
        if best is None:
            item.action, item.kind = "install", "install"
            item.reason = ts.detail or "not installed"
        elif best.version >= lt.version:  # type: ignore[operator]
            item.reason = "up to date"
        else:
            kind = versions.classify(best.version, lt.version)  # type: ignore[arg-type]
            item.kind = kind
            if kind in ("patch", "minor") or major:
                item.action = "update"
                item.reason = f"{kind} update"
                if best.source != "local":
                    item.note = f"{best.source} copy at {best.path} is left untouched; a project-local copy is added"
            else:
                item.action, item.reason = "blocked", f"{kind}-level jump needs --major"
        if major and lt.newer_major and not auto:
            item.action, item.kind, item.target = "update", "major", str(lt.newer_major)
            item.major, item.reason = lt.newer_major.major, "major upgrade (untested — compatibility self-test decides)"
        elif lt.newer_major and item.action in ("skip", "update"):
            item.note = (item.note + "; " if item.note else "") + f"major v{lt.newer_major.major}.x available (not applied)"
        plan.append(item)
    return plan


def apply_plan(ctx: Context, plan: list[PlanItem], dry_run: bool = False) -> list[installer.Result]:
    results: list[installer.Result] = []
    go = ctx.go or installer.find_go()
    for it in plan:
        if it.action not in ("install", "update") or it.spec is None:
            continue
        target = versions.parse(it.target)
        if dry_run:
            results.append(installer.Result(it.tool, "planned", it.installed, it.target, it.reason))
            continue
        res = installer.install_tool(ctx.layout, it.spec, target, ctx.runner, go,  # type: ignore[arg-type]
                                     major=it.major, allow_untested=it.kind == "major")
        results.append(res)
        src = f"go-install:{it.spec.install_target(target, it.major)}"  # type: ignore[arg-type]
        state.log_history(ctx.layout, it.tool, res.old or it.installed, res.new or it.target,
                          "success" if res.ok else ("rolled-back" if res.status == "rolled-back" else "failure"),
                          src, None if res.ok else res.reason)
        if res.ok and it.kind == "major" and it.major is not None:
            sel = state.load_selection(ctx.layout)
            sel["accepted_majors"].setdefault(it.tool, [])
            if it.major not in sel["accepted_majors"][it.tool]:
                sel["accepted_majors"][it.tool].append(it.major)
            state.save_selection(ctx.layout, sel)
    return results


def refresh_selection(ctx: Context) -> dict[str, str | None]:
    """Re-run selection for every tool and rebuild bin/active."""
    chosen = {}
    for ts in collect(ctx, with_latest=False):
        chosen[ts.spec.name] = ts.selection.chosen.path if ts.selection.chosen else None
    if not ctx.in_docker:
        installer.refresh_active(ctx.layout, chosen)
    return chosen


# ── assets: data that versions independently of its tool (nuclei templates) ──
_TPL_RE = re.compile(r"templates?[^\n]*?version:?\s*v?(\d+\.\d+\.\d+)", re.I)


def _tool_path(ctx: Context, tool: str) -> str | None:
    for ts in collect(ctx, [tool], with_latest=False):
        return ts.selection.chosen.path if ts.selection.chosen else None
    return None


def asset_installed_version(ctx: Context, asset: AssetSpec) -> Version | None:
    exe = _tool_path(ctx, asset.requires_tool)
    if exe and asset.version_args:
        res = ctx.runner([exe, *asset.version_args], timeout=20, env=clean_env())
        m = (re.compile(asset.version_regex) if asset.version_regex else _TPL_RE).search(res.output or "")
        if m:
            return versions.parse(m.group(1))
    if asset.name == "nuclei-templates":          # nuclei keeps its own record too
        cfg = Path.home() / ".config" / "nuclei" / ".templates-config.json"
        data = state.read_json(cfg, {}) or {}
        if isinstance(data, dict):
            return versions.parse(str(data.get("nuclei-templates-version", "")))
    return None


def asset_status(ctx: Context, name: str = "nuclei-templates") -> dict:
    asset = ctx.manifest.assets.get(name)
    if not asset:
        return {}
    inst = asset_installed_version(ctx, asset)
    latest, err = None, None
    key = f"latest:{name}"
    e = ctx.cache.get(key, allow_stale=ctx.offline)  # type: ignore[union-attr]
    if e and not e.get("error") and not ctx.refresh:
        latest = versions.parse(e.get("version"))
    elif not ctx.offline:
        try:
            latest = upstream.latest_release_tag(ctx.http, asset.repo)
            ctx.cache.put(key, {"version": str(latest)} if latest else {"error": "no release found"})  # type: ignore[union-attr]
            ctx.cache.save()  # type: ignore[union-attr]
        except upstream.UpstreamError as exc:
            err = str(exc)
    else:
        err = "offline"
    if _tool_path(ctx, asset.requires_tool) is None:
        status = "MISSING"
    elif inst is None or latest is None:
        status = "UNKNOWN"
    else:
        status = "UPDATE" if inst < latest else "OK"
    return {"tool": name, "status": status, "installed": str(inst) if inst else None,
            "latest_compatible": str(latest) if latest else None, "detail": err or ""}


def update_asset(ctx: Context, name: str = "nuclei-templates", dry_run: bool = False) -> installer.Result:
    asset = ctx.manifest.assets[name]
    before = asset_installed_version(ctx, asset)
    res = installer.Result(name, "failed", str(before) if before else None)
    exe = _tool_path(ctx, asset.requires_tool)
    if exe is None:
        res.reason = f"{asset.requires_tool} is not installed"
        return res
    if dry_run:
        res.status, res.reason = "planned", f"would run: {asset.requires_tool} {' '.join(asset.update_args)}"
        return res
    run = ctx.runner([exe, *asset.update_args], timeout=900, env=clean_env())
    after = asset_installed_version(ctx, asset)
    if run.ok:
        res.status = "updated" if (after and after != before) else "unchanged"
        res.new = str(after) if after else None
        state.record_asset(ctx.layout, name, res.new)
    else:
        res.reason = redact((run.error or " ".join(run.output.strip().splitlines()[-2:]))[:300])
    state.log_history(ctx.layout, name, res.old, res.new, "success" if res.ok else "failure",
                      f"{asset.requires_tool} {' '.join(asset.update_args)}", res.reason, kind="asset")
    return res


templates_status = asset_status
update_templates = update_asset


# ── install (fresh) / lock / snapshot ─────────────────────────────────
def install_all(ctx: Context, names: Iterable[str] | None = None,
                lock: dict[str, Version] | None = None) -> list[installer.Result]:
    """Fresh install. Without a lock: newest compatible release, resolved NOW.
    With a lock: exactly those versions. An existing copy that already satisfies
    the target is used as-is (reported, never duplicated or overwritten)."""
    results: list[installer.Result] = []
    go = ctx.go or installer.find_go()
    wanted = [s for n, s in ctx.manifest.tools.items() if (names is None or n in set(names))
              and (lock is None or n in lock)]
    sel_state = state.load_selection(ctx.layout)
    ctx.refresh = ctx.refresh or lock is None
    for spec in wanted:
        sel = _select(ctx, spec, sel_state)
        if lock is not None:
            target = lock[spec.name]
            have = next((c for c in sel.candidates if c.source == "local" and c.usable), None)
            if have and have.version == target:
                results.append(installer.Result(spec.name, "unchanged", str(target), str(target), "matches lock", have.path))
                continue
            res = installer.install_tool(ctx.layout, spec, target, ctx.runner, go)
            results.append(res)
            if res.ok:
                sel_state["prefer"][spec.name] = "local"
        else:
            lt = _latest(ctx, spec)
            if lt.version is None:
                if sel.chosen:
                    results.append(installer.Result(spec.name, "unchanged", str(sel.chosen.version), None,
                                                    f"keeping existing {sel.chosen.source} copy ({lt.error})", sel.chosen.path))
                else:
                    results.append(installer.Result(spec.name, "failed", None, None, f"cannot resolve a release: {lt.error}"))
                continue
            if sel.chosen and sel.chosen.version >= lt.version:  # type: ignore[operator]
                results.append(installer.Result(spec.name, "unchanged", str(sel.chosen.version), str(lt.version),
                                                f"using existing {sel.chosen.source} copy", sel.chosen.path))
                continue
            res = installer.install_tool(ctx.layout, spec, lt.version, ctx.runner, go)
            results.append(res)
        r = results[-1]
        state.log_history(ctx.layout, spec.name, r.old, r.new, "success" if r.ok else "failure",
                          f"install:{'lock' if lock else 'latest-compatible'}", None if r.ok else r.reason)
    ctx.cache.save()  # type: ignore[union-attr]
    if lock is not None:
        state.save_selection(ctx.layout, sel_state)
    return results


def snapshot(ctx: Context) -> dict:
    installed = {}
    for ts in collect(ctx, with_latest=False):
        if ts.installed:
            installed[ts.spec.name] = str(ts.installed)
    go = installer.find_go()
    gv = installer.go_version(go, ctx.runner) if go else None
    return state.build_lock(ctx.manifest, installed, f"go{gv}" if gv else None)
