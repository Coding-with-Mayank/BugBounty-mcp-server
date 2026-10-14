"""
smart_hunt.py — the decision-support layer, tested as a (fake) AI client
would actually drive it: start a session, hand back a tool's result,
get the next recommendation, repeat.

Scope checks use the real scope.evaluate() against an in-memory list —
no DNS involved — so these stay fast while still exercising the real
matching rules (bare domain vs *.wildcard) that the engine depends on.
"""
from __future__ import annotations

import pytest

from mcp_server.persistence import JsonStore
from mcp_server.scope import ScopeDecision, evaluate
from mcp_server.smart_hunt import SmartHuntEngine, clean, in_target


def _scope_check_for(scope_list, blocked_list=()):
    async def check(target: str) -> ScopeDecision:
        return evaluate(target, scope_list=list(scope_list), blocked_list=list(blocked_list))
    return check


def _engine(tmp_path=None, *, scope=("*.example.com",), blocked=(), require_scope=True, store=True):
    async def scope_check(target: str) -> ScopeDecision:
        return evaluate(target, scope_list=list(scope), blocked_list=list(blocked))

    return SmartHuntEngine(
        store=JsonStore(tmp_path / "hunts") if (store and tmp_path) else None,
        scope_lists=lambda: (list(scope), list(blocked)),
        scope_check=scope_check,
        task_lookup=lambda task_id: None,
        require_explicit_scope=require_scope,
    )


def ok(tool: str, data: dict, **extra) -> dict:
    """A well-formed tool result envelope, as server.result() produces."""
    return {"tool": tool, "target": "x", "timestamp": "t", "data": data, "guidance": {}, **extra}


# ── helpers ──────────────────────────────────────────────────────────────────

class TestHelpers:
    def test_in_target_matches_apex_and_subdomains_only(self):
        assert in_target("example.com", "example.com")
        assert in_target("https://a.example.com/x", "example.com")
        assert not in_target("evilexample.com", "example.com")
        assert not in_target("example.com.evil.com", "example.com")

    def test_clean_strips_control_chars_and_caps_length(self):
        # Control characters are replaced with a space (not deleted) and then
        # whitespace is collapsed — so "ESC[31m" (an ANSI color code some
        # recon tool might emit) becomes harmless literal text, not erased.
        assert clean("a\x1b[31mb\x00c", limit=20) == "a [31mb c"
        assert clean("x" * 500, limit=20) == "x" * 20
        assert clean(None) == ""

    def test_clean_collapses_whitespace_to_one_line(self):
        assert clean("line1\nline2\tline3") == "line1 line2 line3"


# ── start() ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestStart:
    async def test_rejects_empty_or_malformed_target(self):
        eng = _engine()
        assert "error" in await eng.start("")
        assert "error" in await eng.start("not a domain!!")
        assert "error" in await eng.start("localhost")

    async def test_rejects_unknown_depth(self):
        eng = _engine()
        res = await eng.start("example.com", depth="extreme")
        assert "error" in res and "depth" in res["error"]

    async def test_refuses_to_start_in_open_mode_by_default(self):
        eng = _engine(scope=())
        res = await eng.start("example.com")
        assert "error" in res and "open mode" in res["error"]

    async def test_open_mode_allowed_when_explicitly_overridden(self):
        eng = _engine(scope=(), require_scope=False)
        res = await eng.start("example.com")
        assert "error" not in res
        assert res["warning"].startswith("ALLOWED_SCOPE is empty")

    async def test_refuses_an_out_of_scope_target(self):
        eng = _engine(scope=("*.other.com",))
        res = await eng.start("example.com")
        assert res.get("allowed") is False and "error" in res

    async def test_successful_start_recommends_subdomain_enum_first(self):
        eng = _engine()
        res = await eng.start("example.com")
        assert res["recommendation"]["tool"] == "subdomain_enum"
        assert res["recommendation"]["args"] == {"domain": "example.com"}
        assert res["session_id"].startswith("hunt_")
        assert res["done"] is False

    async def test_target_is_normalised_from_a_url(self):
        eng = _engine()
        res = await eng.start("https://Example.COM/some/path")
        assert res["target"] == "example.com"

    async def test_max_steps_is_clamped(self):
        eng = _engine()
        assert (await eng.start("example.com", max_steps=1))["session_id"]
        s = eng._sessions[list(eng._sessions)[0]]
        assert s.max_steps == 5  # clamped up from 1
        eng2 = _engine()
        await eng2.start("example.com", max_steps=9999)
        s2 = next(iter(eng2._sessions.values()))
        assert s2.max_steps == 200  # clamped down


# ── next(): plumbing ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestNextPlumbing:
    async def test_unknown_session_errors(self):
        eng = _engine()
        assert "error" in await eng.next("hunt_nope")

    async def test_closed_session_errors(self):
        eng = _engine()
        sid = (await eng.start("example.com"))["session_id"]
        eng.close(sid)
        assert "error" in await eng.next(sid)

    async def test_unknown_tool_name_is_rejected(self):
        eng = _engine()
        sid = (await eng.start("example.com"))["session_id"]
        res = await eng.next(sid, tool="rm_rf_slash", result={})
        assert "error" in res

    async def test_non_dict_result_is_rejected(self):
        eng = _engine()
        sid = (await eng.start("example.com"))["session_id"]
        res = await eng.next(sid, tool="subdomain_enum", result="not a dict")
        assert "error" in res

    async def test_calling_next_with_nothing_just_repeats_the_recommendation(self):
        eng = _engine()
        start = await eng.start("example.com")
        again = await eng.next(start["session_id"])
        assert again["recommendation"]["tool"] == start["recommendation"]["tool"]

    async def test_args_default_to_the_pending_recommendations_args(self):
        eng = _engine()
        sid = (await eng.start("example.com"))["session_id"]  # pending: subdomain_enum {domain: example.com}
        out = await eng.next(sid, tool="subdomain_enum", result=ok("subdomain_enum", {"subdomains": []}))
        assert out["recorded"]["outcome"] == "ok"

    async def test_unknown_task_id_errors(self):
        eng = _engine()
        sid = (await eng.start("example.com"))["session_id"]
        assert "error" in await eng.next(sid, task_id="task_nope")

    async def test_queued_or_running_task_asks_to_wait(self):
        eng = SmartHuntEngine(
            store=None, scope_lists=lambda: (["*.example.com"], []),
            scope_check=_scope_check_for(["*.example.com"]),
            task_lookup=lambda tid: {"task_id": tid, "status": "running", "tool": "nuclei_scan", "args": {}, "result": None, "error": None},
        )
        sid = (await eng.start("example.com"))["session_id"]
        res = await eng.next(sid, task_id="task_abc")
        assert res["waiting"] is True and res["task_status"] == "running"

    async def test_completed_task_is_consumed_and_not_double_counted(self):
        calls = {"n": 0}

        def lookup(tid):
            calls["n"] += 1
            return {"task_id": tid, "status": "completed", "tool": "subdomain_enum",
                    "args": {"domain": "example.com"}, "result": ok("subdomain_enum", {"subdomains": ["a.example.com"]}),
                    "error": None}

        eng = SmartHuntEngine(
            store=None, scope_lists=lambda: (["*.example.com"], []),
            scope_check=_scope_check_for(["*.example.com"]),
            task_lookup=lookup,
        )
        sid = (await eng.start("example.com"))["session_id"]
        first = await eng.next(sid, task_id="task_abc")
        assert first["recorded"]["learned"] == 1
        again = await eng.next(sid, task_id="task_abc")
        assert "recorded" not in again and "already recorded" in again["note"]

    async def test_failed_task_is_recorded_as_an_error_step(self):
        def lookup(tid):
            return {"task_id": tid, "status": "failed", "tool": "port_scan", "args": {"target": "example.com"},
                    "result": None, "error": "naabu: permission denied"}

        eng = SmartHuntEngine(
            store=None, scope_lists=lambda: (["*.example.com"], []),
            scope_check=_scope_check_for(["*.example.com"]),
            task_lookup=lookup,
        )
        sid = (await eng.start("example.com"))["session_id"]
        res = await eng.next(sid, task_id="task_x")
        assert res["recorded"]["outcome"] == "error"

    async def test_partial_task_result_is_ingested_and_backs_off(self):
        partial = {
            "partial": True, "note": "...", "commands_captured": 1,
            "captured": [{"cmd": ["subfinder", "-d", "example.com"], "stdout": "a.example.com\nb.example.com\n",
                         "stderr": "", "returncode": -1, "truncated": False}],
        }

        def lookup(tid):
            return {"task_id": tid, "status": "cancelled", "tool": "subdomain_enum",
                    "args": {"domain": "example.com"}, "result": partial, "error": "Cancelled."}

        eng = SmartHuntEngine(
            store=None, scope_lists=lambda: (["*.example.com"], []),
            scope_check=_scope_check_for(["*.example.com"]),
            task_lookup=lookup,
        )
        sid = (await eng.start("example.com"))["session_id"]
        res = await eng.next(sid, task_id="task_x")
        assert res["recorded"]["outcome"] == "partial"
        assert res["recorded"]["learned"] == 2
        assert sorted(eng._sessions[sid].facts["subdomains"]) == ["a.example.com", "b.example.com"]
        # A cancelled/interrupted run can't be trusted as "fully covered" —
        # it should still be eligible to be retried, not backed off forever.
        assert eng._sessions[sid].facts["failed"]["subdomain_enum"] == 1


# ── ingestion correctness, per tool ─────────────────────────────────────────

@pytest.mark.asyncio
class TestIngestion:
    async def test_subdomain_enum_flags_suspicious_and_filters_out_of_target_hosts(self):
        eng = _engine()
        sid = (await eng.start("example.com"))["session_id"]
        result = ok("subdomain_enum", {"subdomains": ["admin.example.com", "www.example.com", "evil.com"]})
        out = await eng.next(sid, tool="subdomain_enum", result=result)
        f = eng._sessions[sid].facts
        assert sorted(f["subdomains"]) == ["admin.example.com", "www.example.com"]  # evil.com dropped
        assert out["recorded"]["learned"] == 2
        assert any(x["subdomain"] == "admin.example.com" for x in f["suspicious"])

    async def test_alive_check_tracks_interesting_hosts_from_titles(self):
        eng = _engine()
        sid = (await eng.start("example.com"))["session_id"]
        result = ok("alive_check", {
            "hosts": [
                {"url": "https://admin.example.com", "status_code": 200, "title": "Admin Login", "tech": ["nginx"]},
                {"url": "https://www.example.com", "status_code": 200, "title": "Welcome", "tech": []},
            ],
            "interesting": [{"url": "https://admin.example.com", "title": "Admin Login"}],
        })
        await eng.next(sid, tool="alive_check", result=result)
        f = eng._sessions[sid].facts
        assert set(f["alive"]) == {"https://admin.example.com", "https://www.example.com"}
        assert f["interesting_hosts"] == ["https://admin.example.com"]

    async def test_crawl_buckets_urls_js_files_api_paths_and_params(self):
        eng = _engine()
        sid = (await eng.start("example.com"))["session_id"]
        result = ok("crawl", {
            "all_urls": ["https://example.com/app.js", "https://example.com/api/v1/users?id=5",
                        "https://example.com/admin/config"],
            "js_files": ["https://example.com/app.js"],
            "api_paths": ["https://example.com/api/v1/users?id=5"],
            "interesting": ["https://example.com/admin/config"],
        })
        await eng.next(sid, tool="crawl", result=result)
        f = eng._sessions[sid].facts
        assert f["js_files"] == ["https://example.com/app.js"]
        assert f["api_paths"] == ["https://example.com/api/v1/users?id=5"]
        assert f["param_urls"] == ["https://example.com/api/v1/users?id=5"]
        assert f["interesting_urls"] == ["https://example.com/admin/config"]

    async def test_port_scan_records_ports_per_host(self):
        eng = _engine()
        sid = (await eng.start("example.com"))["session_id"]
        result = ok("port_scan", {"ports": [{"port": 443, "protocol": "tcp"}, {"port": 22, "protocol": "tcp"}]})
        await eng.next(sid, tool="port_scan", result=result, args={"target": "example.com"})
        assert eng._sessions[sid].facts["ports"]["example.com"] == [22, 443]

    async def test_nuclei_findings_are_deduped_and_out_of_target_urls_dropped(self):
        eng = _engine()
        sid = (await eng.start("example.com"))["session_id"]
        result = ok("nuclei_scan", {"findings": [
            {"template_id": "exposed-panel", "name": "Admin Panel", "severity": "high", "url": "https://example.com/admin"},
            {"template_id": "exposed-panel", "name": "Admin Panel", "severity": "high", "url": "https://example.com/admin"},
            {"template_id": "tls-version", "name": "Weak TLS", "severity": "low", "url": "https://evil.com"},
        ]})
        out = await eng.next(sid, tool="nuclei_scan", result=result, args={"targets": ["https://example.com"]})
        f = eng._sessions[sid].facts
        assert len(f["findings"]) == 1
        assert f["findings"][0]["severity"] == "high"
        assert out["recorded"]["learned"] == 1

    async def test_full_recon_pipeline_is_unpacked_into_the_same_facts(self):
        eng = _engine()
        sid = (await eng.start("example.com"))["session_id"]
        result = {
            "tool": "full_recon", "target": "example.com", "pipeline": {
                "subdomains": ok("subdomain_enum", {"subdomains": ["a.example.com"]}),
                "alive": ok("alive_check", {"hosts": [{"url": "https://a.example.com", "status_code": 200}], "interesting": []}),
            },
        }
        await eng.next(sid, tool="full_recon", result=result, args={"domain": "example.com"})
        f = eng._sessions[sid].facts
        assert f["subdomains"] == ["a.example.com"]
        assert "https://a.example.com" in f["alive"]
        assert f["ran"]["subdomain_enum"] == 1 and f["ran"]["alive_check"] == 1

    async def test_tool_level_error_is_recorded_and_backs_off_after_two(self):
        eng = _engine()
        sid = (await eng.start("example.com"))["session_id"]
        for _ in range(2):
            out = await eng.next(sid, tool="subdomain_enum", result={"error": "subfinder: rate limited"})
        assert out["recorded"]["outcome"] == "error"
        # a 3rd failure can't even be ranked anymore once backed off — recommendation moved on
        assert eng._sessions[sid].facts["failed"]["subdomain_enum"] == 2

    async def test_missing_binary_error_marks_tool_unavailable_and_stops_recommending_it(self):
        eng = _engine()
        sid = (await eng.start("example.com"))["session_id"]
        await eng.next(sid, tool="subdomain_enum", result={"error": "'subfinder' not found in PATH."})
        f = eng._sessions[sid].facts
        assert "subdomain_enum" in f["unavailable"]


# ── analysis / wrap-up priority ──────────────────────────────────────────────

@pytest.mark.asyncio
class TestWrapUp:
    async def test_high_severity_finding_jumps_ahead_of_further_recon(self):
        eng = _engine()
        sid = (await eng.start("example.com"))["session_id"]
        await eng.next(sid, tool="nuclei_scan",
                       result=ok("nuclei_scan", {"findings": [
                           {"template_id": "cve-x", "name": "RCE", "severity": "critical", "url": "https://example.com"},
                       ]}),
                       args={"targets": ["https://example.com"]})
        out = await eng.next(sid)
        assert out["recommendation"]["tool"] == "analyze_findings"

    async def test_explain_finding_recommended_for_severe_findings_before_report(self):
        eng = _engine()
        sid = (await eng.start("example.com"))["session_id"]
        await eng.next(sid, tool="nuclei_scan",
                       result=ok("nuclei_scan", {"findings": [
                           {"template_id": "cve-x", "name": "RCE", "severity": "critical", "url": "https://example.com"},
                       ]}), args={"targets": ["https://example.com"]})
        await eng.next(sid, tool="analyze_findings", result={"analysis": {}}, args={"findings": [], "target": "example.com"})
        out = await eng.next(sid)
        assert out["recommendation"]["tool"] == "explain_finding"

    async def test_report_recommended_once_analysis_and_explanation_are_done(self):
        eng = _engine()
        sid = (await eng.start("example.com"))["session_id"]
        finding = {"template_id": "cve-x", "name": "RCE", "severity": "critical", "url": "https://example.com"}
        await eng.next(sid, tool="nuclei_scan", result=ok("nuclei_scan", {"findings": [finding]}),
                       args={"targets": ["https://example.com"]})
        await eng.next(sid, tool="analyze_findings", result={"analysis": {}}, args={})
        await eng.next(sid, tool="explain_finding", result={"explanation": {}}, args={"finding": finding})
        out = await eng.next(sid)
        assert out["recommendation"]["tool"] == "generate_report"


# ── depth gating & step budget ────────────────────────────────────────────────

@pytest.mark.asyncio
class TestDepthAndBudget:
    async def test_light_depth_never_recommends_a_standard_or_deep_tool(self):
        eng = _engine()
        sid = (await eng.start("example.com", depth="light"))["session_id"]
        out = await eng.next(sid, tool="subdomain_enum", result=ok("subdomain_enum", {"subdomains": ["a.example.com"]}))
        seen_tools = {out["recommendation"]["tool"], *[r["tool"] for r in out["alternatives"]]}
        assert not seen_tools & {"port_scan", "dir_fuzz", "xss_scan", "sqli_scan", "subdomain_brute", "nuclei_scan"}

    async def test_step_budget_forces_a_wrap_up(self):
        eng = _engine()
        sid = (await eng.start("example.com", max_steps=5))["session_id"]
        tool, args = "subdomain_enum", {"domain": "example.com"}
        out = {}
        for _ in range(10):
            out = await eng.next(sid, tool=tool, result={"error": "simulated no-op"}, args=args)
            if out.get("done"):
                break
            tool, args = out["recommendation"]["tool"], out["recommendation"]["args"]
        assert out["done"] is True
        assert len(eng._sessions[sid].steps) <= 5
        assert eng._sessions[sid].status == "completed"

    async def test_done_response_includes_manual_review_candidates_and_summary(self):
        # max_steps is clamped to a minimum of 5 (see test_max_steps_is_clamped),
        # so reaching "done" here means every candidate backed off (2 failures
        # each), not that the tiny budget alone forced it.
        eng = _engine(require_scope=False, scope=())
        sid = (await eng.start("evil-corp-does-not-exist-xyz.test", max_steps=1))["session_id"]
        tool, args = "subdomain_enum", {"domain": "evil-corp-does-not-exist-xyz.test"}
        out = {}
        for _ in range(12):
            out = await eng.next(sid, tool=tool, result={"error": "no results"}, args=args)
            if out.get("done"):
                break
            tool, args = out["recommendation"]["tool"], out["recommendation"]["args"]
        assert out["done"] is True
        assert "manual_review_candidates" in out
        assert out["summary"]["session_id"] == sid


# ── scope enforcement (defense in depth) ──────────────────────────────────────

@pytest.mark.asyncio
class TestScopeEnforcement:
    async def test_recommended_targets_never_include_blocked_hosts(self):
        eng = _engine(scope=("*.example.com",), blocked=("internal.example.com",))
        sid = (await eng.start("example.com"))["session_id"]
        out = await eng.next(sid, tool="subdomain_enum",
                             result=ok("subdomain_enum", {"subdomains": ["internal.example.com", "www.example.com"]}))
        probe = out["recommendation"]
        if probe["tool"] == "alive_check":
            assert "https://internal.example.com" not in probe["args"]["targets"]

    async def test_narrowing_scope_mid_session_stops_new_recommendations_for_dropped_hosts(self):
        # Narrowing TO an empty list means open mode (allowed=True for
        # everything) per scope.evaluate()'s own semantics — so to actually
        # narrow what's allowed, point the scope at a different host.
        scope_box = {"list": ["*.example.com"]}

        async def scope_check(t):
            return evaluate(t, scope_list=scope_box["list"], blocked_list=[])

        eng = SmartHuntEngine(store=None, scope_lists=lambda: (scope_box["list"], []),
                              scope_check=scope_check, task_lookup=lambda t: None)
        sid = (await eng.start("example.com"))["session_id"]
        await eng.next(sid, tool="subdomain_enum", result=ok("subdomain_enum", {"subdomains": ["a.example.com"]}))
        scope_box["list"] = ["*.other.com"]  # scope redirected elsewhere mid-session
        out = await eng.next(sid)
        rec = out.get("recommendation")
        assert rec is None or "a.example.com" not in str(rec.get("args"))


# ── status / close / listing ───────────────────────────────────────────────────

@pytest.mark.asyncio
class TestStatusAndClose:
    async def test_status_without_session_id_lists_all_sessions(self):
        eng = _engine()
        await eng.start("example.com")
        await eng.start("example.com", depth="light")
        listing = eng.status()
        assert listing["count"] == 2

    async def test_status_unknown_session_errors(self):
        eng = _engine()
        assert "error" in eng.status("hunt_nope")

    async def test_summary_carries_an_untrusted_data_notice(self):
        eng = _engine()
        sid = (await eng.start("example.com"))["session_id"]
        summary = eng.status(sid)
        assert "untrusted" in summary["notice"].lower()

    async def test_close_stops_further_recommendations(self):
        eng = _engine()
        sid = (await eng.start("example.com"))["session_id"]
        closed = eng.close(sid)
        assert closed["status"] == "closed"
        assert "error" in await eng.next(sid)

    async def test_close_unknown_session_errors(self):
        eng = _engine()
        assert "error" in eng.close("hunt_nope")


# ── persistence ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestPersistence:
    async def test_session_survives_a_restart(self, tmp_path):
        eng1 = _engine(tmp_path)
        start = await eng1.start("example.com")
        sid = start["session_id"]
        await eng1.next(sid, tool="subdomain_enum", result=ok("subdomain_enum", {"subdomains": ["a.example.com"]}))

        eng2 = _engine(tmp_path)
        n = eng2.load_persisted()
        assert n == 1
        status = eng2.status(sid)
        assert status["progress"]["subdomains"] == 1

    async def test_no_store_means_purely_in_memory(self):
        eng = _engine(store=False)
        await eng.start("example.com")
        assert eng.load_persisted() == 0

    async def test_pending_recommendation_survives_a_restart(self, tmp_path):
        eng1 = _engine(tmp_path)
        start = await eng1.start("example.com")
        sid = start["session_id"]

        eng2 = _engine(tmp_path)
        eng2.load_persisted()
        again = await eng2.next(sid)
        assert again["recommendation"]["tool"] == start["recommendation"]["tool"]

    async def test_malformed_record_does_not_crash_restore(self, tmp_path):
        store = JsonStore(tmp_path / "hunts")
        store.save("hunt_broken01", {"id": "hunt_broken01"})  # missing required fields
        eng = _engine(tmp_path)
        assert eng.load_persisted() == 0


# ── dict-keyed facts stay bounded on a very long-running hunt ────────────────

@pytest.mark.asyncio
class TestFactsSizeCaps:
    """tech/ports/paths are dicts keyed by host — one entry per distinct
    host touched, not per finding — so the list-oriented _add() cap doesn't
    bound them. A client that calls tech_detect/port_scan/dir_fuzz directly
    with a huge target list (bypassing Smart Hunt's own small batches)
    must not be able to grow a session's facts without limit."""

    async def test_tech_detect_dict_evicts_oldest_host_beyond_cap(self, monkeypatch):
        import mcp_server.smart_hunt as sh
        monkeypatch.setitem(sh.CAPS, "tech_hosts", 5)

        eng = _engine()
        sid = (await eng.start("example.com", max_steps=10))["session_id"]
        f = eng._sessions[sid].facts
        targets = [f"https://h{i}.example.com" for i in range(8)]
        result = ok("tech_detect", {"technology_map": {u: ["nginx"] for u in targets}})
        await eng.next(sid, tool="tech_detect", result=result, args={"targets": targets})
        assert len(f["tech"]) == 5
        assert "https://h0.example.com" not in f["tech"]  # oldest evicted
        assert "https://h7.example.com" in f["tech"]  # newest kept

    async def test_port_scan_dict_evicts_oldest_host_beyond_cap(self, monkeypatch):
        import mcp_server.smart_hunt as sh
        monkeypatch.setitem(sh.CAPS, "port_hosts", 5)

        eng = _engine()
        sid = (await eng.start("example.com", max_steps=10))["session_id"]
        f = eng._sessions[sid].facts
        for i in range(8):
            await eng.next(sid, tool="port_scan", result=ok("port_scan", {"ports": [{"port": 80}]}),
                           args={"target": f"h{i}.example.com"})
        assert len(f["ports"]) == 5
        assert "h0.example.com" not in f["ports"]
        assert "h7.example.com" in f["ports"]

    async def test_dir_fuzz_dict_evicts_oldest_base_beyond_cap(self, monkeypatch):
        import mcp_server.smart_hunt as sh
        monkeypatch.setitem(sh.CAPS, "fuzz_hosts", 5)

        eng = _engine()
        sid = (await eng.start("example.com", max_steps=10))["session_id"]
        f = eng._sessions[sid].facts
        for i in range(8):
            base = f"https://h{i}.example.com"
            await eng.next(sid, tool="dir_fuzz",
                           result=ok("dir_fuzz", {"paths": [{"url": base + "/admin", "status": 200}]}),
                           args={"url": base + "/FUZZ"})
        assert len(f["paths"]) == 5
        assert "https://h0.example.com" not in f["paths"]

    async def test_re_scanning_an_already_present_host_does_not_evict_anything(self, monkeypatch):
        """Updating an existing key must not count as a new insertion — a
        host that gets re-scanned shouldn't push an unrelated host out."""
        import mcp_server.smart_hunt as sh
        monkeypatch.setitem(sh.CAPS, "port_hosts", 5)

        eng = _engine()
        sid = (await eng.start("example.com", max_steps=10))["session_id"]
        f = eng._sessions[sid].facts
        for i in range(5):
            await eng.next(sid, tool="port_scan", result=ok("port_scan", {"ports": [{"port": 80}]}),
                           args={"target": f"h{i}.example.com"})
        assert len(f["ports"]) == 5
        # Re-scan the very first host (bypassing coverage so _ingest runs again).
        f["covered"]["ports"].clear()
        await eng.next(sid, tool="port_scan", result=ok("port_scan", {"ports": [{"port": 443}]}),
                       args={"target": "h0.example.com"})
        assert len(f["ports"]) == 5  # no growth
        assert f["ports"]["h0.example.com"] == [443]  # value updated in place
        assert "h1.example.com" in f["ports"]  # nothing else got evicted
