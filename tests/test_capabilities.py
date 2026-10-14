"""
Tests for mcp_server.capabilities — the shared environment/diagnostics
module used by the get_capabilities MCP tool, the /health and
/capabilities HTTP endpoints, and hunt.py's doctor command.

check_go_tools() calls the real shutil.which() against whatever's
actually on PATH in the test environment — deliberately not mocked,
since the whole point of this module is reporting PATH reality
accurately. Assertions are about shape/logic, not about which specific
tools happen to be installed in CI.
"""
from __future__ import annotations

import sys

from mcp_server.capabilities import (
    OPTIONAL_TOOLS,
    REQUIRED_TOOLS,
    check_go_tools,
    check_python,
    check_wordlists,
    get_capabilities,
    is_running_in_docker,
)


class TestCheckGoTools:
    def test_returns_every_required_and_optional_tool(self):
        result = check_go_tools()
        assert set(result["required"].keys()) == set(REQUIRED_TOOLS.keys())
        assert set(result["optional"].keys()) == set(OPTIONAL_TOOLS.keys())

    def test_each_entry_has_availability_and_purpose(self):
        result = check_go_tools()
        for _tool, info in {**result["required"], **result["optional"]}.items():
            assert isinstance(info["available"], bool)
            assert isinstance(info["purpose"], str) and info["purpose"]

    def test_missing_lists_match_availability_flags(self):
        result = check_go_tools()
        for tool in result["missing_required"]:
            assert result["required"][tool]["available"] is False
        for tool in result["missing_optional"]:
            assert result["optional"][tool]["available"] is False

    def test_gobuster_is_required_not_optional(self):
        # gobuster dns is actually invoked by subdomain_brute with no
        # fallback - regression check against it being miscategorized.
        assert "gobuster" in REQUIRED_TOOLS
        assert "gobuster" not in OPTIONAL_TOOLS

    def test_anew_documented_as_unused_not_silently_required(self):
        # anew is checked for but not invoked by any current handler -
        # this is a documentation/classification check, not a tools check.
        assert "anew" in OPTIONAL_TOOLS
        assert "not currently invoked" in OPTIONAL_TOOLS["anew"]


class TestCheckPython:
    def test_reports_actual_running_version(self):
        result = check_python()
        assert result["version"] == f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    def test_ok_true_on_this_test_runner(self):
        # The project requires >=3.11; if this test is running at all,
        # the interpreter running it must already satisfy that.
        result = check_python()
        assert result["ok"] is True


class TestCheckWordlists:
    def test_reports_missing_files_correctly(self, tmp_path):
        result = check_wordlists(tmp_path)
        assert result["dir"] == str(tmp_path)
        assert result["subdomains_txt"] is False
        assert result["directories_txt"] is False

    def test_reports_present_files_correctly(self, tmp_path):
        (tmp_path / "subdomains.txt").write_text("admin\n")
        (tmp_path / "directories.txt").write_text("admin\n")
        result = check_wordlists(tmp_path)
        assert result["subdomains_txt"] is True
        assert result["directories_txt"] is True

    def test_partial_presence_reported_independently(self, tmp_path):
        (tmp_path / "subdomains.txt").write_text("admin\n")
        result = check_wordlists(tmp_path)
        assert result["subdomains_txt"] is True
        assert result["directories_txt"] is False


class TestIsRunningInDocker:
    def test_returns_bool(self):
        # Can't assert a specific value - depends on the environment this
        # test happens to run in - just that it doesn't crash and returns
        # a real bool either way.
        assert isinstance(is_running_in_docker(), bool)


class TestGetCapabilities:
    def test_status_degraded_when_required_tool_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "mcp_server.capabilities.check_go_tools",
            lambda: {
                "required": {"nuclei": {"available": False, "purpose": "x"}},
                "optional": {},
                "missing_required": ["nuclei"],
                "missing_optional": [],
            },
        )
        result = get_capabilities(tmp_path)
        assert result["status"] == "degraded"
        assert any("nuclei" in issue for issue in result["issues"])

    def test_status_ready_when_nothing_missing(self, tmp_path, monkeypatch):
        (tmp_path / "subdomains.txt").write_text("x\n")
        (tmp_path / "directories.txt").write_text("x\n")
        monkeypatch.setattr(
            "mcp_server.capabilities.check_go_tools",
            lambda: {"required": {}, "optional": {}, "missing_required": [], "missing_optional": []},
        )
        result = get_capabilities(tmp_path)
        assert result["status"] == "ready"
        assert result["issues"] == []

    def test_missing_optional_tools_do_not_cause_degraded_status(self, tmp_path, monkeypatch):
        (tmp_path / "subdomains.txt").write_text("x\n")
        (tmp_path / "directories.txt").write_text("x\n")
        monkeypatch.setattr(
            "mcp_server.capabilities.check_go_tools",
            lambda: {
                "required": {},
                "optional": {"gowitness": {"available": False, "purpose": "x"}},
                "missing_required": [],
                "missing_optional": ["gowitness"],
            },
        )
        result = get_capabilities(tmp_path)
        assert result["status"] == "ready"

    def test_missing_wordlists_produce_issues(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "mcp_server.capabilities.check_go_tools",
            lambda: {"required": {}, "optional": {}, "missing_required": [], "missing_optional": []},
        )
        result = get_capabilities(tmp_path)
        assert result["status"] == "degraded"
        assert len(result["issues"]) == 2  # subdomains.txt AND directories.txt missing

    def test_mcp_tool_count_included_when_provided(self, tmp_path):
        result = get_capabilities(tmp_path, mcp_tool_count=27)
        assert result["mcp_tools"] == {"count": 27}

    def test_mcp_tool_count_omitted_when_not_provided(self, tmp_path):
        result = get_capabilities(tmp_path)
        assert "mcp_tools" not in result

    def test_environment_field_is_docker_or_native(self, tmp_path):
        result = get_capabilities(tmp_path)
        assert result["environment"] in ("docker", "native")


class TestHttpxIdentityCheck:
    """shutil.which('httpx') alone can't distinguish ProjectDiscovery's httpx
    from the CLI script the Python httpx *library* installs under the same
    name. These put a fake `httpx` on a private PATH and check the verdict."""

    def _fake_httpx(self, tmp_path, monkeypatch, stderr: str, exit_code: int):
        script = tmp_path / "httpx"
        script.write_text(f"#!/bin/sh\necho '{stderr}' >&2\nexit {exit_code}\n")
        script.chmod(0o755)
        monkeypatch.setenv("PATH", str(tmp_path))
        return str(script)

    def test_projectdiscovery_httpx_is_accepted(self, tmp_path, monkeypatch):
        self._fake_httpx(tmp_path, monkeypatch, "[INF] Current Version: v1.6.10", 0)
        from mcp_server import capabilities
        assert capabilities._probe("httpx") == (True, None)

    def test_python_library_cli_is_rejected_with_explanation(self, tmp_path, monkeypatch):
        path = self._fake_httpx(tmp_path, monkeypatch, "Error: No such option: -version", 2)
        from mcp_server import capabilities
        available, note = capabilities._probe("httpx")
        assert available is False
        assert path in note and "Python" in note

    def test_check_go_tools_reports_the_wrong_httpx_as_missing_with_a_note(self, tmp_path, monkeypatch):
        self._fake_httpx(tmp_path, monkeypatch, "Error: No such option: -version", 2)
        from mcp_server import capabilities
        report = capabilities.check_go_tools()
        assert "httpx" in report["missing_required"]
        assert "note" in report["required"]["httpx"]

    def test_get_capabilities_surfaces_the_note_as_an_issue(self, tmp_path, monkeypatch):
        self._fake_httpx(tmp_path, monkeypatch, "Error: No such option: -version", 2)
        from mcp_server import capabilities
        report = capabilities.get_capabilities(tmp_path)
        assert any("different 'httpx'" in i for i in report["issues"])

    def test_other_tools_are_not_identity_checked(self, tmp_path, monkeypatch):
        script = tmp_path / "ffuf"
        script.write_text("#!/bin/sh\nexit 1\n")
        script.chmod(0o755)
        monkeypatch.setenv("PATH", str(tmp_path))
        from mcp_server import capabilities
        assert capabilities._probe("ffuf") == (True, None)

    def test_missing_binary_has_no_note(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PATH", str(tmp_path))
        from mcp_server import capabilities
        assert capabilities._probe("httpx") == (False, None)
