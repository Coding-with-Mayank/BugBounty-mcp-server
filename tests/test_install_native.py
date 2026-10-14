"""
Guards for install-native.sh.

Like test_dockerfile.py these are static checks on the script's source plus
a `bash -n` syntax pass and a real --dry-run — they can't prove a full
install works on every machine (that needs Go + network), but they pin the
properties that were deliberately designed in and are easy to regress.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "install-native.sh"
DOCKERFILE = ROOT / "Dockerfile"


class TestInstallerBasics:
    def test_script_exists_and_is_executable(self):
        assert SCRIPT.exists()
        assert SCRIPT.stat().st_mode & 0o111, "install-native.sh must be chmod +x"

    def test_bash_syntax_is_valid(self):
        res = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
        assert res.returncode == 0, res.stderr

    def test_uses_strict_mode(self):
        assert "set -euo pipefail" in SCRIPT.read_text()

    def test_help_works(self):
        res = subprocess.run([str(SCRIPT), "--help"], capture_output=True, text=True, timeout=10)
        assert res.returncode == 0 and "--dry-run" in res.stdout

    def test_unknown_option_is_rejected(self):
        res = subprocess.run([str(SCRIPT), "--nope"], capture_output=True, text=True, timeout=10)
        assert res.returncode == 2

    def test_dry_run_changes_nothing(self, tmp_path):
        # Copy to an empty dir so a dry run that *did* write would be visible.
        (tmp_path / "requirements.txt").write_text("")
        script = tmp_path / "install-native.sh"
        script.write_text(SCRIPT.read_text())
        script.chmod(0o755)
        res = subprocess.run(
            [str(script), "--dry-run", "--no-go-tools"],
            capture_output=True, text=True, timeout=60, cwd=tmp_path,
        )
        assert res.returncode == 0, res.stderr
        created = {p.name for p in tmp_path.iterdir()}
        assert created == {"requirements.txt", "install-native.sh"}, f"dry run wrote: {created}"


class TestInstallerSafety:
    def test_does_not_need_or_use_root(self):
        text = SCRIPT.read_text()
        # `sudo` may only appear inside advisory messages, never as a command.
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(("info", "warn", "err", "#")) or "Debian/Ubuntu" in stripped:
                continue
            assert not re.search(r"\bsudo\b", stripped), f"installer runs sudo: {line!r}"

    def test_never_pipes_remote_content_into_a_shell(self):
        assert not re.search(r"(curl|wget)[^\n|]*\|\s*(ba|z)?sh", SCRIPT.read_text())

    def test_does_not_edit_ai_client_configs(self):
        """It prints the config snippet; it must not silently rewrite the
        user's Claude Desktop / Gemini settings."""
        text = SCRIPT.read_text()
        assert not re.search(r">\s*[^\n]*claude_desktop_config", text)
        assert "does not edit your client config" in text


class TestToolInstallParity:
    """Native and Docker must install the same tools, the same way.

    This used to assert that two lists of hard-coded pins matched. The pins are
    gone (that was the stale-version problem), so the invariant is now stronger:
    ONE manifest, ONE installer, and no version literals anywhere to drift."""

    def test_native_and_docker_use_the_same_installer(self):
        for f in (SCRIPT, DOCKERFILE):
            text = f.read_text()
            assert "mcp_server.toolmgr" in text and " install" in text, f"{f.name} bypasses the shared tool manager"

    def test_neither_installer_hard_codes_a_tool_version(self):
        for f in (SCRIPT, DOCKERFILE):
            offenders = re.findall(r"@(?:v?\d+\.\d+\.\d+|latest)\b", f.read_text())
            assert not offenders, f"{f.name} pins versions again: {offenders}"

    def test_every_required_tool_is_in_the_manifest(self):
        from mcp_server.capabilities import REQUIRED_TOOLS
        from mcp_server.toolmgr.layout import Layout
        from mcp_server.toolmgr.manifest import load_manifest

        m = load_manifest(Layout().manifest)
        for tool in REQUIRED_TOOLS:
            assert tool in m.tools and m.tools[tool].required, f"required tool {tool} is not installable via the manifest"


class TestHttpxNameCollision:
    """Native equivalent of the Dockerfile ordering guard: the Python httpx
    library's CLI must not shadow ProjectDiscovery's httpx."""

    def test_installer_removes_the_venv_httpx_script(self):
        assert 'rm -f "$VENV/bin/httpx"' in SCRIPT.read_text()

    def test_launchers_put_the_selected_tools_before_the_venv(self):
        # bin/active holds one symlink per tool -> the SELECTED (newest compatible)
        # copy. It must precede .venv/bin so PD's httpx wins, and bin/tools must
        # NOT precede it (an old local binary may never shadow a newer system one).
        text = SCRIPT.read_text()
        m = re.search(r'export PATH="([^"]+)"', text)
        assert m, "launcher PATH export not found"
        path = m.group(1)
        assert path.index("bin/active") < path.index(".venv/bin")
        assert path.index("bin/active") < path.index("bin/tools")


class TestNewInstallerOptions:
    def test_help_documents_the_freshness_options(self):
        out = subprocess.run(["bash", str(SCRIPT), "--help"], capture_output=True, text=True).stdout
        for opt in ("--lock", "--locked-python", "--offline", "--enable-auto-update"):
            assert opt in out

    def test_dry_run_with_a_lock_names_the_lock_and_still_changes_nothing(self, tmp_path):
        before = {p.name for p in ROOT.iterdir()}
        out = subprocess.run(["bash", str(SCRIPT), "--dry-run", "--lock", "config/tool-lock.json"],
                             capture_output=True, text=True, cwd=ROOT)
        assert out.returncode == 0, out.stderr
        assert "config/tool-lock.json" in out.stdout
        assert {p.name for p in ROOT.iterdir()} == before

    def test_lock_option_requires_a_value(self):
        r = subprocess.run(["bash", str(SCRIPT), "--lock"], capture_output=True, text=True)
        assert r.returncode == 2 and "needs a FILE" in r.stderr

    def test_sudo_only_ever_appears_inside_quoted_hint_text_and_no_apt_hook_is_installed(self):
        for n, line in enumerate(SCRIPT.read_text().splitlines(), 1):
            if line.strip().startswith("#"):
                continue
            outside_quotes = re.sub(r'"[^"]*"', "", line)
            assert "sudo" not in outside_quotes, f"line {n} uses sudo as a command: {line!r}"
        text = SCRIPT.read_text()
        assert "apt.conf" not in text and "dpkg" not in text.lower(), "APT integration must stay out of the installer"
