"""
Text-based checks on the Dockerfile source — NOT a real build. There's no
Docker daemon available in this environment to actually run `docker build`
and verify at runtime, so every test here catches a regression of a
specific *known* mistake (an instruction ordering, a missing package, a
stale literal); none of it proves the built image actually works. Treat a
passing suite here as "the known-bad patterns haven't crept back in", not
as proof the image works.

TestDockerfileToolInstallOrder guards against a specific, previously-real
bug: requirements.txt includes the Python `httpx` library, which installs
its own CLI script also named `httpx` — to the same /usr/local/bin/ the Go
tools are copied to in this Dockerfile's base image. Whichever install
step runs LAST wins that filename. If the Go-tools COPY ever moves back to
before `pip install`, pip's httpx silently overwrites ProjectDiscovery's
httpx again, breaking alive_check/tech_detect/the screenshot fallback with
no error at build time (shutil.which("httpx") still finds *something*).

TestDockerfileNaabuCapability and TestDockerfileVersionConsistency guard
two smaller, independent things — see their own docstrings.
"""
from __future__ import annotations

from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parent.parent / "Dockerfile"


def _line_index(lines: list[str], needle: str) -> int:
    for i, line in enumerate(lines):
        if needle in line:
            return i
    raise AssertionError(f"Couldn't find {needle!r} in Dockerfile — did it get rewritten?")


class TestDockerfileToolInstallOrder:
    def test_go_tools_copied_after_pip_install(self):
        """The fix: Go binaries must be copied in AFTER pip install, so the
        real httpx (and any other future name collision) wins the
        /usr/local/bin/ filename, not whatever pip happened to install."""
        lines = DOCKERFILE.read_text().splitlines()
        pip_install_idx = _line_index(lines, "pip install --no-cache-dir -r requirements.txt")
        go_tools_copy_idx = _line_index(lines, "COPY --from=go-builder")
        assert go_tools_copy_idx > pip_install_idx, (
            "Go tools are copied in before `pip install -r requirements.txt` runs — "
            "this reintroduces the httpx name collision (see module docstring). "
            "The Go-tools COPY --from=go-builder line must come after pip install."
        )

    def test_nuclei_still_available_when_templates_update_runs(self):
        """The fix must not break the existing `nuclei -update-templates`
        step, which needs the nuclei binary already on PATH."""
        lines = DOCKERFILE.read_text().splitlines()
        go_tools_copy_idx = _line_index(lines, "COPY --from=go-builder")
        nuclei_update_idx = _line_index(lines, "nuclei -update-templates")
        assert go_tools_copy_idx < nuclei_update_idx, (
            "nuclei -update-templates runs before the Go tools are copied in — "
            "the nuclei binary wouldn't exist yet at that point in the build."
        )

    def test_httpx_is_a_declared_python_dependency(self):
        """Confirms the premise: if this ever stops being true, the two
        tests above are guarding against a bug that no longer exists."""
        requirements = (DOCKERFILE.parent / "requirements.txt").read_text()
        assert "httpx" in requirements, (
            "httpx is no longer in requirements.txt — the collision this test "
            "guards against may not apply anymore; reconsider this test's purpose "
            "rather than deleting it blindly."
        )


class TestDockerfileNaabuCapability:
    """naabu's SYN-scan mode needs CAP_NET_RAW; setcap grants it to just
    that binary rather than the whole container. Text-only — can't verify
    the capability actually survives the image layers without a real
    build (see the Dockerfile comment on this), but it does confirm the
    setcap step exists, runs after the binary it targets is actually
    present, and that the apt package providing `setcap` is installed."""

    def test_libcap2_bin_is_installed(self):
        assert "libcap2-bin" in DOCKERFILE.read_text()

    def test_setcap_runs_after_naabu_binary_is_copied_in(self):
        lines = DOCKERFILE.read_text().splitlines()
        go_tools_copy_idx = _line_index(lines, "COPY --from=go-builder")
        setcap_idx = _line_index(lines, "setcap cap_net_raw+ep /usr/local/bin/naabu")
        assert setcap_idx > go_tools_copy_idx, (
            "setcap runs before the Go tools (including naabu) are copied in — "
            "the binary wouldn't exist yet at that point in the build."
        )

    def test_setcap_failure_does_not_break_the_build(self):
        """Matches the Go-install lines' own `|| echo "WARN: ..."` pattern —
        a build must still succeed somewhere that lacks setcap/libcap
        support (certain sandboxed or rootless build environments)."""
        lines = DOCKERFILE.read_text().splitlines()
        setcap_line = next(ln for ln in lines if "setcap cap_net_raw+ep" in ln)
        assert "||" in setcap_line, "setcap has no fallback — a failure here would break the whole build"


class TestDockerfileVersionConsistency:
    """The Dockerfile's LABEL version is a separate, independently
    hand-edited copy of the version string — not something
    mcp_server.__version__ can reach into a Dockerfile to enforce at
    runtime. This is the Dockerfile-side half of the version-consistency
    guard in tests/test_server.py (which covers every Python-level copy)."""

    def test_label_version_matches_pyproject(self):
        import tomllib

        pyproject = tomllib.loads((DOCKERFILE.parent / "pyproject.toml").read_text())
        expected = pyproject["project"]["version"]
        lines = DOCKERFILE.read_text().splitlines()
        label_line = next(ln for ln in lines if ln.strip().startswith('LABEL version='))
        assert f'"{expected}"' in label_line, (
            f"Dockerfile's LABEL version doesn't match pyproject.toml's {expected!r}: {label_line!r}"
        )
