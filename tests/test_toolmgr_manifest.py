"""The manifest is the single source of truth — and a security boundary."""
import copy
import re
from pathlib import Path

import pytest
from toolmgr_helpers import FAKE_MANIFEST, parse_fake

from mcp_server import capabilities
from mcp_server.toolmgr import state, versions
from mcp_server.toolmgr.layout import Layout
from mcp_server.toolmgr.manifest import ManifestError, load_manifest

ROOT = Path(__file__).resolve().parent.parent
REAL = load_manifest(ROOT / "config" / "tools.yaml")


def mutated(path_fn):
    d = copy.deepcopy(FAKE_MANIFEST)
    path_fn(d)
    return d


# ── the real manifest ─────────────────────────────────────────────────
def test_every_real_tool_derives_an_install_target_inside_its_own_repo():
    for name, t in REAL.tools.items():
        v = versions.parse(f"{t.tested_major}.9.9")
        target = t.install_target(v)
        assert target.startswith(f"github.com/{t.repo}"), name
        assert target.endswith(f"@v{t.tested_major}.9.9")
        assert t.min_version.major == t.tested_major


def test_install_targets_reproduce_the_original_pins_exactly():
    # What install-native.sh and the Dockerfile used to hard-code. The manifest
    # must derive precisely these module paths, or an upgrade would break installs.
    expect = {
        "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.6",
        "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@v1.6.10",
        "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.9",
        "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.3",
        "katana": "github.com/projectdiscovery/katana/cmd/katana@v1.1.2",
        "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.2",
        "waybackurls": "github.com/tomnomnom/waybackurls@v0.1.0",
        "gau": "github.com/lc/gau/v2/cmd/gau@v2.2.3",
        "ffuf": "github.com/ffuf/ffuf/v2@v2.1.0",
        "gobuster": "github.com/OJ/gobuster/v3@v3.6.0",
        "gowitness": "github.com/sensepost/gowitness@v2.5.1",
        "anew": "github.com/tomnomnom/anew@v0.1.1",
        "httprobe": "github.com/tomnomnom/httprobe@v0.2.0",
    }
    for name, target in expect.items():
        t = REAL.tools[name]
        assert t.install_target(t.min_version) == target, name


def test_shipped_lock_validates_and_equals_the_minimum_supported_versions():
    lock = state.load_lock(REAL, ROOT / "config" / "tool-lock.json")
    assert lock, "config/tool-lock.json is empty"
    for name, v in lock.items():
        assert v == REAL.tools[name].min_version, f"{name}: lock and manifest floor disagree"


def test_capabilities_fallback_lists_never_drift_from_the_manifest():
    assert {n: t.purpose for n, t in REAL.required.items()} == capabilities._FALLBACK_REQUIRED
    assert {n: t.purpose for n, t in REAL.optional.items()} == capabilities._FALLBACK_OPTIONAL
    assert capabilities.REQUIRED_TOOLS == capabilities._FALLBACK_REQUIRED


def test_compat_flags_cover_what_the_handlers_actually_pass():
    """If a handler starts passing a new flag, the compatibility self-test must
    learn about it, or a future tool that dropped it would be accepted."""
    import ast

    src = (ROOT / "mcp_server" / "server.py").read_text()
    used: dict[str, set[str]] = {}
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.List) and node.elts and isinstance(node.elts[0], ast.Constant):
            tool = node.elts[0].value
            if tool in REAL.tools:
                used.setdefault(tool, set()).update(
                    e.value for e in node.elts[1:] if isinstance(e, ast.Constant)
                    and isinstance(e.value, str) and re.match(r"^--?[A-Za-z]", e.value))
    assert used, "found no tool invocations — did server.py change shape?"
    for tool, flags in used.items():
        declared = {f for c in REAL.tools[tool].compat for f in c.flags}
        missing = flags - declared
        assert not missing, f"{tool}: server.py passes {sorted(missing)} but config/tools.yaml doesn't self-test them"


# ── hard-coded version hunt (the actual bug this work fixes) ──────────
PIN = re.compile(r"@(?:v?\d+\.\d+\.\d+|latest)\b")


@pytest.mark.parametrize("name", ["install-native.sh", "Dockerfile", "Makefile", "setup.sh", "docker-compose.yml", "hunt.py"])
def test_no_tool_version_is_hard_coded_outside_the_manifest(name):
    hits = PIN.findall((ROOT / name).read_text())
    assert not hits, f"{name} pins a tool version again: {hits}"


def test_ci_does_not_pin_tool_versions_either():
    for wf in (ROOT / ".github" / "workflows").glob("*.yml"):
        assert not PIN.findall(wf.read_text()), f"{wf.name} pins a tool version"


# ── validation rejects hostile / malformed manifests ──────────────────
@pytest.mark.parametrize("edit,why", [
    (lambda d: d["tools"]["faketool"].update(module="github.com/evil/faketool"), "different owner"),
    (lambda d: d["tools"]["faketool"].update(module="gitlab.com/projectdiscovery/faketool"), "different host"),
    (lambda d: d["tools"]["faketool"].update(package="../../etc"), "path traversal"),
    (lambda d: d["tools"]["faketool"].update(package="cmd/x; rm -rf /"), "shell metacharacters"),
    (lambda d: d["tools"]["faketool"].update(repo="not a repo"), "bad repo"),
    (lambda d: d["tools"]["faketool"].update(min_version="2.1"), "not 3-part"),
    (lambda d: d["tools"]["faketool"].update(min_version="3.0.0"), "min outside tested major"),
    (lambda d: d["tools"]["faketool"].update(auto_update="always"), "bad policy"),
    (lambda d: d["tools"]["faketool"].update(version_args=["-version; id"]), "unsafe arg"),
    (lambda d: d["tools"]["faketool"].update(version_regex="("), "bad regex"),
    (lambda d: d["tools"]["faketool"]["compat"][0].update(flags=["notaflag"]), "flag shape"),
    (lambda d: d["tools"].update({"Bad Name": d["tools"]["faketool"]}), "unsafe name"),
    (lambda d: d["tools"]["faketool"].update(binary="../x"), "unsafe binary"),
    (lambda d: d["assets"]["faketool-data"].update(requires_tool="nope"), "unknown requires_tool"),
    (lambda d: d.update(schema=2), "unsupported schema"),
])
def test_hostile_or_malformed_manifest_is_rejected(edit, why):
    with pytest.raises(ManifestError):
        parse_fake(mutated(edit))


def test_install_target_refuses_non_release_versions():
    t = parse_fake(FAKE_MANIFEST).tools["faketool"]
    from mcp_server.toolmgr.security import SecurityError
    with pytest.raises(SecurityError):
        t.install_target(versions.parse("2.4.0-rc1"))
    with pytest.raises(SecurityError):
        t.install_target(versions.parse("2.4.0"), major=3)


def test_layout_honours_state_dir_env(monkeypatch, tmp_path):
    monkeypatch.setenv("BBMCP_STATE_DIR", str(tmp_path / "s"))
    assert Layout().installed_file == tmp_path / "s" / "installed-tools.json"


def test_unknown_upstream_owner_is_rejected_even_when_module_and_repo_agree():
    d = mutated(lambda d: d["tools"]["faketool"].update(repo="newowner/faketool", module="github.com/newowner/faketool"))
    with pytest.raises(ManifestError, match="trusted-owner allowlist"):
        parse_fake(d)


def test_trusted_owner_set_is_pinned():
    # Adding an owner must be a deliberate, reviewed change to THIS test as well as to the code.
    from mcp_server.toolmgr.manifest import TRUSTED_OWNERS
    assert {"projectdiscovery", "tomnomnom", "lc", "ffuf", "OJ", "sensepost"} == TRUSTED_OWNERS
    assert {t.repo.split("/")[0] for t in REAL.tools.values()} <= TRUSTED_OWNERS
