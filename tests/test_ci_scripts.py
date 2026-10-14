"""scripts/ci_open_prs.sh and scripts/ci_notify.sh, run for real against a throwaway repo.

`gh` is replaced by a recorder; `origin` is a local bare repository, so the real git
commands run. What is proved: a valid candidate becomes a pushed deps/* branch + PR; a
hostile or failed one publishes nothing; the token never lands in .git/config.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(shutil.which("git") is None or shutil.which("bash") is None, reason="needs git and bash")

FAKE_GH = """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$GH_LOG"
case "$1 $2" in
  "pr list")    printf '%s' "${FAKE_EXISTING_PR:-}" ;;
  "issue list") printf '%s' "${FAKE_EXISTING_ISSUE:-}" ;;
esac
exit 0
"""


@pytest.fixture
def sandbox(tmp_path):
    work = tmp_path / "work"
    origin = tmp_path / "origin.git"
    for rel in ("scripts", "config", "mcp_server"):
        shutil.copytree(ROOT / rel, work / rel, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy(ROOT / "requirements.lock", work / "requirements.lock")
    g = lambda *a, cwd=work: subprocess.run(["git", *a], cwd=cwd, check=True, capture_output=True, text=True)  # noqa: E731
    g("init", "-q", "-b", "main", cwd=work)
    g("config", "user.email", "t@example.com")
    g("config", "user.name", "t")
    g("add", "-A")
    g("commit", "-q", "-m", "base")
    subprocess.run(["git", "init", "-q", "--bare", str(origin)], check=True)
    g("remote", "add", "origin", str(origin))
    g("push", "-q", "origin", "main")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    gh = bindir / "gh"
    gh.write_text(FAKE_GH)
    gh.chmod(0o755)
    log = tmp_path / "gh.log"
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "GH_LOG": str(log), "GH_TOKEN": "ghs_SECRET_TOKEN_VALUE",
           "DEFAULT_BRANCH": "main", "GITHUB_REF_NAME": "main", "RUN_URL": "https://example.invalid/run/1",
           "GITHUB_SERVER_URL": "https://github.com", "BBMCP_OFFLINE": "1"}

    class Box:
        pass
    b = Box()
    b.work, b.origin, b.log, b.env, b.git = work, origin, log, env, g
    b.calls = lambda: log.read_text().splitlines() if log.exists() else []
    b.branches = lambda: subprocess.run(["git", "branch", "--list", "deps/*"], cwd=origin, capture_output=True, text=True).stdout.split()
    return b


def run(box, script, cand, **extra):
    return subprocess.run(["bash", f"scripts/{script}", str(cand)], cwd=box.work, env={**box.env, **extra},
                          capture_output=True, text=True, timeout=120)


def tool_candidate(tmp_path, mutate=None, bump=True):
    data = json.loads((ROOT / "config" / "tool-lock.json").read_text())
    if bump:
        name = sorted(data["tools"])[0]
        major, minor, patch = data["tools"][name]["version"].split(".")[:3]
        new = f"{major}.{minor}.{int(patch) + 1}"        # a newer release INSIDE the tested major
        data["tools"][name]["version"] = new
        data["tools"][name]["target"] = data["tools"][name]["target"].rsplit("@", 1)[0] + f"@v{new}"
    if mutate:
        mutate(data)
    d = tmp_path / "cand" / "tools-candidate"
    d.mkdir(parents=True, exist_ok=True)
    (d / "tool-lock.json").write_text(json.dumps(data, indent=2))
    return tmp_path / "cand"


def test_valid_tool_candidate_opens_a_pr(sandbox, tmp_path):
    cand = tool_candidate(tmp_path)
    done = run(sandbox, "ci_open_prs.sh", cand, TOOLS_VERIFY="success", PYTHON_LOCK_RESULT="skipped")
    assert done.returncode == 0, done.stdout + done.stderr
    assert len(sandbox.branches()) == 1 and sandbox.branches()[0].startswith("deps/tool-lock-")
    calls = sandbox.calls()
    assert any(c.startswith("pr create") and "--base main" in c for c in calls)
    assert any(c.startswith("workflow run ci.yml --ref deps/tool-lock-") for c in calls)
    committed = subprocess.run(["git", "show", f"{sandbox.branches()[0]}:config/tool-lock.json"], cwd=sandbox.origin,
                               capture_output=True, text=True).stdout
    assert committed != (ROOT / "config" / "tool-lock.json").read_text()


def test_token_is_never_written_to_disk_or_argv(sandbox, tmp_path):
    cand = tool_candidate(tmp_path)
    run(sandbox, "ci_open_prs.sh", cand, TOOLS_VERIFY="success")
    assert "SECRET_TOKEN" not in (sandbox.work / ".git" / "config").read_text()
    assert not any("SECRET_TOKEN" in c for c in sandbox.calls())


def test_failed_self_test_publishes_nothing(sandbox, tmp_path):
    cand = tool_candidate(tmp_path)
    done = run(sandbox, "ci_open_prs.sh", cand, TOOLS_VERIFY="failure")
    assert done.returncode == 0 and sandbox.branches() == [] and sandbox.calls() == []


def test_unchanged_lock_publishes_nothing(sandbox, tmp_path):
    cand = tool_candidate(tmp_path, bump=False)
    done = run(sandbox, "ci_open_prs.sh", cand, TOOLS_VERIFY="success")
    assert done.returncode == 0 and sandbox.branches() == [] and sandbox.calls() == []


def test_hostile_tool_candidate_is_rejected_and_fails_the_job(sandbox, tmp_path):
    def evil(d):
        name = sorted(d["tools"])[0]
        d["tools"][name]["target"] = "github.com/attacker/evil/cmd/evil@v1.0.0"
    cand = tool_candidate(tmp_path, evil)
    done = run(sandbox, "ci_open_prs.sh", cand, TOOLS_VERIFY="success")
    assert done.returncode == 1 and "REJECTED" in done.stdout + done.stderr
    assert sandbox.branches() == [] and sandbox.calls() == []


def test_hostile_python_candidate_is_rejected(sandbox, tmp_path):
    d = tmp_path / "cand" / "python-candidate"
    d.mkdir(parents=True)
    (d / "requirements.lock").write_text("--extra-index-url https://evil.example/simple\nfoo==1.0\n")
    done = run(sandbox, "ci_open_prs.sh", tmp_path / "cand", PYTHON_LOCK_RESULT="success")
    assert done.returncode == 1 and sandbox.branches() == [] and sandbox.calls() == []


def test_valid_python_candidate_opens_a_pr(sandbox, tmp_path):
    text = (ROOT / "requirements.lock").read_text()
    d = tmp_path / "cand" / "python-candidate"
    d.mkdir(parents=True)
    (d / "requirements.lock").write_text(text.replace("pydantic==", "pydantic==99.", 1))
    done = run(sandbox, "ci_open_prs.sh", tmp_path / "cand", PYTHON_LOCK_RESULT="success")
    assert done.returncode == 0, done.stdout + done.stderr
    assert sandbox.branches()[0].startswith("deps/python-lock-")


def test_existing_pr_is_updated_not_duplicated(sandbox, tmp_path):
    cand = tool_candidate(tmp_path)
    run(sandbox, "ci_open_prs.sh", cand, TOOLS_VERIFY="success", FAKE_EXISTING_PR="42")
    calls = sandbox.calls()
    assert any(c.startswith("pr edit 42") for c in calls) and not any(c.startswith("pr create") for c in calls)


def test_never_proposes_from_a_non_default_branch(sandbox, tmp_path):
    cand = tool_candidate(tmp_path)
    done = run(sandbox, "ci_open_prs.sh", cand, TOOLS_VERIFY="success", GITHUB_REF_NAME="some-feature")
    assert done.returncode == 0 and sandbox.branches() == [] and sandbox.calls() == []


# ── notify ───────────────────────────────────────────────────────────────────

def test_notify_creates_one_issue_with_sanitised_output(sandbox, tmp_path):
    d = tmp_path / "cand" / "tools-candidate"
    d.mkdir(parents=True)
    (d / "verify.txt").write_text("nuclei: flag removed\n```\n@everyone see #1 <script>\n")
    done = run(sandbox, "ci_notify.sh", tmp_path / "cand", TOOLS_RESULT="success", TOOLS_VERIFY="failure",
               DOCKER_RESULT="success", PYTHON_NEWEST_RESULT="success", PYTHON_LOCK_RESULT="success")
    assert done.returncode == 0, done.stdout + done.stderr
    calls = sandbox.calls()
    create = [c for c in calls if c.startswith("issue create")]
    assert len(create) == 1 and "--label dependency-freshness" in create[0]
    body = Path(create[0].split("--body-file ")[1].split()[0]).read_text()
    assert body.count("```") == 2                      # only OUR opening and closing fence survive
    assert "@everyone" not in body and "<script>" not in body and "#1 " not in body
    assert "flag removed" in body                      # …while the useful content is kept


def test_notify_comments_on_the_existing_issue(sandbox, tmp_path):
    (tmp_path / "cand").mkdir()
    run(sandbox, "ci_notify.sh", tmp_path / "cand", TOOLS_VERIFY="failure", FAKE_EXISTING_ISSUE="7")
    calls = sandbox.calls()
    assert any(c.startswith("issue comment 7") for c in calls) and not any(c.startswith("issue create") for c in calls)
