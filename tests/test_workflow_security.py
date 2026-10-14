"""Regression guard for the GitHub Actions hardening.

The audit found the weekly freshness workflow granting repository-wide write access and a
workflow-wide token to jobs that install and run third-party code (Go modules, PyPI
packages, the security tools themselves). These tests keep that from coming back:

  1. no workflow-level write permission, and every job declares its own permissions;
  2. no workflow-level token / secret in `env`;
  3. every checkout drops its credentials (persist-credentials: false);
  4. every action is pinned to a full commit SHA;
  5. a job that can WRITE never installs or executes upstream code — it may only run the
     reviewed scripts/ci_*.sh against validated artifacts;
  6. a job that DOES run upstream code never sees a token or secret (one documented, read-only
     exception: zizmor in ci.yml);
  7. no `pull_request_target` / `workflow_run` triggers, no `${{ }}` pasted into shell, and
     `shell: bash` so `cmd | tee` cannot hide a failure;
  8. zizmor (when installed) reports nothing.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
WRITE = {"write", "write-all"}
SHA = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
# A step that installs or executes anything that did not come from this repository's own reviewed scripts.
UPSTREAM_CODE = re.compile(
    r"(install-native|pip install|go install|docker (build|run|compose)|npm |\./hunt|python3? -m mcp_server|pytest|uv |\bmake\b)")
UPSTREAM_USES = ("actions/setup-go", "actions/setup-python", "docker/setup-buildx-action", "actions/setup-node")
TOKEN_REF = re.compile(r"github\.token|secrets\.|GITHUB_TOKEN|GH_TOKEN")
# (workflow, job) pairs allowed to hold a READ-ONLY token while running a trusted analysis tool.
READ_ONLY_TOKEN_OK = {("ci.yml", "workflows")}


def load(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def triggers(wf: dict) -> dict:
    on = wf.get("on", wf.get(True))            # YAML 1.1 turns a bare `on:` key into True
    return on if isinstance(on, dict) else {k: None for k in (on if isinstance(on, list) else [on])}


def job_perms(job: dict) -> dict:
    p = job.get("permissions")
    return p if isinstance(p, dict) else {}


def grants_write(perms: object) -> bool:
    """True for `write-all`, or any scope set to `write` (a bare string or a mapping)."""
    if isinstance(perms, str):
        return perms in WRITE
    return isinstance(perms, dict) and any(v in WRITE for v in perms.values())


def is_writer(job: dict) -> bool:
    return grants_write(job.get("permissions"))


def steps(job: dict) -> list[dict]:
    return job.get("steps", [])


def runs_upstream_code(job: dict) -> bool:
    return any(UPSTREAM_CODE.search(s.get("run", "")) or str(s.get("uses", "")).startswith(UPSTREAM_USES) for s in steps(job))


def cases():
    return [pytest.param(p.name, name, job, id=f"{p.name}:{name}")
            for p in WORKFLOWS for name, job in load(p).get("jobs", {}).items()]


def test_workflows_exist():
    assert {p.name for p in WORKFLOWS} >= {"ci.yml", "freshness.yml"}


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_workflow_level_write_and_no_workflow_level_token(path):
    wf = load(path)
    top = wf.get("permissions")
    assert top is not None, f"{path.name}: declare top-level `permissions: {{}}` (default is broad)"
    assert not grants_write(top), f"{path.name}: workflow-wide write permission"
    assert not TOKEN_REF.search(yaml.safe_dump(wf.get("env", {}))), f"{path.name}: a token/secret in workflow-level env reaches every step"
    for name, job in wf["jobs"].items():
        assert "permissions" in job, f"{path.name}:{name}: declare the job's own permissions explicitly"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_dangerous_triggers_absent(path):
    bad = set(triggers(load(path))) & {"pull_request_target", "workflow_run"}
    assert not bad, f"{path.name}: {bad} runs with write access and secrets on attacker-influenced input"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_checkout_drops_credentials(path):
    for name, job in load(path)["jobs"].items():
        for s in steps(job):
            if str(s.get("uses", "")).startswith("actions/checkout@"):
                assert (s.get("with") or {}).get("persist-credentials") is False, \
                    f"{path.name}:{name}: checkout must set persist-credentials: false (token would sit in .git/config)"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_full_commit_sha(path):
    for name, job in load(path)["jobs"].items():
        for s in steps(job):
            ref = s.get("uses")
            if ref and not ref.startswith("./"):
                assert SHA.match(ref), f"{path.name}:{name}: {ref} is not pinned to a 40-character commit SHA"
    text = path.read_text()
    for line in text.splitlines():
        if re.search(r"uses:\s+\S+@[0-9a-f]{40}", line):
            assert re.search(r"#\s*v\d", line), f"{path.name}: pinned action without a '# vX.Y.Z' comment (Dependabot keeps it current): {line.strip()}"


@pytest.mark.parametrize(("wf", "name", "job"), cases())
def test_writers_never_execute_upstream_code(wf, name, job):
    if not is_writer(job):
        return
    for s in steps(job):
        uses = str(s.get("uses", ""))
        assert not uses.startswith(UPSTREAM_USES), f"{wf}:{name} can write but runs {uses}"
        if uses and not uses.startswith(("actions/checkout@", "actions/download-artifact@")):
            pytest.fail(f"{wf}:{name} can write; unexpected action {uses}")
        run = s.get("run", "").strip()
        if run:
            assert re.fullmatch(r"scripts/ci_[a-z_]+\.sh \S+", run), \
                f"{wf}:{name} can write but runs {run!r} — a write-capable job may only run the reviewed scripts/ci_*.sh"
            assert not UPSTREAM_CODE.search(run.replace("scripts/ci_", ""))


@pytest.mark.parametrize(("wf", "name", "job"), cases())
def test_jobs_running_upstream_code_hold_no_write_and_no_token(wf, name, job):
    if is_writer(job) or not runs_upstream_code(job):
        return
    text = yaml.safe_dump(job)
    if (wf, name) in READ_ONLY_TOKEN_OK:
        perms = job_perms(job)
        assert perms and all(v == "read" for v in perms.values()), f"{wf}:{name}: the token exception requires read-only permissions"
        return
    assert not TOKEN_REF.search(text), f"{wf}:{name} runs upstream code and references a token/secret"


def test_the_untrusted_freshness_jobs_are_read_only():
    jobs = load(ROOT / ".github/workflows/freshness.yml")["jobs"]
    for name in ("tools", "docker", "python-newest", "python-lock"):
        assert job_perms(jobs[name]) == {"contents": "read"}, f"freshness:{name} must be contents: read only"
    writers = {n for n, j in jobs.items() if is_writer(j)}
    assert writers == {"publish", "notify"}, f"unexpected write-capable jobs: {writers}"
    assert job_perms(jobs["notify"]).get("contents") == "read" and job_perms(jobs["notify"]).get("issues") == "write"
    assert "contents" not in {k for k, v in job_perms(jobs["notify"]).items() if v == "write"}, "notify must not be able to push"


def test_freshness_publish_depends_on_the_test_jobs_and_checks_their_result():
    jobs = load(ROOT / ".github/workflows/freshness.yml")["jobs"]
    assert set(jobs["publish"]["needs"]) >= {"tools", "python-lock"}
    assert "needs." in jobs["publish"]["if"], "publish must look at what the test jobs concluded"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_expression_is_interpolated_into_shell(path):
    for name, job in load(path)["jobs"].items():
        for s in steps(job):
            assert "${{" not in s.get("run", ""), \
                f"{path.name}:{name}: pass `${{{{ }}}}` values through env: and quote the variable (script injection)"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_shell_is_bash_so_pipelines_fail(path):
    wf = load(path)
    default = ((wf.get("defaults") or {}).get("run") or {}).get("shell")
    assert default == "bash", f"{path.name}: set defaults.run.shell: bash (-eo pipefail); the GitHub default has no pipefail, " \
                              "so `cmd | tee out` reports success even when cmd fails"


def test_freshness_keeps_its_jobs_and_schedule():
    wf = load(ROOT / ".github/workflows/freshness.yml")
    assert "schedule" in triggers(wf) and "workflow_dispatch" in triggers(wf)
    assert {"tools", "docker", "python-newest", "python-lock", "publish", "notify"} <= set(wf["jobs"])
    assert wf["concurrency"]["cancel-in-progress"] is False


def test_ci_can_be_started_on_a_bot_branch():
    assert "workflow_dispatch" in triggers(load(ROOT / ".github/workflows/ci.yml"))


def test_ci_checks_its_own_workflows():
    jobs = load(ROOT / ".github/workflows/ci.yml")["jobs"]
    text = yaml.safe_dump(jobs["workflows"])
    assert "actionlint" in text and "zizmor" in text


def test_dependabot_covers_actions_and_has_cooldown():
    cfg = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text())
    ecosystems = {u["package-ecosystem"]: u for u in cfg["updates"]}
    assert {"github-actions", "docker", "docker-compose"} <= set(ecosystems)
    for u in ecosystems.values():
        assert u.get("cooldown", {}).get("default-days", 0) >= 7


@pytest.mark.skipif(shutil.which("zizmor") is None, reason="zizmor not installed (pip install -r requirements-dev.txt)")
def test_zizmor_reports_nothing():
    done = subprocess.run(["zizmor", "--offline", "--min-severity", "low", ".github/"], cwd=ROOT, capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr


# ── the checks above must actually be able to fail ───────────────────────────

def test_the_original_dangerous_workflow_would_have_been_caught():
    """The pre-audit freshness.yml, reconstructed in miniature, trips the same rules."""
    bad = yaml.safe_load("""
permissions: {contents: write, pull-requests: write, issues: write}
env: {GH_TOKEN: '${{ github.token }}'}
jobs:
  tools:
    steps:
      - uses: actions/checkout@v4
      - run: ./install-native.sh
""")
    assert grants_write(bad["permissions"])
    assert TOKEN_REF.search(yaml.safe_dump(bad["env"]))
    assert not SHA.match(bad["jobs"]["tools"]["steps"][0]["uses"])
    assert (bad["jobs"]["tools"]["steps"][0].get("with") or {}).get("persist-credentials") is not False
    assert runs_upstream_code(bad["jobs"]["tools"])
