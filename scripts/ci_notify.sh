#!/usr/bin/env bash
# shellcheck disable=SC2016   # backticks in the markdown below are literal, not command substitution
# ═══════════════════════════════════════════════════════════════════════════
#  scripts/ci_notify.sh — open (or update) ONE tracking issue when the weekly
#  freshness run finds something broken.  Runs in the isolated `notify` job
#  (issues: write only; no upstream code).  Tool output is untrusted text: it goes
#  through scripts/ci_publish_guard.py (fence breakouts, @mentions, links, size).
#
#  Env: GH_TOKEN RUN_URL TOOLS_RESULT TOOLS_VERIFY DOCKER_RESULT
#       PYTHON_NEWEST_RESULT PYTHON_LOCK_RESULT
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

CAND="${1:?usage: ci_notify.sh CANDIDATES_DIR}"
: "${GH_TOKEN:?GH_TOKEN is required}" "${RUN_URL:?RUN_URL is required}"
LABEL="dependency-freshness"
TITLE="Weekly freshness check found a problem"
GUARD=(python3 scripts/ci_publish_guard.py text)

body="$(mktemp)"
{
    printf 'The weekly dependency-freshness run needs attention: %s\n\n' "$RUN_URL"
    printf '| check | result |\n|---|---|\n'
    printf '| newest tools install and build | %s |\n' "${TOOLS_RESULT:-n/a}"
    printf '| newest tools pass the flag self-test (`hunt verify`) | %s |\n' "${TOOLS_VERIFY:-n/a}"
    printf '| Docker rebuild with current tools | %s |\n' "${DOCKER_RESULT:-n/a}"
    printf '| newest Python dependencies, both MCP SDK generations | %s |\n' "${PYTHON_NEWEST_RESULT:-n/a}"
    printf '| refreshed requirements.lock, tested | %s |\n\n' "${PYTHON_LOCK_RESULT:-n/a}"
    if [[ "${TOOLS_VERIFY:-}" == "failure" && -f "$CAND/tools-candidate/verify.txt" ]]; then
        printf 'A newer tool release no longer accepts flags this project passes. Output of `hunt verify`:\n\n```text\n'
        "${GUARD[@]}" "$CAND/tools-candidate/verify.txt"
        printf '\n```\n\nFresh installs refuse to apply such a release (the old working version is kept). '
        printf 'Update the handler and/or `max_version` in `config/tools.yaml`.\n'
    fi
} > "$body"

gh label create "$LABEL" --color D93F0B --description "Weekly dependency freshness findings" >/dev/null 2>&1 || true
existing="$(gh issue list --label "$LABEL" --state open --json number --jq '.[0].number // empty')"
if [[ -n "$existing" ]]; then
    gh issue comment "$existing" --body-file "$body"
    echo "commented on #$existing"
else
    gh issue create --title "$TITLE" --label "$LABEL" --body-file "$body"
fi
