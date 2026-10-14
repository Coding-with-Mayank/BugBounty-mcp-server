#!/usr/bin/env bash
# shellcheck disable=SC2016   # backticks in the markdown below are literal, not command substitution
# ═══════════════════════════════════════════════════════════════════════════
#  scripts/ci_open_prs.sh — the ONLY step of the freshness workflow that can write.
#
#  Runs in the isolated `publish` job: it installs nothing and executes nothing from
#  upstream. The candidate files in $1 were produced by jobs that DID run upstream code,
#  so they are treated as hostile data and re-validated by scripts/ci_publish_guard.py
#  (the project's own manifest/lock rules) before a single byte is committed.
#
#  Env (all set by the workflow):  GH_TOKEN  DEFAULT_BRANCH  RUN_URL
#                                  TOOLS_VERIFY (success|failure)   PYTHON_LOCK_RESULT
#  The token is given to git per command through the environment: never written to
#  .git/config, never on a command line.
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

CAND="${1:?usage: ci_open_prs.sh CANDIDATES_DIR}"
: "${GH_TOKEN:?GH_TOKEN is required}" "${DEFAULT_BRANCH:?DEFAULT_BRANCH is required}" "${RUN_URL:?RUN_URL is required}"
TOOLS_VERIFY="${TOOLS_VERIFY:-}"
PYTHON_LOCK_RESULT="${PYTHON_LOCK_RESULT:-}"
SERVER="${GITHUB_SERVER_URL:-https://github.com}"
GUARD=(python3 scripts/ci_publish_guard.py)
DAY="$(date -u +%Y%m%d)"
STATUS=0

# Dependency PRs are only ever proposed from the default branch (a manual run from some
# feature branch must not smuggle that branch's commits into a bot PR).
if [[ -n "${GITHUB_REF_NAME:-}" && "$GITHUB_REF_NAME" != "$DEFAULT_BRANCH" ]]; then
    echo "not on $DEFAULT_BRANCH (on $GITHUB_REF_NAME): nothing will be proposed"
    exit 0
fi

auth="$(printf 'x-access-token:%s' "$GH_TOKEN" | base64 | tr -d '\n')"
echo "::add-mask::$auth"
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0="http.${SERVER}/.extraheader"
export GIT_CONFIG_VALUE_0="AUTHORIZATION: basic ${auth}"
git config user.name  "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"

# propose BRANCH TITLE COMMIT_MESSAGE BODY_FILE FILE...   (the files must already be updated)
propose() {
    local branch="$1" title="$2" message="$3" body="$4"; shift 4
    [[ "$branch" == deps/* ]] || { echo "refusing to push to $branch" >&2; return 1; }
    git checkout -q -B "$branch"
    git add -- "$@"
    if git diff --cached --quiet; then
        echo "$title: nothing to commit"; git checkout -q -; return 0
    fi
    git commit -q -m "$message"
    git push --force origin "$branch"
    local existing
    existing="$(gh pr list --head "$branch" --state open --json number --jq '.[0].number // empty')"
    if [[ -n "$existing" ]]; then
        gh pr edit "$existing" --body-file "$body"
        echo "updated PR #$existing"
    else
        gh pr create --base "$DEFAULT_BRANCH" --head "$branch" --title "$title" --body-file "$body"
    fi
    # PRs opened with GITHUB_TOKEN do not start pull_request workflows; start CI on the branch explicitly.
    gh workflow run ci.yml --ref "$branch" \
        || echo "::warning::could not start ci.yml on $branch; close and reopen the PR to run CI"
    git checkout -q -
}

# ── tool lock ───────────────────────────────────────────────────────────────
tools_lock="$CAND/tools-candidate/tool-lock.json"
if [[ "$TOOLS_VERIFY" == "success" && -f "$tools_lock" ]]; then
    set +e; diff_md="$("${GUARD[@]}" diff-tools "$tools_lock")"; rc=$?; set -e
    case "$rc" in
        0)
            body="$(mktemp)"
            {
                printf 'The newest compatible tool releases installed and passed `hunt verify` (the flag self-test).\n\n'
                printf '%s\n\n' "$diff_md"
                printf 'This only updates the reproducible lock — fresh installs already get these versions.\n'
                printf 'Review, let CI run, merge. Run: %s\n' "$RUN_URL"
            } > "$body"
            cp "$tools_lock" config/tool-lock.json
            propose "deps/tool-lock-$DAY" "chore(deps): newer compatible tool releases" \
                "chore(deps): refresh config/tool-lock.json to the newest compatible tool releases" "$body" \
                config/tool-lock.json || STATUS=1
            ;;
        3) echo "tool lock: already current" ;;
        *) echo "::error::tool-lock candidate REJECTED by the publish guard; nothing proposed"; STATUS=1 ;;
    esac
else
    echo "tool lock: not proposing (verify=${TOOLS_VERIFY:-none}, candidate present: $([[ -f $tools_lock ]] && echo yes || echo no))"
fi

# ── python lock ─────────────────────────────────────────────────────────────
py_lock="$CAND/python-candidate/requirements.lock"
if [[ "$PYTHON_LOCK_RESULT" == "success" && -f "$py_lock" ]]; then
    set +e; diff_md="$("${GUARD[@]}" diff-python "$py_lock")"; rc=$?; set -e
    case "$rc" in
        0)
            body="$(mktemp)"
            {
                printf 'Re-resolved `requirements.txt` to the newest allowed releases. The full test suite passed in an\n'
                printf 'environment installed from **exactly this lock** with `--require-hashes`, and on the newest releases\n'
                printf 'with both MCP SDK generations (1.x and 2.x).\n\n'
                printf '%s\n\n' "$diff_md"
                printf 'Review, let CI run, merge. Run: %s\n' "$RUN_URL"
            } > "$body"
            cp "$py_lock" requirements.lock
            propose "deps/python-lock-$DAY" "chore(deps): refresh requirements.lock" \
                "chore(deps): refresh requirements.lock (tests pass on exactly this lock)" "$body" \
                requirements.lock || STATUS=1
            ;;
        3) echo "python lock: already current" ;;
        *) echo "::error::python-lock candidate REJECTED by the publish guard; nothing proposed"; STATUS=1 ;;
    esac
else
    echo "python lock: not proposing (result=${PYTHON_LOCK_RESULT:-none})"
fi

exit "$STATUS"
