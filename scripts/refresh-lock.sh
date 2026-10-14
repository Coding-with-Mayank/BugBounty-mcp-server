#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  scripts/refresh-lock.sh — keep requirements.lock honest.
#
#    scripts/refresh-lock.sh --check [FILE]    Is FILE (default requirements.lock) still a valid,
#                                              hash-pinned resolution of requirements.txt?
#                                              Does NOT chase newer releases, so it never fails
#                                              just because PyPI published something.   (CI, PRs)
#    scripts/refresh-lock.sh --refresh [FILE]  Re-resolve to the NEWEST releases requirements.txt
#                                              allows and rewrite FILE.   (weekly job, `make lock`)
#
#  Needs `uv` (pip install uv). Resolution can build source distributions, which runs package
#  build code — so the weekly job does this in its read-only, no-credentials test job and the
#  separate publish job only ever sees the finished file (and re-validates it).
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE="${1:-}"
LOCK="${2:-requirements.lock}"
PY_FLOOR="3.11"          # the lowest Python the project supports; --universal covers newer ones

usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; }

command -v uv >/dev/null 2>&1 || { echo "uv not found — pip install uv" >&2; exit 2; }
[[ -f requirements.txt ]] || { echo "requirements.txt not found" >&2; exit 2; }

compile() {   # compile() OUTFILE [extra uv args...]   (OUTFILE's existing pins are preferred)
    local out="$1"; shift
    uv pip compile requirements.txt --universal --generate-hashes \
        --python-version "$PY_FLOOR" --no-header -q -o "$out" "$@"
}

# The explanatory comment block at the top of the committed lock (everything up to the first
# non-comment line) — kept across regenerations so the file always says how it was made.
header() { [[ -f "$1" ]] && awk '/^#/ {print; next} {exit}' "$1" || true; }

body() { grep -v '^#' "$1" | sed '/^$/d'; }

case "$MODE" in
    --check)
        [[ -f "$LOCK" ]] || { echo "$LOCK not found" >&2; exit 1; }
        tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
        cp "$LOCK" "$tmp"
        compile "$tmp"                      # no --upgrade: existing pins are kept while they still satisfy
        if diff <(body "$LOCK") <(body "$tmp") >/dev/null; then
            echo "ok: $LOCK is a valid hash-pinned resolution of requirements.txt"
        else
            echo "FAIL: $LOCK no longer matches requirements.txt (a requirement was added, removed or" >&2
            echo "      changed). Regenerate it:  scripts/refresh-lock.sh --refresh" >&2
            diff <(body "$LOCK") <(body "$tmp") | head -20 >&2 || true
            exit 1
        fi
        ;;
    --refresh)
        tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
        compile "$tmp"                      # fresh file: resolves everything to the newest allowed release
        { header "$LOCK"; cat "$tmp"; } > "$LOCK.new"
        mv "$LOCK.new" "$LOCK"
        echo "wrote $LOCK ($(grep -c '^[A-Za-z0-9].*==' "$LOCK") pinned packages)"
        ;;
    -h|--help|"") usage; [[ -n "$MODE" ]] || exit 2 ;;
    *) echo "unknown option: $MODE" >&2; usage >&2; exit 2 ;;
esac
