#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  scripts/gen-env.sh — create or complete .env with RANDOM secrets. Never prints a secret.
#
#    scripts/gen-env.sh            create .env from .env.example if missing (mode 600), then fill in
#                                  every database password that is empty or a known placeholder.
#                                  Idempotent: values you set yourself are never touched.
#    scripts/gen-env.sh --check    change nothing; exit 1 if .env is missing or still has an empty /
#                                  placeholder secret (used by `make up`, setup.sh and CI).
#
#  The docker-compose.yml refuses to start without MONGO_PASSWORD and REDIS_PASSWORD, so a
#  copy of .env.example that skipped this script fails with a clear message instead of
#  running with a guessable password.
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT/.env}"
EXAMPLE="${ENV_EXAMPLE:-$ROOT/.env.example}"
MODE="${1:-}"

SECRETS=(MONGO_PASSWORD REDIS_PASSWORD)

# 192 bits from the kernel CSPRNG, hex: strong, and safe inside a URI without escaping.
random_secret() { od -An -N24 -tx1 /dev/urandom | tr -d ' \n'; }

is_placeholder() {   # empty, or the old shipped default, or anything that says "change me"
    local v="${1:-}"
    [[ -z "$v" || "$v" =~ ^[Cc]hange ]] || [[ "$v" == "password" || "$v" == "admin" || "$v" == "secret" ]]
}

get() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1; }

set_var() {  # set_var NAME VALUE — replace the line, or append it; rewritten without sed -i (portable)
    local name="$1" value="$2" tmp
    tmp="$(mktemp "$ENV_FILE.XXXXXX")"
    awk -v n="$name" -v v="$value" 'BEGIN{FS=OFS="="; done=0}
        $1==n && !done {print n "=" v; done=1; next} {print}
        END{if(!done) print n "=" v}' "$ENV_FILE" > "$tmp"
    chmod 600 "$tmp"
    mv "$tmp" "$ENV_FILE"
}

if [[ "$MODE" == "--check" ]]; then
    [[ -f "$ENV_FILE" ]] || { echo "FAIL: $ENV_FILE does not exist — run scripts/gen-env.sh" >&2; exit 1; }
    bad=0
    for name in "${SECRETS[@]}"; do
        if is_placeholder "$(get "$name")"; then echo "FAIL: $name is empty or a placeholder in $ENV_FILE" >&2; bad=1; fi
    done
    [[ "$bad" -eq 0 ]] && echo "ok: database secrets are set"
    exit "$bad"
elif [[ -n "$MODE" ]]; then
    echo "usage: scripts/gen-env.sh [--check]" >&2; exit 2
fi

if [[ ! -f "$ENV_FILE" ]]; then
    [[ -f "$EXAMPLE" ]] || { echo "$EXAMPLE not found" >&2; exit 2; }
    ( umask 077; cp "$EXAMPLE" "$ENV_FILE" )
    echo "created $ENV_FILE from .env.example (mode 600)"
fi
chmod 600 "$ENV_FILE"

generated=()
for name in "${SECRETS[@]}"; do
    if is_placeholder "$(get "$name")"; then
        set_var "$name" "$(random_secret)"
        generated+=("$name")
    fi
done

# Connection URIs always mirror the passwords (and are rebuilt if a password was just generated).
mongo_pw="$(get MONGO_PASSWORD)"; redis_pw="$(get REDIS_PASSWORD)"
uri_mongo="mongodb://admin:${mongo_pw}@mongodb:27017/bugbounty?authSource=admin"
uri_redis="redis://:${redis_pw}@redis:6379/0"
current_mongo="$(get MONGO_URI)"; current_redis="$(get REDIS_URL)"
if [[ -z "$current_mongo" || "$current_mongo" == *changeme* || " ${generated[*]:-} " == *" MONGO_PASSWORD "* ]]; then
    set_var MONGO_URI "$uri_mongo"
fi
if [[ -z "$current_redis" || "$current_redis" == *changeme* || " ${generated[*]:-} " == *" REDIS_PASSWORD "* ]]; then
    set_var REDIS_URL "$uri_redis"
fi

if [[ ${#generated[@]} -gt 0 ]]; then
    echo "generated random values for: ${generated[*]}"
else
    echo "$ENV_FILE already has database secrets — nothing to do"
fi
