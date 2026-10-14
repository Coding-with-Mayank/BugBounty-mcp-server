#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  BugBounty-mcp-server — native installer (no Docker required)
#
#  Installs everything inside this checkout — nothing global, no sudo:
#    .venv/            Python virtualenv with requirements.txt
#    bin/tools/        ProjectDiscovery + friends — the NEWEST COMPATIBLE release of
#                      each, resolved when you run this (config/tools.yaml says what
#                      "compatible" means). The versions are never baked into this
#                      script, so installing months after the last commit still gets
#                      current tools. Exact versions land in data/installed-tools.json.
#    bin/active/       symlinks to whichever copy of each tool is selected — the newest
#                      compatible one, whether it lives here, in ~/go/bin or on PATH.
#                      Nothing already on your system is ever overwritten.
#    bin/bugbounty-mcp-server   launcher for MCP clients (sets PATH, venv)
#    bin/hunt                   launcher for the standalone CLI
#    wordlists/, data/, reports/, logs/, screenshots/
#
#  Docker is still fully supported — use ./setup.sh for that path.
#  Later:  ./hunt doctor   ./hunt update --check   ./hunt update   (see README)
#
#  Usage:  ./install-native.sh [options]
#    --no-go-tools       skip installing Go-based recon tools
#    --no-wordlists      skip wordlist downloads
#    --no-templates      skip `nuclei -update-templates`
#    --lock FILE         install EXACTLY the tool versions in FILE (see `./hunt snapshot`)
#    --locked-python     install Python deps from requirements.lock (hash-verified)
#    --offline           no network lookups; skips tool/wordlist/template downloads
#    --enable-auto-update  opt in to safe background updates (systemd user timer)
#    --print-config      print the MCP client config snippet and exit
#    --check             only verify an existing install (runs `hunt doctor`)
#    --dry-run           print what would be done, change nothing
#    -h | --help
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

GO_TOOLS=1; WORDLISTS=1; TEMPLATES=1; PRINT_CONFIG=0; CHECK_ONLY=0; DRY_RUN=0
LOCK_FILE=""; LOCKED_PY=0; OFFLINE=0; AUTO_UPDATE=0
while [[ $# -gt 0 ]]; do
    arg="$1"; shift
    case "$arg" in
        --no-go-tools)  GO_TOOLS=0 ;;
        --no-wordlists) WORDLISTS=0 ;;
        --no-templates) TEMPLATES=0 ;;
        --print-config) PRINT_CONFIG=1 ;;
        --check)        CHECK_ONLY=1 ;;
        --dry-run)      DRY_RUN=1 ;;
        --locked-python) LOCKED_PY=1 ;;
        --offline)      OFFLINE=1 ;;
        --enable-auto-update) AUTO_UPDATE=1 ;;
        --lock)         [[ $# -gt 0 ]] || { echo "--lock needs a FILE" >&2; exit 2; }; LOCK_FILE="$1"; shift ;;
        --lock=*)       LOCK_FILE="${arg#--lock=}" ;;
        -h|--help)      sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $arg (try --help)" >&2; exit 2 ;;
    esac
done

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
ok()   { echo "${GREEN}  ✓${RESET} $*"; }
info() { echo "${CYAN}  →${RESET} $*"; }
warn() { echo "${YELLOW}  ⚠${RESET} $*"; }
err()  { echo "${RED}  ✗${RESET} $*" >&2; }
step() { echo; echo "${BOLD}$*${RESET}"; }

# Run a command, or just show it under --dry-run.
run() {
    if [[ $DRY_RUN -eq 1 ]]; then echo "    [dry-run] $*"; else "$@"; fi
}

VENV="$ROOT/.venv"
LAUNCHER="$ROOT/bin/bugbounty-mcp-server"

print_config() {
    cat <<EOF

${BOLD}MCP client configuration${RESET} (Claude Desktop / Gemini CLI / any MCP client):

{
  "mcpServers": {
    "bugbounty-mcp-server": {
      "command": "$LAUNCHER"
    }
  }
}

Claude Desktop config file:
  macOS:  ~/Library/Application Support/Claude/claude_desktop_config.json
  Linux:  ~/.config/Claude/claude_desktop_config.json
Claude Code:  claude mcp add bugbounty-mcp-server -- "$LAUNCHER"

This installer does not edit your client config for you. Merge the snippet
above by hand; set ALLOWED_SCOPE in .env first — empty means open mode (see .env.example).
EOF
}

if [[ $PRINT_CONFIG -eq 1 ]]; then print_config; exit 0; fi

if [[ $CHECK_ONLY -eq 1 ]]; then
    [[ -x "$ROOT/bin/hunt" ]] || { err "Not installed yet. Run ./install-native.sh"; exit 1; }
    exec "$ROOT/bin/hunt" doctor
fi

# ── 1. Platform ──────────────────────────────────────────────────────────────
step "Step 1: Checking platform"
OS="$(uname -s)"
case "$OS" in
    Linux)  ok "Linux ($(uname -m))" ;;
    Darwin) ok "macOS ($(uname -m))" ;;
    *) err "Unsupported OS: $OS. Native install supports Linux and macOS (use WSL2 on Windows, or Docker)."; exit 1 ;;
esac

# ── 2. Python ────────────────────────────────────────────────────────────────
step "Step 2: Python 3.11+"
PYTHON=""
for cand in python3.13 python3.12 python3.11 python3; do
    if command -v "$cand" >/dev/null 2>&1 \
       && "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
        PYTHON="$cand"; break
    fi
done
if [[ -z "$PYTHON" ]]; then
    err "Python 3.11+ not found."
    info "Debian/Ubuntu: sudo apt install python3 python3-venv   |   macOS: brew install python@3.12"
    exit 1
fi
ok "Using $PYTHON ($($PYTHON --version 2>&1))"

if ! "$PYTHON" -c 'import venv, ensurepip' 2>/dev/null; then
    err "Python's venv/ensurepip module is missing."
    info "Debian/Ubuntu: sudo apt install python3-venv"
    exit 1
fi

# ── 3. Virtualenv + dependencies ─────────────────────────────────────────────
step "Step 3: Python environment"
if [[ ! -x "$VENV/bin/python" ]]; then
    info "Creating virtualenv at .venv/"
    run "$PYTHON" -m venv "$VENV"
else
    ok ".venv already exists"
fi
run "$VENV/bin/python" -m pip install --quiet --upgrade pip
if [[ $LOCKED_PY -eq 1 ]]; then
    [[ -f requirements.lock ]] || { err "requirements.lock not found"; exit 1; }
    info "Installing requirements.lock — exact versions, hashes verified (this can take a minute)..."
    run "$VENV/bin/python" -m pip install --quiet --require-hashes -r requirements.lock
else
    info "Installing requirements.txt — newest releases within the supported ranges (this can take a minute)..."
    run "$VENV/bin/python" -m pip install --quiet -r requirements.txt
fi
# The Python `httpx` library installs a CLI script named `httpx`, which would
# shadow ProjectDiscovery's httpx (same collision the Dockerfile documents).
# The library stays importable; only the stray CLI script goes.
run rm -f "$VENV/bin/httpx"
ok "Python dependencies installed"

# ── 4. Go + recon tools ──────────────────────────────────────────────────────
step "Step 4: Recon tools"
# Which tools, which versions and what "compatible" means all live in
# config/tools.yaml; mcp_server.toolmgr resolves the newest compatible release
# of each NOW, builds it into a staging dir, runs a compatibility self-test and
# only then moves it into bin/tools/. The Dockerfile uses the same code.
# A failed tool is a warning, not fatal — `hunt doctor` reports what's missing.
TOOLMGR=("$VENV/bin/python" -m mcp_server.toolmgr)
if [[ $GO_TOOLS -eq 0 ]]; then
    warn "Skipped (--no-go-tools). Tools already on your PATH will still be used."
elif [[ $DRY_RUN -eq 1 ]]; then
    info "Would resolve the newest compatible release of every tool in config/tools.yaml and install it into bin/tools/"
    [[ -n "$LOCK_FILE" ]] && info "…at the exact versions pinned in $LOCK_FILE"
    echo "    [dry-run] ${TOOLMGR[*]} install ${LOCK_FILE:+--lock $LOCK_FILE}"
elif [[ $OFFLINE -eq 1 ]]; then
    warn "Offline: not resolving or building tools. Existing copies on this machine will be used."
else
    if GO_BIN="$(command -v go 2>/dev/null)" || { [[ -x /usr/local/go/bin/go ]] && GO_BIN=/usr/local/go/bin/go; }; then
        ok "Go: $("$GO_BIN" version | awk '{print $3}')"
    else
        warn "Go not found — can't build the recon tools."
        info "Install Go 1.21+ (https://go.dev/dl/ | brew install go | apt install golang-go), then re-run."
        info "Or re-run with --no-go-tools if you already have the tools on PATH."
    fi
    install_args=(install)
    [[ -n "$LOCK_FILE" ]] && install_args+=(--lock "$LOCK_FILE")
    "${TOOLMGR[@]}" "${install_args[@]}" || warn "Some tools could not be installed (continuing) — see ./hunt doctor"
fi
# Whatever happened above, point bin/active at the best copy of each tool
# (newest compatible: bin/tools, ~/go/bin or PATH) so launchers pick the right one.
if [[ $DRY_RUN -eq 0 && -x "$VENV/bin/python" ]]; then
    "${TOOLMGR[@]}" config tools refresh >/dev/null 2>&1 || warn "Could not refresh tool selection (run ./hunt config tools)"
fi

# System tools the Dockerfile apt-installs. Report, don't install (no sudo here).
for t in nmap dig whois; do
    if command -v "$t" >/dev/null 2>&1; then ok "$t found"
    else warn "$t not found (optional) — Debian/Ubuntu: sudo apt install nmap dnsutils whois | macOS: brew install nmap bind whois"; fi
done

# ── 5. Directories, .env, config ─────────────────────────────────────────────
step "Step 5: Directories and configuration"
for d in data reports logs screenshots wordlists output; do run mkdir -p "$d"; done
ok "Created data/ reports/ logs/ screenshots/ wordlists/ output/"

if [[ ! -f .env ]]; then
    if [[ -f .env.example ]]; then run cp .env.example .env; ok "Created .env from .env.example"
    else
        if [[ $DRY_RUN -eq 0 ]]; then
            cat > .env <<'EOF'
# Authorization scope. Comma-separated; wildcards allowed (*.example.com).
# WARNING: empty means "open mode" — active tools will scan ANY target except
# BLOCKED_TARGETS. Set this to the programs you are authorized to test.
# (Smart Hunt, the AI-guided workflow, refuses to start without it.)
ALLOWED_SCOPE=
BLOCKED_TARGETS=
EOF
        fi
        ok "Created .env — set ALLOWED_SCOPE to the programs you are authorized to test"
    fi
else
    ok ".env already exists (left untouched)"
fi

# subfinder reads ~/.config/subfinder; point it at the repo's config only if
# the user has none, never overwrite theirs.
if [[ -f config/subfinder/config.yaml && ! -e "$HOME/.config/subfinder/config.yaml" ]]; then
    run mkdir -p "$HOME/.config/subfinder"
    run cp config/subfinder/config.yaml "$HOME/.config/subfinder/config.yaml"
    ok "Installed default subfinder config"
fi

# ── 6. Wordlists ─────────────────────────────────────────────────────────────
step "Step 6: Wordlists"
if [[ $WORDLISTS -eq 0 || $OFFLINE -eq 1 ]]; then
    warn "Skipped (--no-wordlists / --offline)"
else
    SECLISTS="https://raw.githubusercontent.com/danielmiessler/SecLists/master"
    fetch() {
        local url="$1" dest="$2" name="$3"
        if [[ -f "$dest" ]]; then ok "$name already present"; return; fi
        if [[ $DRY_RUN -eq 1 ]]; then echo "    [dry-run] curl $url -> $dest"; return; fi
        if curl -fsSL --connect-timeout 10 --max-time 60 "$url" -o "$dest" 2>/dev/null; then
            ok "$name ($(wc -l < "$dest" | tr -d ' ') lines)"
        else
            rm -f "$dest"; warn "$name download failed — not critical"
        fi
    }
    fetch "$SECLISTS/Discovery/DNS/subdomains-top1million-20000.txt" wordlists/subdomains.txt "subdomains (20k)"
    fetch "$SECLISTS/Discovery/Web-Content/common.txt"               wordlists/directories.txt "directories"
    fetch "$SECLISTS/Discovery/Web-Content/burp-parameter-names.txt" wordlists/parameters.txt  "parameters"
    fetch "$SECLISTS/Fuzzing/LFI/LFI-Jhaddix.txt"                    wordlists/lfi.txt         "LFI payloads"
fi

# ── 7. Launchers ─────────────────────────────────────────────────────────────
step "Step 7: Launchers"
# PATH order matters: bin/active FIRST. It holds one symlink per tool pointing at
# the SELECTED copy — the newest compatible one, so an older project-local binary
# can never shadow a newer system one, and ProjectDiscovery's httpx wins over the
# Python `httpx` CLI. bin/tools is a last-resort fallback only. These wrappers
# are what MCP clients and `hunt` should invoke — not bare `python`, which would
# inherit the client's (usually minimal) PATH and miss the Go tools.
write_launcher() {
    local path="$1" body="$2"
    if [[ $DRY_RUN -eq 1 ]]; then echo "    [dry-run] write $path"; return; fi
    mkdir -p "$(dirname "$path")"
    cat > "$path" <<EOF
#!/usr/bin/env bash
# Generated by install-native.sh — safe to regenerate by re-running it.
ROOT="$ROOT"
export PATH="\$ROOT/bin/active:\$ROOT/.venv/bin:\$PATH:\$ROOT/bin/tools"
export BBMCP_HOME="\${BBMCP_HOME:-\$ROOT}"
cd "\$ROOT"
$body
EOF
    chmod +x "$path"
}
write_launcher "$LAUNCHER"      'exec "$ROOT/.venv/bin/python" -m mcp_server "$@"'
write_launcher "$ROOT/bin/hunt" 'exec "$ROOT/.venv/bin/python" "$ROOT/hunt.py" "$@"'
ok "bin/bugbounty-mcp-server and bin/hunt"

# ── 8. Nuclei templates ──────────────────────────────────────────────────────
step "Step 8: Nuclei templates"
# Templates version separately from the nuclei binary; this updates THEM.
if [[ $TEMPLATES -eq 0 ]]; then warn "Skipped (--no-templates)"
elif [[ $OFFLINE -eq 1 ]]; then warn "Skipped (--offline)"
elif [[ $DRY_RUN -eq 1 ]]; then echo "    [dry-run] hunt update --templates-only"
else
    info "Updating templates (needs internet)..."
    "$ROOT/bin/hunt" update --templates-only >/dev/null 2>&1 || warn "Template update skipped"
fi

# ── 9. Verify ────────────────────────────────────────────────────────────────
step "Step 9: Verifying"
if [[ $DRY_RUN -eq 1 ]]; then
    info "Dry run complete — nothing was changed."
else
    "$ROOT/bin/hunt" doctor || true
    [[ -f data/installed-tools.json ]] && ok "Exact tool versions recorded in data/installed-tools.json"
    if [[ $AUTO_UPDATE -eq 1 ]]; then
        "$ROOT/bin/hunt" auto-update enable --yes || warn "Could not enable automatic updates"
    else
        info "Keep tools current: ./hunt update --check   then   ./hunt update"
    fi
    print_config
    echo
    ok "Done. Docker is optional — ./setup.sh still works if you prefer containers."
fi
