#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  Bug Bounty MCP Server — setup.sh
#  Does everything: checks deps, configures .env, downloads
#  wordlists, sets up Claude Desktop + Claude CLI + Gemini CLI.
#
#  Usage: ./setup.sh
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

# Everything below uses repo-relative paths (.env, scripts/, docker-compose.yml).
cd "$(dirname "${BASH_SOURCE[0]}")"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}  ✓ $*${RESET}"; }
warn() { echo -e "${YELLOW}  ⚠ $*${RESET}"; }
err()  { echo -e "${RED}  ✗ $*${RESET}"; }
info() { echo -e "${CYAN}  → $*${RESET}"; }
sep()  { echo -e "${CYAN}──────────────────────────────────────────────────${RESET}"; }

echo -e "${BOLD}${CYAN}"
cat << 'EOF'
  ██████╗ ██╗   ██╗ ██████╗     ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
  ██╔══██╗██║   ██║██╔════╝     ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝
  ██████╔╝██║   ██║██║  ███╗    ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝
  ██╔══██╗██║   ██║██║   ██║    ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝
  ██████╔╝╚██████╔╝╚██████╔╝    ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║
  ╚═════╝  ╚═════╝  ╚═════╝     ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝
  Setup v3.0.0
EOF
echo -e "${RESET}"

sep
echo -e "${BOLD}Step 1: Checking prerequisites${RESET}"
sep

# Docker
if command -v docker &>/dev/null; then
    DOCKER_VERSION=$(docker --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
    ok "Docker $DOCKER_VERSION found"
else
    err "Docker not found. Install from https://docs.docker.com/get-docker/"
    exit 1
fi

# Docker daemon running?
if ! docker info &>/dev/null; then
    err "Docker daemon is not running."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        info "Start Docker Desktop app"
    else
        info "Run: sudo systemctl start docker"
    fi
    exit 1
fi
ok "Docker daemon is running"

# Docker Compose
if docker compose version &>/dev/null; then
    ok "Docker Compose v2 found (docker compose)"
    COMPOSE_CMD="docker compose"
elif command -v docker-compose &>/dev/null; then
    ok "Docker Compose v1 found (docker-compose)"
    COMPOSE_CMD="docker-compose"
else
    err "Docker Compose not found."
    info "Install: https://docs.docker.com/compose/install/"
    exit 1
fi

sep
echo -e "${BOLD}Step 2: Setting up configuration${RESET}"
sep

# Creates .env if missing and fills every empty/placeholder database secret with a random
# value (never prints them). docker-compose refuses to start without these — there is no
# default password to fall back to.
if bash scripts/gen-env.sh; then
    ok ".env is ready (random database secrets, mode 600)"
else
    err "Could not create .env with random secrets. Run: bash scripts/gen-env.sh"
    exit 1
fi

sep
echo -e "${BOLD}Step 3: Creating directories${RESET}"
sep

for d in data reports logs screenshots wordlists nuclei-templates n8n-workflows output; do
    mkdir -p "$d"
    ok "Created $d/"
done

sep
echo -e "${BOLD}Step 4: Downloading wordlists${RESET}"
sep

SECLISTS_BASE="https://raw.githubusercontent.com/danielmiessler/SecLists/master"
# shellcheck disable=SC2034  # kept for reference by the optional wordlist helpers below
TOMNOMNOM_BASE="https://raw.githubusercontent.com/tomnomnom"

download_wordlist() {
    local url="$1"
    local dest="$2"
    local name="$3"
    if [[ -f "$dest" ]]; then
        ok "$name already exists"
        return
    fi
    info "Downloading $name..."
    if curl -fsSL --connect-timeout 10 --max-time 60 "$url" -o "$dest" 2>/dev/null; then
        local lines
        lines=$(wc -l < "$dest" | tr -d ' ')
        ok "$name ($lines lines)"
    else
        warn "$name download failed — skipping (not critical)"
        rm -f "$dest"
    fi
}

download_wordlist \
    "$SECLISTS_BASE/Discovery/DNS/subdomains-top1million-20000.txt" \
    "wordlists/subdomains.txt" \
    "subdomains wordlist (20k)"

download_wordlist \
    "$SECLISTS_BASE/Discovery/Web-Content/common.txt" \
    "wordlists/directories.txt" \
    "directories wordlist"

download_wordlist \
    "$SECLISTS_BASE/Discovery/Web-Content/burp-parameter-names.txt" \
    "wordlists/parameters.txt" \
    "parameters wordlist"

download_wordlist \
    "$SECLISTS_BASE/Fuzzing/LFI/LFI-Jhaddix.txt" \
    "wordlists/lfi.txt" \
    "LFI payloads"

sep
echo -e "${BOLD}Step 5: Building Docker image${RESET}"
sep

info "Building Docker image (this takes 5–10 minutes first time, ~2 min after cache)..."
if $COMPOSE_CMD build 2>&1 | tail -20; then
    ok "Docker image built successfully"
else
    err "Build failed. Common fixes:"
    info "  1. Check your internet connection"
    info "  2. Run: $COMPOSE_CMD build --no-cache"
    info "  3. Check Dockerfile for any tool version issues"
    exit 1
fi

sep
echo -e "${BOLD}Step 6: Configuring AI clients${RESET}"
sep

# shellcheck disable=SC2034  # shown in the manual-setup hints printed later
CONTAINER_CMD="docker exec -i bugbounty-mcp python -m mcp_server"

# ── Claude Desktop ────────────────────────────────────────────────────────────
configure_claude_desktop() {
    local config_dir config_file

    if [[ "$OSTYPE" == "darwin"* ]]; then
        config_dir="$HOME/Library/Application Support/Claude"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        config_dir="$HOME/.config/Claude"
    elif [[ "$OSTYPE" == "msys"* ]] || [[ "$OSTYPE" == "win32"* ]]; then
        config_dir="$APPDATA/Claude"
    else
        warn "Unknown OS — skipping Claude Desktop auto-config"
        return
    fi

    config_file="$config_dir/claude_desktop_config.json"
    mkdir -p "$config_dir"

    local mcp_entry
    # shellcheck disable=SC2034  # the config snippets below are written out directly
    mcp_entry=$(cat <<ENTRY
    "bugbounty": {
      "command": "docker",
      "args": ["exec", "-i", "bugbounty-mcp", "python", "-m", "mcp_server"],
      "env": {}
    }
ENTRY
)

    if [[ -f "$config_file" ]]; then
        # Backup existing
        cp "$config_file" "$config_file.bak.$(date +%s)"
        # Check if already has mcpServers
        if python3 -c "
import json, sys
data = json.load(open('$config_file'))
servers = data.setdefault('mcpServers', {})
servers['bugbounty'] = {
    'command': 'docker',
    'args': ['exec', '-i', 'bugbounty-mcp', 'python', '-m', 'mcp_server'],
    'env': {}
}
json.dump(data, open('$config_file', 'w'), indent=2)
print('merged')
" 2>/dev/null; then
            ok "Merged bugbounty server into existing Claude Desktop config"
        else
            warn "Could not merge config. Add manually (see CLAUDE_SETUP.md)"
        fi
    else
        cat > "$config_file" <<EOF
{
  "mcpServers": {
    "bugbounty": {
      "command": "docker",
      "args": ["exec", "-i", "bugbounty-mcp", "python", "-m", "mcp_server"],
      "env": {}
    }
  }
}
EOF
        ok "Created Claude Desktop config at $config_file"
    fi
}

configure_claude_desktop

# ── Claude CLI ────────────────────────────────────────────────────────────────
if command -v claude &>/dev/null; then
    info "Configuring Claude CLI..."
    if claude mcp add bugbounty -- docker exec -i bugbounty-mcp python -m mcp_server 2>/dev/null; then
        ok "Claude CLI: bugbounty MCP server registered"
    else
        warn "Claude CLI config failed. Run manually:"
        info "  claude mcp add bugbounty -- docker exec -i bugbounty-mcp python -m mcp_server"
    fi
else
    info "Claude CLI not found. If you install it later:"
    info "  claude mcp add bugbounty -- docker exec -i bugbounty-mcp python -m mcp_server"
fi

# ── Gemini CLI ────────────────────────────────────────────────────────────────
GEMINI_CONFIG_DIR="$HOME/.gemini"
if [[ -d "$GEMINI_CONFIG_DIR" ]] || command -v gemini &>/dev/null; then
    info "Detected Gemini CLI — writing MCP config..."
    mkdir -p "$GEMINI_CONFIG_DIR"
    GEMINI_CONFIG="$GEMINI_CONFIG_DIR/settings.json"

    if [[ -f "$GEMINI_CONFIG" ]]; then
        python3 -c "
import json
data = json.load(open('$GEMINI_CONFIG'))
data.setdefault('mcpServers', {})['bugbounty'] = {
    'command': 'docker',
    'args': ['exec', '-i', 'bugbounty-mcp', 'python', '-m', 'mcp_server']
}
json.dump(data, open('$GEMINI_CONFIG', 'w'), indent=2)
" 2>/dev/null && ok "Merged bugbounty server into Gemini CLI config" \
              || warn "Could not merge Gemini config. See GEMINI_SETUP.md"
    else
        cat > "$GEMINI_CONFIG" <<EOF
{
  "mcpServers": {
    "bugbounty": {
      "command": "docker",
      "args": ["exec", "-i", "bugbounty-mcp", "python", "-m", "mcp_server"]
    }
  }
}
EOF
        ok "Created Gemini CLI config at $GEMINI_CONFIG"
    fi
else
    info "Gemini CLI not detected. See GEMINI_SETUP.md when you install it."
fi

sep
echo -e "${BOLD}Step 7: Starting services${RESET}"
sep

info "Starting containers..."
if $COMPOSE_CMD up -d; then
    ok "All services started"
else
    err "Startup failed. Check: $COMPOSE_CMD logs"
    exit 1
fi

# Wait for container health
info "Waiting for containers to be healthy..."
sleep 8
if docker inspect bugbounty-mcp --format='{{.State.Status}}' 2>/dev/null | grep -q "running"; then
    ok "bugbounty-mcp is running"
else
    warn "Container may still be starting. Check: $COMPOSE_CMD logs mcp-server"
fi

sep
echo ""
echo -e "${GREEN}${BOLD}  ✓ Setup complete!${RESET}"
echo ""
echo -e "${BOLD}  Quick start:${RESET}"
echo ""
echo -e "${CYAN}  Claude Desktop${RESET}  — Restart the app, then ask:"
echo '  "Use the subdomain_enum tool to find subdomains of example.com"'
echo ""
echo -e "${CYAN}  Claude CLI${RESET}      — Run: claude"
echo '  Then: /mcp  (to see registered servers)'
echo ""
echo -e "${CYAN}  Gemini CLI${RESET}      — Run: gemini"
echo '  Then: @bugbounty subdomain_enum example.com'
echo ""
echo -e "${CYAN}  Manual mode${RESET}     — Run: python hunt.py full example.com"
echo ""
echo -e "${CYAN}  n8n automation${RESET}  — Run: $COMPOSE_CMD --profile automation up -d"
echo "  Then:  $COMPOSE_CMD -f docker-compose.yml -f docker-compose.dev-ports.yml --profile automation up -d"
echo "  and open http://127.0.0.1:5678 — n8n asks you to create the owner account on first visit."
echo ""
echo -e "${CYAN}  View logs${RESET}       — $COMPOSE_CMD logs -f mcp-server"
echo -e "${CYAN}  Stop${RESET}            — $COMPOSE_CMD down"
echo ""
sep
echo -e "${RED}${BOLD}  ⚠  IMPORTANT: Only test targets you have written permission to test.${RESET}"
echo -e "${RED}     Unauthorized scanning is illegal.${RESET}"
sep
echo ""
