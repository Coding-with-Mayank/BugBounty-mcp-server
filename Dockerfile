# ═══════════════════════════════════════════════════════════════
#  Bug Bounty MCP Server - Dockerfile
#  Multi-stage: Go tools → Python runtime
#  Compatible with Claude Desktop, Claude CLI, Gemini CLI
# ═══════════════════════════════════════════════════════════════

# ── Stage 1: Build all Go-based security tools ──────────────────
# Which tools, and what "compatible" means for each, lives in config/tools.yaml —
# the same manifest install-native.sh uses, installed by the same code
# (mcp_server/toolmgr). Nothing in this file pins a tool version, so a rebuild
# months from now gets current, compatible releases.
#
# GO_IMAGE_TAG floats on purpose: current security tools routinely need a newer
# compiler than any fixed Go tag provides. Override to pin it.
ARG GO_IMAGE_TAG=alpine
FROM golang:${GO_IMAGE_TAG} AS go-builder

RUN apk add --no-cache git build-base ca-certificates libpcap-dev python3 py3-yaml

ENV GOPATH=/root/go
ENV PATH=$PATH:/root/go/bin
ENV CGO_ENABLED=1
ENV BBMCP_STATE_DIR=/build/state

WORKDIR /build

# Only what the tool manager needs, so editing application code doesn't re-run the build.
COPY mcp_server/__init__.py mcp_server/__init__.py
COPY mcp_server/toolmgr/ mcp_server/toolmgr/
COPY config/ config/

# TOOLS_REFRESH exists to invalidate Docker's layer cache: without it, `docker
# build` reuses the old tool layer and you'd silently keep last quarter's
# tools. `make refresh-tools` (or --build-arg TOOLS_REFRESH=$(date +%s)) bumps it.
# TOOL_LOCK=config/tool-lock.json reproduces an exact, previously tested set.
# A tool that fails to build is a warning and the build continues (as it always
# did) — unless STRICT_TOOLS=1, which CI uses.
ARG TOOLS_REFRESH=0
ARG TOOL_LOCK=
ARG STRICT_TOOLS=0
RUN echo "tool refresh token: ${TOOLS_REFRESH}" && go version && \
    python3 -m mcp_server.toolmgr install --dest /root/go/bin --allow-root \
        ${TOOL_LOCK:+--lock "$TOOL_LOCK"} $([ "$STRICT_TOOLS" = "1" ] && echo --strict); \
    rc=$?; \
    rm -rf /root/go/bin/.backup /root/go/bin/.staging-*; \
    mkdir -p /build/state && { [ -f /build/state/installed-tools.json ] || echo '{"schema":1,"tools":{}}' > /build/state/installed-tools.json; }; \
    exit $rc

# ── Stage 2: Python runtime ──────────────────────────────────────
FROM python:3.12-slim

LABEL version="3.1.0"
LABEL description="Bug Bounty MCP Server — Works with Claude Desktop, Claude CLI, Gemini CLI"
LABEL maintainer="Coding-with-Mayank"

# System packages: nmap, whois, dnsutils, jq, chromium (for screenshots)
# libcap2-bin: provides setcap, used below to grant naabu raw-socket
# capability without running the whole container as root (see the comment
# on the setcap line for why).
RUN apt-get update && apt-get install -y --no-install-recommends \
    git wget curl nmap dnsutils whois jq \
    build-essential libssl-dev libffi-dev \
    chromium chromium-driver \
    libpcap-dev libcap2-bin \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set Chrome binary for gowitness / httpx screenshots
ENV CHROME_BIN=/usr/bin/chromium
ENV CHROMIUM_FLAGS="--no-sandbox --disable-dev-shm-usage"

WORKDIR /app

# ── Python dependencies: NEWEST compatible, or an exactly LOCKED set — never ambiguous ──
#   --build-arg PYTHON_DEPS=latest   (default) the newest releases requirements.txt allows —
#                                    the same policy as the native installer.
#   --build-arg PYTHON_DEPS=locked   exactly requirements.lock, every package verified against
#                                    its sha256 (--require-hashes): reproducible, and the set CI tests.
# The build prints which one it did, and the image records it (and `pip freeze`) in
# /opt/bbmcp/python-deps.txt — nothing here ever calls an unlocked install "locked".
ARG PYTHON_DEPS=latest
COPY requirements.txt requirements.lock ./
RUN set -eu; \
    case "$PYTHON_DEPS" in \
      latest) echo ">>> Python dependencies: NEWEST compatible (requirements.txt; NOT locked)"; \
              pip install --no-cache-dir --upgrade pip && \
              pip install --no-cache-dir -r requirements.txt ;; \
      locked) echo ">>> Python dependencies: LOCKED (requirements.lock, --require-hashes)"; \
              pip install --no-cache-dir --require-hashes -r requirements.lock ;; \
      *) echo "PYTHON_DEPS must be 'latest' or 'locked' (got '$PYTHON_DEPS')" >&2; exit 2 ;; \
    esac; \
    mkdir -p /opt/bbmcp && { echo "mode=$PYTHON_DEPS"; pip freeze; } > /opt/bbmcp/python-deps.txt
LABEL org.bbmcp.python-deps="${PYTHON_DEPS}"

# Copy all Go binaries — deliberately AFTER pip install, not before.
# requirements.txt includes the Python `httpx` HTTP client library, which
# ships its own CLI entry point also named `httpx` (`from httpx import
# main`) — pip installs it to this same /usr/local/bin/ directory for this
# base image. Whichever of the two installs runs last wins that filename.
# With the old ordering (Go tools copied in, then pip install after), pip's
# httpx script silently overwrote ProjectDiscovery's httpx binary in every
# build, breaking alive_check/tech_detect/the screenshot fallback with no
# error at build time — shutil.which("httpx") still finds *something*
# there, so it looks healthy right up until a handler tries to actually
# run it. Copying the Go tools last makes the real httpx binary win.
COPY --from=go-builder /root/go/bin/ /usr/local/bin/
# The exact versions this image was built with (read by `hunt doctor`).
COPY --from=go-builder /build/state/installed-tools.json /opt/bbmcp/installed-tools.json
ENV BBMCP_IMAGE_STATE=/opt/bbmcp

# naabu's SYN-scan mode needs CAP_NET_RAW to open raw sockets. The container
# itself currently still runs as root (see AGENTS.md's "Known gaps" for why
# a full non-root switch is deferred — it isn't this), so this line isn't
# load-bearing *today*; it's here so naabu keeps working at full speed
# (SYN scan, not the slower connect-scan fallback) the moment the container
# does switch to a non-root user, without that switch depending on also
# getting this exactly right under time pressure. Granting the capability
# directly to the binary (rather than to the whole container) means it
# works for a non-root process without granting it anything else naabu
# doesn't need. Failure here degrades naabu to connect-scan mode, which
# naabu already does gracefully on its own when it lacks the capability —
# never a hard failure either way.
RUN setcap cap_net_raw+ep /usr/local/bin/naabu 2>&1 || echo "WARN: setcap on naabu failed (naabu will fall back to connect-scan mode)"

# Create necessary directories
RUN mkdir -p /app/data /app/reports /app/logs /app/screenshots \
             /root/.config/nuclei /root/.config/subfinder \
             /root/.config/gowitness

# Update Nuclei templates (graceful failure if no internet)
RUN nuclei -update-templates 2>/dev/null || echo "Nuclei template update skipped"

# Copy application code
COPY . /app/

RUN chmod +x /app/setup.sh 2>/dev/null || true

# Validation: every required tool present, runnable, and still accepting the
# flags the handlers pass it. Warns by default; fails the build with STRICT_TOOLS=1.
ARG STRICT_TOOLS=0
RUN python -m mcp_server.toolmgr verify || [ "$STRICT_TOOLS" != "1" ]

# Volumes for persistent data
VOLUME ["/app/data", "/app/reports", "/app/logs", "/app/screenshots"]

# MCP server runs on stdio — no port needed for MCP protocol.
# 8080 = the health/status API. It listens on 127.0.0.1 INSIDE the container unless
# HEALTH_HOST says otherwise (docker-compose.dev-ports.yml sets it, and maps the port
# to the host's loopback only). EXPOSE is documentation; it publishes nothing.
EXPOSE 8080

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Default: run MCP server (Claude/Gemini connects via docker exec)
CMD ["python", "-m", "mcp_server"]
