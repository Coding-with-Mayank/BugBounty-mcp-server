# Bug Bounty MCP Server v3.1.0

> **The world's most practical bug bounty setup** — works with Claude Desktop, Claude CLI, Gemini CLI, and standalone terminal mode. One command to install. AI-guided findings with next steps built in.

```
⚠️  Legal Notice: Only test targets you have explicit written permission to test.
    Unauthorized scanning is illegal. This tool is for authorized security testing only.
```

---

## What's inside

| Tool | Purpose |
|------|---------|
| `subfinder` | Passive subdomain discovery (50+ sources) |
| `httpx` | HTTP probing, tech detection, screenshots |
| `nuclei` | 10,000+ vulnerability templates |
| `naabu` | Fast port scanner |
| `katana` | Web crawler |
| `ffuf` | Directory/parameter fuzzer |
| `gobuster` | Brute-force enumeration |
| `gowitness` | Web screenshots |
| `dnsx` | DNS enumeration |
| `waybackurls + gau` | Historical URL discovery |
| `anew` | Deduplicate output streams |

Everything ships in a single Docker container. No Go, no Python, no tool installation on your host.

---

## Quick Start (3 steps)

```bash
git clone https://github.com/Coding-with-Mayank/BugBounty-mcp-server
cd BugBounty-mcp-server
./setup.sh
```

That's it. Setup auto-handles:
- Checking Docker is running
- Creating `.env` with random passwords
- Downloading wordlists
- Building the Docker image
- Configuring **Claude Desktop**, **Claude CLI**, and **Gemini CLI** automatically
- Starting all services

**No Docker?** `./install-native.sh` does the same setup without it — Python
venv, the Go recon tools under `bin/tools/`, wordlists, Nuclei templates,
and launcher scripts, all under the repo directory. No sudo required.
```bash
git clone https://github.com/Coding-with-Mayank/BugBounty-mcp-server
cd BugBounty-mcp-server
./install-native.sh              # full install
./install-native.sh --dry-run    # see what it would do first
./install-native.sh --check      # just verify an existing install
```
Run `./hunt doctor` afterward to confirm everything's on PATH correctly.

**Tool versions are not baked into the repo.** The installer (and the Docker
build) resolve the newest *compatible* release of each tool **when you run
them**, so installing months after the last commit still gets current tools —
see [Keeping tools up to date](#keeping-tools-up-to-date).

---

## Using with Claude Desktop

After setup, restart Claude Desktop. Then just ask naturally:

```
Find all subdomains of example.com
```
```
Run a full recon on example.com and tell me what's interesting
```
```
Scan https://example.com for vulnerabilities and explain any findings
```
```
Take screenshots of these URLs and tell me what looks like admin panels
```

Claude will call the right tools automatically and return findings with guidance on what's suspicious and what to do next.

---

## Using with Claude CLI

Setup auto-registers the server. To verify:
```bash
claude mcp list
# Should show: bugbounty
```

Then in a Claude CLI session:
```
claude> Run full_recon on example.com
```

Manual registration (if setup didn't catch it):
```bash
claude mcp add bugbounty -- docker exec -i bugbounty-mcp python -m mcp_server
```

---

## Using with Gemini CLI

Setup auto-writes `~/.gemini/settings.json`. To verify:
```bash
cat ~/.gemini/settings.json
```

In Gemini CLI:
```
gemini> @bugbounty subdomain_enum domain=example.com
```

Manual setup — add to `~/.gemini/settings.json`:
```json
{
  "mcpServers": {
    "bugbounty": {
      "command": "docker",
      "args": ["exec", "-i", "bugbounty-mcp", "python", "-m", "mcp_server"]
    }
  }
}
```

---

## Manual Terminal Mode (no AI client needed)

`hunt.py` works standalone — no Docker, no MCP client needed — as long as
the required tools (see `python hunt.py doctor`) are on PATH.

```bash
# Check your environment first: Python version, which tools are
# installed, wordlists, native vs Docker
python hunt.py doctor
python hunt.py doctor --json   # for scripting

# Full recon pipeline
python hunt.py full example.com

# Just subdomains
python hunt.py recon example.com

# Vulnerability scan
python hunt.py scan https://example.com --severity high,critical

# Directory fuzzing
python hunt.py fuzz https://example.com/FUZZ --ext php,asp,bak

# Historical URLs
python hunt.py wayback example.com

# Screenshots
python hunt.py screenshot example.com

# Certificate transparency
python hunt.py cert example.com
```

Or run directly inside the Docker container:
```bash
docker exec -it bugbounty-mcp bash
# Now you have all tools available
subfinder -d example.com -silent
nuclei -u https://example.com -severity high,critical
```

---

## Available MCP Tools

### Recon
| Tool | Description |
|------|-------------|
| `full_recon` | Full automated pipeline: subdomains → alive → ports → tech → screenshots |
| `subdomain_enum` | Passive subdomain discovery with subfinder |
| `subdomain_brute` | Active brute-force with wordlist |
| `alive_check` | Probe hosts with httpx (status, title, tech) |
| `port_scan` | Fast TCP port scan with naabu |
| `dns_enum` | DNS records (A, MX, NS, TXT, CNAME) |
| `screenshot` | Web screenshots with gowitness |
| `crawl` | Website crawling with katana |
| `wayback` | Historical URLs from Wayback + gau |
| `tech_detect` | Technology detection with httpx |

### Scanning
| Tool | Description |
|------|-------------|
| `nuclei_scan` | Full vulnerability scan with 10k+ templates |
| `dir_fuzz` | Directory/file fuzzing with ffuf |
| `xss_scan` | Targeted XSS scanning |
| `sqli_scan` | SQL injection scanning |
| `cors_check` | CORS misconfiguration check |

### Intelligence
| Tool | Description |
|------|-------------|
| `whois_lookup` | WHOIS data |
| `cert_search` | Certificate transparency (crt.sh) |
| `shodan_search` | Shodan query (needs API key) |

### Analysis
| Tool | Description |
|------|-------------|
| `analyze_findings` | Prioritize and chain multiple findings |
| `explain_finding` | Explain what a finding means + write-up template |
| `generate_report` | Professional Markdown bug bounty report |

### Utility
| Tool | Description |
|------|-------------|
| `check_scope` | Check whether a target is allowed under `ALLOWED_SCOPE` before scanning it |
| `get_capabilities` | Which tools/Python version/wordlists are actually available right now, and whether this is running natively or in Docker |

### Task Management
| Tool | Description |
|------|-------------|
| `start_task` | Run any tool above in the background instead of blocking until it finishes |
| `get_task_status` | Poll a background task's status and elapsed time |
| `get_task_results` | Fetch a background task's result once it's done |
| `cancel_task` | Stop a running background task (kills the underlying process) |
| `list_tasks` | List tracked tasks, optionally filtered by status or tool, without knowing their IDs |

Every tool works fine called directly — `start_task` is an additional option for
the slow ones (`nuclei_scan`, `dir_fuzz`, `full_recon`, `port_scan` can run for
minutes). It reuses the exact same handler, scope check, and execution as a
direct call; the only difference is you get a `task_id` back immediately and
poll for the result instead of blocking.

```json
// start_task
{"tool": "nuclei_scan", "args": {"targets": ["https://example.com"]}}
→ {"task_id": "task_28e7fe9d33", "status": "running", ...}

// get_task_status, while it's still going
→ {"status": "running", "elapsed_seconds": 75, "soft_timeout_seconds": 60,
   "soft_timeout_exceeded": true, "options": ["continue", "cancel"]}
```

A task past its `soft_timeout` (default 60s) gets flagged in `get_task_status`
— that's informational, not a pause; keep polling to wait, or call `cancel_task`.
Past its `hard_timeout` (default 900s) it's force-cancelled automatically, the
underlying process killed, and the task marked `timed_out`.

**Partial results on cancellation.** If a task is cancelled, hits its hard
timeout, or fails partway through, you still get back whatever its commands
had already produced — not nothing. `get_task_status`/`get_task_results` set
`partial_results_available: true`, and the result looks like:
```json
{"status": "cancelled", "result": {
  "partial": true,
  "note": "Task stopped (cancelled) before finishing. Below is the raw output ...",
  "commands_captured": 2, "captured": [{"cmd": ["subfinder", "-d", "example.com"], "stdout": "..."}]
}}
```
This is raw, unprocessed command output (whole lines only — any in-flight
line fragment is dropped), not the parsed/deduplicated shape a completed
run returns.

**Task history survives a restart.** Tasks are persisted to
`DATA_DIR/tasks/<task_id>.json` as they run (set `PERSIST_TASKS=false` for
purely in-memory behavior). On startup, finished tasks are restored with
`restored_from_previous_session: true`; anything that was still
queued/running when the server stopped is honestly marked `interrupted`
(its process didn't survive) rather than silently resumed. A graceful
shutdown (Ctrl-C, SIGTERM, or stdin closing) cancels any active tasks first,
so their partial output gets saved instead of lost.

---

## Smart Hunt (AI-guided workflow)

| Tool | Description |
|------|-------------|
| `smart_hunt_start` | Start an investigation for a domain — returns a session + the first recommended tool call |
| `smart_hunt_next` | Report a tool's result (directly, or via a `task_id`), get the next recommendation |
| `smart_hunt_status` | Full session state: everything found so far, tools run, pending recommendation |
| `smart_hunt_close` | Stop a session (keeps its history) |

Smart Hunt isn't a separate AI model and it never calls a tool itself — it's
decision support on top of everything above. It tracks what's actually been
discovered and recommends **one** next tool call at a time, instead of your
AI client having to plan the whole recon-to-report pipeline upfront:

```
smart_hunt_start(target="example.com")
  → session_id, recommends: subdomain_enum

[you run subdomain_enum yourself]

smart_hunt_next(session_id, tool="subdomain_enum", result={...})
  → recommends: alive_check (flagged hosts like admin.* / staging.* go first)

... repeat — nuclei findings jump the queue ahead of further recon;
    a critical finding pauses everything else until it's analyzed,
    explained, and written up ...

  → done: true, with a summary and a manual-review list (logic/auth/
    access-control bugs that no automated tool can find)
```

For the slow tools (`nuclei_scan`, `port_scan`, `crawl`, `dir_fuzz`, etc.)
Smart Hunt tells you to run them via `start_task` and hand back the
`task_id` instead of the raw result — it reads the result itself once the
task finishes (or polls-and-waits if you hand it back too early).

Smart Hunt refuses to start while `ALLOWED_SCOPE` is empty ("open mode") —
an AI iterating on its own shouldn't be pointed at "scan anything." Every
recommended target is also independently checked against scope at
recommendation time, as a second check beneath whatever the tool itself
enforces when you call it. Sessions persist the same way tasks do, so a
long hunt survives a server restart.

---

## AI Guidance System

Every tool response includes a `guidance` block explaining:

- **`risk_level`** — info / low / medium / high / critical
- **`suspicious_items`** — patterns that warrant investigation
- **`next_steps`** — exactly what to try next
- **`manual_steps`** — what to do when automated tools can't go further
- **`limitations`** — why the tool may have missed things

Example:
```json
{
  "tool": "subdomain_enum",
  "data": { "count": 0, "subdomains": [] },
  "guidance": {
    "risk_level": "info",
    "summary": "No subdomains found via passive recon.",
    "limitations": "Passive-only recon cannot find subdomains with no public footprint.",
    "next_steps": [
      "Try active brute-force: subdomain_brute tool",
      "Search cert logs: https://crt.sh/?q=%.example.com",
      "Google dork: site:*.example.com -www",
      "Check VirusTotal: https://virustotal.com/gui/domain/example.com/relations"
    ],
    "manual_steps": [
      "Zone transfer: dig axfr example.com @ns1.example.com",
      "Reverse DNS: for ip in $(host example.com | awk '{print $4}'); do host $ip; done"
    ]
  }
}
```

---

## n8n Workflow Automation (optional)

n8n gives you visual workflows for scheduled scans and notifications.

```bash
# Start with n8n (published on 127.0.0.1 only)
make n8n
# OR
docker compose -f docker-compose.yml -f docker-compose.dev-ports.yml --profile automation up -d
```

Then open **http://127.0.0.1:5678** and **create the owner account right away** — n8n 1.0+ removed
HTTP basic-auth (older versions of this file set `N8N_BASIC_AUTH_*`, which did nothing), so the
first visitor becomes the owner. That is why the port is bound to loopback and the image is pinned
(`N8N_VERSION`, tested default in `docker-compose.yml`). Never expose 5678 to a network.

Use cases:
- **Scheduled daily recon** — cron trigger → subdomain_enum → diff against yesterday → alert on new
- **Vulnerability alerts** — nuclei_scan → filter critical → Slack/Telegram notification
- **Report pipeline** — findings → generate_report → save to Notion / email

---

## Scoping (legal protection)

Set your allowed targets in `.env`:
```bash
# Only test these — everything else is blocked
ALLOWED_SCOPE=example.com,*.example.com,192.168.1.0/24
```

Every active-scanning tool (`port_scan`, `alive_check`, `dns_enum`, `screenshot`,
`crawl`, `tech_detect`, `nuclei_scan`, `dir_fuzz`, `xss_scan`, `sqli_scan`,
`cors_check`, `subdomain_brute`) checks the target against `ALLOWED_SCOPE` before
sending any traffic, and rejects anything that doesn't match. `BLOCKED_TARGETS`
(localhost, cloud metadata IPs, private ranges, both IPv4 and IPv6) is enforced
unconditionally and can't be overridden by `ALLOWED_SCOPE`. Leave `ALLOWED_SCOPE`
empty to run in open mode — the blocklist still applies, but nothing else is
restricted.

The check isn't just string matching on the hostname: the target is resolved
and its current IP is checked against `BLOCKED_TARGETS` too, so a name that's
in scope but currently resolves into a blocked range (a stale record, or a
DNS-rebinding attempt) is still rejected. A resolution failure doesn't block
the scan — a flaky resolver shouldn't stop an authorized test — but it's
surfaced in the response so you know the IP-level check was inconclusive.

Purely passive lookups that never contact the target directly — `subdomain_enum`
(passive sources), `wayback`, `whois_lookup`, `cert_search`, `shodan_search` —
are exempt, since there's nothing to authorize.

Use the `check_scope` tool to test whether a target is allowed before running a
scan (it returns the resolved IPs too), or to see why one was rejected.

---

## Management

```bash
make up          # Start everything
make down        # Stop everything
make logs        # Follow MCP server logs
make status      # Check all tools are working
make shell       # bash inside the container
make rebuild     # Rebuild after code changes
make update      # git pull + rebuild with the newest compatible tools + templates
make refresh-tools # rebuild so the image gets current tool versions (cache-busted)
make test        # Verify all tools
```

---

## Keeping tools up to date

Three different things get updated by three different commands — they are
independent on purpose:

| Command | Updates | Does **not** touch |
|---|---|---|
| `git pull` | this project's code and `config/tools.yaml` | installed tools |
| `./hunt update` | the Go security tools + nuclei **templates** in this checkout | system packages, copies installed elsewhere |
| `sudo apt update && sudo apt upgrade` | APT-managed packages | **this project** |

> `apt update` / `apt upgrade` updates APT-managed packages. This project is not
> automatically upgraded by APT unless the optional signal integration is
> explicitly enabled (and even then APT itself updates nothing here).

```bash
./hunt doctor              # installed vs latest compatible, per tool (--json for machines)
./hunt update --check      # what's newer? changes nothing
./hunt update --dry-run    # exactly what would happen? changes nothing
./hunt update              # apply (asks first; --yes to skip the question)
./hunt rollback nuclei     # restore the previous version
./hunt snapshot            # record exact versions -> config/tool-lock.json
./hunt install --lock config/tool-lock.json   # reproduce exactly those versions
./hunt config tools        # which copy (system / local / go) of each tool is used
```

**Policy:** patch and minor releases are applied *only after* the staged build
passes a compatibility self-test (the flags the handlers use must still exist);
the old working binary is backed up and restored automatically on any failure.
**Major** releases are never applied silently — they're reported, and
`./hunt update --major` tries one explicitly. If the network is down nothing is
changed. Tools you already have (system or `~/go/bin`) are never overwritten, and
the newest compatible copy wins.

**Automatic updates are opt-in** (`./hunt auto-update enable` — user-level
systemd timer, safe updates only, no root). **Docker:** a new *build* is the
only way to update tools inside an image: `make refresh-tools`.

Everything — the trust model, the exact upgrade policy, APT/systemd details,
reproducible installs, Docker behaviour — is in **[docs/UPDATING.md](docs/UPDATING.md)**.

---

## Project Structure

The package is named `bugbounty-mcp-server` (see `pyproject.toml`), matching
the repo's name on GitHub:

```
BugBounty-mcp-server/
├── Dockerfile              # Multi-stage Go tools + Python runtime
├── docker-compose.yml      # MCP server + MongoDB + Redis + optional n8n (no published ports, no default passwords)
├── docker-compose.dev-ports.yml  # opt-in, 127.0.0.1-only port mappings
├── requirements-dev.txt    # test / lint / CI tooling
├── requirements.txt        # Python deps (lower bounds -> fresh installs get current releases)
├── requirements.lock       # Same deps, exact + hash-verified (./install-native.sh --locked-python)
├── hunt                    # CLI launcher: ./hunt doctor | update | install | rollback | ...
├── pyproject.toml          # ruff/pytest/mypy config
├── .env.example            # Configuration template
├── setup.sh                # One-command Docker installer
├── install-native.sh       # One-command installer without Docker
├── Makefile                # Convenience commands
├── hunt.py                 # Standalone manual CLI
├── mcp_server/
│   ├── __main__.py         # Entry point: python -m mcp_server
│   ├── server.py           # All 32 MCP tools
│   ├── core.py             # Shared run_cmd/validation (used by server.py AND hunt.py)
│   ├── guidance.py         # Smart guidance engine
│   ├── scope.py            # ALLOWED_SCOPE / BLOCKED_TARGETS enforcement
│   ├── tasks.py            # Background task lifecycle (start_task etc.)
│   ├── smart_hunt.py       # Smart Hunt: AI-guided next-step recommendations
│   ├── persistence.py      # JSON file store (tasks + Smart Hunt sessions)
│   ├── capabilities.py     # Environment/tool diagnostics (get_capabilities, doctor)
│   ├── mcp_compat.py       # Registers handlers on MCP SDK 1.x AND 2.x
│   ├── toolmgr/            # Tool manager: manifest, detection, upstream lookup, install/update/rollback
│   └── config.py           # Settings
├── tests/                  # pytest suite (551 tests: scope, tasks, core, persistence,
│                            #   smart_hunt, capabilities, server handlers, native install,
│                            #   toolmgr: policy/rollback/security, MCP 1.x+2.x compat)
├── config/
│   ├── tools.yaml          # SINGLE source of truth for external tools (see docs/UPDATING.md)
│   ├── tool-lock.json      # Exact tool versions, for reproducible installs
│   └── subfinder/          # Subfinder API config
├── docs/UPDATING.md        # How versions/updates/rollback/auto-update work + trust model
├── scripts/mcp_smoke.py    # Live MCP stdio session test (native, launcher, or Docker)
├── .github/workflows/      # ci.yml (build/test) + freshness.yml (weekly staleness check)
├── wordlists/              # Downloaded by setup.sh / install-native.sh
├── n8n-workflows/          # n8n automation workflows
├── data/                   # Task + Smart Hunt session persistence (native install; git-ignored)
├── reports/                # Generated reports (git-ignored)
├── screenshots/            # gowitness screenshots (git-ignored)
└── output/                 # Manual hunt output (git-ignored)
```

---

## Troubleshooting

**Not sure what's wrong?** Start here:
```bash
python hunt.py doctor
# Or, from an MCP client: call the get_capabilities tool
# Or over HTTP from inside the container: docker exec bugbounty-mcp curl -s http://127.0.0.1:8080/capabilities
```
Shows Python version, every required/optional tool with its installed vs
latest compatible version and status (OK / UPDATE / MAJOR / MISSING / BROKEN /
INCOMPATIBLE), where each binary came from, nuclei templates, PATH problems,
the MCP SDK in use, wordlist presence, and whether it detects Docker or native.
`./hunt doctor --json` prints the same as a single JSON document.

**`docker compose` says `MONGO_PASSWORD is not set`:** that is intentional — there are no default
passwords. Run `./setup.sh` (or just `scripts/gen-env.sh`) to create `.env` with random secrets.

**Build fails:**
```bash
docker compose build --no-cache
```

**Reproducible image (exact Python dependencies):**
```bash
make build-locked        # = PYTHON_DEPS=locked docker compose build  → requirements.lock, sha256-verified
docker run --rm bugbounty-mcp:latest head -1 /opt/bbmcp/python-deps.txt    # mode=locked | mode=latest
```
The default build uses the newest releases `requirements.txt` allows (`mode=latest`) — the same
policy as the native installer. The image always records which one you got.

**Tool missing inside container:**
```bash
make shell
# Check: which subfinder
# If missing, the Go build step for that tool failed.
# Usually a network issue during build — retry: make refresh-tools
# (a plain rebuild reuses the cached tool layer; refresh-tools forces a fresh resolve)
```

**MCP server not showing in Claude:**
```bash
# Verify container is running
docker ps | grep bugbounty-mcp
# Restart Claude Desktop after running setup.sh
```

**Need MongoDB / Redis / the health API from the host?** Nothing is published by default (the MCP
client reaches the server through `docker exec -i bugbounty-mcp python -m mcp_server`, not a port).
Opt in, loopback only:
```bash
docker compose -f docker-compose.yml -f docker-compose.dev-ports.yml up -d
# 127.0.0.1:8080 health · 127.0.0.1:27017 mongo · 127.0.0.1:6379 redis · 127.0.0.1:5678 n8n (profile)
# Port already in use? Edit the left-hand number in docker-compose.dev-ports.yml.
```

**Screenshots not working:**
```bash
# gowitness needs Chromium (included in Dockerfile)
# If still failing:
docker exec bugbounty-mcp gowitness single -u https://example.com --disable-db
```

---

## License

MIT — use freely for authorized security testing.

**Remember:** Authorization first, always.
