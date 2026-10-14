# AGENTS.md

Orientation for AI coding agents (Claude Code, etc.) working on this repo.
This describes what actually exists today — not a roadmap.

## What this is

An MCP server that wraps common bug-bounty recon/scanning CLI tools
(subfinder, httpx, nuclei, naabu, katana, ffuf, dnsx, waybackurls, gau,
gowitness) behind 32 MCP tools (22 recon/scan/intel/analysis + 5 for
background task management + `get_capabilities` + 4 for Smart Hunt, the
AI-guided workflow — see below), so an AI agent (Claude Desktop, Claude
CLI, Gemini CLI) can drive an authorized recon/scan workflow without
shelling out directly. There's also `hunt.py`, a standalone interactive
CLI for a human running the same underlying tools by hand, and
`install-native.sh`, which installs everything (Python venv, the Go tools
resolved at install time from `config/tools.yaml`, wordlists, Nuclei
templates) without Docker.

This is for **authorized** security testing only. See "Security boundaries"
below before touching anything scope-related.

## Architecture

```
mcp_server/
├── server.py       All 32 MCP tool schemas + handlers + the stdio/health
│                     servers. ~1650 lines, one big file — see "Where
│                     things live" below.
├── core.py          Shared by server.py AND hunt.py: run_cmd() (streaming
│                     subprocess execution — incremental reads via two
│                     background drain-reader tasks, not communicate(), so
│                     a killed process's output-so-far is recoverable, not
│                     just its exit code), is_valid_domain()/sanitize()/
│                     reject_flag_injection()/targets_tempfile(), and
│                     capture_partial_results() — a context-manager sink
│                     that tasks.py uses to recover a cancelled/timed-out
│                     task's output (see below).
├── scope.py         Authorization boundary enforcement. Pure sync pattern-
│                     matching (evaluate()) plus a DNS-resolution-aware
│                     wrapper (resolve_and_check()) that also checks what a
│                     hostname currently resolves to, not just the string.
├── tasks.py          TaskManager — background execution for start_task/
│                     get_task_status/get_task_results/cancel_task/
│                     list_tasks. Wraps any handler in TOOL_HANDLERS in a
│                     cancellable asyncio.Task with soft/hard timeouts;
│                     doesn't know about server.py at all (the handler
│                     lookup is injected). A cancelled/timed-out/failed
│                     task's partial output is preserved (via core.py's
│                     capture_partial_results), not discarded. Optionally
│                     persists task history to disk via persistence.py —
│                     survives a restart; a task that was still
│                     queued/running when the process died is reported
│                     INTERRUPTED, never silently resumed.
├── persistence.py   JsonStore — small dependency-free JSON-file store
│                     (atomic writes, owner-only permissions, ID
│                     validation, corrupt-file quarantine). Backs both
│                     tasks.py's history and smart_hunt.py's sessions.
│                     Deliberately not a database — requirements.txt lists
│                     motor/redis but nothing in the code uses them.
├── smart_hunt.py     Smart Hunt — the AI-guided workflow. Decision support
│                     on top of the MCP tools above, NOT a second AI model
│                     embedded in the server: it tracks what's been found
│                     and recommends one next tool call at a time; the
│                     calling agent still decides what to do with each
│                     result. Refuses to start while ALLOWED_SCOPE is
│                     empty; every recommended target is independently
│                     re-checked against scope; target-derived text
│                     (titles, subdomains) is treated as untrusted before
│                     it can reach a model's context.
├── capabilities.py  Environment/tool diagnostics — shared by the
│                     get_capabilities MCP tool, the /health and
│                     /capabilities HTTP endpoints, AND hunt.py's `doctor`
│                     command. One REQUIRED_TOOLS/OPTIONAL_TOOLS list, not
│                     three copies.
├── guidance.py       GuidanceEngine — generates the "next steps" /
│                     confidence framing attached to every tool result.
└── config.py         pydantic-settings Settings, read from .env / env vars.

hunt.py             Standalone CLI. Shares core.py (run_cmd, scope
                    enforcement via scope_allows()/filter_in_scope(),
                    argv validation) and capabilities.py with server.py —
                    same-repo import, hunt.py sits at the repo root right
                    next to the mcp_server package. Active commands
                    (scan/fuzz/screenshot/full/alive) are scope-gated the
                    same way server.py's handlers are.

install-native.sh  Installs everything server.py/hunt.py need without
                    Docker: Python venv, Go tools under bin/tools/,
                    wordlists, Nuclei templates, launcher scripts. Tool
                    installs are delegated to mcp_server.toolmgr (the SAME
                    code the Dockerfile runs). Idempotent; --dry-run/--check/
                    --print-config/--lock/--locked-python/--offline/
                    --enable-auto-update supported.

config/tools.yaml   THE single source of truth for external tools: tested
                    major, minimum version, compatibility flags, update
                    policy. There is deliberately no "version to install".
                    NEVER hard-code a tool version anywhere else (a test
                    fails if you do); add a tool/flag here, and list every
                    flag a handler passes under `compat:`.

mcp_server/toolmgr/ Stdlib+PyYAML only (it runs in the Docker Go stage).
                    manifest.py (validated, TRUSTED_OWNERS) · versions.py
                    (policy classifier) · detect.py (candidates, Go build
                    info, selection) · upstream.py (Go proxy / GitHub API,
                    allowlisted hosts, cache) · installer.py (stage →
                    validate → backup → atomic swap → rollback) · ops.py
                    (plans, assets, lock) · autoupdate.py (opt-in systemd,
                    static APT signal) · cli.py (hunt doctor|update|...).
                    Invariants: argv lists only (never a shell); never write
                    outside bin/tools; never touch a system copy; never
                    apply a major without --major; refuse root unless
                    --allow-root; keep working versions on ANY failure.

mcp_server/mcp_compat.py  Registers tool handlers on MCP SDK 1.x (decorators)
                    and 2.x (add_request_handler). scripts/mcp_smoke.py runs
                    a LIVE stdio session — unit tests alone did not catch the
                    2.x `input_schema` field rename; run it on both SDKs.

tests/              pytest suite (551 tests). conftest.py redirects
                    config.py's /app/* default paths to a temp dir — those
                    defaults are only correct inside the Docker image.
```

Every MCP tool is still available as a direct, synchronous call — nothing
about the original 22 tools changed. `start_task` is an *additional* way to
invoke any of them: it runs the same handler in the background instead of
blocking the call until it finishes, and hands back a `task_id` to poll.
There's still no plugin system (the tool handlers in `TOOL_HANDLERS` are
still hardcoded, not dynamically loaded).

### Where things live in server.py

- `TOOLS: list[types.Tool]` — every tool's name/description/JSON schema.
- `TOOL_HANDLERS: dict[str, handler]` — the single tool-name-to-handler
  dispatch table, defined once after all handlers. `call_tool()` (direct
  calls) and `task_manager` (background calls via `start_task`) both read
  from this same dict — there's exactly one dispatch table, not two.
- `call_tool()` — the MCP dispatch entry point; looks up `TOOL_HANDLERS`
  and calls the matching handler directly (blocks until it returns).
- Each `_handler(args: dict) -> dict` does its own validation, scope check,
  and `run_cmd()` call(s), then wraps the result with `result()` (which
  attaches `guide.generate(...)` guidance). This is unchanged regardless of
  whether the handler was called directly or via `start_task`.
- `run_cmd()` — the only place that spawns subprocesses. Always
  `create_subprocess_exec` (never `shell=True`), always has a `timeout=`,
  and explicitly handles `asyncio.CancelledError` by killing the child
  process before re-raising (it's a `BaseException`, not an `Exception` —
  a bare `except Exception` doesn't catch it, so this needs its own
  clause). This is what makes `cancel_task` and the task manager's hard
  timeout actually kill the subprocess instead of leaving it orphaned —
  don't remove it if you're touching `run_cmd`.

## Install / run / test

```bash
# Docker
./setup.sh              # or: docker compose up -d --build
# Native (no Docker, no sudo) — tools resolved at install time, see docs/UPDATING.md
./install-native.sh && ./hunt doctor

# Tests — no Docker or external tools needed, run_cmd is mocked throughout
pip install -r requirements.txt
pip install pytest pytest-asyncio
pytest tests/ -v         # or: make pytest

# Lint / types
ruff check mcp_server/ hunt.py tests/ --ignore E501,E402
mypy mcp_server/          # hunt.py isn't clean under mypy yet, mcp_server/ is
```

CI (`.github/workflows/ci.yml`) runs a Docker build + tool-presence + MCP
smoke test job, a `pytest` job, and a `ruff` job.

## Security boundaries — read before changing server.py or scope.py

- **Never add a generic shell/command-execution tool.** Every tool takes
  structured args and builds an explicit argv list; there is no path from
  arbitrary AI-agent input to an arbitrary shell command, and it needs to
  stay that way.
- **Every handler that sends traffic to a target must call `_scope_check()`
  or `_filter_in_scope()`** (both in `server.py`, both `async`, both go
  through `scope.resolve_and_check()`). Passive-only lookups that never
  contact the target — `subdomain_enum`, `wayback`, `whois_lookup`,
  `cert_search`, `shodan_search` — are the only intentional exceptions.
  If you add a new active-scanning tool, wire the scope check in from the
  start; there's a test in `tests/test_server.py::TestHandlerScopeEnforcement`
  for exactly this pattern — copy it for the new handler.
- **`scope.py`'s blocklist always wins over `ALLOWED_SCOPE`.** Don't add a
  bypass, override, or "trusted" flag that lets a scope entry beat the
  blocklist — that's the one thing this project can't get wrong.
- Any value that reaches a subprocess `argv` (domain/target/url) should go
  through `reject_flag_injection()` (or `is_valid_domain()` for
  domain-only params) before use — a value starting with `-` can be
  parsed as a CLI flag by the downstream Go tool instead of as data.
- Don't reintroduce a duplicated inline `tempfile.NamedTemporaryFile(...)`
  block — use the `targets_tempfile()` context manager; it exists because
  the old inline pattern leaked files on exceptions.
- If you add a subprocess-spawning code path that doesn't go through
  `run_cmd()`, it needs its own `CancelledError`-safe kill-on-cancel
  handling — `start_task`/`cancel_task` rely on cancellation actually
  reaching and killing the child process, not just unwinding the
  coroutine.

## Coding conventions

- Python 3.11+, type hints on new code, `ruff` clean (`select =
  ["E","F","W","I","UP","B","SIM"]`, see `pyproject.toml`).
- `run_cmd()`/subprocess calls: always argv list, always a timeout, never
  `shell=True`.
- New MCP tools: add the schema to `TOOLS` and the handler to the
  `TOOL_HANDLERS` dict — that one addition makes it available both via
  direct `call_tool()` calls and via `start_task`, since both read the same
  dict. Follow the existing `_handler(args: dict) -> dict` shape, wrapped
  in `result()`.
- Tests mock `run_cmd` and `server.dns_resolver` — never make a test that
  depends on live network or a live security-tool binary being installed.
  The one exception is `TestRunCmdCancellation`/`TestTaskManagerRealSubprocess`,
  which deliberately spawn a real `sleep` subprocess — the point there is
  proving the OS process actually dies, which a mock can't demonstrate.

## Security & CI invariants (enforced by tests — don't undo them)
- Every CLI entry point goes through `mcp_server/cliutil.run_cli` (broken pipes are not errors; see its docstring for why a plain `except BrokenPipeError` is not enough).
- Workflows: `permissions: {}` at the top, actions pinned to full SHAs, `persist-credentials: false`, write-capable jobs run only `scripts/ci_*.sh`, jobs that run upstream code hold no token. `tests/test_workflow_security.py` + zizmor + actionlint.
- Docker: no published ports in `docker-compose.yml` (loopback-only opt-in in `docker-compose.dev-ports.yml`), no default passwords (`scripts/gen-env.sh`), DB/n8n secrets blanked in the scanner container, n8n pinned. `tests/test_docker_security.py`.
- Health API binds 127.0.0.1 unless `HEALTH_HOST` is set. Docker `PYTHON_DEPS=latest|locked` is explicit and recorded in the image.
- MongoDB/Redis are still started by compose but the application does not use them (persistence.py is file-based); they are internal-only.

## Known gaps (don't assume these exist)

The refactor gap list (TaskManager fixes, shared CLI/MCP core, native
installer, streaming `run_cmd` + partial-result capture, task/session
persistence, Smart Hunt) is done — 335 tests passing, `ruff`/`mypy` clean
across every source file including `hunt.py` (its two former findings were
`COMMANDS`'s handlers having no single sound call signature for mypy to
infer; fixed with an explicit `CommandHandler = Callable[..., Coroutine[Any,
Any, None]]` alias rather than left for mypy to guess at). Smart Hunt's
dict-keyed facts (`tech`, `ports`, `paths` — one entry per distinct host
touched, which the list-oriented per-item `_add()` cap doesn't bound) now
evict their oldest entry once `CAPS["tech_hosts"]`/`"port_hosts"`/
`"fuzz_hosts"` is hit, via the `_set_capped()` helper, mirroring the
oldest-first trimming `tasks.py` does for `max_tracked`.

What's left:

- **The updater (mcp_server/toolmgr, config/tools.yaml) was built and tested
  without Go, Docker or a running systemd.** Everything is covered by unit
  tests against a fake `go`/fake upstream, a live MCP stdio session on SDK
  1.30 and 2.3, and a real `install-native.sh` run (Python side). NOT yet
  exercised against reality — CI (`.github/workflows/ci.yml` native + docker
  jobs) is the first real run, so watch it: an actual `go install` of every
  tool; the Docker build and `STRICT_TOOLS=1` gate; real `--help` output
  matching each `compat:` flag list in `config/tools.yaml` (a flag listed in
  the manifest but absent from a tool's help blocks that tool's update — fix
  the manifest, not the check); the systemd unit files under real
  `systemd --user`; nuclei's `-templates-version` output format (the code
  falls back to `~/.config/nuclei/.templates-config.json`).
- **nuclei is invoked with `-json`** (server.py). nuclei v3's documented flag
  is `-jsonl`/`-j`; whether `-json` is still accepted by current releases is
  unverified. The compat check requires `-json` in the help text, so if it
  was dropped, updates to that release are refused (the old version stays)
  and the weekly freshness job opens an issue — at which point the handler
  should move to `-jsonl`.
- **gowitness stays on v2** (`tested_major: 2`, `major_in_path: false`): v3
  renamed the CLI (`gowitness scan …`) and the handlers speak v2. v3 is
  reported, never auto-installed.

- Smart Hunt (`smart_hunt.py`) is new and deliberately conservative: it
  only recommends one step at a time and never calls a tool itself. Not yet
  covered: a `smart_hunt_resume`-style shortcut for re-attaching to a
  session without knowing its id (`smart_hunt_status` with no `session_id`
  lists them all, which covers this today).
- **The Docker container still runs fully as root.** naabu now has
  `CAP_NET_RAW` applied directly to the binary via `setcap` (so it can do
  SYN scans without needing to be root), but that's prep, not the fix
  itself — the whole container is still root. The reason this is still
  open, concretely: every directory the server writes to is bind-mounted
  from the host in `docker-compose.yml` (`./data`, `./reports`,
  `./screenshots`, `./wordlists`, `./nuclei-templates`, `./logs`,
  `./config/subfinder`), and a bind mount's effective ownership inside
  the container comes from the *host* directory's UID, not from a
  Dockerfile `RUN chown` (which only affects the image layer, which the
  mount then covers up). Fixing this needs a build `ARG` for UID/GID
  (`ARG UID=1000` / `ARG GID=1000`, `useradd -u "$UID" -g "$GID" ...`)
  matched by `user: "${UID:-1000}:${GID:-1000}"` in `docker-compose.yml`
  and `setup.sh` defaulting those to `$(id -u):$(id -g)` of whoever runs
  it — and then an actual `docker-compose up` cycle to confirm it starts
  cleanly and every bind-mounted directory is still writable, which this
  sandbox has no Docker daemon or real host filesystem to verify.

## Don't reorder the Dockerfile's pip-install / Go-tools-copy steps

`requirements.txt` includes the Python `httpx` library, which installs its
own CLI script also named `httpx` — to the same `/usr/local/bin/` the Go
tools are copied to. Whichever step runs last wins that filename. The Go
tools `COPY --from=go-builder` is deliberately positioned *after*
`pip install -r requirements.txt` (see the comment right above it in the
Dockerfile) so the real binary always wins. `tests/test_dockerfile.py` is a
text-based ordering guard, not a real build — there's no Docker daemon in
this environment to verify a build empirically.

See `CHANGELOG.md` for what's already been fixed and why each fix mattered.
