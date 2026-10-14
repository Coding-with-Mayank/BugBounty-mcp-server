# Changelog

## Unreleased — security & reliability audit (CI, Docker, pipes, dependency locks)

### Fixed
- **`hunt doctor | head` (and every CLI command) no longer ends in a traceback / exit 120.**
  Output smaller than the 8 KiB stdio buffer is only written by the interpreter's exit-time flush,
  which ran after every `except BrokenPipeError` had been left, and `hunt.py`'s
  `sys.exit(toolmgr_main())` path sat outside the guard. New `mcp_server/cliutil.run_cli` flushes
  inside the guarded block and points the dead descriptor at /dev/null. Intermittent by nature
  (it depended on whether the reader left before or after that flush), so the existing test only
  failed sometimes; `tests/test_cliutil.py` reproduces it deterministically (fails on the old code).
- **`mypy` failed under MCP SDK 2.x** (`mcp_compat.py`'s 1.x-only branch). Now clean under 1.x and 2.x.
- **Weekly freshness could never report a failed compatibility check**: `cmd | tee file` under the
  default `bash -e` (no `pipefail`) always "succeeded". All workflows now use `shell: bash`.
- `hunt update --offline` said "Update check failed"; it now says it was offline and changed nothing.

### Security
- **freshness.yml rewritten with a trust split.** Jobs that install/run upstream code (Go modules,
  PyPI packages, the tools) are `contents: read`, hold no token and persist no credentials; their
  only output is artifacts. A separate `publish` job holds the write token, executes nothing from
  upstream, and re-validates every artifact (`scripts/ci_publish_guard.py`: the project's own lock
  validator, strict hash-pinned-only Python lock grammar, sanitised issue text). A separate `notify`
  job has `issues: write` only. PRs it opens now get CI started via `workflow_dispatch`.
- **All Actions pinned to full commit SHAs** (Dependabot keeps them current, 7-day cooldown);
  `permissions: {}` at the top of every workflow; `persist-credentials: false` on every checkout.
- `tests/test_workflow_security.py` (+ zizmor and actionlint in CI) fail the build if a global write
  permission, a workflow-wide token, an unpinned action, or a write-capable job that runs upstream
  code ever returns. On the original files zizmor reported 32 findings (19 high); now 0.
- **Docker: nothing is published by default.** MongoDB (27017), Redis (6379), the health API (8080)
  and n8n (5678) were published on every interface. Opt-in loopback-only mappings live in
  `docker-compose.dev-ports.yml`.
- **No default passwords.** `${MONGO_PASSWORD:-changeme_please}` fallbacks removed; compose refuses
  to start without secrets; `.env.example` ships them empty; `scripts/gen-env.sh` (used by
  `setup.sh` and `make up`) generates 192-bit random values, never prints them, mode 600.
  Redis's password no longer appears in the process list / `docker inspect`.
- The scanner container no longer receives the database / n8n secrets (they were forwarded by `env_file`).
- **n8n**: `N8N_BASIC_AUTH_*` had been removed from n8n in 1.0 and protected nothing, on `:latest`,
  on all interfaces. Now pinned (`N8N_VERSION`), loopback-only, telemetry off, `executeCommand` excluded.
- The health API binds `127.0.0.1` unless `HEALTH_HOST` says otherwise (`/capabilities` is unauthenticated).
- `no-new-privileges` on every container; `init: true` on the scanner container.

### Added
- `PYTHON_DEPS=latest|locked` Docker build switch (`make build-locked`); the image records which in
  `/opt/bbmcp/python-deps.txt`. `scripts/refresh-lock.sh --check|--refresh`; CI now FAILS on lock
  drift (it only warned) and tests `locked` alongside MCP 1.x and 2.x on Python 3.11 / 3.12 / 3.13.
- `pip-audit` of `requirements.lock`, actionlint, zizmor and shellcheck of every script in CI.
- `hunt update --help` and its output state what it does and does not manage.

### Not done / unverified here (see the audit report)
- Non-root container (needs a real compose cycle to verify bind-mount ownership).
- Docker, Go tool installs and real GitHub Actions runs were not executable in the audit sandbox.


## Unreleased — tools and dependencies stay current (no more hard-coded versions)

Installing months after the last commit used to install the versions that
were hard-coded in `install-native.sh` and the `Dockerfile` (and the two
lists were kept in sync by a test that asserted they matched — i.e. it
guarded the staleness). They are gone. See `docs/UPDATING.md`.

### Added

- **`config/tools.yaml`** — the single source of truth for external tools:
  `tested_major`, `min_version` (the old pins, so nothing can downgrade),
  compatibility flags, update policy. No "version to install" field exists.
- **`mcp_server/toolmgr/`** — resolves the newest *compatible* release at
  install/update time (Go module proxy, GitHub Releases as fallback), builds
  it in a private staging dir, validates it (identity, version, flag
  self-test), backs up the working binary, swaps atomically, re-verifies,
  and restores on any failure. Used by `install-native.sh`, `hunt`, the
  systemd timer, CI **and the Dockerfile** — one code path.
- **`./hunt`** launcher and commands: `doctor [--json --offline --selftest
  --strict]`, `update [--check --dry-run --yes --major --offline --tool
  --templates-only]`, `install [--lock]`, `rollback`, `snapshot`, `config
  tools`, `auto-update enable|disable|status`, `verify`.
- Policy: patch/minor applied only after the self-test; **major never
  silent** (`--major`); 0.x minors count as major; never a downgrade; network
  failure changes nothing.
- Existing tools are detected first (project-local, `~/go/bin`, `PATH`);
  system copies are never overwritten; the **newest compatible copy wins**
  via `bin/active/` symlinks (previously `bin/tools` always won, so an older
  local binary shadowed a newer system one).
- nuclei **engine and templates** reported and updated separately.
- Version detection from the binary's embedded Go build info — works for
  tools with no `--version` flag (waybackurls, anew, httprobe), which are
  never executed (they'd block on stdin).
- `config/tool-lock.json` (the exact set the repo shipped before) and
  `requirements.lock` (hash-verified, universal) for reproducible installs:
  `install --lock`, `install-native.sh --lock / --locked-python`.
- Opt-in automatic updates: user-level systemd timer; optional APT *signal*
  (a root hook that only `touch`es a marker — **no repository code ever runs
  as root**; the root-side text is printed for you to read and run).
- Docker: tool versions resolved at build time by the same manifest;
  `TOOLS_REFRESH` (cache-bust), `TOOL_LOCK`, `STRICT_TOOLS`, floating
  `GO_IMAGE_TAG`; a build-time `verify` gate; `make refresh-tools`.
- CI: Docker (strict) + native (fresh, from-lock, upgrade, rollback) +
  tests on Python 3.11/3.12 × MCP SDK 1.x/2.x + lint/mypy/shellcheck; weekly
  `freshness.yml` (newest tools, Docker rebuild, newest Python deps → PRs or
  an issue); Dependabot for Docker/Actions.
- `scripts/mcp_smoke.py` — a live MCP stdio session (handshake, list, call,
  input validation) usable against native, a launcher, or a Docker image.
- 216 new tests (335 -> 551), including attack-style tests for each finding of a security
  review of the updater (verified by reverting each fix and watching its test
  fail).

### Fixed (found while testing this work)

- A timed-out child process only had its *direct* process killed, leaving
  descendants running (a timed-out `go install` would have orphaned its
  compilers). Children now run in their own process group and the whole group
  is killed; output goes to a temp file so a runaway binary can't exhaust
  memory. (Surfaced as an intermittent failure of the existing leaked-`sleep`
  tests — caused by one of the new tests, not flakiness.)
- `fd` leak in the atomic binary swap ("Text file busy" on exec) — caught by
  the first installer test run, before it could affect a real install.

### Changed

- **MCP SDK 2.x is now supported** alongside 1.x (`requirements.txt`:
  `mcp>=1.0.0,<3.0.0`, previously `<2.0.0`). `server.py` registers handlers
  through `mcp_server/mcp_compat.py`. Only registration differs between the
  SDKs; the 2.x path re-adds the `inputSchema` argument validation 1.x did
  implicitly. A live session on 2.3.0 caught a bug the unit tests could not
  (2.x names the field `input_schema`).
- `hunt doctor --json` now prints **only** JSON (it used to print the human
  report first and the JSON after, so nothing could parse it). All previous
  JSON keys are kept; `tools`, `assets`, `python_env`, `path_problems`, `go`
  are added. Human output keeps its sections and adds Installed/Latest/Status.
- `capabilities.py` reads its tool lists from the manifest (literal fallback
  kept, drift-guarded by a test). `interactsh-client`, previously only in the
  Docker image (`@latest`), and `httprobe` are now managed on both paths.
- `Makefile update` now actually refreshes tools (a plain `docker compose
  build` reuses the cached tool layer and would have printed "Updated!"
  while changing nothing). Docker Go stage uses a floating `golang:alpine`
  (newer tools need newer compilers).
- `.gitignore`/`.dockerignore`: `bin/` (native install output).

### Tests replaced (not weakened)

- `test_pinned_versions_match_the_dockerfile` and
  `test_every_required_tool_is_installed_by_the_script` asserted that two
  hard-coded pin lists matched. With the pins gone they are replaced by
  stricter checks: both installers go through the same tool manager, neither
  contains a version literal, every required tool is in the manifest, the
  manifest derives the *original* install paths, and the lock equals the
  manifest minimums.
- `test_launchers_put_the_go_tools_dir_before_the_venv` →
  `…selected_tools_before_the_venv` (`bin/active` before `.venv/bin`, and
  `bin/tools` must not precede it).
- `test_doctor_json_flag_produces_valid_json` updated to the pure-JSON contract.

## Unreleased — setup.sh executable bit

### Fixed

- `setup.sh` was tracked in git as mode `100644` (not executable) in every
  commit that ever touched it, while `install-native.sh` was correctly
  `100755` — inconsistent, and it breaks `README.md`'s Quick Start, whose
  very first command for a fresh clone is `./setup.sh`. Caught while
  packaging the repo for delivery and checking that `install-native.sh`'s
  executable bit survived `git archive` (it does; file mode is part of
  what git tracks per blob, not a filesystem-only attribute) — compared
  it against `setup.sh` for the same check and found the bit had never
  been set at all.

## Unreleased — GitHub repo rename completed

The owner-only step from the entry two below this one is done: the GitHub
repository is renamed to `BugBounty-mcp-server`, matching the package name
and MCP server identifier that were already updated locally. `README.md`'s
clone URL, `cd` line, and Project Structure tree root label updated to
match; the old URL still works as GitHub's automatic redirect. Nothing
else changed — the local names had anticipated this since before it
happened, which is exactly why this is such a small entry.

## Unreleased — naabu capability hardening, Dockerfile version drift fix

Picked up the oldest still-open item in this file: "Docker non-root
hardening" was flagged as worth doing all the way back in the very first
entry below, and never revisited since.

### Added

- `setcap cap_net_raw+ep` applied to the `naabu` binary at build time (via
  the newly-added `libcap2-bin` package), so naabu can do SYN scans using
  just that one capability on that one binary — not by running as root.
  This isn't load-bearing yet (the container still runs fully as root —
  see "Not done" below), but it means naabu keeps working at full speed
  (SYN scan, not its slower connect-scan auto-fallback) the moment a
  future pass does switch the container to non-root, without that switch
  also having to get this exactly right under time pressure. Checked
  first whether this even applies to the tools this codebase actually
  invokes: `naabu` is only ever called with `-host`/`-silent`/`-json`/
  `-top-ports` (`server.py`'s `_port_scan`, `hunt.py`'s `cmd_ports`) —
  never `-s syn` — and naabu already auto-falls-back to connect-scan
  gracefully when it lacks the capability, so this was never a hard
  blocker, just a quiet, always-slower-than-it-needed-to-be mode.
- `tests/test_dockerfile.py` — 4 new tests (text-based, same caveat as
  the rest of this file: no Docker daemon available here to verify a real
  build): `libcap2-bin` is installed, the `setcap` step runs after the
  `naabu` binary actually exists in the image, and that step has a
  `|| echo "WARN: ..."` fallback matching the Go-install lines' own
  pattern (a sandboxed/rootless build environment that can't set file
  capabilities must not fail the whole build over it).

### Fixed

- Found while reading through the Dockerfile for this: `LABEL
  version="3.0.0"` — a *fifth* independently hardcoded copy of the
  version string, on top of the four already caught and fixed in the
  entry below. Bumped to match; added
  `TestDockerfileVersionConsistency` (parses `pyproject.toml` with
  `tomllib`, same approach `TestVersionConsistency` in
  `tests/test_server.py` already uses for the Python-level copies) so
  this one can't drift again either without a test catching it. There is
  no way to make a Dockerfile `LABEL` reference a Python constant at
  build time the way `hunt.py`/`server.py` now reference
  `mcp_server.__version__` directly — a test is the available substitute.

### Not done in this pass (and why)

- **The container still runs fully as root.** Traced through what an
  actual non-root switch would require, concretely, rather than leaving
  the same vague "worth doing" note this file already carried: every
  directory the running server writes to is bind-mounted from the host in
  `docker-compose.yml` — `./data`, `./reports`, `./screenshots`,
  `./wordlists`, `./nuclei-templates`, `./logs`, and
  `./config/subfinder`. A bind mount's effective ownership inside the
  container comes from the *host* directory's owning UID, not from
  anything a Dockerfile `RUN chown` bakes into the image — the chown only
  affects the image layer, which the bind mount then covers up entirely
  at `docker-compose up` time. So switching to a fixed non-root UID
  inside the image (the "just add a `USER` line" version of this fix)
  would make every one of those writes fail with a permission error
  unless that UID happens to match whatever UID actually owns `./data`
  etc. on the host — which varies by machine and isn't something this
  sandbox has a real host filesystem or a Docker daemon to test against.
  Getting this right needs the standard fix for exactly this problem:
  a build `ARG` for UID/GID (`ARG UID=1000` / `ARG GID=1000`,
  `useradd -u "$UID" -g "$GID" ...`) combined with
  `user: "${UID:-1000}:${GID:-1000}"` in `docker-compose.yml`, with
  `setup.sh` defaulting those to `$(id -u):$(id -g)` of whoever actually
  runs it — so the in-container user's UID is made to match whichever
  host user's directories it's writing into, instead of being some fixed
  number that may or may not line up. That's a real build-and-run cycle
  to get right and verify (does `docker-compose up` actually start
  cleanly with an arbitrary host UID; do the existing `./data` etc.
  directories that `setup.sh` already creates end up with the right
  owner either way), not something to bolt on blind from here.

## Unreleased — Cleanup: hunt.py type safety, Smart Hunt facts caps, version consistency, README accuracy

Short follow-up pass after the session below, going back over what it
shipped rather than starting new work.

### Fixed

- `mypy hunt.py` had two open findings (`Cannot call function of unknown
  type`) at both dispatch sites in `main()` — `COMMANDS`'s handlers have
  genuinely different signatures (`cmd_doctor` takes only a `json_output`
  kwarg; every other handler takes a positional target plus
  command-specific `**kwargs`), so mypy couldn't infer a single callable
  type for the dict's values. Rather than leave it unchecked, added an
  explicit `CommandHandler = Callable[..., Coroutine[Any, Any, None]]`
  alias (first tried `Awaitable[Any]`, which `asyncio.run()` itself then
  rejected — it specifically wants `Coroutine`) with a comment explaining
  why no more precise type is possible here. `mypy` is now clean across
  all 12 source files, `hunt.py` included — previously only
  `mcp_server/` was.
- Found and fixed a real resource leak while chasing an intermittent
  `pytest -rw` warning (`Exception ignored ... Event loop is closed`):
  `run_cmd()`'s `except asyncio.CancelledError` branch killed the child
  process but never awaited it, so the `asyncio.subprocess.Process`
  object (and the pipe transport it owns) could get garbage-collected
  later, sometimes after the event loop that owned it had already closed.
  Added `await proc.wait()` (suppressed) right after the kill, before
  re-raising — safe to await here since `CancelledError` has already been
  delivered at that point, so this await isn't itself re-cancelled.
- Four independently hardcoded copies of the version string
  (`pyproject.toml`, `mcp_server/__init__.py`'s `__version__`, `hunt.py`'s
  banner, and *two* places in `server.py`'s health endpoint) had already
  drifted apart — all still said `3.0.0` despite `README.md`'s title
  already having been manually bumped at some point. No single source of
  truth, so nothing caught it. Made `mcp_server.__version__` the one
  place the version is defined; `hunt.py`'s banner and both `server.py`
  health-endpoint fields now reference it instead of their own literal.
  Bumped to `3.1.0` (new features, no breaking changes) and added
  `TestVersionConsistency` (3 tests, including one that parses
  `pyproject.toml` with `tomllib` and compares) so this can't silently
  drift again without a test failing.
- `README.md`'s "Task Management" section still said task state was
  "in-memory only... no partial-result capture... see `CHANGELOG.md` for
  why that's a known limitation" — both claims were fixed two sessions
  ago (see below) and the docs were never updated to match. Replaced with
  accurate descriptions of both the persistence and partial-result
  behavior, with real example JSON. Also: README's "Quick Start" had no
  mention of `install-native.sh` at all (added a subsection), the
  "Available MCP Tools" table was missing `list_tasks` and the entire
  Smart Hunt tool family (added a "Smart Hunt" section with a worked
  example), and "Project Structure" still said "All 27 MCP tool schemas"
  and listed neither `core.py`, `persistence.py`, `smart_hunt.py`, nor
  `install-native.sh` (all added two sessions ago). Also caught and fixed
  the opposite mistake from an earlier pass: a previous edit had changed
  the Project Structure tree's root folder label to the new package name
  (`BugBounty-mcp-server/`) while `git clone` + `cd` still points at the
  actual (not-yet-renamed) GitHub repo — reverted that one line back to
  match reality, since showing a directory name nobody will actually get
  from following the README is worse than showing the honest interim
  state.
- Smart Hunt's dict-keyed facts (`tech`/`ports`/`paths` — one entry per
  *distinct host touched*, not per finding, so the existing per-item
  `_add()` list cap doesn't bound them) had no cap at all: a client
  calling `tech_detect`/`port_scan`/`dir_fuzz` directly with a large
  target list — bypassing Smart Hunt's own small batch recommendations —
  could grow a session's facts without limit over a long-running hunt.
  Added `_set_capped()` (evicts the oldest host once
  `CAPS["tech_hosts"]`/`"port_hosts"`/`"fuzz_hosts"` is hit, mirroring
  the oldest-first trimming `tasks.py` already does for `max_tracked`)
  and 4 new tests, including one confirming that updating an *existing*
  key in place never evicts anything (only genuinely new keys count
  toward the cap).
- `AGENTS.md`'s architecture overview still described task state as
  in-memory-only with no partial-result capture (pointing at a
  `CHANGELOG.md` section that, at the time, hadn't been written yet —
  this file was two full sessions behind the code) and still said "27 MCP
  tools" in two places. Rewritten to describe current reality and point
  at the two new entries below instead.

### Added

- 3 new tests for version consistency (above), plus the 4 Smart Hunt
  facts-cap tests mentioned earlier in this entry (bringing that suite to
  51). 331 tests total (up from 324 at the start of this pass).

## Unreleased — Partial-result capture wired in, task/session persistence, Smart Hunt

Continuation of the session below: that session got through TaskManager
completion, the shared CLI/MCP core, the native installer, and the
streaming `run_cmd` rewrite itself (195 tests at that point), but left the
actual wiring of partial-result capture into `TaskManager`, task/session
persistence, and Smart Hunt as open work. This session did all three.

### Added — partial-result capture, wired in

- `TaskManager._run()` now wraps the handler call in
  `core.capture_partial_results()`. A cancelled, hard-timed-out, or failed
  task's `result` is no longer always `None` — if any `run_cmd()` call
  inside it produced output before the task stopped, that output comes
  back as `{"partial": true, "commands_captured": N, "captured": [...]}`
  (raw per-command stdout/stderr, in order, explicitly labeled as
  unprocessed — not parsed/deduplicated/scope-filtered the way a
  completed run's result is). A task with no captured output at all keeps
  `result: null`, unchanged from before. `get_task_status` /
  `get_task_results` surface a `partial_results_available: true` flag,
  computed from both the task's terminal status and the result shape (so
  a handler that legitimately returns its own `"partial"` key in a
  *completed* result is never mistaken for an interrupted one).
- `tests/test_core.py` (32 new tests) — real-subprocess tests for the
  `run_cmd` streaming rewrite and the capture scope: timeout/cancellation
  actually kill and reap the child (verified via a pidfile + `os.kill(pid,
  0)` polling loop, not a mock), a single 1.5 MB line is returned intact
  (`readline()` would raise `LimitOverrunError` here — real risk for
  minified JSON from `httpx`/`katana`), concurrent captures via
  `capture_partial_results()` don't leak into each other's sink, and a
  size-capped/flagged capture for a pathologically large command.
- `tests/test_tasks.py` — 8 new `TestPartialResultPreservation` tests:
  cancelled and hard-timed-out tasks return gathered output, a multi-stage
  handler's already-finished commands survive alongside the interrupted
  one, a plain exception (not just cancellation) also preserves whatever
  ran first, concurrent tasks capture independently.
- `tests/test_server.py` — one real end-to-end test: starts the actual
  `subdomain_enum` handler against a fake `subfinder` binary that's
  already printed partial output, cancels it mid-run via `cancel_task`,
  and confirms `get_task_results` hands the partial subdomains back
  through the real MCP tool-call path, not just the isolated
  `TaskManager`.

### Added — task/session persistence

- New `mcp_server/persistence.py` — `JsonStore`, a small dependency-free
  JSON-file store (one file per record, `<dir>/<id>.json`). Deliberately
  not a database: `requirements.txt` has carried `motor`/`redis` since
  before this project's `tests/` directory existed, and nothing has ever
  used them (see the very first "Not done" section in this file) — a
  native, non-Docker install shouldn't need to stand up a database server
  just to remember what a scan found. Guarantees, each with its own test:
  atomic writes (temp file in the same directory, `fsync`'d, then
  `os.replace()`'d — a crash mid-write can't corrupt an existing record,
  and a reader never sees a half-written one), owner-only permissions
  (`0600` files / `0700` directory — these records hold recon findings
  and endpoints for programs being tested), IDs validated against a
  strict filename pattern before ever touching the filesystem (closes off
  path traversal via a crafted ID), corrupt files quarantined to
  `<name>.json.corrupt` and skipped rather than blocking every other
  record from loading, and oversized records (>5 MB) replaced with a
  small stub rather than written whole. Every public method swallows and
  logs OS/JSON errors instead of raising — persistence is explicitly
  best-effort and must never be the reason a scan fails.
- `tasks.py`: `_Task.to_record()`/`from_record()`, a new `INTERRUPTED`
  terminal status (assigned only when restoring history after a restart —
  the task was queued/running when the previous process died, its
  subprocess died with it, and this is reported honestly rather than
  pretended-resumed), `TaskManager(store=...)` (optional — `None` is
  exactly the old pure-in-memory behavior, which is what every
  pre-existing test still gets), `load_persisted()` (call once at
  startup; returns how many were restored vs. found interrupted), and
  `shutdown()` (cancels every still-active task so its partial output
  gets captured and persisted instead of vanishing with the process,
  rather than just dying with whatever was in memory). Task args are
  redacted before being written to disk — anything matching
  `key|token|secret|passw|auth|cookie|bearer` (case-insensitive) in an
  arg's key is masked, since a task's on-disk record shouldn't become a
  place API keys or session cookies get copied to.
- `server.py`: constructs the task store from `DATA_DIR/tasks`, restores
  history at startup (`main()`, before serving), and now installs a
  `SIGTERM` handler (alongside the stdio-EOF and Ctrl-C paths that already
  existed) so a `docker stop` or a client killing the process shuts down
  the same graceful way — `finally: await task_manager.shutdown()` runs
  on every exit path, not just some of them.
- `config.py`: `persist_tasks` setting (default `true`).
- `tests/test_persistence.py` (38 tests) — `JsonStore` in isolation
  (roundtrip, permissions, unsafe IDs rejected, a failed write leaves the
  *previous* record intact with no temp-file litter, an unwritable
  location never raises, corrupt/malformed files are quarantined and
  skipped without crashing startup, oversized records become stubs,
  prune/cleanup) plus `TaskManager` integration (history survives a
  simulated restart, a task that was `running` when the record was last
  written is correctly reported `interrupted`, interrupted tasks don't
  count toward the concurrency limit, partial results persist and
  restore, `shutdown()` cancels and preserves, credentials in task args
  are redacted on disk, evicted tasks are deleted from disk too). Plus
  one test that doesn't simulate anything: spawns a real Python
  subprocess that starts a task and writes "started" to stdout, waits for
  that signal, sends a real `SIGKILL` (not a graceful stop), then
  restores from the same directory in a fresh `TaskManager` and confirms
  the task comes back `interrupted` with `running_count: 0` — the actual
  crash-recovery claim, not a stand-in for it.

### Added — Smart Hunt

- New `mcp_server/smart_hunt.py` — the "Smart Hunt" AI-guided workflow
  from the earlier specs, built the way the session two sessions ago
  concluded it should be: decision support on top of the existing MCP
  tools, not a second AI model embedded in the server (no LLM call, no
  provider dependency — the calling agent still decides what to do with
  each result; Smart Hunt only tracks what's been found and recommends
  *which tool* to call next). `smart_hunt_start` / `smart_hunt_next` /
  `smart_hunt_status` / `smart_hunt_close` — 4 new MCP tools, 32 total.
  Recommendation logic (`_candidates()`/`_rank()`) is plain, inspectable
  rules, not anything learned: a flagged subdomain (admin/staging/api-
  looking) gets probed before the rest of a batch; a critical or high
  finding takes over the session — every recon candidate is filtered out
  of consideration (not just outranked by priority number, which an
  earlier version of this got wrong — see below) until it's analyzed,
  explained, and reported; a tool that fails twice in a row stops being
  recommended; a missing binary gets flagged via `get_capabilities`
  instead of being retried forever. Sessions persist via the same
  `JsonStore` tasks use, under `DATA_DIR/hunts`. Three defense-in-depth
  properties, each independently tested: Smart Hunt refuses to *start* a
  session while `ALLOWED_SCOPE` is empty ("open mode") even though the
  underlying tools allow it when called directly — an AI iterating on its
  own shouldn't be pointed at "scan anything" — every recommended target
  is independently re-checked against scope at recommendation time (not
  just trusted from the tool result), and every host/title/URL that flows
  back from a target's own systems is length-capped and stripped of
  control characters before it can reach a model's context, with the
  session summary carrying an explicit "this is untrusted data" notice.
- `config.py`: `smart_hunt_enabled`, `smart_hunt_require_scope` settings.
- `tests/test_smart_hunt.py` (47 tests) — `start()` validation and scope
  gating, `next()` plumbing (unknown/closed session, queued-task waiting,
  duplicate task_id not double-counted, failed/partial task results
  ingested correctly), per-tool ingestion correctness for every recon/
  scan/intel tool including the `full_recon` pipeline unpacking into the
  same facts, wrap-up priority ordering, depth gating, step-budget
  wrap-up, scope enforcement (recommended targets never include a blocked
  host; narrowing scope mid-session stops recommending now-out-of-scope
  hosts), and persistence (session survives a restart, pending
  recommendation survives a restart, a malformed record doesn't crash
  restore). Found and fixed a real bug while writing these: the original
  design added "analyze this finding" as one more candidate competing on
  a priority number — but a freshly-started session's very first
  bootstrap step (`subdomain_enum`, priority 100, since it's always the
  cheapest first move) outranked even a critical finding's "go analyze
  this now" recommendation (96), so a critical finding found via a
  direct `nuclei_scan` call before any recon had run would get buried
  behind a from-scratch recon restart instead of immediately surfacing.
  Fixed by *filtering* the candidate set down to wrap-up-only while an
  unreported severe finding exists, rather than relying on priority
  numbers to win a fair fight they weren't actually set up to win.
- `tests/test_server.py` — `TestSmartHuntEndToEnd` (3 tests): the full
  loop through the real MCP handlers (`smart_hunt_start` → real
  `subdomain_enum` against a fake `subfinder` → `smart_hunt_next` →
  `alive_check` recommended next, flagged subdomain first → `status` →
  `close`), the open-mode refusal, and that all 4 tools are actually
  registered in both `TOOLS` and `TOOL_HANDLERS`.

### Changed

- Project renamed (locally) to `bugbounty-mcp-server`:
  `pyproject.toml`'s package name and the MCP server's registered
  identifier (`Server("bugbounty-mcp-server")` in `server.py`, visible to
  MCP clients) were updated. The actual GitHub repository is still named
  `advanced-bugbounty-mcp` — renaming it is an owner-only action on
  GitHub's side (Settings → repository name) that this environment can't
  take; `README.md`'s clone URL and directory references deliberately
  still point at the current repo name so the instructions keep working
  until that happens, and `AGENTS.md` now documents this explicitly so it
  isn't mistaken for leftover work next time.
- 324 tests total by the end of this session (195 → 324: +32
  `test_core.py`, +8 `TestPartialResultPreservation` in `test_tasks.py`,
  +38 `test_persistence.py`, +47 `test_smart_hunt.py`, and +4 in
  `test_server.py` — the partial-result end-to-end test plus the 3 Smart
  Hunt end-to-end tests). `ruff` and `mypy mcp_server/` both clean
  throughout.

## Unreleased — get_capabilities/doctor, a real Docker build bug, more native-path fixes

Continuation of the previous "background task management" pass — same
prioritization logic (see that section below for the reasoning on why
task management came before this). This phase built the `doctor`/
`get_capabilities` diagnostics both spec documents asked for, and along
the way found two more real bugs, one of them significant.

### Fixed — significant

- **The Docker image's `httpx` binary was getting silently overwritten by
  an unrelated Python CLI of the same name, in every build.**
  `requirements.txt` requires the Python `httpx` HTTP client library
  (used by `_cert_search`), which ships its own CLI entry point also
  named `httpx`. The Dockerfile copied the real Go `httpx` tool
  (ProjectDiscovery's, used by `alive_check`/`tech_detect`) to
  `/usr/local/bin/` *before* `pip install -r requirements.txt` ran —
  since both installs write to the same directory in the `python:3.12-slim`
  base image, whichever ran last won that filename, and pip ran last.
  `shutil.which("httpx")` still found *something* there, so nothing
  looked wrong until a handler actually tried to run it. Fixed by moving
  the Go-tools `COPY` to after `pip install` (still before
  `nuclei -update-templates`, which needs `nuclei` already on PATH).
  Added `tests/test_dockerfile.py` as a text-based ordering guard and
  verified it actually catches the regression — reverted to the old
  order, watched the test fail, restored the fix, watched it pass again.
  This is not a real `docker build` verification (no Docker daemon
  available here) — it guards the ordering mistake, not runtime proof.

### Fixed — native execution

- `server.py`'s `subdomain_brute`/`dir_fuzz` had the same hardcoded
  `/app/wordlists/...` default that `hunt.py`'s `fuzz` command had
  (fixed last phase) — Docker-only, broken for native execution. Fixed
  with the same relative-path pattern (`WORDLISTS_DIR` resolved from
  `server.py`'s own location), plus two tool-schema descriptions and two
  error-guidance messages that also hardcoded the stale path.
- `.env.example` didn't document `STRICT_SCOPE` or any of the four
  task-management settings, despite all five being fully implemented —
  unlike every other setting in this project. Added, with the env var
  names verified against `config.py`'s actual field names by loading
  `Settings()` with all five set.

### Added

- `mcp_server/capabilities.py` — environment/tool diagnostics, consolidating
  three separately-drifting copies of "which tools are installed" (the
  `/health` endpoint's inline list, `hunt.py`'s `check_tools()`, and
  nothing exposed to MCP agents at all). Classifies tools as required
  (called directly by a handler, no fallback: subfinder, httpx, naabu,
  nuclei, ffuf, katana, waybackurls, gau, dnsx, gobuster) or optional
  (gowitness — has a working fallback; anew — not actually invoked by any
  current handler despite being checked for).
- `get_capabilities` MCP tool and a `/capabilities` HTTP endpoint, both
  exposing the full report: Python version, every tool's availability and
  purpose, wordlist presence, native-vs-Docker detection, overall
  ready/degraded status with plain-language issues.
- `/health` refactored to derive its tool summary from the same
  `check_go_tools()` instead of its own separate list — and, as a result,
  fixed a real behavior bug along the way: it used to count missing
  `gowitness`/`anew` (both optional) toward "degraded" status just like
  the 10 required tools. Verified this doesn't affect the docker-compose
  healthcheck, which only checks the HTTP status code, not the JSON body.
- `hunt.py doctor` (and `doctor --json`) — same full report, reusing
  `capabilities.get_capabilities()` via a plain same-repo import (`hunt.py`
  sits at the repo root next to the `mcp_server` package). This is the
  first piece of real code-sharing between `hunt.py` and `server.py`
  beyond the standard library — a small, safe slice of the "shared core"
  idea, not the full CLI/MCP dedup (still not attempted — see below).
- `tests/test_capabilities.py` (18 tests), `tests/test_hunt_cli.py` (8
  tests) — the latter actually invokes `python hunt.py ...` as a real
  subprocess rather than importing the module, specifically because two
  real bugs in the `doctor` wiring only showed up that way: `main()`
  always required a positional target and always called
  `handler(target, **kwargs)`, but `doctor` takes neither (special-cased
  in the dispatcher); and a leftover `return` statement from the old
  `check_tools()` survived the refactor and referenced a name that no
  longer existed. Both reproduced with real tracebacks from a real
  `python hunt.py doctor` run before being fixed, then re-verified the
  same way. 152 tests total (up from 121 at the start of this phase).
- Server-level tests confirming `get_capabilities` is registered in both
  `TOOLS` and `TOOL_HANDLERS` and reachable via the real `call_tool()`
  dispatch path, plus a regression test that `WORDLISTS_DIR` no longer
  hardcodes `/app/wordlists`.

### Not done in this phase

Same list as before, still not attempted: full CLI/MCP core dedup beyond
`capabilities.py` (the bulk of `run_cmd`/scope enforcement/task management
duplication between `hunt.py` and `server.py` remains), native (non-Docker)
*installer* completion (`setup.sh` is still Docker-only, though `hunt.py`
itself already runs natively), `server.py`'s file-split into
`tools/`+`core/`, and the "Smart Hunt" autonomous-loop question from two
phases ago — still open, still worth an explicit answer before any code
gets written for it.

## Unreleased — Background task management, strict_scope, hunt.py native fix

Response to two more spec documents proposing a much larger "autonomous
Smart Hunt" AI-driven investigation loop, plus a review of the prior pass.
Deliberately did NOT build "Smart Hunt" as a self-driving loop inside the
server — the spec's own workflow has the *project* doing "AI Analysis" and
"AI Re-evaluation" as steps, which means the server would need to embed
its own LLM call. That contradicts the project's own AI-provider-neutrality
principle (no core dependency on a specific provider/API key) and is
redundant with what the calling agent (Claude Code, Gemini CLI, etc.)
already does — deciding what to do next with tool results *is* what an
agentic MCP client's own loop already does. What's genuinely valuable and
provider-neutral from that spec is the execution infrastructure a good
loop needs: cancellable long-running tasks with timeouts. That's what this
pass built.

### Added: background task management

- New `mcp_server/tasks.py` — `TaskManager` with `start_task`/
  `get_task_status`/`get_task_results`/`cancel_task`, matching the names
  both spec documents used. Wraps any handler already in `TOOL_HANDLERS`
  in a cancellable `asyncio.Task` — reuses the exact same validation,
  scope check, and execution every direct tool call already goes through;
  nothing about any of the 22 original tools changed. Every tool still
  works fine called directly — this is an additional option for slow ones
  (`nuclei_scan`, `dir_fuzz`, `full_recon`, `port_scan`).
- Soft timeout (default 60s): `get_task_status` flags a still-running task
  as slow and suggests continuing to wait or cancelling. Purely advisory —
  doesn't stop or pause anything (a background asyncio task can't be
  meaningfully paused mid-subprocess anyway).
- Hard timeout (default 900s): force-cancels automatically, kills the
  subprocess, marks the task `timed_out`.
- `max_concurrent_tasks` (default 10): new `start_task` calls are rejected
  once this many are already queued/running.
- `max_tracked_tasks` (default 200): oldest *finished* tasks are evicted
  once exceeded; running tasks are never evicted.
- Found and fixed a real leak while building this: `asyncio.CancelledError`
  is a `BaseException`, not an `Exception` — `run_cmd`'s existing exception
  handling never caught it, so external cancellation (which is exactly
  what `cancel_task` and the hard-timeout path both do) would leave the
  child process (nuclei/naabu/ffuf/...) running orphaned in the background
  even after the task was reported as cancelled. Added an explicit
  `except asyncio.CancelledError` that kills the process then re-raises
  (never swallow cancellation). Verified against a REAL subprocess, not a
  mock: spawned `sleep 30` through the actual task manager, cancelled it,
  confirmed via `pgrep` that the OS process was actually gone — both for
  external cancellation and for the hard-timeout path.
- Known limitation, stated plainly rather than glossed over: no partial-
  result capture. A cancelled or timed-out task returns no result at all,
  not whatever was found before it stopped. `run_cmd` uses `communicate()`,
  which buffers to completion — doing this properly needs a streaming
  rewrite of `run_cmd` (reading output incrementally instead of waiting
  for EOF), which is a bigger, riskier change to the one function every
  single tool depends on. Deferred rather than rushed.
- `TOOL_HANDLERS` (the tool-name → handler dispatch table) was previously
  a local variable rebuilt inside `call_tool()` on every call. Hoisted to
  module level so both `call_tool()` and the task manager read the exact
  same dict — one dispatch table, not two. (This is a small, safe slice of
  the "shared core between CLI and MCP" idea from the review — not the
  full refactor into `core/`/`tools/` packages, which is a much bigger,
  higher-risk change deferred for its own pass.)
- 26 new tests (92 → 118): `TaskManager` lifecycle in isolation (18 tests
  — completion, failure, soft/hard timeout, cancellation, concurrency
  limit, eviction) plus integration tests through the real `server.py`
  wiring (8 tests — including the two real-subprocess proofs above).

### Fixed

- `hunt.py`'s own docstring claims "works standalone: no Docker" — true in
  general, but its `fuzz` command's default wordlist path was hardcoded to
  `/app/wordlists/...` (Docker-only). `setup.sh` actually downloads
  wordlists to `<repo-root>/wordlists/`, which the Dockerfile then copies
  to `/app/wordlists/` at the same relative position (`COPY . /app/`) — so
  a path resolved relative to `hunt.py`'s own file location is correct in
  both native and Docker layouts. Fixed; verified against the Dockerfile.
- Added `STRICT_SCOPE` (default `false`, preserving existing behavior):
  when DNS resolution fails during a scope check, the default is still to
  proceed on the hostname-level match with a warning (a flaky resolver
  shouldn't block an authorized scan) — but `STRICT_SCOPE=true` flips that
  to fail closed instead, for environments that would rather a scan not
  run at all than run without IP-level verification. This was a fair
  critique of the previous pass's unconditional fail-open default; rather
  than picking a side, made it configurable and documented the tradeoff.

### Not done in this pass (and why)

- **"Smart Hunt" as a self-driving loop** — see the explanation at the top.
  If an embedded LLM call inside the server actually is what's wanted
  (not agent-side reasoning via better tools + task infra), that needs a
  real conversation about which provider, whose API key, and what budget
  before any of it gets built.
- **Full CLI/MCP core dedup** (`hunt.py` and `server.py` sharing a `core/`
  package) — the `TOOL_HANDLERS` hoist above is a small, safe slice of
  this; the full version touches both files' control flow throughout and
  deserves its own careful, fully-verified pass.
- **Native (non-Docker) installer** — `hunt.py` itself already runs
  natively; what's missing is a scripted way to install Go tool
  dependencies outside Docker, which needs real-environment verification
  (apt/brew package names across platforms) this sandbox can't do
  reliably.
- **`doctor`/`capabilities` CLI command** — genuinely still useful, lower
  priority than task management this pass.
- **`server.py` file split** — 1550 lines now (grew from adding task
  management), organizational rather than correctness-affecting, real but
  not urgent.

## Unreleased — Scope hardening: DNS-resolution-aware checking

Follow-up to the audit pass below, prompted by a request to harden scope
enforcement further. The gap: `scope.evaluate()` only ever checked the
hostname *string* against `ALLOWED_SCOPE`/`BLOCKED_TARGETS` — never what
that hostname actually resolves to. A name that matches `ALLOWED_SCOPE`
but currently resolves into a blocked range (a stale record, or an active
DNS-rebinding attempt: get an in-scope name pointed at 169.254.169.254 or
a private range between the scope check and the request) would pass.

- Added `scope.resolve_and_check()` — resolves the hostname and checks
  every returned IP against `BLOCKED_TARGETS`, in addition to the existing
  hostname-level check. Only ever narrows the decision (allowed → denied),
  never widens it. A resolution failure or timeout does **not** deny the
  request (a flaky resolver shouldn't block an authorized scan) but is
  surfaced via `resolution_warning` so the caller knows the IP-level check
  was inconclusive. Bare-IP targets skip resolution entirely (nothing to
  resolve). The original synchronous `evaluate()` is unchanged and still
  has its own full test coverage.
- `server.py`'s `_scope_check()` / `_filter_in_scope()` (and the
  `check_scope` tool) now go through `resolve_and_check()`. All three now
  do real DNS resolution by default via a swappable `server.dns_resolver`
  module attribute — swappable specifically so tests never touch live DNS.
  `_filter_in_scope()` resolves all targets concurrently via
  `asyncio.gather`, not sequentially.
  During this wiring, found and fixed a real bug: `_check_scope()`'s call
  to `resolve_and_check()` was missing `resolver=dns_resolver` (the other
  two call sites had it), so it always fell through to live DNS regardless
  of test mocking — caught because the test asserting fake-resolver output
  got real Cloudflare IPs for `example.com` back instead.
- `BLOCKED_TARGETS`'s default was incomplete: `127.0.0.1` blocked only that
  one address (not the rest of the loopback range), `172.16.0.0/12` — the
  middle RFC1918 range — was missing from `config.py`'s default entirely
  (though `.env.example` already had it, so the two had drifted apart),
  and there was no IPv6 coverage at all. Default is now
  `127.0.0.0/8`, `169.254.0.0/16` (link-local, covers the metadata IP as a
  subset), all three RFC1918 ranges, plus `::1`, `fe80::/10`, `fc00::/7`.
  `config.py` and `.env.example` now match, and a test
  (`test_shipped_config_default_has_full_coverage`) checks the real
  shipped default directly so the two files can't drift apart again
  without a test failing.
- Added `AGENTS.md`.
- Added 16 new tests (68 → 84) covering the resolution wrapper directly,
  the full blocklist ranges, and the server-level wiring (concurrent
  resolution, rebinding denial, resolution-failure non-blocking, bare-IP
  and already-out-of-scope short-circuiting so a hostname that's already
  going to be denied doesn't spend a DNS round trip finding that out a
  second way).

### Not done in this pass (and why)

Two much larger specs were provided alongside this request — effectively a
full platform redesign: async task queue (start/poll/cancel for
long-running scans), SQLite-backed session/scan history, a plugin
architecture replacing the hardcoded tool handlers, native (non-Docker)
install parity, a `doctor`/`capabilities` CLI surface, scan profiles
(passive/standard/deep), HTML/JSON report formats, and redirect-following
validation (checking the target *after* an HTTP redirect, not just the
initial hostname).

None of that is implemented here. Each is a legitimate idea, but doing them
justice means either a real product decision (does a task queue's async
model, a SQLite schema, a plugin interface actually fit how you want to use
this?) or verification this sandbox can't do (an actual Docker build, a
live redirect against a real target). Bolting all of that on unilaterally
in one pass — especially the parts that change the execution model from
synchronous request/response to something stateful — risked breaking a
tool that currently works and is tested, without your buy-in on the
resulting shape. Happy to scope any one of them properly if you want to
go there next.

## Unreleased — Correctness & safety audit

This pass focused on making the tool's existing promises actually true, and
on closing gaps a security-tool audit would flag first. No new scanning
features were added — everything below is a fix, a test, or a hardening
change to code that already existed.

### Fixed — critical

- **`ALLOWED_SCOPE` / `BLOCKED_TARGETS` were never enforced.** `config.py`
  parsed them into `scope_list` / `blocked_list`, and the README promised
  "the server will reject any target not in scope," but nothing in
  `server.py` ever checked them — every tool would scan any target it was
  given. Added `mcp_server/scope.py` (exact match, `*.` wildcard, CIDR,
  hard-blocked list that can't be overridden) and wired it into every
  active-scanning handler: `port_scan`, `alive_check`, `dns_enum`,
  `screenshot`, `crawl`, `tech_detect`, `subdomain_brute`, `nuclei_scan`,
  `dir_fuzz`, and `xss_scan`/`sqli_scan`/`cors_check` (via
  `_nuclei_targeted`). Passive-only lookups (`subdomain_enum`, `wayback`,
  `whois_lookup`, `cert_search`, `shodan_search`) are intentionally exempt
  since they never contact the target. Added a `check_scope` tool to test
  a target ahead of time.
- **`requirements.txt` pinned `mcp>=1.0.0` with no upper bound.** `mcp`
  2.0.0 is now the default `pip install` target and removes the
  `@server.list_tools()` / `@server.call_tool()` decorator API this codebase
  is built on — a fresh build pulls 2.0.0 and the server crashes on import.
  Reproduced directly (import succeeds on 1.29.0, fails on 2.0.0) and pinned
  to `mcp>=1.0.0,<2.0.0` with a comment explaining why.

### Fixed — correctness / robustness

- Values that reach a tool's `argv` (domain, target, url) were never checked
  for a leading `-`, so e.g. a "domain" of `-oJ` could be parsed as a CLI
  flag by the downstream Go binary instead of as data. Added
  `reject_flag_injection()`; domain-only parameters use the stricter
  `is_valid_domain()` (previously defined but never called anywhere).
- The temp-file-for-`-l`/`-f`-flag pattern was duplicated across six
  handlers using `tempfile.NamedTemporaryFile(delete=False)` with a manual
  `Path(tmp).unlink()` — any exception between creation and that line leaked
  the file. Replaced with one `targets_tempfile()` context manager that
  cleans up in `finally`.
- `datetime.utcnow()` (deprecated in 3.12, scheduled for removal) replaced
  with `datetime.now(UTC)` in `server.py` and `guidance.py`.
- Removed the deprecated pydantic v1-style `env="X"` kwarg from every
  `Field()` in `config.py` — redundant since `BaseSettings` already matches
  field names to env vars case-insensitively, and pydantic v2 warns on
  every unrecognized `Field` kwarg on every startup.

### Added

- `tests/` — previously nonexistent. 61 tests covering `scope.py` (pattern
  matching, target parsing, the subdomain-suffix bypass case, blocklist
  precedence) and `server.py` (scope enforcement actually blocking each
  fixed handler, flag-injection rejection, temp-file cleanup including
  on exception).
- `pyproject.toml` — didn't exist; ruff/pytest/mypy had no shared config.
- A `test` job in CI running the new suite. The existing `build` job
  (Docker build, Go-tool check, MCP-initialize smoke test) and `lint` job
  are unchanged in structure; `lint` now also covers `tests/`.
- `make pytest` — run the unit suite without needing a running container.

### Cleanup

- Ruff-clean across `mcp_server/` and `hunt.py` (unused imports, ambiguous
  single-letter variable names, a dead local variable, bare
  `except: pass` blocks replaced with `contextlib.suppress`, an
  `asyncio.TimeoutError` alias replaced with the builtin now that
  `pyproject.toml` declares the 3.11+ target).

### Not done in this pass (and why)

- **Docker non-root hardening.** naabu's SYN-scan mode needs `CAP_NET_RAW`;
  doing this properly means moving to a non-root user with explicit
  capabilities added, not just adding a `USER` line. Worth doing, but it
  needs an actual container build to verify, which wasn't available here.
- **`hunt.py` doesn't share the scope module.** It's a separate, standalone
  CLI a person runs directly against their own target (same trust model as
  running `subfinder` by hand), so it's lower priority than the MCP-exposed
  path — but wiring it in for consistency is a reasonable follow-up.
- **MongoDB/Redis persistence and caching.** `requirements.txt` lists
  `motor`/`redis`, but no code in this repo currently uses them — there's
  no `db.py` or `cache.py` module and nothing in `server.py` references a
  database. If that's a planned feature, it needs to be built, not just
  wired up.
