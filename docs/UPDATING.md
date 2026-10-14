# Keeping tools and dependencies current

This project drives third-party security tools (nuclei, subfinder, httpx, …)
that release constantly. The repository **does not hard-code their versions**,
so cloning it months after the last commit still gives you current tools — and
the update machinery never silently breaks a setup that works.

## The three updates are independent

| You run | It updates | It does **not** touch |
|---|---|---|
| `git pull` | this project's own code and `config/tools.yaml` | installed tools, system packages |
| `./hunt update` | the Go security tools, the nuclei **templates**, in *this* checkout (`bin/tools/`) | your system packages, any copy of a tool installed elsewhere |
| `sudo apt update && sudo apt upgrade` | APT-managed packages | **this project** — APT does not know it exists |

> `apt update` / `apt upgrade` updates APT-managed packages. This project is
> **not** automatically upgraded by APT unless you explicitly opt in to the
> optional signal described under [APT](#apt-optional-signal-only) — and even
> then APT itself updates nothing here.

Docker is a fourth, separate case: tools live *inside the image*, so a new
**build** is the only way to update them (`docker pull` cannot — see [Docker](#docker)).

## Fresh install

```bash
git clone https://github.com/Coding-with-Mayank/BugBounty-mcp-server
cd BugBounty-mcp-server
./install-native.sh
```

For every tool in [`config/tools.yaml`](../config/tools.yaml) the installer
resolves the **newest stable release inside the tested major version at that
moment**, builds it, tests it, and only then puts it in `bin/tools/`. Exact
versions are written to `data/installed-tools.json` (not committed).

Python dependencies work the same way: `requirements.txt` has lower bounds, so
a fresh `pip install` takes the newest allowed releases.

## Day to day

```bash
./hunt doctor            # installed vs latest compatible, per tool; PATH/Python/MCP health
./hunt doctor --json     # the same, as ONE JSON document (nothing else on stdout)
./hunt update --check    # what is newer? changes nothing   (--fail-on-outdated exits 10, for CI)
./hunt update --dry-run  # exactly what would happen? changes nothing
./hunt update            # apply, after asking
./hunt update --yes      # apply without asking (automation)
./hunt rollback nuclei   # restore the previous version
```

Example (`./hunt update`):

```text
BugBounty MCP Tool Update

Tool      Installed      Target  Status   Note
nuclei    3.3.9      ->  3.11.1  UPDATED
subfinder 2.6.6      ->  2.16.0  UPDATED
httpx     1.6.10     ->  1.12.0  UPDATED
```

(Illustrative — versions depend on what upstream has released.)

## The upgrade policy

| Release | Behaviour |
|---|---|
| **patch** (3.3.9 → 3.3.10) | applied |
| **minor** (3.3.9 → 3.4.0) | applied **only if** the staged build passes the compatibility self-test |
| **major** (3.x → 4.x) | **never applied silently.** Reported, with the exact command. `./hunt update --major` tries it; the self-test still decides |
| **0.x minor** (0.1 → 0.2) | treated like a major (semver promises nothing for 0.x) |
| older than installed | never — no downgrades |

Majors are structurally safe too: Go puts the major in the module path
(`…/nuclei/v3/cmd/nuclei`), so "latest" cannot wander to an untested major.

**The compatibility self-test** runs each tool's own help text and checks that it
still lists every flag this project's handlers pass it (`compat:` in
`config/tools.yaml`; a test fails if a handler starts using a flag the manifest
doesn't cover). A renamed or removed flag therefore *blocks the update* and the
old version stays.

### What happens to the binary

```text
resolve exact version → go install into a private staging dir (never the live one)
  → validate: regular file, executable, right program, right version, flags OK
  → back up the working binary  →  atomic rename into place
  → verify the INSTALLED file again → on any failure restore the backup
```

Backups live in `bin/tools/.backup/<tool>-<version>` (last 3 kept).
`./hunt rollback <tool>` swaps one back — and keeps what it replaced, so a
rollback is itself undoable. Every action is logged to
`data/update-history.json` (timestamp, tool, old/new version, source,
success/failure, reason; credentials are redacted).

### If the network is down

`./hunt update` reports `Update check failed — keeping every existing tool`,
changes nothing, and exits 0. `--offline` skips lookups entirely (answers come
from the last cached check). Upstream lookups are cached for 24 h
(`check_interval_hours` in the manifest), so repeated `doctor` runs don't hammer
anyone; GitHub's anonymous rate limit can be lifted with `GITHUB_TOKEN`.

## Tools you already have

Before installing anything the project looks for existing copies — project-local
(`bin/tools`), `~/go/bin`, and anywhere on `PATH` — and **never overwrites a
system copy**. The **newest compatible** copy wins, so an old local binary can't
shadow a newer system one:

```bash
./hunt config tools                         # every copy found, and which is selected
./hunt config tools set nuclei system       # pin: system | local | go | auto | /abs/path
./hunt config tools reset nuclei
```

The selection is realised as symlinks in `bin/active/`, which the launchers
(`bin/hunt`, `bin/bugbounty-mcp-server`) put first on `PATH`. A binary with the
right name but the wrong origin (e.g. the Python `httpx` CLI) is rejected by
identity checks (Go build info / output signature).

## nuclei: engine and templates are separate

`./hunt doctor` and `./hunt update` track the nuclei **engine** and the nuclei
**templates** as two items and report them separately; updating the binary does
not update the templates, and `./hunt update --templates-only` updates just those
(it runs nuclei's own `-update-templates`).

## Reproducible installs

```bash
./hunt snapshot                                  # record what's installed → config/tool-lock.json
./hunt install --lock config/tool-lock.json      # install EXACTLY those versions
./install-native.sh --lock config/tool-lock.json
./install-native.sh --locked-python              # Python deps from requirements.lock (hash-verified)
```

So you choose: **fresh + current** (default) or **stable + reproducible**
(lockfiles). `config/tool-lock.json` ships as the set this repository used before
the manifest existed. A lock is validated against the manifest before use — it can
only say "tool X at version V", never a different module or option.

## Optional: automatic updates (off by default)

```bash
./hunt auto-update enable      # shows exactly what it will do, asks first
./hunt auto-update status
./hunt auto-update disable     # (also: ./hunt update --disable-auto)
```

Enabling creates **user-level** systemd units only
(`~/.config/systemd/user/bugbounty-mcp-update.{service,timer}`): no root, no
sudo. Roughly daily the timer runs `./hunt update --auto`, which:

* applies **patch/minor** updates of tools *this project installed*, each only
  after the self-test passes (a failure keeps the old version);
* **never** applies a major, never touches system packages;
* is throttled (default 24 h, `--interval HOURS`) and refuses to run as root.

It requires `systemd --user`; on macOS/containers it says so, and you can call
`<repo>/hunt update --auto` from cron/launchd yourself.

### APT (optional signal only)

APT cannot update this project and we deliberately do **not** run repository code
from an APT hook (that would execute whatever is in a git checkout *as root*).
If you want APT activity to trigger the same throttled user-level check:

```bash
./hunt auto-update enable --apt-signal
```

This prints a root-side snippet for **you** to read and run. It installs a
config that does exactly one thing after `apt update` / dpkg runs — `touch` a
marker file. A user-level systemd `.path` unit notices the touch and starts the
ordinary `hunt update --auto` (throttled, as you). The hook runs no repository
code, uses no network, can't slow `apt` meaningfully, and can't loop.
`./hunt auto-update disable` prints the removal commands.

## Docker

Tool versions are resolved **at image build time** by the same code and manifest
as the native installer (the Dockerfile contains no versions). Consequences:

* `docker pull` / `docker compose pull` **cannot** update tools inside an image
  you already have. Only a new build can.
* A plain `docker compose build` reuses cached layers (including the tools). Use:

  ```bash
  make refresh-tools        # = TOOLS_REFRESH=$(date +%s) docker compose build --pull ; up -d
  # or: TOOLS_REFRESH=$(date +%s) docker compose build --pull
  ```

  `TOOLS_REFRESH` changes only the tool layer's cache key; Python layers stay cached.
* `TOOL_LOCK=config/tool-lock.json docker compose build` reproduces an exact set.
* `STRICT_TOOLS=1` makes the build **fail** if a required tool is missing,
  broken, or incompatible (CI uses it). Without it the build warns and continues,
  as it always did.
* The image records its exact versions at `/opt/bbmcp/installed-tools.json`;
  `docker exec bugbounty-mcp python -m mcp_server.toolmgr verify` (or
  `make docker-verify`) checks them.
* Inside a running container `./hunt update` reports what a rebuild would change
  but does not modify image binaries (images are immutable); it can update nuclei
  templates.

## Trust model

* **Trust root: this repository.** `config/tools.yaml` decides what is
  downloaded. Protect it like code (review, signed commits).
* **Source of tool code: the Go module proxy**, verified by Go's checksum
  database (`GOSUMDB`). The updater scrubs `GOFLAGS`, `GOINSECURE`,
  `GONOSUMDB`, `GOPRIVATE`, `GOSUMDB=off`, `LD_PRELOAD`, `CGO_*` and similar from
  the build environment. A user-level `go env -w` file is trusted.
* **No archives are downloaded**, so there is no archive-extraction surface;
  nothing is piped into a shell.
* **Version lookups:** `proxy.golang.org` and `api.github.com` only, HTTPS only,
  redirects re-checked, 2 MB response cap, strict version parsing (a hostile tag
  like `v2.3.1; rm -rf /` is dropped before it can reach a command line).
* **Ownership:** every module must be `github.com/<repo>` *and* its owner must be
  in `TRUSTED_OWNERS` (in code, not in the data file).
* **Not defended against:** a compromised upstream publishing a malicious
  release that still passes the flag self-test, or a compromised repository. The
  self-test is a *compatibility* check, not malware detection. This is the usual
  limit of "update to latest"; `hunt snapshot`/lock files and `max_version` exist
  so you can hold a version you trust.
* **Privilege:** mutating commands refuse root (`--allow-root` exists for Docker
  builds). If you do run `hunt doctor` as root it will not execute binaries that
  aren't root-owned and write-protected.

## Maintainers: keeping the repository itself fresh

`.github/workflows/freshness.yml` runs weekly: installs the newest compatible
tools on a clean runner, runs `hunt verify`, and either opens a PR refreshing
`config/tool-lock.json` or opens an issue when a newer release breaks
compatibility; rebuilds Docker cache-busted; and re-tests against the newest
Python dependencies (including the MCP SDK), refreshing `requirements.lock`.
`.github/dependabot.yml` covers Docker base images and Actions. A newly released
**major** shows up in `hunt update --check` and in the workflow log — adopting it
means updating `tested_major`/`min_version` in the manifest *and* the handlers.

## Adding or changing a tool

Edit `config/tools.yaml` only. List every flag the handlers pass under `compat:`
(`tests/test_toolmgr_manifest.py` fails if you forget). New upstream owners also
need `TRUSTED_OWNERS` (and its pinning test) updated.


## Python dependencies: newest compatible vs locked

| You want | Native | Docker |
|---|---|---|
| the newest releases `requirements.txt` allows (default) | `./install-native.sh` | `docker compose build` |
| exactly the tested, sha256-verified set in `requirements.lock` | `./install-native.sh --locked-python` | `make build-locked` (`PYTHON_DEPS=locked`) |

A Docker image records which one it is: `docker run --rm IMAGE head -1 /opt/bbmcp/python-deps.txt`
prints `mode=latest` or `mode=locked`, followed by the full `pip freeze`. `hunt update` never touches
Python packages — that is `pip install -U -r requirements.txt` (or re-run the installer).

`scripts/refresh-lock.sh --check` verifies the lock still matches `requirements.txt` (CI fails if not);
`--refresh` (`make lock`) re-resolves to the newest allowed releases — run the tests before committing.

## How the weekly freshness job stays safe

It has to install and run upstream code, so it is split by trust (details in the header of
`.github/workflows/freshness.yml`): test jobs are read-only with no token and hand over *files*; a
separate publish job holds the write token, executes nothing from upstream, and re-validates every file
with `scripts/ci_publish_guard.py` before opening a PR. `tests/test_workflow_security.py` fails the
build if that split is ever undone.
