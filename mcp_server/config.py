"""
Configuration — reads from .env file and environment variables.
All values have safe defaults so the server starts even without a .env.
"""
from __future__ import annotations

import os
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _state_root() -> Path:
    """
    Where logs/reports/screenshots/data live by default.

    Inside the Docker image the code is copied to /app (Dockerfile:
    `COPY . /app/`), so /app is the right root there and is what the
    volumes in docker-compose.yml mount over. In a native checkout /app
    doesn't exist and isn't writable, so these used to crash on import
    (config.py calls ensure_dirs() at import time) — now they resolve to
    the repo root instead, the same directories setup.sh and the native
    installer create. BBMCP_HOME overrides both for custom layouts.
    Individual LOG_FILE/DATA_DIR/... env vars still win over all of this.
    """
    override = os.environ.get("BBMCP_HOME")
    if override:
        return Path(override).expanduser()
    if Path("/app/mcp_server").is_dir():
        return Path("/app")
    return Path(__file__).resolve().parent.parent


_ROOT = _state_root()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ── Server ────────────────────────────────────────────────────────
    debug: bool = Field(False)
    log_file: str = Field(str(_ROOT / "logs" / "mcp_server.log"))
    reports_dir: str = Field(str(_ROOT / "reports"))
    screenshots_dir: str = Field(str(_ROOT / "screenshots"))
    data_dir: str = Field(str(_ROOT / "data"))

    # ── Scope & Safety ────────────────────────────────────────────────
    # Comma-separated list of allowed domains/IPs you have permission to test
    # Leave empty to allow all (your responsibility to test legally)
    allowed_scope: str = Field("")

    # Always blocked — never scan these, regardless of ALLOWED_SCOPE.
    # 127.0.0.0/8 (not just .1 — the whole loopback range), 169.254.0.0/16
    # (link-local, covers the 169.254.169.254 cloud-metadata address as a
    # subset), and all three RFC1918 private ranges, plus IPv6 loopback
    # (::1), link-local (fe80::/10), and unique-local (fc00::/7).
    blocked_targets: str = Field(
        "localhost,127.0.0.0/8,0.0.0.0,169.254.0.0/16,169.254.169.254,"
        "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,"
        "::1,fe80::/10,fc00::/7",
    )

    # If a target's DNS can't be resolved (or resolution times out), should
    # the scan proceed anyway on the hostname-level check alone (False,
    # default - a flaky resolver shouldn't block an authorized scan), or be
    # denied until resolution succeeds (True - stricter, for environments
    # that would rather fail closed than scan without IP-level verification)?
    strict_scope: bool = Field(False)

    # ── Task management ───────────────────────────────────────────────
    # start_task/get_task_status/get_task_results/cancel_task run any
    # existing tool as a cancellable background task instead of blocking
    # the MCP call until it finishes - useful for nuclei_scan/dir_fuzz/
    # full_recon, which can run for minutes.
    task_soft_timeout: int = Field(60)    # seconds - "still running" advisory
    task_hard_timeout: int = Field(900)   # seconds - force-cancel ceiling
    max_concurrent_tasks: int = Field(10)  # reject new start_task calls beyond this
    max_tracked_tasks: int = Field(200)   # oldest finished tasks evicted beyond this
    # Keep task history (status, results, partial output) in DATA_DIR/tasks so it
    # survives a server restart. Set PERSIST_TASKS=false for a purely in-memory
    # server. Interrupted tasks are reported as such, never resumed.
    persist_tasks: bool = Field(True)

    # Smart Hunt (see smart_hunt.py). Investigation sessions persist under
    # DATA_DIR/hunts the same way tasks do. Refuses to start a session while
    # ALLOWED_SCOPE is empty unless explicitly overridden — an AI iterating
    # on its own shouldn't be pointed at "open mode".
    smart_hunt_enabled: bool = Field(True)
    smart_hunt_require_scope: bool = Field(True)

    # ── MongoDB ───────────────────────────────────────────────────────
    mongo_uri: str = Field(
        "mongodb://admin:changeme_please@mongodb:27017/bugbounty?authSource=admin",
    )
    mongo_password: str = Field("changeme_please")

    # ── Redis ─────────────────────────────────────────────────────────
    redis_url: str = Field("redis://:changeme_please@redis:6379/0")
    redis_password: str = Field("changeme_please")

    # ── Intelligence API keys (all optional) ──────────────────────────
    shodan_api_key: str | None = Field(None)
    virustotal_api_key: str | None = Field(None)
    censys_api_id: str | None = Field(None)
    censys_api_secret: str | None = Field(None)
    securitytrails_api_key: str | None = Field(None)

    # ── Scanning defaults ─────────────────────────────────────────────
    default_threads: int = Field(50)
    default_timeout: int = Field(120)
    rate_limit: int = Field(50)          # requests/sec for nuclei
    max_subdomains: int = Field(500)  # cap results

    # ── Notifications (optional) ──────────────────────────────────────
    slack_webhook: str | None = Field(None)
    telegram_bot_token: str | None = Field(None)
    telegram_chat_id: str | None = Field(None)

    def ensure_dirs(self) -> None:
        """Create all required directories if they don't exist."""
        dirs = [Path(self.reports_dir), Path(self.screenshots_dir), Path(self.data_dir), Path(self.log_file).parent]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)

    @property
    def scope_list(self) -> list[str]:
        if not self.allowed_scope:
            return []
        return [s.strip() for s in self.allowed_scope.split(",") if s.strip()]

    @property
    def blocked_list(self) -> list[str]:
        return [s.strip() for s in self.blocked_targets.split(",") if s.strip()]


# Singleton used across the package
settings = Settings()
settings.ensure_dirs()
