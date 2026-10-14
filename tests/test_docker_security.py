"""Static checks on the Docker configuration — NOT a runtime test.

There is no Docker daemon in most dev/CI sandboxes, so these read docker-compose.yml,
docker-compose.dev-ports.yml, the Dockerfile and .env.example and pin the SECURE-BY-DEFAULT
properties, so the specific mistakes found in the audit cannot quietly return:

  * databases / n8n / the health API published on every interface,
  * guessable fallback passwords (`${MONGO_PASSWORD:-changeme_please}`),
  * n8n `:latest` and basic-auth settings n8n removed in 1.0 (they protect nothing),
  * DB / n8n secrets forwarded into the container that runs scanners,
  * an unlocked pip install reported as locked.

A passing suite means "these known-bad patterns are absent" — the real container behaviour is
verified by the `docker` job in ci.yml (build, start, health, MCP smoke).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
COMPOSE_TEXT = (ROOT / "docker-compose.yml").read_text()
COMPOSE = yaml.safe_load(COMPOSE_TEXT)
DEV = yaml.safe_load((ROOT / "docker-compose.dev-ports.yml").read_text())
DOCKERFILE = (ROOT / "Dockerfile").read_text()
ENV_EXAMPLE = (ROOT / ".env.example").read_text()
SERVICES = COMPOSE["services"]


def test_base_compose_publishes_nothing():
    for name, svc in SERVICES.items():
        assert not svc.get("ports"), f"{name} publishes ports in the default compose file: {svc['ports']}"


def test_dev_override_binds_loopback_only():
    published = [(n, p) for n, s in DEV["services"].items() for p in s.get("ports", [])]
    assert published, "the dev override should publish something (health / databases / n8n)"
    for name, port in published:
        assert str(port).startswith("127.0.0.1:"), f"{name}: {port} is not bound to 127.0.0.1"


@pytest.mark.parametrize("svc", ["mongodb", "redis"])
def test_database_services_are_not_in_the_dev_override_on_other_interfaces(svc):
    for p in DEV["services"][svc]["ports"]:
        assert not str(p).startswith(("0.0.0.0", ":")) and re.match(r"127\.0\.0\.1:\d+:\d+$", str(p))


def test_no_weak_fallback_secrets_anywhere():
    # `${VAR:-something}` for a secret means "run with a guessable password if unset".
    assert not re.search(r"\$\{[A-Z0-9_]*(PASSWORD|SECRET|TOKEN|KEY)[A-Z0-9_]*:-", COMPOSE_TEXT)
    assert "changeme" not in COMPOSE_TEXT.lower()


@pytest.mark.parametrize("var", ["MONGO_PASSWORD", "REDIS_PASSWORD"])
def test_database_secrets_are_required(var):
    assert re.search(r"\$\{" + var + r":\?[^}]+\}", COMPOSE_TEXT), f"{var} must use ${{{var}:?message}}"


def test_env_example_ships_no_default_passwords():
    assert "changeme" not in ENV_EXAMPLE.lower()
    for var in ("MONGO_PASSWORD", "REDIS_PASSWORD"):
        assert re.search(rf"^{var}=$", ENV_EXAMPLE, re.M), f"{var} must be empty in .env.example"
    assert not re.search(r"^(N8N_USER|N8N_PASSWORD)=", ENV_EXAMPLE, re.M)


def test_redis_password_never_on_a_command_line():
    redis = SERVICES["redis"]
    assert "$$REDIS_PASSWORD" in " ".join(map(str, redis["command"]))        # read from the container's env
    assert "${REDIS_PASSWORD" not in " ".join(map(str, redis["command"]))   # not interpolated into Cmd
    health = " ".join(map(str, redis["healthcheck"]["test"]))
    assert "REDISCLI_AUTH" in health and " -a " not in health


def test_scanner_container_does_not_receive_other_services_secrets():
    env = SERVICES["mcp-server"]["environment"]
    for var in ("MONGO_PASSWORD", "MONGO_URI", "REDIS_PASSWORD", "REDIS_URL", "N8N_USER", "N8N_PASSWORD"):
        assert env.get(var) == "", f"{var} must be blanked for mcp-server (env_file would otherwise forward it)"


def test_n8n_is_pinned_and_has_no_dead_auth_settings():
    n8n = SERVICES["n8n"]
    image = n8n["image"]
    assert ":" in image and "latest" not in image
    assert re.search(r":\$\{N8N_VERSION:-\d+\.\d+\.\d+\}$", image), image    # pinned default, overridable
    flat = " ".join(map(str, n8n["environment"]))
    assert "BASIC_AUTH" not in flat, "n8n removed basic auth in 1.0; these settings protect nothing"
    assert "N8N_DIAGNOSTICS_ENABLED=false" in flat


def test_every_image_is_pinned_to_a_tag():
    for name, svc in SERVICES.items():
        image = svc.get("image")
        if image:
            assert ":" in image.split("/")[-1] and not image.endswith(":latest"), f"{name}: unpinned image {image}"


def test_hardening_flags_present():
    for name, svc in SERVICES.items():
        assert "no-new-privileges:true" in svc.get("security_opt", []), name


def test_health_check_uses_loopback_inside_the_container():
    test = " ".join(SERVICES["mcp-server"]["healthcheck"]["test"])
    assert "127.0.0.1:8080/health" in test


def test_health_api_listens_on_loopback_by_default():
    from mcp_server.server import _health_bind
    assert _health_bind({}) == ("127.0.0.1", 8080)
    assert _health_bind({"HEALTH_HOST": "0.0.0.0", "HEALTH_PORT": "9000"}) == ("0.0.0.0", 9000)
    assert _health_bind({"HEALTH_HOST": "  "}) == ("127.0.0.1", 8080)
    for bad in ("abc", "0", "70000", "-1"):
        assert _health_bind({"HEALTH_PORT": bad})[1] == 8080


def test_dockerfile_never_calls_an_unlocked_install_locked():
    assert "ARG PYTHON_DEPS=latest" in DOCKERFILE
    locked = re.search(r"^\s+locked\)(.*?);;", DOCKERFILE, re.S | re.M)     # the case branch, not text inside an echo
    latest = re.search(r"^\s+latest\)(.*?);;", DOCKERFILE, re.S | re.M)
    assert locked and latest
    assert "--require-hashes -r requirements.lock" in locked.group(1) and "LOCKED" in locked.group(1)
    assert "requirements.lock" not in latest.group(1) and "NOT locked" in latest.group(1)
    assert "PYTHON_DEPS must be 'latest' or 'locked'" in DOCKERFILE               # anything else fails loudly
    assert "COPY requirements.txt requirements.lock" in DOCKERFILE


def test_compose_passes_the_python_deps_switch_to_the_build():
    assert SERVICES["mcp-server"]["build"]["args"]["PYTHON_DEPS"] == "${PYTHON_DEPS:-latest}"
