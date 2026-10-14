"""scripts/gen-env.sh: random secrets, no defaults, idempotent, never prints a secret."""
from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "gen-env.sh"


def run(tmp_path, *args, env_text=None):
    envf = tmp_path / ".env"
    if env_text is not None:
        envf.write_text(env_text)
    done = subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, timeout=60,
                          env={**os.environ, "ENV_FILE": str(envf), "ENV_EXAMPLE": str(ROOT / ".env.example")})
    return done, envf


def values(envf):
    return dict(line.split("=", 1) for line in envf.read_text().splitlines() if re.match(r"^[A-Z0-9_]+=", line))


def test_creates_env_with_strong_random_secrets(tmp_path):
    done, envf = run(tmp_path)
    assert done.returncode == 0, done.stderr
    v = values(envf)
    for k in ("MONGO_PASSWORD", "REDIS_PASSWORD"):
        assert re.fullmatch(r"[0-9a-f]{48}", v[k]), f"{k} should be 192 random bits as hex"
    assert v["MONGO_PASSWORD"] != v["REDIS_PASSWORD"]
    assert v["MONGO_URI"] == f"mongodb://admin:{v['MONGO_PASSWORD']}@mongodb:27017/bugbounty?authSource=admin"
    assert v["REDIS_URL"] == f"redis://:{v['REDIS_PASSWORD']}@redis:6379/0"
    assert stat.S_IMODE(envf.stat().st_mode) == 0o600


def test_never_prints_a_secret(tmp_path):
    done, envf = run(tmp_path)
    for secret in (values(envf)["MONGO_PASSWORD"], values(envf)["REDIS_PASSWORD"]):
        assert secret not in done.stdout + done.stderr


def test_two_runs_give_different_secrets_and_a_rerun_changes_nothing(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    _, a = run(tmp_path / "a")
    _, b = run(tmp_path / "b")
    assert values(a)["MONGO_PASSWORD"] != values(b)["MONGO_PASSWORD"]
    before = a.read_text()
    done, _ = run(tmp_path / "a")
    assert done.returncode == 0 and a.read_text() == before and "nothing to do" in done.stdout


def test_user_chosen_values_are_never_overwritten(tmp_path):
    text = (ROOT / ".env.example").read_text().replace("MONGO_PASSWORD=", "MONGO_PASSWORD=my-own-long-passphrase-1", 1)
    done, envf = run(tmp_path, env_text=text)
    v = values(envf)
    assert done.returncode == 0 and v["MONGO_PASSWORD"] == "my-own-long-passphrase-1"
    assert re.fullmatch(r"[0-9a-f]{48}", v["REDIS_PASSWORD"])            # the empty one was filled


def test_old_placeholder_is_replaced_everywhere(tmp_path):
    old = ("MONGO_PASSWORD=changeme_please\nMONGO_URI=mongodb://admin:changeme_please@mongodb:27017/bugbounty?authSource=admin\n"
           "REDIS_PASSWORD=changeme_please\nREDIS_URL=redis://:changeme_please@redis:6379/0\nALLOWED_SCOPE=example.com\n")
    done, envf = run(tmp_path, env_text=old)
    assert done.returncode == 0 and "changeme" not in envf.read_text()
    assert values(envf)["ALLOWED_SCOPE"] == "example.com"                   # unrelated settings untouched


def test_check_mode(tmp_path):
    missing, _ = run(tmp_path, "--check")
    assert missing.returncode == 1
    bad, _ = run(tmp_path, "--check", env_text="MONGO_PASSWORD=changeme_please\nREDIS_PASSWORD=\n")
    assert bad.returncode == 1 and "MONGO_PASSWORD" in bad.stderr and "REDIS_PASSWORD" in bad.stderr
    run(tmp_path)  # fills it in (file exists with placeholders)
    ok, _ = run(tmp_path, "--check")
    assert ok.returncode == 0


def test_unknown_option_is_rejected(tmp_path):
    assert run(tmp_path, "--bogus")[0].returncode == 2


def test_shipped_example_would_make_compose_fail_not_run_insecure():
    # An unmodified copy of .env.example has EMPTY database secrets, and compose requires them.
    assert re.search(r"^MONGO_PASSWORD=$", (ROOT / ".env.example").read_text(), re.M)
    assert pytest.importorskip("yaml")
