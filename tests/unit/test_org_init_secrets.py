"""org_init writes private keys to local disk, so it has to be hard to do by accident.

The org root private key is the trust anchor for the whole system; docs/02 says it
lives on two encrypted USB keys held by two custodians.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

SCRIPT = ["scripts/org_init.py"]

#: org_init drops and recreates the schema -- that is what it is for -- so the two
#: tests that let it run need the OWNER role, and they empty the development
#: database. Same effect as running `make org-init` by hand.
OWNER_DSN = os.environ.get(
    "ALERTING_TEST_DSN",
    os.environ.get("ALERTING_DSN", "postgres://alerting_owner:devpass@127.0.0.1:5432/alerting"),
)

#: The refusal tests must fail *before* any connection is attempted, so the DSN they
#: pass is deliberately one that could never work.
UNUSED_DSN = "postgres://never:used@127.0.0.1:1/nothing"


def run(args: list[str], env_extra: dict[str, str] | None = None):
    env = {**os.environ, **(env_extra or {})}
    return subprocess.run([sys.executable, *SCRIPT, *args], capture_output=True, text=True, env=env)


def test_it_refuses_without_the_confirmation(tmp_path):
    """The old guard only asked when ALERTING_ENV happened to be set, which is
    neither the default nor how CI runs it."""
    result = run(["--dsn", UNUSED_DSN, "--home", str(tmp_path / "clients")])
    assert result.returncode != 0
    assert "--i-understand-this-is-a-demo" in result.stderr


@pytest.mark.parametrize("environment", ["production", "prod", "staging", "PRODUCTION"])
def test_it_refuses_outright_in_a_real_environment(tmp_path, environment):
    result = run(
        [
            "--dsn",
            UNUSED_DSN,
            "--home",
            str(tmp_path / "clients"),
            "--i-understand-this-is-a-demo",
        ],
        {"ALERTING_ENV": environment},
    )
    assert result.returncode != 0
    assert "refusing to run" in result.stderr


def test_every_generated_secret_is_owner_only(tmp_path):
    home = tmp_path / "clients"
    result = run(
        [
            "--dsn",
            OWNER_DSN,
            "--home",
            str(home),
            "--secrets-dir",
            str(tmp_path / "secrets"),
            "--i-understand-this-is-a-demo",
        ]
    )
    assert result.returncode == 0, result.stderr

    secrets_dir = tmp_path / "secrets"
    written = sorted(secrets_dir.glob("*.SECRET"))
    assert {p.name for p in written} == {
        "api-key.SECRET",
        "server-key.SECRET",
        "root-key.SECRET",
    }
    for path in written:
        assert path.stat().st_mode & 0o077 == 0, f"{path.name} is not owner-only"

    # The per-person wake key is a secret too: whoever reads it can compute that
    # person's codes and send a phishing SMS that passes all three card checks.
    wake_keys = sorted(home.glob("*/wake_key.hex"))
    assert wake_keys
    for path in wake_keys:
        assert path.stat().st_mode & 0o077 == 0, f"{path} is world- or group-readable"


def test_secrets_land_beside_home_not_in_the_current_directory(tmp_path):
    """They used to be hardcoded to ./var regardless of --dsn and --home, so pointing
    the script elsewhere still dropped the root key into the working directory."""
    home = tmp_path / "somewhere" / "clients"
    result = run(
        [
            "--dsn",
            OWNER_DSN,
            "--home",
            str(home),
            "--i-understand-this-is-a-demo",
        ]
    )
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "somewhere" / "root-key.SECRET").exists()
