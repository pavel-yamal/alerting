"""Logging must not leak, and a secret file must not be world-readable."""

from __future__ import annotations

import json
import logging

import pytest

from alerting.server.config import Settings, read_secret_file
from alerting.server.logging_config import JsonFormatter, configure


def test_configure_is_idempotent_and_sets_the_level():
    configure("WARNING")
    configure("INFO")
    assert logging.getLogger().level == logging.INFO


def test_channel_logs_stay_at_info_even_when_the_root_is_turned_down():
    """Delivery attempts are the operational record an incident review reads."""
    configure("WARNING")
    try:
        assert logging.getLogger("alerting.channel.sms").getEffectiveLevel() == logging.INFO
        assert logging.getLogger("alerting.auth").getEffectiveLevel() == logging.INFO
    finally:
        configure("INFO")


def test_json_formatter_emits_parseable_lines():
    record = logging.LogRecord(
        "alerting.test", logging.INFO, __file__, 1, "сообщение %s", ("x",), None
    )
    parsed = json.loads(JsonFormatter().format(record))
    assert parsed["level"] == "INFO"
    assert parsed["message"] == "сообщение x"
    assert parsed["logger"] == "alerting.test"


def test_a_world_readable_secret_is_refused(tmp_path):
    path = tmp_path / "secret"
    path.write_text("s3cret", encoding="utf-8")
    path.chmod(0o644)

    with pytest.raises(PermissionError, match="readable by group or others"):
        read_secret_file(path, "test key")


def test_a_group_readable_secret_is_refused(tmp_path):
    path = tmp_path / "secret"
    path.write_text("s3cret", encoding="utf-8")
    path.chmod(0o640)

    with pytest.raises(PermissionError):
        read_secret_file(path, "test key")


@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_a_properly_locked_secret_is_read(tmp_path, mode):
    path = tmp_path / "secret"
    path.write_text("  s3cret\n", encoding="utf-8")
    path.chmod(mode)

    assert read_secret_file(path, "test key") == "s3cret"


def test_a_missing_secret_file_says_which_one(tmp_path):
    with pytest.raises(FileNotFoundError, match="server key"):
        read_secret_file(tmp_path / "nope", "server key")


def test_settings_read_every_value_from_the_environment(monkeypatch, tmp_path):
    """Five of these used to be code-only, so a deployed node could not set them."""
    monkeypatch.setenv("ALERTING_ORG", "other")
    monkeypatch.setenv("ALERTING_ESCALATION_CONFIG", "/etc/alerting/ladder.yaml")
    monkeypatch.setenv("ALERTING_WORDLIST", "/etc/alerting/words.txt")
    monkeypatch.setenv("ALERTING_HEADS_DIR", "/var/lib/alerting/heads")
    monkeypatch.setenv("ALERTING_SPOOL_DIR", "/var/lib/alerting/spool")
    monkeypatch.setenv("ALERTING_ESCALATION_INTERVAL_S", "12.5")
    monkeypatch.setenv("ALERTING_ALLOW_STUB_CHANNELS", "1")

    settings = Settings.from_env()

    assert settings.org_id == "other"
    assert settings.escalation_config == "/etc/alerting/ladder.yaml"
    assert settings.wordlist_path == "/etc/alerting/words.txt"
    assert str(settings.heads_dir) == "/var/lib/alerting/heads"
    assert str(settings.spool_dir) == "/var/lib/alerting/spool"
    assert settings.escalation_interval_s == 12.5
    assert settings.allow_stub_channels is True


def test_the_server_private_key_is_not_an_environment_variable(monkeypatch):
    """Passing it through the environment put it in /proc, systemctl show and ps."""
    monkeypatch.setenv("ALERTING_SERVER_KEY", "would-be-a-private-key")
    settings = Settings.from_env()

    assert settings.server_key_file == ""
    assert settings.load_server_key() == "", "the old variable must be ignored"


def test_the_server_key_is_read_from_a_locked_file(tmp_path, monkeypatch):
    path = tmp_path / "server-key"
    path.write_text("a-key", encoding="utf-8")
    path.chmod(0o600)
    monkeypatch.setenv("ALERTING_SERVER_KEY_FILE", str(path))

    assert Settings.from_env().load_server_key() == "a-key"


def test_a_bad_interval_is_a_clear_error(monkeypatch):
    monkeypatch.setenv("ALERTING_ESCALATION_INTERVAL_S", "soon")
    with pytest.raises(ValueError, match="must be a number"):
        Settings.from_env()
