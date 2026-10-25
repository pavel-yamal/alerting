"""The panel refuses to start in a configuration nobody could sign in with."""

from __future__ import annotations

import pytest

from alerting.clients.panel.cli import main


@pytest.mark.parametrize(
    "argv",
    [
        ["--org", "acme"],  # device login half-configured: --root-key missing
        ["--root-key", "AAAA"],  # and the other half
        [],  # neither device login nor demo keys
    ],
)
def test_an_unusable_configuration_is_refused(argv, monkeypatch):
    for name in ("ALERTING_PANEL_ORG", "ALERTING_PANEL_ROOT_PUBKEY", "ALERTING_PANEL_SERVER_KEYS"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(SystemExit) as stopped:
        main(argv)
    assert stopped.value.code == 2


@pytest.mark.parametrize("argv", [["sessions"], ["end-session", "p-003"], ["end-session", "--all"]])
def test_admin_commands_need_the_running_panels_token(argv, tmp_path, capsys):
    """No token file: no panel on this host wrote one, and nothing is sent."""
    assert main(["--state", str(tmp_path), *argv]) == 1
    assert "admin.token" in capsys.readouterr().err
