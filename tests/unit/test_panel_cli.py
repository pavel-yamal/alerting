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
