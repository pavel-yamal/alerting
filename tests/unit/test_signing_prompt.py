"""The approver must see every field their signature will cover.

Recomputing the canonical bytes proves we signed *those* bytes; it says nothing about
whether the approver saw what is in them. A compromised server that widened the
audience or flipped START to STOP would still collect a correct signature over its own
content unless the human is shown all of it.

Reported by an automated review on PR #1. These tests exist because the first fix
added the renderer without wiring it in, and nothing caught that.
"""

from __future__ import annotations

import pytest

from alerting.clients.approver_cli import KNOWN_PAYLOAD_FIELDS, cmd_sign, show_payload
from alerting.core.envelope import Action, Audience
from alerting.orgkit import make_order


@pytest.fixture
def payload(org) -> dict:
    return make_order(
        org,
        audience=Audience(sites=("hq",), groups=("fire-wardens",), persons=("x-101",)),
        text="Задымление, 3 этаж",
    ).to_payload()


def rendered(payload: dict, capsys) -> str:
    show_payload(payload, "ZGVyaXZlZA")
    return capsys.readouterr().out


def test_every_signed_field_is_rendered(payload, capsys):
    """Whatever the signature covers, the approver sees."""
    out = rendered(payload, capsys)
    for key in payload:
        if key in {"v", "type", "nonce", "order_id", "issued_at"}:
            continue  # identity and housekeeping, not decision content
        assert key in KNOWN_PAYLOAD_FIELDS, f"{key} is not accounted for by the prompt"

    assert "EVAC.BUILDING" in out
    assert "critical" in out
    assert "START" in out, "the action decides START vs STOP and must be visible"
    assert "hq" in out and "fire-wardens" in out and "x-101" in out
    assert "primary#1" in out
    assert "Задымление, 3 этаж" in out
    assert "БОЕВОЕ" in out


def test_a_widened_audience_is_visible(payload, capsys):
    """The substitution the finding describes has to be readable on screen."""
    widened = {
        **payload,
        "audience": {"sites": ["hq", "plant", "depot"], "groups": [], "persons": []},
    }
    out = rendered(widened, capsys)
    assert "plant" in out and "depot" in out


def test_a_flipped_action_is_visible(payload, capsys):
    out = rendered({**payload, "action": Action.STOP.value}, capsys)
    assert "STOP" in out


def test_a_cancel_target_is_visible(payload, capsys):
    out = rendered({**payload, "type": "cancel", "cancels": "order-being-revoked"}, capsys)
    assert "order-being-revoked" in out


def test_an_empty_audience_is_called_out(payload, capsys):
    empty = {**payload, "audience": {"sites": [], "groups": [], "persons": []}}
    assert "ПУСТО" in rendered(empty, capsys)


def test_a_drill_is_labelled_as_one(payload, capsys):
    assert "УЧЕНИЕ" in rendered({**payload, "drill": True}, capsys)


def test_an_unrendered_field_is_flagged_rather_than_signed_blind(payload, capsys):
    out = rendered({**payload, "some_new_field": "surprise"}, capsys)
    assert "НЕПОКАЗАННЫЕ ПОЛЯ" in out
    assert "some_new_field" in out


def test_cmd_sign_actually_uses_the_renderer(payload, monkeypatch, capsys):
    """The regression that slipped through: the renderer existed but was never called."""

    class FakeApi:
        def get(self, path: str) -> dict:
            return {"payload": payload}

        def post(self, path: str, body: object = None) -> dict:
            return {"dispatched": False, "signatures": 1, "blocking": ["quorum_not_met"]}

    class Args:
        order_id = payload["order_id"]
        yes = True
        person = "p-001"
        passphrase = "x"
        home = None

    monkeypatch.setattr("alerting.clients.approver_cli.sign_payload", lambda *a, **k: "sig")

    # The key is unlocked once in `main`, before the first request, and handed to the
    # command -- so the command no longer loads it and this test no longer patches
    # the loader.
    stored = type("K", (), {"key_id": "ed25519:k", "private_key": None})()
    cmd_sign(Args(), FakeApi(), stored)
    out = capsys.readouterr().out
    assert "ВЫ ПОДПИСЫВАЕТЕ" in out
    assert "аудитория" in out
    assert "действие" in out
