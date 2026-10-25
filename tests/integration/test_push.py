"""Push to the decision-makers' app, end to end on the server.

Who is told what: a proposal goes to the decision-makers who did not make it, an
order that went out to everyone but its last signer, a rejection to whoever
proposed or signed. Nobody whose key is revoked; nothing at all with no keys
configured; and never anything that could get in an order's way.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from alerting.clients.transport import SignedRequests
from alerting.core.clock import FixedClock
from alerting.core.signing import DOMAIN_ORDER, generate_keypair, public_key_to_b64u, sign_payload
from alerting.orgadmin import add_key, revoke_keys, verified_current
from alerting.orgkit import Org
from alerting.server.app import create_app
from alerting.server.config import Settings
from alerting.server.mobilepush import MobilePush, PushResult
from alerting.server.services.bootstrap import publish_org
from tests.integration.conftest import signer_for
from tests.integration.test_enrollment import publish

BODY = {"scenario": "EVAC.BUILDING", "severity": "critical", "drill": False,
        "audience": {"groups": ["fire-wardens"]}}  # fmt: skip


class FakePush(MobilePush):
    """Both platforms configured; records every notification instead of sending."""

    def __init__(self) -> None:
        super().__init__(None, None)
        self.sent: list[tuple[str, str, dict[str, str]]] = []
        self.answer = PushResult(ok=True, status_code=200)

    @property
    def configured(self) -> dict[str, bool]:
        return {"ios": True, "android": True}

    async def send_apns(self, token, env, title, body, data):  # type: ignore[override]
        self.sent.append((token, title, data))
        return self.answer

    async def send_fcm(self, token, title, body, data):  # type: ignore[override]
        self.sent.append((token, title, data))
        return self.answer


@pytest.fixture
def server(settings: Settings, clock: FixedClock, org: Org) -> Iterator[TestClient]:
    app = create_app(settings, clock, start_escalation=False)
    publish_org(app.state.alerting.repo, org, audit=app.state.alerting.audit)
    app.state.alerting.notifier.push = FakePush()
    with TestClient(app) as client:
        yield client


def fake(server: TestClient) -> FakePush:
    push: FakePush = server.app.state.alerting.notifier.push
    return push


def settle(server: TestClient) -> None:
    """Notifications run after the response; wait for the ones under way."""
    deadline = time.monotonic() + 5
    while server.app.state.alerting.notifier._tasks and time.monotonic() < deadline:
        time.sleep(0.01)


def register(server, org, clock, person_id: str, token: str, platform: str = "ios"):
    server.auth = signer_for(org, person_id, clock)
    return server.post(
        "/v1/push/tokens", json={"token": token, "platform": platform, "device_label": "iPhone"}
    )


def every_lpr_has_a_phone(server, org, clock) -> None:
    for person_id in ("p-001", "p-002", "p-003"):
        assert register(server, org, clock, person_id, f"token-{person_id}").status_code == 200


def propose(server, org, clock, person_id: str = "p-001") -> dict[str, Any]:
    server.auth = signer_for(org, person_id, clock)
    proposal: dict[str, Any] = server.post("/v1/proposals", json=BODY).json()
    settle(server)
    return proposal


def sign(server, org, clock, proposal, person_id: str) -> dict[str, Any]:
    person = org.person(person_id)
    server.auth = signer_for(org, person_id, clock)
    result: dict[str, Any] = server.post(
        f"/v1/proposals/{proposal['order_id']}/signatures",
        json={
            "key_id": person.key_id,
            "sig": sign_payload(DOMAIN_ORDER, proposal["payload"], person.private_key),
        },
    ).json()
    settle(server)
    return result


def tokens_told(server) -> list[str]:
    told = sorted(token for token, _, _ in fake(server).sent)
    fake(server).sent.clear()
    return told


def test_a_proposal_asks_the_other_decision_makers_and_says_nothing_of_its_content(
    server, org, clock
):
    every_lpr_has_a_phone(server, org, clock)
    proposal = propose(server, org, clock, "p-001")

    sent = fake(server).sent
    assert sorted(token for token, _, _ in sent) == ["token-p-002", "token-p-003"]
    _, title, data = sent[0]
    assert title == "Нужна ваша подпись"
    assert data == {"order_id": proposal["order_id"], "open": "proposal"}
    # It passes through Apple and Google: no scenario, no drill or real, no text.
    everything = repr(sent)
    for leak in ("EVAC", "эвакуац", "БОЕВ", "critical"):
        assert leak not in everything


def test_an_order_that_went_out_is_announced_to_all_but_its_last_signer(server, org, clock):
    every_lpr_has_a_phone(server, org, clock)
    proposal = propose(server, org, clock, "p-001")
    tokens_told(server)
    assert sign(server, org, clock, proposal, "p-001")["dispatched"] is False
    assert tokens_told(server) == [], "a first signature is news to nobody"
    assert sign(server, org, clock, proposal, "p-002")["dispatched"] is True
    assert tokens_told(server) == ["token-p-001", "token-p-003"]
    assert fake(server).sent == []


def test_a_rejection_tells_whoever_proposed_or_signed_it(server, org, clock):
    every_lpr_has_a_phone(server, org, clock)
    proposal = propose(server, org, clock, "p-001")
    sign(server, org, clock, proposal, "p-001")
    tokens_told(server)
    server.auth = signer_for(org, "p-002", clock)
    assert server.post(f"/v1/proposals/{proposal['order_id']}/reject", json={}).status_code == 200
    settle(server)
    assert tokens_told(server) == ["token-p-001"], "p-003 had no part in it"


def test_a_revoked_decision_maker_is_told_nothing(server, org, clock):
    every_lpr_has_a_phone(server, org, clock)
    server.auth = signer_for(org, "p-001", clock)
    current = verified_current(
        server.get("/v1/directory").json(), public_key_to_b64u(org.root_public_key)
    )
    revoked, _ = revoke_keys(current, person_id="p-003", kid=None, at=clock.now(), reason="lost")
    publish(server, org, revoked)
    propose(server, org, clock, "p-001")
    assert tokens_told(server) == ["token-p-002"]


def test_revoking_a_lost_phones_key_silences_that_phone_but_not_the_owners_other(
    server, org, clock
):
    """p-002 has a second phone with its own key. Losing it revokes that key, not the
    person: the first phone keeps getting notifications, the lost one gets none."""
    server.auth = signer_for(org, "p-001", clock)
    directory = verified_current(
        server.get("/v1/directory").json(), public_key_to_b64u(org.root_public_key)
    )
    private, public = generate_keypair()
    enrolled, second = add_key(
        directory, person_id="p-002", name="Кузнецова Е. П.", role="lpr",
        public_key=public_key_to_b64u(public), issued_at=clock.now(),
    )  # fmt: skip
    publish(server, org, enrolled)

    register(server, org, clock, "p-002", "token-first-phone")
    server.auth = SignedRequests(
        org_id=org.org_id, key_id=second.key_id, person_id="p-002",
        private_key=private, clock=clock,
    )  # fmt: skip
    lost = server.post("/v1/push/tokens", json={"token": "token-lost-phone", "platform": "ios"})
    assert lost.status_code == 200, lost.text

    propose(server, org, clock, "p-001")
    assert tokens_told(server) == ["token-first-phone", "token-lost-phone"]

    server.auth = signer_for(org, "p-001", clock)
    current = verified_current(
        server.get("/v1/directory").json(), public_key_to_b64u(org.root_public_key)
    )
    revoked, _ = revoke_keys(current, person_id=None, kid=second.key_id, at=clock.now(),
                             reason="lost")  # fmt: skip
    publish(server, org, revoked)
    propose(server, org, clock, "p-001")
    assert tokens_told(server) == ["token-first-phone"]


def test_only_decision_makers_register_and_only_for_themselves(server, org, clock):
    assert register(server, org, clock, "x-101", "token-x").status_code == 403
    assert register(server, org, clock, "p-004", "token-duty").status_code == 403
    assert register(server, org, clock, "p-001", "short").status_code == 422
    assert register(server, org, clock, "p-001", "token-a", platform="web").status_code == 422

    answer = register(server, org, clock, "p-001", "token-shared-phone").json()
    assert answer == {"token": "…-phone", "configured": True}, "the token never comes back"
    # The same phone handed to someone else moves with them.
    register(server, org, clock, "p-002", "token-shared-phone")
    rows = server.app.state.alerting.repo.push_tokens_for(["p-001", "p-002"])
    assert [(r["person_id"], r["apns_env"]) for r in rows] == [("p-002", "production")]

    # Removing is for one's own device only, and answers the same either way.
    server.auth = signer_for(org, "p-001", clock)
    assert server.post("/v1/push/tokens/remove", json={"token": "token-shared-phone"}).json()
    assert server.app.state.alerting.repo.push_tokens_for(["p-002"])
    server.auth = signer_for(org, "p-002", clock)
    server.post("/v1/push/tokens/remove", json={"token": "token-shared-phone"})
    assert server.app.state.alerting.repo.push_tokens_for(["p-002"]) == []


def test_dead_tokens_are_forgotten_and_failures_counted(server, org, clock):
    every_lpr_has_a_phone(server, org, clock)
    repo = server.app.state.alerting.repo
    fake(server).answer = PushResult(ok=False, gone=True, error="Unregistered")
    propose(server, org, clock, "p-001")
    assert [r["person_id"] for r in repo.push_tokens_for(["p-001", "p-002", "p-003"])] == ["p-001"]

    fake(server).answer = PushResult(ok=False, status_code=503, error="Unavailable")
    propose(server, org, clock, "p-002")
    row = repo.push_tokens_for(["p-001"])[0]
    assert row["failure_count"] == 1 and row["last_error"] == "Unavailable"

    fake(server).answer = PushResult(ok=True, status_code=200, apns_env="sandbox")
    propose(server, org, clock, "p-002")
    row = repo.push_tokens_for(["p-001"])[0]
    assert row["failure_count"] == 0 and row["apns_env"] == "sandbox"
    assert row["last_success_at"] == clock.now()


def test_the_test_button_reports_each_device(server, org, clock):
    register(server, org, clock, "p-001", "token-p-001")
    register(server, org, clock, "p-001", "token-p-001-tab", platform="android")
    server.auth = signer_for(org, "p-001", clock)
    answer = server.post("/v1/push/test", json={}).json()
    assert answer["configured"] == {"ios": True, "android": True}
    assert sorted((d["platform"], d["ok"]) for d in answer["devices"]) == [
        ("android", True),
        ("ios", True),
    ]


def test_a_push_that_fails_never_gets_in_the_orders_way(server, org, clock):
    every_lpr_has_a_phone(server, org, clock)

    async def broken(*args, **kwargs):
        raise RuntimeError("Apple is down")

    fake(server).send_apns = broken  # type: ignore[method-assign]
    proposal = propose(server, org, clock, "p-001")
    sign(server, org, clock, proposal, "p-001")
    assert sign(server, org, clock, proposal, "p-002")["dispatched"] is True


def test_with_no_keys_nothing_is_attempted(settings, clock, org):
    app = create_app(settings, clock, start_escalation=False)
    publish_org(app.state.alerting.repo, org, audit=app.state.alerting.audit)
    with TestClient(app) as client:
        notifier = app.state.alerting.notifier
        assert not notifier.enabled
        register(client, org, clock, "p-002", "token-p-002")
        propose(client, org, clock, "p-001")
        assert notifier._tasks == set()
        assert register(client, org, clock, "p-001", "token-p-001").json()["configured"] is False


def test_configured_keys_are_read_and_checked_at_start(tmp_path, settings):
    """A key file the node cannot use stops it at start, rather than a push stand
    that believes it works and silently does not."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    p8 = tmp_path / "apns.p8"
    p8.write_bytes(key)
    os.chmod(p8, 0o600)
    settings.apns_team_id, settings.apns_key_id, settings.apns_key_file = "T", "K", str(p8)
    apns, fcm = settings.load_push()
    assert apns is not None and apns.topic == "me.yamal.alert" and fcm is None

    os.chmod(p8, 0o644)
    with pytest.raises(PermissionError):
        settings.load_push()
    os.chmod(p8, 0o600)
    settings.apns_team_id = ""
    with pytest.raises(RuntimeError, match="TEAM_ID"):
        settings.load_push()
