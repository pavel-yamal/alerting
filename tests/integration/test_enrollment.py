"""Enrolling and revoking device keys, and managing contacts, through the server.

The directory change is signed offline by the root (``alerting-org directory``) and
only carried by ``POST /v1/bundles``; the server verifies it like any device would.
Contacts are server-held personal data and decide only where orders are sent.
"""

from __future__ import annotations

import secrets
from typing import Any

import pytest
from fastapi.testclient import TestClient

from alerting.clients.transport import SignedRequests
from alerting.core.audit_chain import Event
from alerting.core.clock import FixedClock
from alerting.core.signing import (
    DOMAIN_DIRECTORY,
    b64u_encode,
    generate_keypair,
    public_key_to_b64u,
)
from alerting.orgadmin import add_key, retire_keys, revoke_keys, verified_current
from alerting.orgkit import Org, sign_bundle
from tests.integration.conftest import signer_for, signing_client
from tests.integration.test_e2e_ws import connect_executor
from tests.integration.test_events import dispatch

pytestmark = pytest.mark.asyncio


@pytest.fixture
def client(settings, clock: FixedClock, org: Org):
    """Signing as a duty officer: enrolment is an operator's job, not only a director's."""
    with signing_client(settings, clock, org, "p-003") as test_client:
        yield test_client


def current(client: TestClient, org: Org):
    return verified_current(
        client.get("/v1/directory").json(), public_key_to_b64u(org.root_public_key)
    )


def publish(client: TestClient, org: Org, payload: Any) -> dict[str, Any]:
    bundle = sign_bundle(payload, DOMAIN_DIRECTORY, org.root_private_key)
    response = client.post("/v1/bundles", json={"bundle": bundle})
    assert response.status_code == 200, response.text
    return response.json()


def chain(client: TestClient, event: Event) -> list[dict[str, Any]]:
    entries = client.app.state.alerting.repo.audit_entries(0, 10_000)
    return [e["data"] for e in entries if e["event"] == event]


async def test_a_newly_enrolled_device_can_sign_in_at_once(client, org, clock):
    private, public = generate_keypair()
    payload, entry = add_key(
        current(client, org), person_id="x-104", name="Новиков П. С.", role="executor",
        public_key=public_key_to_b64u(public), issued_at=clock.now(),
    )  # fmt: skip
    newcomer = SignedRequests(
        org_id=org.org_id, key_id=entry.key_id, person_id="x-104",
        private_key=private, clock=clock,
    )  # fmt: skip
    assert client.get("/v1/directory", auth=newcomer).status_code == 403, "not enrolled yet"

    assert publish(client, org, payload)["invalidated"] == []
    assert client.get("/v1/directory", auth=newcomer).status_code == 200
    assert client.get("/v1/roster", auth=newcomer).status_code == 403, "an executor, not more"

    enrolled = chain(client, Event.KEY_ENROLLED)[-1]
    assert enrolled == {
        "person_id": "x-104", "key_id": entry.key_id, "role": "executor",
        "published_by": "p-003",
    }, "pseudonym and role, never the name"  # fmt: skip


async def test_a_revoked_device_is_refused_and_running_events_it_signed_are_reported(
    client, org, clock
):
    evac = await dispatch(client, org, clock, scenario="EVAC.BUILDING", ttl_s=120, seq=1)
    payload, _ = revoke_keys(
        current(client, org), person_id="p-002", kid=None, at=clock.now(), reason="утерян"
    )
    result = publish(client, org, payload)
    assert len(result["invalidated"]) == 1 and evac.order_id in result["invalidated"][0]

    response = client.get("/v1/directory", auth=signer_for(org, "p-002", clock))
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "unknown or revoked key"

    revoked = chain(client, Event.KEY_REVOKED)[-1]
    assert revoked["person_id"] == "p-002" and revoked["reason"] == "утерян"
    published = chain(client, Event.DIRECTORY_PUBLISHED)[-1]
    assert published["invalidated"] == result["invalidated"]


async def test_retiring_keeps_the_events_a_key_signed_before(client, org, clock):
    await dispatch(client, org, clock, scenario="EVAC.BUILDING", ttl_s=120, seq=1)
    clock.advance(10)
    payload, _ = retire_keys(current(client, org), person_id="p-002", kid=None, at=clock.now())
    assert publish(client, org, payload)["invalidated"] == []
    assert chain(client, Event.KEY_RETIRED)[-1]["person_id"] == "p-002"

    clock.advance(10)
    gone = client.get("/v1/directory", auth=signer_for(org, "p-002", clock))
    assert gone.status_code == 403, "no requests after retirement"


async def test_contacts_are_set_and_deactivated_by_operators_only(client, executor_client, org):
    wake_key = b64u_encode(secrets.token_bytes(32))
    body = {
        "person_id": "x-104", "name": "Новиков П. С.", "phone": "+79000000999",
        "site": "HQ", "groups": ["fire-wardens"], "role": "executor", "wake_key": wake_key,
    }  # fmt: skip
    assert executor_client.post("/v1/contacts", json=body).status_code == 403

    assert client.post("/v1/contacts", json=body).status_code == 200
    roster = {p["person_id"]: p for p in client.get("/v1/roster").json()["people"]}
    assert roster["x-104"]["groups"] == ["fire-wardens"]
    stored = client.app.state.alerting.repo.contact("x-104")
    assert stored["wake_key"] == wake_key and stored["phone"] == "+79000000999"
    set_entry = chain(client, Event.CONTACT_SET)[-1]
    assert set_entry["wake_key_issued"] is True
    assert not {"phone", "name", "site", "groups"} & set(set_entry), "personal data stays out"

    moved = {k: v for k, v in body.items() if k != "wake_key"} | {"site": "Склад"}
    assert client.post("/v1/contacts", json=moved).status_code == 200
    stored = client.app.state.alerting.repo.contact("x-104")
    assert stored["site"] == "Склад" and stored["wake_key"] == wake_key, "the device's key stays"

    for bad in ({"role": "admin"}, {"wake_key": "short"}, {"groups": ["a,b"]}):
        assert client.post("/v1/contacts", json={**body, **bad}).status_code == 422, bad

    assert executor_client.post("/v1/contacts/x-104/deactivate").status_code == 403
    assert client.post("/v1/contacts/x-104/deactivate").status_code == 200
    assert "x-104" not in {p["person_id"] for p in client.get("/v1/roster").json()["people"]}
    assert client.post("/v1/contacts/nobody/deactivate").status_code == 404
    assert chain(client, Event.CONTACT_DEACTIVATED)[-1]["person_id"] == "x-104"


async def test_an_open_socket_is_closed_once_its_key_is_revoked(client, org, clock, monkeypatch):
    """The handshake alone let a phone revoked after connecting keep receiving orders."""
    from starlette.websockets import WebSocketDisconnect

    from alerting.server.api import ws

    monkeypatch.setattr(ws, "KEY_RECHECK_S", 0.05)
    socket = connect_executor(client, org, "x-101", clock.now())
    try:
        payload, _ = revoke_keys(
            current(client, org), person_id="x-101", kid=None, at=clock.now(), reason="lost"
        )
        publish(client, org, payload)
        with pytest.raises(WebSocketDisconnect) as closed:
            while True:
                socket.receive_json()
        assert closed.value.code == 4403
    finally:
        socket.__exit__(None, None, None)
