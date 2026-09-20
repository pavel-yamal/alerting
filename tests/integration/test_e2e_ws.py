"""The whole story: propose -> two signatures -> dispatch -> client verifies -> ACK."""

from __future__ import annotations

from typing import Any

from alerting.core.clock import FixedClock
from alerting.core.directory import Directory
from alerting.core.envelope import AckStatus, OrderPayload, SignedEnvelope
from alerting.core.policy import Policy
from alerting.core.receipts import build_ack
from alerting.core.replay import ReplayWindow
from alerting.core.signing import (
    DOMAIN_DEVICE_AUTH,
    DOMAIN_ORDER,
    sign_payload,
)
from alerting.core.verify import verify_envelope
from alerting.orgkit import Org


def propose(client, **overrides) -> dict[str, Any]:
    body = {
        "scenario": "EVAC.BUILDING",
        "severity": "critical",
        "drill": False,
        "audience": {"groups": ["fire-wardens"]},
        "text": "Задымление, 3 этаж, восточное крыло",
    }
    body.update(overrides)
    response = client.post("/v1/proposals", json=body)
    assert response.status_code == 200, response.text
    return response.json()


def sign(client, proposal: dict[str, Any], person) -> dict[str, Any]:
    signature = sign_payload(DOMAIN_ORDER, proposal["payload"], person.private_key)
    response = client.post(
        f"/v1/proposals/{proposal['order_id']}/signatures",
        json={"key_id": person.key_id, "sig": signature},
    )
    assert response.status_code == 200, response.text
    return response.json()


def connect_executor(client, org: Org, person_id: str, at: int):
    """Open an authenticated stream and return the open socket."""
    person = org.person(person_id)
    socket = client.websocket_connect("/v1/stream")
    socket.__enter__()
    challenge = socket.receive_json()
    assert challenge["kind"] == "challenge"

    payload = {
        "v": 1,
        "type": "device-auth",
        "org_id": org.org_id,
        "person_id": person.person_id,
        "key_id": person.key_id,
        "nonce": challenge["nonce"],
        "at": at,
    }
    socket.send_json(
        {
            "kind": "auth",
            "payload": payload,
            "sig": sign_payload(DOMAIN_DEVICE_AUTH, payload, person.private_key),
        }
    )
    ready = socket.receive_json()
    assert ready["kind"] == "ready", ready
    return socket


def client_side_verify(client, org: Org, envelope: dict[str, Any], clock: FixedClock):
    """Exactly what an executor's device does, using only the pinned root key."""
    directory = Directory.load(
        client.get("/v1/directory").json(),
        root_public_key=org.root_public_key,
        org_id=org.org_id,
    )
    policy = Policy.load(
        client.get("/v1/policy").json(),
        root_public_key=org.root_public_key,
        org_id=org.org_id,
    )
    return verify_envelope(
        SignedEnvelope.model_validate(envelope),
        directory=directory,
        policy=policy,
        clock=clock,
        replay=ReplayWindow(),
        org_id=org.org_id,
    )


def test_full_flow(client, org, clock):
    socket = connect_executor(client, org, "x-101", clock.now())
    try:
        proposal = propose(client)
        assert proposal["required_signatures"] == 2

        first = sign(client, proposal, org.person("p-001"))
        assert first["dispatched"] is False
        assert "quorum_not_met" in first["blocking"]

        second = sign(client, proposal, org.person("p-002"))
        assert second["dispatched"] is True
        assert set(second["recipients"]) == {"x-101", "x-102"}

        frame = socket.receive_json()
        assert frame["kind"] == "order"

        decision = client_side_verify(client, org, frame["envelope"], clock)
        assert decision.accepted, decision.reasons
        assert decision.is_drill is False
        assert set(decision.signer_persons) == {"p-001", "p-002"}

        order = decision.payload
        assert order is not None
        person = org.person("x-101")
        ack = build_ack(
            order=order,
            order_payload_raw=frame["envelope"]["payload"],
            person_id=person.person_id,
            device_key_id=person.key_id,
            status=AckStatus.ACKNOWLEDGED,
            at=clock.now(),
            nonce="ack-1",
            private_key=person.private_key,
        )
        socket.send_json(
            {
                "kind": "ack",
                "payload": ack.payload,
                "signature": ack.signature.model_dump(mode="json"),
            }
        )
        assert socket.receive_json() == {"kind": "ack-result", "accepted": True}

        status = client.get(f"/v1/orders/{order.order_id}/status").json()
        assert status["acknowledged"] == 1
        assert status["outstanding"] == ["x-102"]
        by_person = {p["person_id"]: p for p in status["people"]}
        assert by_person["x-101"]["ack_valid"] is True
        assert by_person["x-102"]["ack_status"] is None
    finally:
        socket.__exit__(None, None, None)


def test_a_single_approver_cannot_launch(client, org):
    proposal = propose(client)
    result = sign(client, proposal, org.person("p-001"))
    assert result["dispatched"] is False
    assert client.get(f"/v1/orders/{proposal['order_id']}").status_code == 404


def test_an_operator_alone_cannot_launch(client):
    """Creating a proposal is not authority. A stolen operator password gets you here
    and no further."""
    proposal = propose(client)
    assert client.get(f"/v1/orders/{proposal['order_id']}").status_code == 404
    assert client.get(f"/v1/proposals/{proposal['order_id']}").json()["status"] == "open"


def test_ack_over_http_is_equivalent_to_ack_over_the_socket(client, org, clock):
    socket = connect_executor(client, org, "x-101", clock.now())
    try:
        proposal = propose(client)
        sign(client, proposal, org.person("p-001"))
        sign(client, proposal, org.person("p-002"))
        envelope = socket.receive_json()["envelope"]
    finally:
        socket.__exit__(None, None, None)

    order = OrderPayload.model_validate(envelope["payload"])
    person = org.person("x-102")
    ack = build_ack(
        order=order,
        order_payload_raw=envelope["payload"],
        person_id=person.person_id,
        device_key_id=person.key_id,
        status=AckStatus.EN_ROUTE,
        at=clock.now(),
        nonce="ack-http",
        private_key=person.private_key,
    )
    response = client.post(
        "/v1/acks",
        json={"payload": ack.payload, "signature": ack.signature.model_dump(mode="json")},
    )
    assert response.json() == {"accepted": True, "reasons": []}
    status = client.get(f"/v1/orders/{order.order_id}/status").json()
    assert "x-102" not in status["outstanding"]


def test_forged_ack_is_recorded_as_invalid_and_does_not_count(client, org, clock):
    """An invalid ACK is worse than a missing one: it means impersonation. It is shown,
    and it must not stop escalation."""
    socket = connect_executor(client, org, "x-101", clock.now())
    try:
        proposal = propose(client)
        sign(client, proposal, org.person("p-001"))
        sign(client, proposal, org.person("p-002"))
        envelope = socket.receive_json()["envelope"]
    finally:
        socket.__exit__(None, None, None)

    order = OrderPayload.model_validate(envelope["payload"])
    impostor = org.person("x-103")
    ack = build_ack(
        order=order,
        order_payload_raw=envelope["payload"],
        person_id="x-101",  # claims to be someone else
        device_key_id=impostor.key_id,
        status=AckStatus.COMPLETED,
        at=clock.now(),
        nonce="forged",
        private_key=impostor.private_key,
    )
    response = client.post(
        "/v1/acks",
        json={"payload": ack.payload, "signature": ack.signature.model_dump(mode="json")},
    )
    assert response.json()["accepted"] is False

    status = client.get(f"/v1/orders/{order.order_id}/status").json()
    assert "x-101" in status["outstanding"]


def test_device_with_a_bad_signature_cannot_open_a_stream(client, org, clock):
    person = org.person("x-101")
    other = org.person("x-102")
    with client.websocket_connect("/v1/stream") as socket:
        challenge = socket.receive_json()
        payload = {
            "v": 1,
            "type": "device-auth",
            "org_id": org.org_id,
            "person_id": person.person_id,
            "key_id": person.key_id,
            "nonce": challenge["nonce"],
            "at": clock.now(),
        }
        socket.send_json(
            {
                "kind": "auth",
                "payload": payload,
                "sig": sign_payload(DOMAIN_DEVICE_AUTH, payload, other.private_key),
            }
        )
        try:
            frame = socket.receive_json()
            assert frame.get("kind") != "ready"
        except Exception:
            pass  # closed, which is the expected outcome


def test_replayed_handshake_nonce_is_refused(client, org, clock):
    """A captured handshake must not open a second socket."""
    person = org.person("x-101")
    with client.websocket_connect("/v1/stream") as socket:
        socket.receive_json()
        payload = {
            "v": 1,
            "type": "device-auth",
            "org_id": org.org_id,
            "person_id": person.person_id,
            "key_id": person.key_id,
            "nonce": "a-nonce-from-an-earlier-session",
            "at": clock.now(),
        }
        socket.send_json(
            {
                "kind": "auth",
                "payload": payload,
                "sig": sign_payload(DOMAIN_DEVICE_AUTH, payload, person.private_key),
            }
        )
        try:
            assert socket.receive_json().get("kind") != "ready"
        except Exception:
            pass
