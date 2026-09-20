"""Signed ACK receipts and what makes them evidence rather than telemetry."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from alerting.core.envelope import AckStatus, SignedAck
from alerting.core.errors import Reason
from alerting.core.receipts import build_ack, verify_ack
from alerting.core.signing import payload_digest
from alerting.orgkit import make_order


@pytest.fixture
def order_pair(org):
    order = make_order(org)
    return order, order.to_payload()


def make(org, order_pair, person_id="x-101", status=AckStatus.ACKNOWLEDGED, **kwargs):
    order, raw = order_pair
    person = org.person(person_id)
    return build_ack(
        order=order,
        order_payload_raw=raw,
        person_id=person.person_id,
        device_key_id=person.key_id,
        status=status,
        at=org.issued_at + 30,
        nonce="n-1",
        private_key=person.private_key,
        **kwargs,
    )


def test_valid_ack_verifies(org, directory, order_pair):
    ack = make(org, order_pair)
    ok, reasons = verify_ack(ack, directory=directory, org_id=org.org_id)
    assert ok, reasons


def test_ack_pins_the_exact_order_the_executor_saw(org, directory, order_pair):
    """Without order_digest, a compromised server could later claim the order said
    something milder than what the executor acted on."""
    _, raw = order_pair
    ack = make(org, order_pair)
    assert ack.parse_payload().order_digest == payload_digest(raw)

    ok, _ = verify_ack(
        ack,
        directory=directory,
        org_id=org.org_id,
        expected_order_digest=payload_digest({**raw, "text": "другой текст"}),
    )
    assert not ok


def test_tampered_ack_fails(org, directory, order_pair):
    ack = make(org, order_pair)
    tampered = SignedAck(payload={**ack.payload, "status": "completed"}, signature=ack.signature)
    ok, reasons = verify_ack(tampered, directory=directory, org_id=org.org_id)
    assert not ok
    assert Reason.BAD_SIGNATURE in reasons


def test_ack_signed_by_an_unknown_device_fails(org, directory, order_pair):
    ack = make(org, order_pair)
    forged = SignedAck(
        payload={**ack.payload, "device_key_id": "ed25519:nobody"},
        signature=ack.signature.model_copy(update={"key_id": "ed25519:nobody"}),
    )
    ok, reasons = verify_ack(forged, directory=directory, org_id=org.org_id)
    assert not ok
    assert Reason.UNKNOWN_SIGNER in reasons


def test_ack_claiming_someone_elses_person_id_fails(org, directory, order_pair):
    """An invalid ACK is worse than a missing one: somebody is impersonating an
    executor, and the dashboard must say so."""
    ack = make(org, order_pair)
    device = org.person("x-101")
    impersonation = build_ack(
        order=order_pair[0],
        order_payload_raw=order_pair[1],
        person_id="x-102",
        device_key_id=device.key_id,
        status=AckStatus.COMPLETED,
        at=org.issued_at + 30,
        nonce="n-2",
        private_key=device.private_key,
    )
    ok, reasons = verify_ack(impersonation, directory=directory, org_id=org.org_id)
    assert not ok
    assert Reason.UNKNOWN_SIGNER in reasons
    assert ack is not None


def test_ack_for_another_org_fails(org, directory, order_pair):
    ack = make(org, order_pair)
    ok, reasons = verify_ack(ack, directory=directory, org_id="someone-else")
    assert not ok
    assert Reason.ORG_MISMATCH in reasons


def test_cannot_comply_requires_a_reason(org, order_pair):
    with pytest.raises(ValidationError, match="must state a reason"):
        make(org, order_pair, status=AckStatus.CANNOT_COMPLY)


def test_cannot_comply_with_a_reason_is_valid(org, directory, order_pair):
    ack = make(org, order_pair, status=AckStatus.CANNOT_COMPLY, reason="путь отрезан огнём")
    ok, _ = verify_ack(ack, directory=directory, org_id=org.org_id)
    assert ok


def test_malformed_ack_payload_is_rejected(org, directory, order_pair):
    ack = make(org, order_pair)
    broken = SignedAck(payload={"nonsense": True}, signature=ack.signature)
    ok, reasons = verify_ack(broken, directory=directory, org_id=org.org_id)
    assert not ok
    assert Reason.MALFORMED in reasons


def test_signature_key_id_must_match_the_declared_device(org, directory, order_pair):
    ack = make(org, order_pair)
    mismatched = SignedAck(
        payload=ack.payload,
        signature=ack.signature.model_copy(update={"key_id": org.person("x-102").key_id}),
    )
    ok, reasons = verify_ack(mismatched, directory=directory, org_id=org.org_id)
    assert not ok
    assert Reason.BAD_SIGNATURE in reasons
