"""Signed ACK receipts.

An ACK is not just "seen". It is evidence, signed by the executor's device, of *which
exact order* they had in front of them — ``order_digest`` pins the canonical payload.
Without that field a compromised server could later claim the order said something
milder than what the executor acted on.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from alerting.core.directory import Directory
from alerting.core.envelope import (
    AckPayload,
    AckStatus,
    OrderPayload,
    Signature,
    SignedAck,
)
from alerting.core.errors import Reason
from alerting.core.signing import (
    ALG_ED25519,
    DOMAIN_ACK,
    payload_digest,
    sign_payload,
    verify_signature,
)


def build_ack(
    *,
    order: OrderPayload,
    order_payload_raw: Mapping[str, Any],
    person_id: str,
    device_key_id: str,
    status: AckStatus,
    at: int,
    nonce: str,
    private_key: Ed25519PrivateKey,
    reason: str | None = None,
) -> SignedAck:
    """Construct and sign a receipt for ``order``."""
    payload = AckPayload(
        v=1,
        type="ack",
        order_id=order.order_id,
        org_id=order.org_id,
        person_id=person_id,
        device_key_id=device_key_id,
        status=status,
        at=at,
        nonce=nonce,
        order_digest=payload_digest(order_payload_raw),
        reason=reason,
    )
    raw = payload.to_payload()
    return SignedAck(
        payload=raw,
        signature=Signature(
            key_id=device_key_id,
            alg=ALG_ED25519,
            sig=sign_payload(DOMAIN_ACK, raw, private_key),
        ),
    )


def verify_ack(
    ack: SignedAck,
    *,
    directory: Directory,
    org_id: str,
    expected_order_digest: str | None = None,
) -> tuple[bool, tuple[Reason, ...]]:
    """Verify a receipt.

    An invalid ACK is displayed more prominently than a missing one: it means somebody
    is trying to pass themselves off as an executor.
    """
    reasons: list[Reason] = []
    try:
        payload = ack.parse_payload()
    except Exception:
        return False, (Reason.MALFORMED,)

    if payload.to_payload() != ack.payload:
        return False, (Reason.NOT_CANONICAL,)
    if payload.org_id != org_id:
        reasons.append(Reason.ORG_MISMATCH)
    if payload.device_key_id != ack.signature.key_id:
        reasons.append(Reason.BAD_SIGNATURE)

    status = directory.signer_status(payload.device_key_id, payload.at)
    if status is not None:
        reasons.append(status)
    else:
        entry = directory.lookup(payload.device_key_id)
        assert entry is not None
        if not verify_signature(
            DOMAIN_ACK, ack.payload, ack.signature.sig, entry.public()
        ):
            reasons.append(Reason.BAD_SIGNATURE)
        elif entry.person_id != payload.person_id:
            reasons.append(Reason.UNKNOWN_SIGNER)

    if expected_order_digest is not None and payload.order_digest != expected_order_digest:
        reasons.append(Reason.MALFORMED)

    deduped = tuple(dict.fromkeys(reasons))
    return not deduped, deduped
