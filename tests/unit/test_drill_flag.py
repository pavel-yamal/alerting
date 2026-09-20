"""The drill flag: the field most likely to hurt someone if it is wrong.

It lives inside the signed payload, has no default, and is never inferred from a
scenario code or carried as transport metadata.
"""

from __future__ import annotations

from alerting.core.envelope import OrderPayload, SignedEnvelope
from alerting.core.errors import Reason
from alerting.core.verify import verify_envelope
from alerting.orgkit import make_order, sign_order


def two(org):
    return [org.person("p-001"), org.person("p-002")]


def test_missing_drill_flag_is_a_rejection_not_a_default(org, verify_kwargs):
    envelope = sign_order(make_order(org), two(org))
    stripped = dict(envelope.payload)
    del stripped["drill"]
    decision = verify_envelope(
        SignedEnvelope(payload=stripped, signatures=envelope.signatures),
        **verify_kwargs,
    )
    assert decision.rejected
    assert Reason.DRILL_FLAG_MISSING in decision.reasons


def test_drill_flag_must_be_a_boolean(org, verify_kwargs):
    envelope = sign_order(make_order(org), two(org))
    decision = verify_envelope(
        SignedEnvelope(payload={**envelope.payload, "drill": 1}, signatures=envelope.signatures),
        **verify_kwargs,
    )
    assert decision.rejected


def test_drill_is_covered_by_the_signature(org, verify_kwargs):
    """Flipping drill->real must not survive, or a drill could be escalated in flight."""
    envelope = sign_order(make_order(org, drill=True), two(org))
    flipped = SignedEnvelope(
        payload={**envelope.payload, "drill": False}, signatures=envelope.signatures
    )
    decision = verify_envelope(flipped, **verify_kwargs)
    assert decision.rejected
    assert Reason.BAD_SIGNATURE in decision.reasons


def test_drill_order_verifies_and_is_labelled(org, verify_kwargs):
    decision = verify_envelope(sign_order(make_order(org, drill=True), two(org)), **verify_kwargs)
    assert decision.accepted
    assert decision.is_drill is True


def test_real_order_is_labelled(org, verify_kwargs):
    decision = verify_envelope(sign_order(make_order(org, drill=False), two(org)), **verify_kwargs)
    assert decision.accepted
    assert decision.is_drill is False


def test_drill_is_not_inferred_from_the_scenario():
    """TEST.PING is a technical scenario, but that alone must not imply drill=True."""
    from alerting.orgkit import build_org

    org = build_org()
    order = OrderPayload.model_validate(
        make_order(org, scenario="TEST.PING", severity="info", drill=False).to_payload()
    )
    assert order.drill is False
