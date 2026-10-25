"""Only roles the signed policy names as approvers may satisfy a quorum.

A verified signature is not the same thing as authority to approve. The directory
holds every enrolled key, executors' ACK-signing devices included, so without this
allowlist two executors could launch a critical evacuation and one could stand it
down — silently contradicting docs/02-trust-and-approval.md.

Reported by an automated review on PR #1.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from alerting.core.directory import KeyEntry
from alerting.core.envelope import Severity
from alerting.core.errors import Reason
from alerting.core.policy import PolicyPayload, QuorumRule
from alerting.core.quorum import evaluate_quorum
from alerting.core.verify import verify_envelope
from alerting.orgkit import APPROVER_ROLES, make_order, sign_order


def entry(key_id: str, person_id: str, role: str) -> KeyEntry:
    return KeyEntry(
        key_id=key_id,
        public_key="x" * 43,
        person_id=person_id,
        name=person_id,
        role=role,
        valid_from=0,
    )


def test_two_executors_cannot_launch_a_critical_order(org, verify_kwargs):
    """The hole this allowlist closes."""
    order = make_order(org, severity=Severity.CRITICAL, scenario="EVAC.BUILDING")
    envelope = sign_order(order, [org.person("x-101"), org.person("x-102")])

    decision = verify_envelope(envelope, **verify_kwargs)
    assert decision.rejected
    assert Reason.QUORUM_NOT_MET in decision.reasons
    assert Reason.UNAUTHORIZED_SIGNER_ROLE in decision.reasons


def test_one_executor_cannot_stand_down_an_order(org, verify_kwargs):
    launch = make_order(org, seq=1)
    cancel = make_order(org, seq=2, order_type="cancel", cancels=launch.order_id, action="STOP")
    decision = verify_envelope(
        sign_order(cancel, [org.person("x-103")]),
        cancel_target=launch,
        **verify_kwargs,
    )
    assert decision.rejected
    assert Reason.UNAUTHORIZED_SIGNER_ROLE in decision.reasons


def test_approvers_still_launch_normally(org, verify_kwargs):
    envelope = sign_order(make_order(org), [org.person("p-001"), org.person("p-002")])
    assert verify_envelope(envelope, **verify_kwargs).accepted


def test_an_executor_signature_does_not_count_toward_a_quorum(org, verify_kwargs):
    """One approver plus one executor is one approver, not two."""
    envelope = sign_order(make_order(org), [org.person("p-001"), org.person("x-101")])
    decision = verify_envelope(envelope, **verify_kwargs)
    assert decision.rejected
    assert Reason.QUORUM_NOT_MET in decision.reasons


def test_an_extra_executor_signature_does_not_invalidate_a_real_quorum(org, verify_kwargs):
    """Dropping it is enough; the order two approvers signed stays valid."""
    envelope = sign_order(
        make_order(org),
        [org.person("p-001"), org.person("p-002"), org.person("x-101")],
    )
    decision = verify_envelope(envelope, **verify_kwargs)
    assert decision.accepted, decision.reasons
    assert set(decision.signer_persons) == {"p-001", "p-002"}
    assert "x-101" not in decision.signer_persons


def test_quorum_counts_only_permitted_roles():
    signers = [entry("k1", "p1", "lpr"), entry("k2", "x1", "executor")]
    result = evaluate_quorum(signers, QuorumRule(m=2), issued_at=100, approver_roles=APPROVER_ROLES)
    assert not result.met
    assert result.detail["effective"] == 1
    assert result.detail["dropped_unauthorized"] is True


def test_a_policy_that_names_no_approvers_cannot_be_built(org):
    """Required with no default, for the same reason drill has none: a policy that
    does not say who may approve must be unusable, not permissive."""
    payload = org.policy_bundle["payload"]
    without = {k: v for k, v in payload.items() if k != "approver_roles"}
    with pytest.raises(ValidationError):
        PolicyPayload.model_validate(without)

    with pytest.raises(ValidationError):
        PolicyPayload.model_validate({**payload, "approver_roles": []})
