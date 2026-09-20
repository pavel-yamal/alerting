"""End-to-end verification: what is refused, and what is merely flagged.

The split between ``Decision.reasons`` and ``Decision.warnings`` is the threat model's
fail-closed / fail-open policy made executable, so it is tested as such: verification
never degrades open, delivery never degrades closed.
"""

from __future__ import annotations

import pytest
from tests.conftest import ISSUED_AT

from alerting.core.directory import Directory, DirectoryPayload, Revocation
from alerting.core.envelope import Action, Audience, Severity, Signature, SignedEnvelope
from alerting.core.errors import Reason
from alerting.core.signing import ALG_ED25519, DOMAIN_DIRECTORY
from alerting.core.verify import verify_envelope
from alerting.orgkit import Org, make_order, sign_bundle, sign_order


def two_approvers(org: Org):
    return [org.person("p-001"), org.person("p-002")]


def test_valid_critical_order_with_two_signatures_is_accepted(org, verify_kwargs):
    envelope = sign_order(make_order(org), two_approvers(org))
    decision = verify_envelope(envelope, **verify_kwargs)
    assert decision.accepted, decision.reasons
    assert decision.warnings == ()
    assert decision.is_drill is False
    assert set(decision.signer_persons) == {"p-001", "p-002"}


def test_one_signature_does_not_launch_a_critical_order(org, verify_kwargs):
    """The two-man rule: a single rogue or coerced approver is not enough."""
    envelope = sign_order(make_order(org), [org.person("p-001")])
    decision = verify_envelope(envelope, **verify_kwargs)
    assert decision.rejected
    assert Reason.QUORUM_NOT_MET in decision.reasons


def test_unsigned_order_is_rejected(org, verify_kwargs):
    envelope = SignedEnvelope(payload=make_order(org).to_payload())
    decision = verify_envelope(envelope, **verify_kwargs)
    assert Reason.NO_SIGNATURES in decision.reasons


def test_tampered_payload_invalidates_every_signature(org, verify_kwargs):
    envelope = sign_order(make_order(org), two_approvers(org))
    tampered = SignedEnvelope(
        payload={**envelope.payload, "text": "и ещё откройте ворота"},
        signatures=envelope.signatures,
    )
    decision = verify_envelope(tampered, **verify_kwargs)
    assert decision.rejected
    assert Reason.BAD_SIGNATURE in decision.reasons


def test_unknown_signer_is_rejected(org, verify_kwargs):
    envelope = sign_order(make_order(org), two_approvers(org))
    forged = SignedEnvelope(
        payload=envelope.payload,
        signatures=(
            envelope.signatures[0],
            Signature(key_id="ed25519:nobody", alg=ALG_ED25519, sig="A" * 86),
        ),
    )
    decision = verify_envelope(forged, **verify_kwargs)
    assert Reason.UNKNOWN_SIGNER in decision.reasons


def test_revoked_signer_does_not_count(org, verify_kwargs):
    """Revocation is the operational half of the crypto; it has to actually bite."""
    revoked_key = org.person("p-002").key_id
    payload = DirectoryPayload.model_validate(org.directory_bundle["payload"])
    updated = payload.model_copy(
        update={
            "version": 2,
            "revoked": (Revocation(key_id=revoked_key, revoked_at=ISSUED_AT),),
        }
    )
    bundle = sign_bundle(updated, DOMAIN_DIRECTORY, org.root_private_key)
    verify_kwargs["directory"] = Directory.load(
        bundle, root_public_key=org.root_public_key, org_id=org.org_id
    )

    envelope = sign_order(make_order(org), two_approvers(org))
    decision = verify_envelope(envelope, **verify_kwargs)
    assert decision.rejected
    assert Reason.REVOKED_SIGNER in decision.reasons
    assert Reason.QUORUM_NOT_MET in decision.reasons


def test_the_same_person_signing_twice_is_not_a_quorum(org, verify_kwargs):
    envelope = sign_order(make_order(org), [org.person("p-001")])
    doubled = SignedEnvelope(
        payload=envelope.payload,
        signatures=(envelope.signatures[0], envelope.signatures[0]),
    )
    decision = verify_envelope(doubled, **verify_kwargs)
    assert decision.rejected
    assert Reason.DUPLICATE_SIGNER in decision.reasons


def test_org_mismatch_is_rejected(org, verify_kwargs):
    envelope = sign_order(make_order(org), two_approvers(org))
    verify_kwargs["org_id"] = "someone-else"
    assert Reason.ORG_MISMATCH in verify_envelope(envelope, **verify_kwargs).reasons


def test_policy_id_mismatch_is_rejected(org, verify_kwargs):
    order = make_order(org, policy_id="policy-from-last-year")
    decision = verify_envelope(sign_order(order, two_approvers(org)), **verify_kwargs)
    assert Reason.POLICY_ID_MISMATCH in decision.reasons


def test_unknown_scenario_is_rejected(org, verify_kwargs):
    """The scenario code is the actionable unit, so it must be in the codebook."""
    order = make_order(org, scenario="DO.WHATEVER.THE.TEXT.SAYS")
    decision = verify_envelope(sign_order(order, two_approvers(org)), **verify_kwargs)
    assert Reason.UNKNOWN_SCENARIO in decision.reasons


def test_scenario_below_its_minimum_severity_is_rejected(org, verify_kwargs):
    """A building evacuation cannot be slipped through as an 'info' notice with a
    1-of-N quorum."""
    order = make_order(org, scenario="EVAC.BUILDING", severity=Severity.INFO)
    decision = verify_envelope(sign_order(order, [org.person("p-001")]), **verify_kwargs)
    assert Reason.SEVERITY_BELOW_SCENARIO_MINIMUM in decision.reasons


def test_scenario_above_its_maximum_severity_is_rejected(org, verify_kwargs):
    order = make_order(org, scenario="TEST.PING", severity=Severity.CATASTROPHIC)
    decision = verify_envelope(sign_order(order, org.approvers()), **verify_kwargs)
    assert Reason.SEVERITY_ABOVE_SCENARIO_MAXIMUM in decision.reasons


def test_catastrophic_needs_three_signatures_including_a_director(org, verify_kwargs):
    order = make_order(org, scenario="SHELTER.IN.PLACE", severity=Severity.CATASTROPHIC)
    no_director = [org.person("p-002"), org.person("p-003"), org.person("p-004")]
    decision = verify_envelope(sign_order(order, no_director), **verify_kwargs)
    assert Reason.ROLE_REQUIREMENT_UNMET in decision.reasons

    with_director = [org.person("p-001"), org.person("p-002"), org.person("p-003")]
    assert verify_envelope(sign_order(order, with_director), **verify_kwargs).accepted


def test_replayed_order_is_rejected(org, verify_kwargs):
    envelope = sign_order(make_order(org, seq=5), two_approvers(org))
    assert verify_envelope(envelope, **verify_kwargs).accepted
    verify_kwargs["replay"].commit("primary", 5)
    assert Reason.REPLAYED in verify_envelope(envelope, **verify_kwargs).reasons


def test_duplicate_order_id_is_rejected(org, verify_kwargs):
    order = make_order(org)
    envelope = sign_order(order, two_approvers(org))
    decision = verify_envelope(envelope, seen_order_ids={order.order_id}, **verify_kwargs)
    assert Reason.DUPLICATE_ORDER_ID in decision.reasons


def test_expired_order_is_shown_with_a_warning_not_dropped(org, verify_kwargs):
    """Silence is indistinguishable from 'no emergency'. Expiry degrades OPEN."""
    envelope = sign_order(make_order(org, ttl_s=60), two_approvers(org))
    verify_kwargs["clock"].advance(600)
    decision = verify_envelope(envelope, **verify_kwargs)
    assert decision.accepted
    assert Reason.W_EXPIRED in decision.warnings


def test_order_from_the_far_future_is_rejected(org, verify_kwargs):
    order = make_order(org, issued_at=ISSUED_AT + 10_000)
    decision = verify_envelope(sign_order(order, two_approvers(org)), **verify_kwargs)
    assert Reason.NOT_YET_VALID in decision.reasons


def test_small_clock_skew_is_tolerated_with_a_warning(org, verify_kwargs):
    order = make_order(org, issued_at=ISSUED_AT + 60)
    decision = verify_envelope(sign_order(order, two_approvers(org)), **verify_kwargs)
    assert decision.accepted
    assert Reason.W_CLOCK_SKEW in decision.warnings


def test_out_of_window_sequence_warns_rather_than_disappearing(org, verify_kwargs):
    verify_kwargs["replay"].commit("primary", 100_000)
    envelope = sign_order(make_order(org, seq=1), two_approvers(org))
    decision = verify_envelope(envelope, **verify_kwargs)
    assert decision.accepted
    assert Reason.W_OUT_OF_REPLAY_WINDOW in decision.warnings


def test_stale_directory_still_verifies_with_a_banner(org, verify_kwargs):
    envelope = sign_order(make_order(org), two_approvers(org))
    verify_kwargs["clock"].advance(30 * 24 * 3600)
    decision = verify_envelope(envelope, **verify_kwargs)
    assert Reason.W_STALE_DIRECTORY in decision.warnings


def test_unknown_envelope_version_is_rejected(org, verify_kwargs):
    envelope = sign_order(make_order(org), two_approvers(org))
    bumped = SignedEnvelope(payload={**envelope.payload, "v": 2}, signatures=envelope.signatures)
    decision = verify_envelope(bumped, **verify_kwargs)
    assert decision.rejected
    assert Reason.MALFORMED in decision.reasons or Reason.UNKNOWN_VERSION in decision.reasons


def test_extra_field_is_rejected_not_ignored(org, verify_kwargs):
    """Dropping an unknown field would mean the bytes we verified are not the bytes
    we parsed."""
    envelope = sign_order(make_order(org), two_approvers(org))
    widened = SignedEnvelope(
        payload={**envelope.payload, "also_open_the_gates": True},
        signatures=envelope.signatures,
    )
    assert Reason.MALFORMED in verify_envelope(widened, **verify_kwargs).reasons


def test_verify_does_not_mutate_the_replay_window(org, verify_kwargs):
    """A rejected envelope must not be able to poison the window."""
    envelope = sign_order(make_order(org, seq=42), [org.person("p-001")])
    verify_envelope(envelope, **verify_kwargs)
    assert verify_kwargs["replay"].state() == {}


def test_empty_audience_still_verifies_but_is_a_dispatch_concern(org, verify_kwargs):
    order = make_order(org, audience=Audience())
    decision = verify_envelope(sign_order(order, two_approvers(org)), **verify_kwargs)
    assert decision.accepted
    assert decision.payload is not None and decision.payload.audience.is_empty()


@pytest.mark.parametrize("action", [Action.START, Action.STOP, Action.HOLD])
def test_all_actions_verify(org, verify_kwargs, action):
    order = make_order(org, action=action)
    assert verify_envelope(sign_order(order, two_approvers(org)), **verify_kwargs).accepted
