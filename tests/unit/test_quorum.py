"""M-of-N evaluation in isolation."""

from __future__ import annotations

from alerting.core.directory import KeyEntry
from alerting.core.errors import Reason
from alerting.core.policy import QuorumRule
from alerting.core.quorum import evaluate_quorum


def entry(key_id: str, person_id: str, role: str = "duty_officer") -> KeyEntry:
    return KeyEntry(
        key_id=key_id,
        public_key="x" * 43,
        person_id=person_id,
        name=person_id,
        role=role,
        valid_from=0,
    )


def test_one_of_n_met():
    result = evaluate_quorum([entry("k1", "p1")], QuorumRule(m=1), issued_at=100)
    assert result.met
    assert result.signer_person_ids == ("p1",)


def test_two_of_n_not_met_by_one():
    result = evaluate_quorum([entry("k1", "p1")], QuorumRule(m=2), issued_at=100)
    assert not result.met
    assert Reason.QUORUM_NOT_MET in result.reasons


def test_two_of_n_met():
    signers = [entry("k1", "p1"), entry("k2", "p2")]
    assert evaluate_quorum(signers, QuorumRule(m=2), issued_at=100).met


def test_one_person_with_two_devices_cannot_satisfy_two_of_n():
    """The two-man rule is about two humans, not two keys."""
    signers = [entry("k1", "p1"), entry("k2", "p1")]
    result = evaluate_quorum(signers, QuorumRule(m=2), issued_at=100)
    assert not result.met
    assert Reason.NOT_DISTINCT_PERSONS in result.reasons


def test_distinct_persons_can_be_disabled():
    signers = [entry("k1", "p1"), entry("k2", "p1")]
    rule = QuorumRule(m=2, distinct_persons=False)
    assert evaluate_quorum(signers, rule, issued_at=100).met


def test_duplicate_key_is_rejected_outright():
    signers = [entry("k1", "p1"), entry("k1", "p1")]
    result = evaluate_quorum(signers, QuorumRule(m=1), issued_at=100)
    assert not result.met
    assert Reason.DUPLICATE_SIGNER in result.reasons


def test_role_requirement_unmet():
    signers = [entry("k1", "p1"), entry("k2", "p2"), entry("k3", "p3")]
    rule = QuorumRule(m=3, min_from_role={"director": 1})
    result = evaluate_quorum(signers, rule, issued_at=100)
    assert not result.met
    assert Reason.ROLE_REQUIREMENT_UNMET in result.reasons


def test_role_requirement_met():
    signers = [
        entry("k1", "p1", role="director"),
        entry("k2", "p2"),
        entry("k3", "p3"),
    ]
    rule = QuorumRule(m=3, min_from_role={"director": 1})
    assert evaluate_quorum(signers, rule, issued_at=100).met


def test_signature_spread_needs_an_independent_observation():
    """Signature entries carry no self-asserted timestamp, so spread can only be
    enforced where the server observed arrival times. Clients pass None."""
    signers = [entry("k1", "p1"), entry("k2", "p2")]
    rule = QuorumRule(m=2, max_signature_spread_s=300)

    assert evaluate_quorum(signers, rule, issued_at=1000).met  # client: skipped
    assert evaluate_quorum(
        signers, rule, issued_at=1000, observed_at={"k1": 1010, "k2": 1200}
    ).met
    late = evaluate_quorum(
        signers, rule, issued_at=1000, observed_at={"k1": 1010, "k2": 1600}
    )
    assert not late.met
    assert Reason.SIGNATURE_SPREAD_EXCEEDED in late.reasons


def test_no_signers_never_meets_quorum():
    result = evaluate_quorum([], QuorumRule(m=1), issued_at=100)
    assert not result.met
    assert result.detail["effective"] == 0
