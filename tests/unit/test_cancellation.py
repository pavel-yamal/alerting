"""Stand-down («отбой»).

Cancel quorum is deliberately one below launch: the safe direction is stopping. The
compensating guardrails are attribution, an un-erased original, executor training, and
re-issue at full quorum — see docs/adr/0003-cancel-quorum.md.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from alerting.core.envelope import Severity
from alerting.core.errors import Reason
from alerting.core.verify import verify_envelope
from alerting.orgkit import make_order, sign_order


def test_cancel_needs_only_one_signature_where_launch_needs_two(org, verify_kwargs):
    launch = make_order(org, seq=1)
    assert verify_envelope(
        sign_order(launch, [org.person("p-001")]), **verify_kwargs
    ).rejected

    cancel = make_order(
        org, seq=2, order_type="cancel", cancels=launch.order_id, action="STOP"
    )
    decision = verify_envelope(
        sign_order(cancel, [org.person("p-001")]),
        cancel_target=launch,
        **verify_kwargs,
    )
    assert decision.accepted, decision.reasons


def test_a_drill_cancel_cannot_stand_down_a_real_order(org, verify_kwargs):
    real = make_order(org, seq=1, drill=False)
    drill_cancel = make_order(
        org, seq=2, order_type="cancel", cancels=real.order_id, drill=True, action="STOP"
    )
    decision = verify_envelope(
        sign_order(drill_cancel, [org.person("p-001")]),
        cancel_target=real,
        **verify_kwargs,
    )
    assert decision.rejected
    assert Reason.DRILL_MISMATCH in decision.reasons


def test_a_real_cancel_cannot_stand_down_a_drill(org, verify_kwargs):
    drill = make_order(org, seq=1, drill=True)
    real_cancel = make_order(
        org, seq=2, order_type="cancel", cancels=drill.order_id, drill=False, action="STOP"
    )
    decision = verify_envelope(
        sign_order(real_cancel, [org.person("p-001")]),
        cancel_target=drill,
        **verify_kwargs,
    )
    assert Reason.DRILL_MISMATCH in decision.reasons


def test_cancel_for_an_unknown_order_warns_rather_than_failing(org, verify_kwargs):
    """If we never saw the original there is nothing to stand down, but we also cannot
    cross-check the drill flag, so the operator is told."""
    cancel = make_order(org, order_type="cancel", cancels="never-seen", action="STOP")
    decision = verify_envelope(
        sign_order(cancel, [org.person("p-001")]), **verify_kwargs
    )
    assert decision.accepted
    assert Reason.CANCEL_TARGET_MISSING in decision.warnings


def test_catastrophic_cancel_still_needs_two_signatures(org, verify_kwargs):
    launch = make_order(org, severity=Severity.CATASTROPHIC, scenario="SHELTER.IN.PLACE")
    cancel = make_order(
        org,
        seq=2,
        severity=Severity.CATASTROPHIC,
        scenario="SHELTER.IN.PLACE",
        order_type="cancel",
        cancels=launch.order_id,
        action="STOP",
    )
    one = verify_envelope(
        sign_order(cancel, [org.person("p-001")]), cancel_target=launch, **verify_kwargs
    )
    assert Reason.QUORUM_NOT_MET in one.reasons

    two = verify_envelope(
        sign_order(cancel, [org.person("p-001"), org.person("p-002")]),
        cancel_target=launch,
        **verify_kwargs,
    )
    assert two.accepted, two.reasons


def test_a_cancel_must_name_its_target(org):
    with pytest.raises(ValidationError, match="must name"):
        make_order(org, order_type="cancel")


def test_an_order_may_not_carry_a_cancel_target(org):
    with pytest.raises(ValidationError, match="only a cancel"):
        make_order(org, order_type="order", cancels="o1")


def test_a_cancel_cannot_cancel_itself(org):
    with pytest.raises(ValidationError, match="itself"):
        make_order(org, order_type="cancel", order_id="o1", cancels="o1")


def test_ttl_must_be_positive(org):
    with pytest.raises(ValidationError, match="strictly after"):
        make_order(org, ttl_s=0)
