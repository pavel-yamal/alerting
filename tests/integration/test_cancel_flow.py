"""Launch, then «отбой» — including the guardrails that make the lower cancel
quorum defensible."""

from __future__ import annotations

import pytest

from alerting.core.envelope import Audience
from alerting.orgkit import make_order, sign_order

pytestmark = pytest.mark.asyncio


async def launch(services, org, clock, **kwargs):
    order = make_order(
        org, issued_at=clock.now(), audience=Audience(groups=("fire-wardens",)), **kwargs
    )
    result = await services.dispatcher.dispatch(
        sign_order(order, [org.person("p-001"), org.person("p-002")]), channels=("ws", "sms")
    )
    assert result.accepted, result.decision.reasons
    return order


async def stand_down(services, org, clock, target, signers, **kwargs):
    cancel = make_order(
        org,
        issued_at=clock.now(),
        seq=target.seq + 1,
        order_type="cancel",
        cancels=target.order_id,
        action="STOP",
        audience=Audience(groups=("fire-wardens",)),
        **kwargs,
    )
    return cancel, await services.dispatcher.dispatch(
        sign_order(cancel, signers), channels=("ws", "sms")
    )


async def test_one_approver_can_stand_down_what_two_launched(services, org, clock):
    """The safe direction is stopping: an evacuation must not continue for 20 minutes
    because the second director is on a plane."""
    order = await launch(services, org, clock)
    clock.advance(30)
    cancel, result = await stand_down(
        services, org, clock, order, [org.person("p-003")]
    )
    assert result.accepted, result.decision.reasons
    assert cancel.cancels == order.order_id


async def test_the_cancel_names_who_issued_it(services, org, clock):
    """Guardrail: a stand-down is loudly attributed, so a suspicious one is visible."""
    order = await launch(services, org, clock)
    _, result = await stand_down(services, org, clock, order, [org.person("p-003")])
    assert result.decision.signer_persons == ("p-003",)


async def test_the_original_order_is_not_erased(services, org, clock):
    """Guardrail: both stay on the record, with full history."""
    order = await launch(services, org, clock)
    await stand_down(services, org, clock, order, [org.person("p-003")])
    assert services.repo.order(order.order_id) is not None
    assert order.order_id in services.repo.cancelled_order_ids()


async def test_a_drill_cancel_cannot_stand_down_a_real_order(services, org, clock):
    order = await launch(services, org, clock, drill=False)
    _, result = await stand_down(
        services, org, clock, order, [org.person("p-003")], drill=True
    )
    assert not result.accepted
    assert "drill_mismatch" in [str(r) for r in result.decision.reasons]


async def test_re_issuing_at_full_quorum_countermands_a_cancel(services, org, clock):
    """Guardrail: a wrongly issued stand-down can itself be overridden."""
    order = await launch(services, org, clock)
    await stand_down(services, org, clock, order, [org.person("p-003")])

    clock.advance(10)
    again = await launch(services, org, clock, seq=order.seq + 2)
    assert again.order_id not in services.repo.cancelled_order_ids()


async def test_the_cancel_reaches_the_same_people(services, org, clock):
    order = await launch(services, org, clock)
    sent_before = len(services.channels["sms"].sent)
    _, result = await stand_down(services, org, clock, order, [org.person("p-003")])
    assert len(services.channels["sms"].sent) > sent_before
    assert set(result.recipients) == {"x-101", "x-102"}


async def test_the_cancel_is_recorded_as_its_own_event(services, org, clock):
    order = await launch(services, org, clock)
    cancel, _ = await stand_down(services, org, clock, order, [org.person("p-003")])
    events = [
        e["data"]
        for e in services.repo.audit_entries(0, 1000)
        if e["event"] == "cancel.issued"
    ]
    assert events and events[0]["cancels"] == order.order_id
    assert events[0]["order_id"] == cancel.order_id
