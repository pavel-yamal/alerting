"""The delivery canary.

It is the only path in the system that dispatches an order without a quorum, so most
of these tests are about the limits that make that acceptable rather than about the
happy path. Any one of them failing open turns the canary into a way to send an
unapproved order.
"""

from __future__ import annotations

from typing import Any

import pytest

from alerting.core.audit_chain import Event
from alerting.core.envelope import Audience
from alerting.server.services.canary import CANARY_PERSON_ID, CanaryService

pytestmark = pytest.mark.asyncio


class FakeSocket:
    def __init__(self) -> None:
        self.frames: list[dict[str, Any]] = []

    async def send_json(self, data: dict[str, Any]) -> None:
        self.frames.append(data)

    async def close(self, code: int) -> None:  # pragma: no cover
        pass


def canary_for(services, **kwargs) -> CanaryService:
    return CanaryService(
        services.repo,
        services.dispatcher,
        services.audit,
        services.clock,
        node_id="test-node",
        leader=None,
        **kwargs,
    )


def entries(services, event: Event) -> list[dict[str, Any]]:
    return [e for e in services.repo.audit_entries(0, 10_000) if e["event"] == str(event)]


# --- the happy path ----------------------------------------------------------


async def test_the_canary_delivers_to_a_connected_device(services):
    await services.connections.attach(CANARY_PERSON_ID, FakeSocket())
    canary = canary_for(services)

    assert await canary.tick() is True

    run = services.repo.latest_canary_run()
    assert run is not None and run["ok"] is True
    assert run["delivered"] >= 1


async def test_a_canary_order_is_in_the_chain_and_says_so(services):
    await services.connections.attach(CANARY_PERSON_ID, FakeSocket())
    await canary_for(services).tick()

    dispatched = [e for e in entries(services, Event.ORDER_DISPATCHED) if e["data"].get("canary")]
    assert len(dispatched) == 1, "an order that dispatched must be in the chain"
    assert dispatched[0]["data"]["drill"] is True
    assert dispatched[0]["data"]["recipients"] == 1


async def test_a_failing_canary_is_recorded_without_pretending(services):
    """Nobody connected: the ws channel cannot deliver and push is a stub."""
    assert await canary_for(services).tick() is False

    run = services.repo.latest_canary_run()
    assert run is not None and run["ok"] is False
    assert "push:stub" in run["detail"]


# --- the limits that make a quorum-free dispatch acceptable -------------------


async def test_a_canary_order_may_not_be_real(services):
    canary = canary_for(services)
    recipient = canary.recipient()
    assert recipient is not None
    order = canary._order(recipient).model_copy(update={"drill": False})

    with pytest.raises(ValueError, match="must be drills"):
        await services.dispatcher.dispatch_canary(order, recipient)


async def test_a_canary_order_may_not_widen_its_audience(services, org):
    """The one limit that decides whether this is a probe or a way to page everybody."""
    canary = canary_for(services)
    recipient = canary.recipient()
    assert recipient is not None

    for audience in (
        Audience(groups=("fire-wardens",)),
        Audience(sites=("hq",)),
        Audience(persons=(CANARY_PERSON_ID, "x-101")),
        Audience(persons=(CANARY_PERSON_ID,), groups=("fire-wardens",)),
    ):
        order = canary._order(recipient).model_copy(update={"audience": audience})
        with pytest.raises(ValueError, match="canary audience"):
            await services.dispatcher.dispatch_canary(order, recipient)


async def test_a_canary_order_may_not_ask_for_acknowledgement(services):
    """Also what keeps the escalation ladder away from it."""
    canary = canary_for(services)
    recipient = canary.recipient()
    assert recipient is not None
    order = canary._order(recipient).model_copy(update={"requires_ack": True})

    with pytest.raises(ValueError, match="acknowledgement"):
        await services.dispatcher.dispatch_canary(order, recipient)


async def test_a_canary_order_may_not_borrow_another_scenario(services):
    canary = canary_for(services)
    recipient = canary.recipient()
    assert recipient is not None
    order = canary._order(recipient).model_copy(update={"scenario": "EVAC.BUILDING"})

    with pytest.raises(ValueError, match="scenario"):
        await services.dispatcher.dispatch_canary(order, recipient)


async def test_the_siren_is_not_among_the_canary_channels(services):
    """Structural, not configured: there is no setting that puts it back."""
    assert "siren" not in services.dispatcher.CANARY_CHANNELS


async def test_the_canary_recipient_is_in_no_real_audience(services, org):
    """`recipients_for` matches sites, groups and named persons. The canary contact
    is in no group, at its own site, and nobody names it."""
    from alerting.core.envelope import OrderPayload

    order = OrderPayload.model_validate(
        {
            "v": 1,
            "type": "order",
            "order_id": "o-1",
            "org_id": org.org_id,
            "stream_id": "primary",
            "seq": 1,
            "nonce": "n",
            "issued_at": services.clock.now(),
            "not_valid_after": services.clock.now() + 900,
            "severity": "critical",
            "drill": False,
            "scenario": "EVAC",
            "action": "START",
            "audience": {"sites": ["hq"], "groups": ["fire-wardens", "alternates"]},
            "requires_ack": True,
            "ack_deadline_s": 120,
            "policy_id": "demo-policy-2026-01",
        }
    )
    reached = {r.person_id for r in services.state.recipients_for(order)}

    assert reached, "the test is meaningless if this audience reaches nobody"
    assert CANARY_PERSON_ID not in reached


# --- it must not crowd out real orders ---------------------------------------


async def test_canary_orders_do_not_fill_the_escalation_window(services):
    """`tick` sweeps the 200 most recent orders. Hourly canaries fill that window in
    eight days, after which a genuine unacknowledged order would drop out of it and
    never be escalated."""
    await services.connections.attach(CANARY_PERSON_ID, FakeSocket())
    canary = canary_for(services)
    for _ in range(5):
        await canary.tick()

    assert services.repo.audit_count() > 0
    assert services.repo.orders(200) == [], "canary orders leaked into the real list"


# --- transitions, not every run ----------------------------------------------


async def test_only_transitions_reach_the_chain(services):
    """The canary order is already in the chain; a second entry per run would say
    nothing new, and hourly forever is a lot of nothing."""
    canary = canary_for(services)
    await canary.tick()  # first run, failing
    await canary.tick()
    await canary.tick()
    assert entries(services, Event.CANARY_FAILED) == [], "first observation is not a change"

    await services.connections.attach(CANARY_PERSON_ID, FakeSocket())
    await canary.tick()
    assert len(entries(services, Event.CANARY_RECOVERED)) == 1

    await canary.tick()
    assert len(entries(services, Event.CANARY_RECOVERED)) == 1, "no entry per run"


async def test_a_missing_canary_contact_is_reported_not_crashed(services):
    services.repo.forget_contact(CANARY_PERSON_ID)
    canary = canary_for(services)

    assert await canary.tick() is False
    run = services.repo.latest_canary_run()
    assert run is not None and "no canary contact" in run["detail"]


async def test_only_the_leader_runs_the_canary(services, app_dsn):
    from alerting.server.db import locks
    from alerting.server.db.leader import LeaderLock

    holder = LeaderLock(app_dsn, key=locks.CANARY)
    try:
        assert holder.acquire() is True
        follower = canary_for(services)
        follower.leader = LeaderLock(app_dsn, key=locks.CANARY)
        try:
            assert await follower.tick() is False
            assert services.repo.latest_canary_run() is None, "a follower ran the canary"
        finally:
            follower.leader.release()
    finally:
        holder.release()
