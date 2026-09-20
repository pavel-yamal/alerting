"""Drills must be unmistakable, and must never fire the live siren."""

from __future__ import annotations

import pytest

from alerting.core.envelope import Audience
from alerting.orgkit import make_order, sign_order
from alerting.server.channels.siren import PATTERN_DRILL, PATTERN_REAL

pytestmark = pytest.mark.asyncio


async def dispatch(services, org, clock, *, drill, channels=("ws", "push", "sms", "siren")):
    order = make_order(
        org,
        issued_at=clock.now(),
        drill=drill,
        audience=Audience(groups=("fire-wardens",)),
    )
    envelope = sign_order(order, [org.person("p-001"), org.person("p-002")])
    result = await services.dispatcher.dispatch(envelope, channels=channels)
    assert result.accepted, result.decision.reasons
    return order, result


async def test_a_drill_never_sounds_the_live_siren(services, org, clock):
    """The one that would actually hurt people: a drill that triggers a real
    evacuation on a day nobody expects one."""
    _, result = await dispatch(services, org, clock, drill=True)

    siren = services.channels["siren"]
    assert siren.activations == []
    refusals = [r for r in result.receipts if r.channel == "siren"]
    assert refusals and all(r.status == "refused" for r in refusals)
    assert "drill not enabled" in refusals[0].detail


async def test_a_drill_at_an_enabled_site_uses_the_drill_pattern(services, org, clock):
    services.state.drill_enabled_sites = frozenset({"hq"})
    await dispatch(services, org, clock, drill=True)
    patterns = [pattern for _, pattern, _ in services.channels["siren"].activations]
    assert patterns == [PATTERN_DRILL]


async def test_a_real_order_uses_the_live_pattern(services, org, clock):
    await dispatch(services, org, clock, drill=False)
    patterns = [pattern for _, pattern, _ in services.channels["siren"].activations]
    assert patterns == [PATTERN_REAL]


async def test_drill_sms_is_visibly_a_drill(services, org, clock):
    await dispatch(services, org, clock, drill=True, channels=("sms",))
    texts = [text for _, text in services.channels["sms"].sent]
    assert texts and all("УЧЕНИЕ" in text for text in texts)


async def test_real_sms_is_not_labelled_as_a_drill(services, org, clock):
    await dispatch(services, org, clock, drill=False, channels=("sms",))
    texts = [text for _, text in services.channels["sms"].sent]
    assert texts and all("УЧЕНИЕ" not in text for text in texts)


async def test_the_drill_flag_reaches_the_audit_chain(services, org, clock):
    order, _ = await dispatch(services, org, clock, drill=True, channels=("ws",))
    dispatched = [
        e
        for e in services.repo.audit_entries(0, 1000)
        if e["event"] == "order.dispatched" and e["data"].get("order_id") == order.order_id
    ]
    assert dispatched and dispatched[0]["data"]["drill"] is True
