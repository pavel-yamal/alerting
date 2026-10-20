"""The escalation ladder on a fake clock.

Day to day this matters more than the signatures: the common failure is a phone on
silent, not a forgery.
"""

from __future__ import annotations

import pytest

from alerting.core.envelope import AckStatus, Audience
from alerting.core.receipts import build_ack
from alerting.orgkit import make_order, sign_order

pytestmark = pytest.mark.asyncio


async def dispatch(services, org, clock, **kwargs):
    order = make_order(
        org,
        issued_at=clock.now(),
        audience=Audience(groups=("fire-wardens",)),
        **kwargs,
    )
    envelope = sign_order(order, [org.person("p-001"), org.person("p-002")])
    result = await services.dispatcher.dispatch(envelope)
    assert result.accepted, result.decision.reasons
    return order


def channel(services, name):
    return services.channels[name]


async def test_ladder_climbs_while_nobody_acknowledges(services, org, clock):
    await dispatch(services, org, clock)
    sms, voice, siren = (channel(services, n) for n in ("sms", "voice", "siren"))

    assert sms.sent == []

    clock.advance(70)
    await services.escalation.tick()
    assert len(sms.sent) == 2, "both fire wardens get the wake-up SMS"
    assert voice.calls == []

    clock.advance(130)  # 200s total
    await services.escalation.tick()
    assert len(voice.calls) == 2

    clock.advance(450)  # 650s total — the siren rung
    await services.escalation.tick()
    assert siren.activations, "siren is the last rung, not the first"


async def test_acknowledging_stops_escalation_for_that_person(services, org, clock):
    order = await dispatch(services, org, clock)
    raw = order.to_payload()
    person = org.person("x-101")
    ack = build_ack(
        order=order,
        order_payload_raw=raw,
        person_id=person.person_id,
        device_key_id=person.key_id,
        status=AckStatus.ACKNOWLEDGED,
        at=clock.now(),
        nonce="n",
        private_key=person.private_key,
    )
    services.repo.record_ack(
        order.order_id,
        person.person_id,
        person.key_id,
        "acknowledged",
        clock.now(),
        ack.model_dump(mode="json"),
        True,
    )

    clock.advance(70)
    await services.escalation.tick()
    phones = {phone for phone, _ in channel(services, "sms").sent}
    assert org.person("x-102").phone in phones
    assert org.person("x-101").phone not in phones


async def test_rungs_are_idempotent_across_repeated_ticks(services, org, clock):
    await dispatch(services, org, clock)
    clock.advance(70)
    for _ in range(5):
        await services.escalation.tick()
    assert len(channel(services, "sms").sent) == 2, "no duplicate SMS on re-tick"


async def test_an_expired_order_stops_escalating(services, org, clock):
    # MUSTER does not last until a stand-down: its delivery window is its life.
    await dispatch(services, org, clock, scenario="MUSTER", ttl_s=120)
    clock.advance(600)
    await services.escalation.tick()
    assert channel(services, "sms").sent == []


async def test_an_event_until_stand_down_keeps_escalating_past_its_window(services, org, clock):
    """EVAC.BUILDING lasts until cancelled (signed into the policy): people who have
    not answered keep being chased after the envelope's delivery window closes."""
    await dispatch(services, org, clock, scenario="EVAC.BUILDING", ttl_s=120)
    clock.advance(600)
    await services.escalation.tick()
    assert channel(services, "sms").sent, "the ladder must not stop at the window"


async def test_a_cancelled_order_stops_escalating(services, org, clock):
    order = await dispatch(services, org, clock)
    cancel = make_order(
        org,
        issued_at=clock.now(),
        seq=order.seq + 1,
        order_type="cancel",
        cancels=order.order_id,
        action="STOP",
        audience=Audience(groups=("fire-wardens",)),
    )
    result = await services.dispatcher.dispatch(sign_order(cancel, [org.person("p-001")]))
    assert result.accepted, result.decision.reasons

    clock.advance(300)
    await services.escalation.tick()
    assert channel(services, "sms").sent == [], "the stand-down ends the ladder"


async def test_an_invalid_ack_does_not_stop_escalation(services, org, clock):
    """Impersonation must not be able to silence the ladder."""
    order = await dispatch(services, org, clock)
    services.repo.record_ack(
        order.order_id,
        "x-101",
        "ed25519:forged",
        "completed",
        clock.now(),
        {"forged": True},
        False,
        ["bad_signature"],
    )
    clock.advance(70)
    await services.escalation.tick()
    assert len(channel(services, "sms").sent) == 2


async def test_escalation_audit_trail_is_pseudonymous(services, org, clock):
    await dispatch(services, org, clock)
    clock.advance(70)
    await services.escalation.tick()

    entries = list(services.repo.audit_entries(0, 1000))
    rungs = [e for e in entries if e["event"] == "escalation.rung_fired"]
    assert rungs
    blob = str(entries)
    assert org.person("x-101").phone not in blob, "no phone numbers in the chain"
    assert org.person("x-101").name not in blob, "no names in the chain"
