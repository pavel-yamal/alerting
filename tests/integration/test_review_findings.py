"""Regressions for the findings an automated review raised on PR #1.

Each test fails against the code as it was before the fix.
"""

from __future__ import annotations

import pytest

from alerting.core.envelope import Audience
from alerting.core.signing import private_key_to_b64u, public_key_to_b64u
from alerting.orgkit import make_order, sign_order

pytestmark = pytest.mark.asyncio


async def dispatch(services, org, clock, *, audience=None, **kwargs):
    order = make_order(
        org,
        issued_at=clock.now(),
        audience=audience if audience is not None else Audience(groups=("fire-wardens",)),
        **kwargs,
    )
    result = await services.dispatcher.dispatch(
        sign_order(order, [org.person("p-001"), org.person("p-002")]),
        channels=("ws", "sms"),
    )
    return order, result


# --- P1: "cannot comply" must not retire someone from escalation -----------


async def test_cannot_comply_keeps_the_escalation_ladder_running(services, org, clock):
    """A refusal is the case reassignment exists for. Treating it as handled stopped
    the ladder exactly at the duty-officer, alternate and siren rungs."""
    order, _ = await dispatch(services, org, clock)

    for person_id in ("x-101", "x-102"):
        services.repo.record_ack(
            order.order_id,
            person_id,
            org.person(person_id).key_id,
            "cannot_comply",
            clock.now(),
            {"status": "cannot_comply", "reason": "путь отрезан огнём"},
            True,
        )

    assert services.repo.acknowledged_person_ids(order.order_id) == set()
    assert services.repo.refused_person_ids(order.order_id) == {"x-101", "x-102"}

    clock.advance(700)
    fired = await services.escalation.tick()
    assert fired, "everyone refused, so the ladder must keep climbing"
    assert services.channels["siren"].activations, "the siren rung must still be reached"


async def test_a_real_acknowledgement_still_stops_escalation(services, org, clock):
    order, _ = await dispatch(services, org, clock)
    for person_id in ("x-101", "x-102"):
        services.repo.record_ack(
            order.order_id,
            person_id,
            org.person(person_id).key_id,
            "en_route",
            clock.now(),
            {"status": "en_route"},
            True,
        )
    clock.advance(700)
    await services.escalation.tick()
    assert services.channels["siren"].activations == []


# --- P1: an order that reaches nobody is never a success -------------------


async def test_an_order_matching_no_contact_is_flagged_not_reported_as_sent(services, org, clock):
    _, result = await dispatch(
        services, org, clock, audience=Audience(groups=("nobody-by-this-name",))
    )
    assert result.accepted, "the signatures are valid; this is a delivery failure"
    assert result.reached_nobody is True
    assert result.recipients == []

    events = [
        entry["event"]
        for entry in services.repo.audit_entries(0, 1000)
        if entry["event"] == "dispatch.no_recipients"
    ]
    assert events, "reaching nobody has to be in the record"


async def test_a_normal_dispatch_is_not_flagged(services, org, clock):
    _, result = await dispatch(services, org, clock)
    assert result.reached_nobody is False
    assert set(result.recipients) == {"x-101", "x-102"}


async def test_the_api_refuses_a_proposal_addressed_to_nobody(client):
    response = client.post(
        "/v1/proposals",
        json={
            "scenario": "EVAC.BUILDING",
            "severity": "critical",
            "drill": False,
            "audience": {"sites": [], "groups": [], "persons": []},
        },
    )
    assert response.status_code == 422
    assert "reach nobody" in response.text


async def test_the_api_requires_an_audience_at_all(client):
    """Omitting it must not quietly default to an empty one."""
    response = client.post(
        "/v1/proposals",
        json={"scenario": "EVAC.BUILDING", "severity": "critical", "drill": False},
    )
    assert response.status_code == 422


# --- P2: audit heads have to be signed -------------------------------------


async def test_published_heads_are_signed_when_a_server_key_is_configured(
    settings, clock, org, tmp_path
):
    from alerting.core.audit_chain import head_of
    from alerting.core.signing import (
        DOMAIN_AUDIT_HEAD,
        generate_keypair,
        verify_signature,
    )
    from alerting.server.app import AppServices
    from alerting.server.services.bootstrap import publish_org

    private, public = generate_keypair()
    settings.server_private_key = private_key_to_b64u(private)
    settings.db_path = str(tmp_path / "signed.db")

    services = AppServices(settings, clock)
    try:
        publish_org(services.repo, org, audit=services.audit)
        entries = list(services.repo.audit_entries(0, 1000))
        head = services.audit.publish_head(len(entries) - 1, head_of(entries), clock.now())

        assert head["signature"], "an unsigned head gives no tamper-evidence at all"
        assert verify_signature(DOMAIN_AUDIT_HEAD, head["payload"], head["signature"], public)
        assert public_key_to_b64u(public)
    finally:
        services.close()


async def test_an_unconfigured_server_key_is_warned_about(settings, clock, tmp_path, caplog):
    import logging

    from alerting.server.app import AppServices

    settings.db_path = str(tmp_path / "unsigned.db")
    settings.server_private_key = ""
    caplog.set_level(logging.WARNING, logger="alerting.server")

    services = AppServices(settings, clock)
    try:
        assert "UNSIGNED" in caplog.text
    finally:
        services.close()
