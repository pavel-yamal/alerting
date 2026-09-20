"""A channel with no provider must never report delivery.

This was the most dangerous bug in the repo: `push`, `sms`, `voice` and `siren` all
returned `status="sent"` while sending nothing, so the ACK dashboard and the escalation
ladder both believed delivery had succeeded — a lie at the exact moment the truth
matters most.
"""

from __future__ import annotations

import pytest

from alerting.core.envelope import Audience
from alerting.orgkit import make_order, sign_order
from alerting.server.app import AppServices
from alerting.server.channels.base import DELIVERED_STATUSES
from alerting.server.services.bootstrap import publish_org

pytestmark = pytest.mark.asyncio


async def dispatch(services, org, clock, channels=("ws", "push", "sms", "voice")):
    order = make_order(org, issued_at=clock.now(), audience=Audience(groups=("fire-wardens",)))
    result = await services.dispatcher.dispatch(
        sign_order(order, [org.person("p-001"), org.person("p-002")]), channels=channels
    )
    assert result.accepted, result.decision.reasons
    return order, result


async def test_stub_channels_report_stub_not_sent(services, org, clock):
    _, result = await dispatch(services, org, clock)
    by_channel = {r.channel: r for r in result.receipts if r.person_id == "x-101"}

    for name in ("push", "sms", "voice"):
        assert by_channel[name].status == "stub", f"{name} must not claim delivery"
        assert "no provider" in by_channel[name].detail


async def test_stub_is_not_counted_as_delivered(services, org, clock):
    assert "stub" not in DELIVERED_STATUSES
    order, _ = await dispatch(services, org, clock, channels=("sms",))

    status = services.dispatcher.status(order.order_id)
    assert status["stub_attempts"] == 2, "both wardens got a stub attempt"
    assert all(p["delivered"] is False for p in status["people"])


async def test_a_real_channel_still_reports_sent(services, org, clock):
    """The WebSocket adapter genuinely delivers, so it must not be tarred with the
    same brush — but only when somebody is actually connected."""
    assert services.channels["ws"].delivers is True

    order, _ = await dispatch(services, org, clock, channels=("ws",))
    status = services.dispatcher.status(order.order_id)
    # Nobody is connected in this test, so ws reports failed/offline — which is the
    # honest answer, and distinct from "stub".
    assert status["delivery"].get("stub", 0) == 0
    assert status["delivery"].get("failed") == 2


async def test_a_node_refuses_to_start_with_stub_channels_in_its_ladder(settings, clock, tmp_path):
    """The guard that stops a production box booting with four fake channels."""
    settings.db_path = str(tmp_path / "guard.db")
    settings.allow_stub_channels = False

    with pytest.raises(RuntimeError, match="no provider"):
        AppServices(settings, clock)


async def test_the_guard_can_be_waived_explicitly(settings, clock, tmp_path, org, caplog):
    import logging

    settings.db_path = str(tmp_path / "waived.db")
    settings.allow_stub_channels = True
    caplog.set_level(logging.WARNING, logger="alerting.server")

    services = AppServices(settings, clock)
    try:
        publish_org(services.repo, org)
        assert "will NOT deliver" in caplog.text
    finally:
        services.close()


async def test_a_missing_escalation_ladder_is_a_startup_failure(settings, clock, tmp_path):
    """It used to fall back to the built-in ladder silently, so a node ran different
    channels and timings than the operator had configured."""
    settings.db_path = str(tmp_path / "noladder.db")
    settings.escalation_config = str(tmp_path / "does-not-exist.yaml")

    with pytest.raises(RuntimeError, match="escalation ladder not found"):
        AppServices(settings, clock)


async def test_the_builtin_ladder_must_be_asked_for_by_name(settings, clock, tmp_path):
    settings.db_path = str(tmp_path / "builtin.db")
    settings.escalation_config = "builtin"
    settings.allow_stub_channels = True

    services = AppServices(settings, clock)
    try:
        assert services.escalation_plan.ladders
    finally:
        services.close()
