"""ALERTING_DELIVERY=rss: two decision-makers sign, the order goes to the feed, and
nothing is sent to anyone -- neither the order nor its stand-down."""

from __future__ import annotations

import dataclasses
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from alerting.core.clock import FixedClock
from alerting.orgkit import Org
from alerting.server.app import create_app
from alerting.server.config import Settings
from alerting.server.services.bootstrap import publish_org
from tests.integration.conftest import signer_for
from tests.integration.test_feed import items, stand_down
from tests.integration.test_mobile import dispatch


@pytest.fixture
def server(settings: Settings, clock: FixedClock, org: Org) -> Iterator[TestClient]:
    rss = dataclasses.replace(settings, delivery="rss")
    app = create_app(rss, clock, start_escalation=False)
    publish_org(app.state.alerting.repo, org, audit=app.state.alerting.audit)
    with TestClient(app) as client:
        yield client


def sent(server: TestClient, order_id: str) -> list[object]:
    return list(server.app.state.alerting.repo.dispatches(order_id))


def test_a_signed_order_goes_to_the_feed_and_to_nobody(server, org, clock):
    order_id = dispatch(server, org, clock, drill=False, text="Задымление")
    assert sent(server, order_id) == []

    server.auth = signer_for(org, "p-003", clock)
    status = server.get(f"/v1/orders/{order_id}/status").json()
    assert status["rss_only"] is True and status["reached_nobody"] is False
    assert status["people"] == []
    order = server.get(f"/v1/orders/{order_id}").json()
    assert order["payload"]["requires_ack"] is False

    feed = items(server)
    assert [item["guid"] for item in feed] == [order_id]
    assert feed[0]["title"] == "Полная эвакуация здания"


def test_the_stand_down_too_goes_only_to_the_feed(server, org, clock):
    order_id = dispatch(server, org, clock, drill=False)
    clock.advance(60)
    cancel_id = stand_down(server, org, clock, order_id, "Ложная тревога")
    assert sent(server, cancel_id) == []
    titles = [item["title"] for item in items(server)]
    assert titles[0] == "ОТБОЙ: Полная эвакуация здания"


def test_a_drill_is_in_the_feed_and_marked(server, org, clock):
    order_id = dispatch(server, org, clock, drill=True)
    feed = items(server)
    assert [item["guid"] for item in feed] == [order_id]
    assert feed[0]["title"].startswith("УЧЕНИЕ. ")


def test_the_list_says_where_orders_go(server, org, clock):
    server.auth = signer_for(org, "p-001", clock)
    assert server.get("/v1/proposals").json()["delivery"] == "rss"


def test_an_unknown_delivery_mode_is_refused():
    with pytest.raises(ValueError, match="ALERTING_DELIVERY"):
        Settings(delivery="sms")
