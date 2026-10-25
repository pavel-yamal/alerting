"""The public RSS feed: real alerts and stand-downs, nothing about who got them."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from alerting.core.clock import FixedClock
from alerting.core.signing import DOMAIN_ORDER, sign_payload
from alerting.orgkit import Org
from alerting.server.app import create_app
from alerting.server.config import Settings
from alerting.server.services.bootstrap import publish_org
from tests.integration.conftest import signer_for
from tests.integration.test_mobile import dispatch


@pytest.fixture
def server(settings: Settings, clock: FixedClock, org: Org) -> Iterator[TestClient]:
    app = create_app(settings, clock, start_escalation=False)
    publish_org(app.state.alerting.repo, org, audit=app.state.alerting.audit)
    with TestClient(app) as client:
        yield client


def stand_down(server: TestClient, org: Org, clock: FixedClock, target: str, text: str) -> str:
    """One decision-maker stands a critical event down (cancel quorum is 1)."""
    lpr = org.person("p-001")
    server.auth = signer_for(org, "p-001", clock)
    body = {"scenario": "EVAC.BUILDING", "severity": "critical", "drill": False,
            "action": "STOP", "cancels": target, "text": text,
            "audience": {"groups": ["fire-wardens"]}}  # fmt: skip
    proposal = server.post("/v1/proposals", json=body).json()
    sig = sign_payload(DOMAIN_ORDER, proposal["payload"], lpr.private_key)
    signed = server.post(
        f"/v1/proposals/{proposal['order_id']}/signatures", json={"key_id": lpr.key_id, "sig": sig}
    )
    assert signed.json()["dispatched"], signed.text
    order_id: str = proposal["order_id"]
    return order_id


def items(server: TestClient) -> list[dict[str, str]]:
    response = TestClient(server.app).get("/v1/feed.rss")  # no signature: it is public
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/rss+xml")
    channel = ET.fromstring(response.content).find("channel")
    assert channel is not None
    return [{child.tag: child.text or "" for child in item} for item in channel.iter("item")]


def test_a_real_alert_and_its_stand_down_are_in_the_feed(server, org, clock):
    order_id = dispatch(server, org, clock, drill=False, text="Задымление, 3 этаж <b>")
    clock.advance(60)
    cancel_id = stand_down(server, org, clock, order_id, "Ложная тревога")

    feed = items(server)
    assert [i["guid"] for i in feed] == [cancel_id, order_id]  # newest first
    alert = feed[1]
    assert alert["title"] == "Полная эвакуация здания"
    assert alert["description"].startswith("Задымление, 3 этаж <b>")  # text, not markup
    assert alert["category"] == "EVAC.BUILDING"
    assert feed[0]["title"] == "ОТБОЙ: Полная эвакуация здания"
    assert feed[0]["description"] == "Ложная тревога"


def test_drills_and_the_audience_stay_out(server, org, clock):
    dispatch(server, org, clock, drill=True)
    assert items(server) == []

    dispatch(server, org, clock, drill=False)
    raw = TestClient(server.app).get("/v1/feed.rss").text
    for private in ("fire-wardens", "x-101", "p-001", org.person("p-001").name):
        assert private not in raw
