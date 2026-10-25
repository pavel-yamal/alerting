"""The public RSS feed: real alerts and stand-downs, nothing about who got them."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Iterator
from dataclasses import replace

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
    """Two decision-makers stand a critical event down, as they launched it."""
    server.auth = signer_for(org, "p-001", clock)
    body = {"scenario": "EVAC.BUILDING", "severity": "critical", "drill": False,
            "action": "STOP", "cancels": target, "text": text,
            "audience": {"groups": ["fire-wardens"]}}  # fmt: skip
    proposal = server.post("/v1/proposals", json=body).json()
    for person_id in ("p-001", "p-002"):
        lpr = org.person(person_id)
        server.auth = signer_for(org, person_id, clock)
        sig = sign_payload(DOMAIN_ORDER, proposal["payload"], lpr.private_key)
        signed = server.post(
            f"/v1/proposals/{proposal['order_id']}/signatures",
            json={"key_id": lpr.key_id, "sig": sig},
        )
    assert signed.json()["dispatched"], signed.text
    order_id: str = proposal["order_id"]
    return order_id


CANCELS = "{urn:x-alerting:rss:1}cancels"
ATOM_LINK = "{http://www.w3.org/2005/Atom}link"


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
    # Which event it ends, by guid: the title cannot tell two of one scenario apart.
    assert feed[0][CANCELS] == order_id
    assert CANCELS not in alert


def test_drills_and_the_audience_stay_out(server, org, clock):
    dispatch(server, org, clock, drill=True)
    assert items(server) == []

    dispatch(server, org, clock, drill=False)
    raw = TestClient(server.app).get("/v1/feed.rss").text
    for private in ("fire-wardens", "x-101", "p-001", org.person("p-001").name):
        assert private not in raw


def test_a_proposal_waits_for_its_second_signature_without_a_deadline(server, org, clock):
    """No timer anywhere: the second decision-maker may sign a week later, and the
    order goes out like any other -- no "expired", no "signatures too far apart"."""
    server.auth = signer_for(org, "p-001", clock)
    body = {"scenario": "EVAC.BUILDING", "severity": "critical", "drill": False,
            "audience": {"groups": ["fire-wardens"]},
            "ttl_s": 600}  # sent by a client of the previous build: ignored  # fmt: skip
    proposal = server.post("/v1/proposals", json=body).json()

    def sign(person_id: str) -> dict:
        person = org.person(person_id)
        server.auth = signer_for(org, person_id, clock)
        sig = sign_payload(DOMAIN_ORDER, proposal["payload"], person.private_key)
        return server.post(
            f"/v1/proposals/{proposal['order_id']}/signatures",
            json={"key_id": person.key_id, "sig": sig},
        ).json()

    assert sign("p-001")["dispatched"] is False
    clock.advance(7 * 24 * 3600)
    second = sign("p-002")
    assert second["dispatched"] is True, second
    # A week also makes the key directory stale; that warning is about the directory.
    assert "warn_expired" not in second["warnings"]
    assert [i["guid"] for i in items(server)] == [proposal["order_id"]]


def channel_of(client: TestClient, **headers: str) -> ET.Element:
    channel = ET.fromstring(client.get("/v1/feed.rss", headers=headers).content).find("channel")
    assert channel is not None
    return channel


def test_the_channel_links_to_itself_with_an_absolute_url(server):
    """RSS readers refuse a relative channel link. Without ALERTING_PUBLIC_URL it is
    built from the host the request came to -- the Host nginx passes on."""
    channel = channel_of(TestClient(server.app), host="alert.example.org")
    assert channel.findtext("link") == "http://alert.example.org/v1/feed.rss"
    atom = channel.find(ATOM_LINK)
    assert atom is not None and atom.get("rel") == "self"
    assert atom.get("href") == "http://alert.example.org/v1/feed.rss"


def test_the_public_url_wins_over_what_the_request_says(settings, clock, org):
    """Behind nginx in a container the node sees http and its internal address."""
    app = create_app(
        replace(settings, public_url="https://alert.example.org"), clock, start_escalation=False
    )
    publish_org(app.state.alerting.repo, org, audit=app.state.alerting.audit)
    with TestClient(app) as client:
        channel = channel_of(client, host="10.0.0.5:7070")
    assert channel.findtext("link") == "https://alert.example.org/v1/feed.rss"
    atom = channel.find(ATOM_LINK)
    assert atom is not None and atom.get("href") == "https://alert.example.org/v1/feed.rss"
