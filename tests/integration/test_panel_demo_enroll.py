"""Self-service enrolment on a demonstration stand (docs/adr/0016, demo_enroll.py).

The App Store reviewer has no custodian to meet, so a demo panel holding the demo
org's root key enrols any app key as a demo decision-maker. These tests hold the
fences: off by default, refused with a root that is not the pinned one, and an
enrolled key is an ordinary directory key -- it logs in and signs like any other.
"""

from __future__ import annotations

import pathlib
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from alerting.clients.bundles import PinnedOrg
from alerting.clients.keystore import save_key
from alerting.clients.panel.app import APP_CLIENT, APP_HEADER, CSRF_HEADER, create_panel
from alerting.clients.panel.demo_enroll import DEMO_KEY_DAYS, DemoEnroll
from alerting.core.clock import FixedClock
from alerting.core.signing import (
    DOMAIN_SESSION_DELEGATION,
    generate_keypair,
    public_key_to_b64u,
    sign_payload,
)
from alerting.orgkit import Org
from alerting.server.app import create_app
from alerting.server.config import Settings
from alerting.server.services.bootstrap import publish_org

APP = {CSRF_HEADER: "1", APP_HEADER: APP_CLIENT}


@pytest.fixture
def homes(tmp_path: pathlib.Path, org: Org) -> pathlib.Path:
    root = tmp_path / "clients"
    person = org.person("p-004")
    home = root / person.person_id
    save_key(person.person_id, person.private_key, "demo", role=person.role, directory=home)
    PinnedOrg(org.org_id, public_key_to_b64u(org.root_public_key), home).save()
    return root


@pytest.fixture
def server(settings: Settings, clock: FixedClock, org: Org) -> Iterator[TestClient]:
    app = create_app(settings, clock, start_escalation=False)
    publish_org(app.state.alerting.repo, org, audit=app.state.alerting.audit)
    with TestClient(app) as client:
        yield client


def make_panel(
    server: TestClient, clock: FixedClock, org: Org, homes: Any, tmp: Any, **kw: Any
) -> FastAPI:
    return create_panel(
        homes=homes,
        server_url="http://testserver",
        transport=server._transport,
        clock=clock,
        org_id=org.org_id,
        root_public_key=public_key_to_b64u(org.root_public_key),
        state_dir=tmp / "panel",
        server_keys=False,
        **kw,
    )


@pytest.fixture
def demo_panel(server, clock, org, homes, tmp_path) -> FastAPI:
    return make_panel(
        server, clock, org, homes, tmp_path,
        demo_enroll=DemoEnroll(org.root_private_key, "p-004", "demo"),
    )  # fmt: skip


def enroll(panel: FastAPI) -> tuple[Any, Any]:
    private, public = generate_keypair()
    response = TestClient(panel).post(
        "/api/demo/enroll", json={"public_key": public_key_to_b64u(public)}, headers=APP
    )
    return response, private


def login(panel: FastAPI, person_id: str, key_id: str, private: Any) -> Any:
    client = TestClient(panel)
    begun = client.post(
        "/api/device/begin", json={"person_id": person_id, "key_id": key_id}, headers=APP
    ).json()
    return client.post(
        "/api/device/finish",
        json={
            "challenge": begun["challenge"],
            "signature": sign_payload(DOMAIN_SESSION_DELEGATION, begun["delegation"], private),
        },
        headers=APP,
    )


def test_an_enrolled_app_key_is_a_demo_lpr_that_logs_in_at_once(demo_panel, server, clock):
    assert TestClient(demo_panel).get("/api/config").json()["demo"] is True
    first, private = enroll(demo_panel)
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["person_id"] == "demo-001" and body["role"] == "lpr"

    entry = next(
        e for e in server.app.state.alerting.repo.latest_bundle("directory")["payload"]["keys"]
        if e["person_id"] == "demo-001"
    )  # fmt: skip
    assert entry["valid_until"] == clock.now() + DEMO_KEY_DAYS * 86400, "demo keys expire"

    session = login(demo_panel, "demo-001", body["key_id"], private)
    assert session.status_code == 200, session.text
    assert session.json()["role"] == "lpr" and session.json()["token"]

    second, _ = enroll(demo_panel)
    assert second.json()["person_id"] == "demo-002", "each phone is its own person"


def test_off_unless_asked(server, clock, org, homes, tmp_path):
    panel = make_panel(server, clock, org, homes, tmp_path)
    assert TestClient(panel).get("/api/config").json()["demo"] is False
    response, _ = enroll(panel)
    assert response.status_code in (404, 405)


def test_a_root_that_is_not_the_pinned_one_is_refused_at_start(server, clock, org, homes, tmp_path):
    stranger, _ = generate_keypair()
    with pytest.raises(ValueError, match="does not match"):
        make_panel(
            server, clock, org, homes, tmp_path,
            demo_enroll=DemoEnroll(stranger, "p-004", "demo"),
        )  # fmt: skip


def test_the_same_key_twice_and_a_request_without_the_panel_header(demo_panel):
    _private, public = generate_keypair()
    key = {"public_key": public_key_to_b64u(public)}
    client = TestClient(demo_panel)
    assert client.post("/api/demo/enroll", json=key).status_code == 403
    assert client.post("/api/demo/enroll", json=key, headers=APP).status_code == 200
    assert client.post("/api/demo/enroll", json=key, headers=APP).status_code == 409
