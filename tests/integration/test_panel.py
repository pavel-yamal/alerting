"""The duty officer's web panel, driven against the real server app.

The panel is a client: it unlocks a person's key, signs every request with it, and
signs orders only after the person has seen them. These tests run it the way it is
deployed -- key homes on disk as ``org_init`` writes them, the server's own ASGI app
behind the transport -- so what is checked is the panel's behaviour, not a mock's.
"""

from __future__ import annotations

import pathlib
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from alerting.clients.bundles import PinnedOrg
from alerting.clients.keystore import save_key
from alerting.clients.panel.app import CSRF_HEADER, create_panel
from alerting.core.clock import FixedClock
from alerting.core.signing import public_key_to_b64u
from alerting.orgkit import Org
from alerting.server.app import create_app
from alerting.server.config import Settings
from alerting.server.services.bootstrap import publish_org

PASSPHRASE = "demo"
PANEL = {CSRF_HEADER: "1"}


@pytest.fixture
def homes(tmp_path: pathlib.Path, org: Org) -> pathlib.Path:
    root = tmp_path / "clients"
    for person in org.people.values():
        home = root / person.person_id
        save_key(person.person_id, person.private_key, PASSPHRASE, role=person.role, directory=home)
        PinnedOrg(org.org_id, public_key_to_b64u(org.root_public_key), home).save()
    return root


@pytest.fixture
def server(settings: Settings, clock: FixedClock, org: Org) -> Iterator[TestClient]:
    app = create_app(settings, clock, start_escalation=False)
    publish_org(app.state.alerting.repo, org, audit=app.state.alerting.audit)
    with TestClient(app) as client:
        yield client


@pytest.fixture
def panel_app(homes: pathlib.Path, server: TestClient, clock: FixedClock) -> Any:
    # The server's in-process transport: requests go through its real auth gate.
    return create_panel(
        homes=homes, server_url="http://testserver", transport=server._transport, clock=clock
    )


def browser(panel_app: Any, person_id: str) -> TestClient:
    """One logged-in browser. Each has its own cookie jar, like two workstations."""
    client = TestClient(panel_app)
    response = client.post(
        "/api/login", json={"person_id": person_id, "passphrase": PASSPHRASE}, headers=PANEL
    )
    assert response.status_code == 200, response.text
    return client


def propose(client: TestClient, **overrides: Any) -> str:
    body = {
        "scenario": "EVAC.BUILDING",
        "severity": "critical",
        "drill": True,
        "groups": ["fire-wardens"],
        "text": "Задымление, 3 этаж",
    } | overrides
    response = client.post("/api/proposals", json=body, headers=PANEL)
    assert response.status_code == 200, response.text
    order_id: str = response.json()["order_id"]
    return order_id


def sign(client: TestClient, order_id: str) -> dict[str, Any]:
    review = client.get(f"/api/proposals/{order_id}").json()
    response = client.post(
        f"/api/proposals/{order_id}/sign", json={"digest": review["digest"]}, headers=PANEL
    )
    assert response.status_code == 200, response.text
    result: dict[str, Any] = response.json()
    return result


def test_a_critical_order_needs_two_people_and_then_goes_out(panel_app):
    officer = browser(panel_app, "p-003")
    director = browser(panel_app, "p-001")

    order_id = propose(officer)
    first = sign(officer, order_id)
    assert not first["dispatched"]

    # The second signer finds the proposal in the shared list, not by being told its id.
    listed = director.get("/api/proposals").json()["proposals"]
    assert [p["order_id"] for p in listed] == [order_id]
    assert listed[0]["signed_by"] == ["Орлов Д. С. (duty_officer)"]

    second = sign(director, order_id)
    assert second["dispatched"] and second["recipients"] > 0

    status = officer.get(f"/api/orders/{order_id}").json()
    assert status["drill"] is True
    assert status["acknowledged"] == 0
    assert {p["person_id"] for p in status["people"]} == set(status["outstanding"])
    assert all(p["name"] for p in status["people"])


def test_the_same_person_cannot_supply_both_signatures(panel_app):
    officer = browser(panel_app, "p-003")
    order_id = propose(officer)
    sign(officer, order_id)

    review = officer.get(f"/api/proposals/{order_id}").json()
    assert review["signed_by_me"] is True
    again = officer.post(
        f"/api/proposals/{order_id}/sign", json={"digest": review["digest"]}, headers=PANEL
    ).json()
    assert again["dispatched"] is False


def test_nothing_is_signed_unless_it_is_what_the_person_reviewed(panel_app, server):
    officer = browser(panel_app, "p-003")
    order_id = propose(officer)

    response = officer.post(
        f"/api/proposals/{order_id}/sign", json={"digest": "0" * 64}, headers=PANEL
    )
    assert response.status_code == 409
    assert officer.get(f"/api/proposals/{order_id}").json()["signed_by"] == []


def test_drill_has_no_default(panel_app):
    officer = browser(panel_app, "p-003")
    response = officer.post(
        "/api/proposals",
        json={"scenario": "TEST.PING", "severity": "info", "groups": ["fire-wardens"]},
        headers=PANEL,
    )
    assert response.status_code == 422


def test_a_request_from_another_site_is_refused(panel_app):
    """A page on another origin can make the browser send the cookie, but cannot set
    a custom header without a preflight this app never answers."""
    officer = browser(panel_app, "p-003")
    response = officer.post(
        "/api/proposals",
        json={"scenario": "TEST.PING", "severity": "info", "drill": True, "groups": ["x"]},
    )
    assert response.status_code == 403


def test_login_refusals(panel_app):
    client = TestClient(panel_app)

    def login(person_id: str, passphrase: str) -> int:
        return client.post(
            "/api/login", json={"person_id": person_id, "passphrase": passphrase}, headers=PANEL
        ).status_code

    assert login("p-003", "wrong") == 401
    assert login("nobody", PASSPHRASE) == 401
    assert login("../p-003", PASSPHRASE) == 400
    # Executors sign receipts, not orders; the panel is not theirs.
    assert login("x-101", PASSPHRASE) == 403
    assert client.get("/api/me").status_code == 401


def test_stand_down_is_an_order_that_is_reviewed_and_signed_too(panel_app):
    officer = browser(panel_app, "p-003")
    director = browser(panel_app, "p-001")
    order_id = propose(officer, scenario="TEST.PING", severity="info")
    assert sign(officer, order_id)["dispatched"]

    response = director.post(
        f"/api/orders/{order_id}/cancel", json={"text": "Ложное срабатывание"}, headers=PANEL
    )
    assert response.status_code == 200, response.text
    cancel_id = response.json()["order_id"]

    review = director.get(f"/api/proposals/{cancel_id}").json()
    assert review["fields"]["cancels"] == order_id
    assert review["fields"]["action"] == "STOP"
    assert review["fields"]["drill"] is True
    assert sign(director, cancel_id)["dispatched"]


def test_meta_comes_from_the_verified_policy(panel_app):
    officer = browser(panel_app, "p-003")
    meta = officer.get("/api/meta").json()
    codes = {s["code"] for s in meta["scenarios"]}
    assert "EVAC.BUILDING" in codes and "CANARY" not in codes
    assert meta["severities"]["critical"]["launch"] == 2
    assert "fire-wardens" in meta["groups"]
