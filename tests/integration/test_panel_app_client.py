"""The decision-makers' native app as a panel client (docs/adr/0016).

The app's page is served from its own bundle (``capacitor://localhost`` on iOS,
``https://localhost`` on Android), not from the panel's origin, so it cannot ride the
panel's cookie. It says so on ``/api/device/finish`` and gets the session token in
the body, then sends it as ``Authorization: Bearer``. Everything else -- the
delegation, the order signatures by the device key -- is the browser's flow.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from alerting.clients.panel.app import APP_CLIENT, APP_HEADER, CSRF_HEADER, create_panel
from alerting.core.clock import FixedClock
from alerting.core.signing import (
    DOMAIN_ORDER,
    DOMAIN_SESSION_DELEGATION,
    key_id,
    public_key_to_b64u,
    sign_payload,
)
from alerting.orgkit import Org
from alerting.server.app import create_app
from alerting.server.config import Settings
from alerting.server.services.bootstrap import publish_org
from tests.integration.conftest import signer_for


@pytest.fixture
def server(settings: Settings, clock: FixedClock, org: Org) -> Iterator[TestClient]:
    app = create_app(settings, clock, start_escalation=False)
    publish_org(app.state.alerting.repo, org, audit=app.state.alerting.audit)
    with TestClient(app) as client:
        client.auth = signer_for(org, "p-003", clock)
        yield client


def make_panel(
    server: TestClient, clock: FixedClock, org: Org, state: Any, **kwargs: Any
) -> FastAPI:
    return create_panel(
        homes=None,
        server_url="http://testserver",
        transport=server._transport,
        clock=clock,
        org_id=org.org_id,
        root_public_key=public_key_to_b64u(org.root_public_key),
        state_dir=state,
        server_keys=False,
        **kwargs,
    )


@pytest.fixture
def panel_app(server: TestClient, clock: FixedClock, org: Org, tmp_path: Any) -> FastAPI:
    return make_panel(server, clock, org, tmp_path / "panel")


APP = {CSRF_HEADER: "1", APP_HEADER: APP_CLIENT, "Origin": "capacitor://localhost"}


class App:
    """What the app does: the device key unlocked by biometrics, a token in memory."""

    def __init__(self, panel_app: Any, person_id: str, private_key: Any) -> None:
        self.client = TestClient(panel_app)
        self.person_id = person_id
        self.private_key = private_key
        self.key_id = key_id(private_key.public_key())
        self.token: str | None = None

    def headers(self) -> dict[str, str]:
        return {**APP, "Authorization": f"Bearer {self.token}"} if self.token else dict(APP)

    def login(self) -> Any:
        begun = self.client.post(
            "/api/device/begin",
            json={"person_id": self.person_id, "key_id": self.key_id},
            headers=APP,
        )
        assert begun.status_code == 200, begun.text
        signature = sign_payload(
            DOMAIN_SESSION_DELEGATION, begun.json()["delegation"], self.private_key
        )
        finished = self.client.post(
            "/api/device/finish",
            json={"challenge": begun.json()["challenge"], "signature": signature},
            headers=APP,
        )
        if finished.status_code == 200:
            self.token = finished.json()["token"]
        return finished

    def propose(self) -> str:
        response = self.client.post(
            "/api/proposals",
            json={"scenario": "EVAC.BUILDING", "severity": "critical", "drill": True,
                  "groups": ["all"], "text": "Задымление"},
            headers=self.headers(),
        )  # fmt: skip
        assert response.status_code == 200, response.text
        order_id: str = response.json()["order_id"]
        return order_id

    def sign(self, order_id: str) -> Any:
        view = self.client.get(f"/api/proposals/{order_id}", headers=self.headers()).json()
        return self.client.post(
            f"/api/proposals/{order_id}/sign",
            json={
                "digest": view["digest"],
                "sig": sign_payload(DOMAIN_ORDER, view["payload"], self.private_key),
            },
            headers=self.headers(),
        )


def test_the_token_comes_in_the_body_and_no_cookie_is_set(panel_app, org):
    app = App(panel_app, "p-001", org.person("p-001").private_key)
    finished = app.login()
    assert finished.status_code == 200, finished.text
    assert finished.json()["token"]
    assert finished.json()["device_key"] is True
    assert "set-cookie" not in finished.headers
    assert not app.client.cookies, "the app session lives in the app's memory, not a cookie"

    me = app.client.get("/api/me", headers=app.headers())
    assert me.status_code == 200 and me.json()["person_id"] == "p-001"
    assert app.client.get("/api/me").status_code == 401, "no token, no session"


def test_two_apps_reach_quorum_with_device_keys(panel_app, org):
    director = App(panel_app, "p-001", org.person("p-001").private_key)
    deputy = App(panel_app, "p-002", org.person("p-002").private_key)
    assert director.login().status_code == 200
    assert deputy.login().status_code == 200

    order_id = director.propose()
    assert director.sign(order_id).json()["dispatched"] is False
    second = deputy.sign(order_id)
    assert second.status_code == 200 and second.json()["dispatched"] is True, second.text
    for session in panel_app.state.panel.sessions.values():
        assert session.signer is None, "no device key ever reached the panel"


def test_the_duty_officer_is_refused_and_no_session_is_left(panel_app, org):
    duty = App(panel_app, "p-004", org.person("p-004").private_key)
    refused = duty.login()
    assert refused.status_code == 403
    assert "ЛПР" in refused.json()["detail"]
    assert not panel_app.state.panel.sessions, "the session opened for the check is closed"


def test_the_browser_still_gets_a_cookie_and_no_token(panel_app, org):
    """Without the app header nothing changes for the panel page."""
    client = TestClient(panel_app)
    private = org.person("p-001").private_key
    begun = client.post(
        "/api/device/begin",
        json={"person_id": "p-001", "key_id": key_id(private.public_key())},
        headers={CSRF_HEADER: "1"},
    ).json()
    finished = client.post(
        "/api/device/finish",
        json={
            "challenge": begun["challenge"],
            "signature": sign_payload(DOMAIN_SESSION_DELEGATION, begun["delegation"], private),
        },
        headers={CSRF_HEADER: "1"},
    )
    assert finished.status_code == 200
    assert "token" not in finished.json()
    assert "set-cookie" in finished.headers


def test_logout_with_the_token_ends_the_session(panel_app, org):
    app = App(panel_app, "p-001", org.person("p-001").private_key)
    app.login()
    assert app.client.post("/api/logout", headers=app.headers()).status_code == 200
    assert app.client.get("/api/me", headers=app.headers()).status_code == 401


def test_mutations_still_need_the_panel_header(panel_app, org):
    app = App(panel_app, "p-001", org.person("p-001").private_key)
    app.login()
    headers = {"Authorization": f"Bearer {app.token}"}
    response = app.client.post("/api/proposals", json={}, headers=headers)
    assert response.status_code == 403


def preflight(panel_app: Any, origin: str) -> Any:
    return TestClient(panel_app).options(
        "/api/device/begin",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": f"authorization,content-type,{CSRF_HEADER}",
        },
    )


def test_cors_answers_only_the_app_origins(panel_app):
    for origin in ("capacitor://localhost", "https://localhost"):
        answer = preflight(panel_app, origin)
        assert answer.status_code == 200, origin
        assert answer.headers["access-control-allow-origin"] == origin
        assert "access-control-allow-credentials" not in answer.headers, (
            "cookies never go cross-origin: the app authenticates with its token"
        )
    evil = preflight(panel_app, "https://evil.example")
    assert "access-control-allow-origin" not in evil.headers


def test_the_app_can_be_turned_off(server, clock, org, tmp_path):
    panel = make_panel(server, clock, org, tmp_path / "off", app_origins=())
    assert "access-control-allow-origin" not in preflight(panel, "capacitor://localhost").headers


def test_the_privacy_policy_is_public_and_names_the_operator(server, clock, org, tmp_path):
    panel = make_panel(
        server, clock, org, tmp_path / "pp",
        org_label="АНО «Ямал-Медиа»", privacy_contact="<b>dpo@example.ru</b>",
    )  # fmt: skip
    page = TestClient(panel).get("/privacy")
    assert page.status_code == 200
    assert page.headers["content-type"].startswith("text/html")
    assert "АНО «Ямал-Медиа»" in page.text
    assert "&lt;b&gt;dpo@example.ru&lt;/b&gt;" in page.text, "settings are text, not markup"
    assert "{contact}" not in page.text and "{org_label}" not in page.text
