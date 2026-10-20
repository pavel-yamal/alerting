"""The panel with the key in the person's browser, not in the panel.

The "browser" here is Python holding the device key, doing exactly what the page's
JavaScript does: sign the delegation it is handed, render the payload, sign it. The
panel is created without any key homes, so there is nothing it could sign with.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from alerting.clients.panel.app import CSRF_HEADER, create_panel
from alerting.core.clock import FixedClock
from alerting.core.signing import (
    DOMAIN_ORDER,
    DOMAIN_SESSION_DELEGATION,
    generate_keypair,
    key_id,
    public_key_to_b64u,
    sign_payload,
)
from alerting.orgadmin import add_key, revoke_keys, verified_current
from alerting.orgkit import Org
from alerting.server.app import create_app
from alerting.server.config import Settings
from alerting.server.services.bootstrap import publish_org
from tests.integration.conftest import signer_for
from tests.integration.test_enrollment import publish

PANEL = {CSRF_HEADER: "1"}


@pytest.fixture
def server(settings: Settings, clock: FixedClock, org: Org) -> Iterator[TestClient]:
    app = create_app(settings, clock, start_escalation=False)
    publish_org(app.state.alerting.repo, org, audit=app.state.alerting.audit)
    with TestClient(app) as client:
        client.auth = signer_for(org, "p-003", clock)
        yield client


@pytest.fixture
def panel_app(server, clock, org, tmp_path) -> Any:
    return create_panel(
        homes=None,
        server_url="http://testserver",
        transport=server._transport,
        clock=clock,
        org_id=org.org_id,
        root_public_key=public_key_to_b64u(org.root_public_key),
        state_dir=tmp_path / "panel",
        server_keys=False,
    )


class Browser:
    """What the page does, with the device key it keeps."""

    def __init__(self, panel_app: Any, person_id: str, private_key: Any) -> None:
        self.client = TestClient(panel_app)
        self.person_id = person_id
        self.private_key = private_key
        self.key_id = key_id(private_key.public_key())

    def login(self, *, tamper: bool = False) -> Any:
        begun = self.client.post(
            "/api/device/begin",
            json={"person_id": self.person_id, "key_id": self.key_id},
            headers=PANEL,
        )
        assert begun.status_code == 200, begun.text
        delegation = begun.json()["delegation"]
        # The page checks what it is asked to sign: its own key, a bounded lifetime.
        assert delegation["key_id"] == self.key_id
        assert delegation["person_id"] == self.person_id
        assert delegation["not_after"] - delegation["not_before"] <= 12 * 3600
        if tamper:
            delegation = dict(delegation, not_after=delegation["not_after"] + 1)
        signature = sign_payload(DOMAIN_SESSION_DELEGATION, delegation, self.private_key)
        return self.client.post(
            "/api/device/finish",
            json={"challenge": begun.json()["challenge"], "signature": signature},
            headers=PANEL,
        )

    def propose(self) -> str:
        response = self.client.post(
            "/api/proposals",
            json={"scenario": "EVAC.BUILDING", "severity": "critical", "drill": True,
                  "groups": ["fire-wardens"], "text": "Задымление"},
            headers=PANEL,
        )  # fmt: skip
        assert response.status_code == 200, response.text
        order_id: str = response.json()["order_id"]
        return order_id

    def sign(self, order_id: str, *, payload_override: dict[str, Any] | None = None) -> Any:
        view = self.client.get(f"/api/proposals/{order_id}").json()
        payload = payload_override or view["payload"]
        return self.client.post(
            f"/api/proposals/{order_id}/sign",
            json={
                "digest": view["digest"],
                "sig": sign_payload(DOMAIN_ORDER, payload, self.private_key),
            },
            headers=PANEL,
        )


def test_two_browsers_reach_quorum_without_the_panel_holding_a_key(panel_app, org):
    director = Browser(panel_app, "p-001", org.person("p-001").private_key)
    deputy = Browser(panel_app, "p-002", org.person("p-002").private_key)
    me = director.login()
    assert me.status_code == 200, me.text
    assert me.json()["device_key"] is True
    assert deputy.login().status_code == 200

    order_id = director.propose()
    first = director.sign(order_id)
    assert first.status_code == 200, first.text
    assert first.json()["dispatched"] is False
    second = deputy.sign(order_id)
    assert second.status_code == 200 and second.json()["dispatched"] is True, second.text

    for session in panel_app.state.panel.sessions.values():
        assert session.signer is None, "no device key ever reached the panel"


def test_a_browser_signature_over_another_payload_is_not_sent(panel_app, org):
    director = Browser(panel_app, "p-001", org.person("p-001").private_key)
    director.login()
    order_id = director.propose()
    view = director.client.get(f"/api/proposals/{order_id}").json()
    widened = dict(view["payload"], audience={"groups": ["everyone"]})
    response = director.sign(order_id, payload_override=widened)
    assert response.status_code == 409


def test_a_delegation_altered_before_signing_is_refused(panel_app, org):
    director = Browser(panel_app, "p-001", org.person("p-001").private_key)
    assert director.login(tamper=True).status_code == 401


def test_a_key_not_in_the_directory_cannot_sign_in(panel_app):
    private, _ = generate_keypair()
    assert Browser(panel_app, "p-001", private).login().status_code == 401


def test_executors_cannot_use_the_panel(panel_app, org):
    executor = Browser(panel_app, "x-101", org.person("x-101").private_key)
    assert executor.login().status_code == 403


def test_the_demo_login_is_off(panel_app, org):
    response = TestClient(panel_app).post(
        "/api/login", json={"person_id": "p-001", "passphrase": "demo"}, headers=PANEL
    )
    assert response.status_code == 404
    config = TestClient(panel_app).get("/api/config").json()
    assert config == {"org_id": org.org_id, "device_login": True, "server_keys": False}


def test_a_freshly_enrolled_browser_key_works_and_revocation_ends_it(panel_app, server, org, clock):
    """The full path: key made on the device, enrolled by the custodians, revoked."""
    private, public = generate_keypair()
    current = verified_current(
        server.get("/v1/directory").json(), public_key_to_b64u(org.root_public_key)
    )
    payload, _ = add_key(
        current, person_id="p-010", name="Орлова Е. В.", role="director",
        public_key=public_key_to_b64u(public), issued_at=clock.now(),
    )  # fmt: skip
    publish(server, org, payload)

    ipad = Browser(panel_app, "p-010", private)
    assert ipad.login().status_code == 200
    assert ipad.client.get("/api/me").json()["role"] == "director"

    current = verified_current(
        server.get("/v1/directory").json(), public_key_to_b64u(org.root_public_key)
    )
    revoked, _ = revoke_keys(current, person_id="p-010", kid=None, at=clock.now(), reason="lost")
    publish(server, org, revoked)
    assert ipad.client.post(
        "/api/proposals",
        json={"scenario": "EVAC.BUILDING", "severity": "critical", "drill": True,
              "groups": ["fire-wardens"]},
        headers=PANEL,
    ).status_code >= 400, "the session's requests are refused the moment the key is"  # fmt: skip
