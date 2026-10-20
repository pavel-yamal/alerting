"""The executor's phone client, driven against the real server app.

The order stream is the server's own WebSocket (Starlette's in-process socket stands
in for the network), and verification is the CLI's ``verify_one`` against the pinned
root key. What is checked is the flow an executor sees: an order arrives, is judged
genuine *on the client*, the device reports receipt, and the person's tap reaches
the duty officer's status board.
"""

from __future__ import annotations

import contextlib
import pathlib
import time
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from alerting.clients.bundles import PinnedOrg
from alerting.clients.keystore import save_key
from alerting.clients.mobile.app import CSRF_HEADER, SESSION_LIFETIME_S, create_mobile
from alerting.core.clock import FixedClock
from alerting.core.signing import DOMAIN_ORDER, public_key_to_b64u, sign_payload
from alerting.orgkit import Org
from alerting.server.app import create_app
from alerting.server.config import Settings
from alerting.server.services.bootstrap import publish_org
from tests.integration.conftest import signer_for

PASSPHRASE = "demo"
MOBILE = {CSRF_HEADER: "1"}
WORDLIST = pathlib.Path("config/wordlist.ru.txt")


class InProcessSocket:
    """The server app's own WebSocket, behind the client's socket interface."""

    def __init__(self, client: TestClient, path: str) -> None:
        self._context = client.websocket_connect(path)
        self._socket = self._context.__enter__()

    def recv(self) -> str:
        return self._socket.receive_text()

    def send(self, text: str) -> None:
        self._socket.send_text(text)

    def close(self) -> None:
        # Called from the listener thread and from whoever ends the session; the
        # first call closes, later ones are no-ops.
        context, self._context = self._context, None
        if context is not None:
            with contextlib.suppress(Exception):
                context.__exit__(None, None, None)


class Monotonic:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def wait_for(condition: Callable[[], Any], timeout: float = 10.0) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = condition()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("condition not met in time")


@pytest.fixture
def homes(tmp_path: pathlib.Path, org: Org) -> pathlib.Path:
    root = tmp_path / "clients"
    for person in org.people.values():
        home = root / person.person_id
        save_key(person.person_id, person.private_key, PASSPHRASE, role=person.role, directory=home)
        PinnedOrg(org.org_id, public_key_to_b64u(org.root_public_key), home).save()
        (home / "wake_key.hex").write_text(person.wake_key.hex(), encoding="utf-8")
    return root


@pytest.fixture
def server(settings: Settings, clock: FixedClock, org: Org) -> Iterator[TestClient]:
    app = create_app(settings, clock, start_escalation=False)
    publish_org(app.state.alerting.repo, org, audit=app.state.alerting.audit)
    with TestClient(app) as client:
        yield client


@pytest.fixture
def monotonic() -> Monotonic:
    return Monotonic()


@pytest.fixture
def mobile_app(homes, server, clock, monotonic) -> Iterator[Any]:
    app = create_mobile(
        homes=homes,
        server_url="http://testserver",
        wordlist=WORDLIST,
        transport=server._transport,
        connector=lambda url: InProcessSocket(server, "/v1/stream"),
        clock=clock,
        monotonic=monotonic,
    )
    yield app
    # Before the server fixture tears down: its shutdown closes executor sockets,
    # and a listener still attached would race the portal it runs on.
    app.state.mobile.shutdown()


def phone(mobile_app: Any, person_id: str) -> TestClient:
    client = TestClient(mobile_app)
    response = client.post(
        "/api/login", json={"person_id": person_id, "passphrase": PASSPHRASE}, headers=MOBILE
    )
    assert response.status_code == 200, response.text
    wait_for(lambda: client.get("/api/inbox").json()["connected"])
    return client


def dispatch(server: TestClient, org: Org, clock: FixedClock, **overrides: Any) -> str:
    """Propose and sign as two real approvers, the way the panel or CLI would."""
    body = {
        "scenario": "EVAC.BUILDING",
        "severity": "critical",
        "drill": True,
        "audience": {"groups": ["fire-wardens"]},
        "text": "Задымление, 3 этаж",
    } | overrides
    server.auth = signer_for(org, "p-003", clock)
    proposal = server.post("/v1/proposals", json=body).json()
    for person_id in ("p-003", "p-001"):
        person = org.person(person_id)
        server.auth = signer_for(org, person_id, clock)
        server.post(
            f"/v1/proposals/{proposal['order_id']}/signatures",
            json={
                "key_id": person.key_id,
                "sig": sign_payload(DOMAIN_ORDER, proposal["payload"], person.private_key),
            },
        ).raise_for_status()
        if overrides.get("severity") in ("info", "warning"):  # one signature suffices
            break
    order_id: str = proposal["order_id"]
    return order_id


def status_of(server: TestClient, org: Org, clock: FixedClock, order_id: str) -> dict[str, Any]:
    server.auth = signer_for(org, "p-003", clock)
    result: dict[str, Any] = server.get(f"/v1/orders/{order_id}/status").json()
    return result


def test_an_order_arrives_verified_and_the_tap_reaches_the_duty_officer(
    mobile_app, server, org, clock
):
    executor = phone(mobile_app, "x-101")
    order_id = dispatch(server, org, clock)

    inbox = wait_for(lambda: executor.get("/api/inbox").json()["orders"])
    order = inbox[0]
    assert order["order_id"] == order_id
    assert order["accepted"] is True and order["reasons"] == []
    assert order["drill"] is True and order["scenario"] == "EVAC.BUILDING"
    assert order["description"]
    assert len(order["signers"]) == 2
    assert len(order["wake_words"]) == 3

    # The device reported receipt by itself; nobody has tapped yet.
    me = next(
        p for p in status_of(server, org, clock, order_id)["people"] if p["person_id"] == "x-101"
    )
    assert me["ack_status"] == "received" and me["ack_valid"] is True

    response = executor.post(
        f"/api/orders/{order_id}/ack", json={"status": "acknowledged"}, headers=MOBILE
    )
    assert response.status_code == 200, response.text
    status = status_of(server, org, clock, order_id)
    assert "x-101" not in status["outstanding"]
    assert executor.get("/api/inbox").json()["orders"][0]["my_ack"] == "acknowledged"


def test_cannot_comply_needs_a_reason(mobile_app, server, org, clock):
    executor = phone(mobile_app, "x-101")
    order_id = dispatch(server, org, clock)
    wait_for(lambda: executor.get("/api/inbox").json()["orders"])

    missing = executor.post(
        f"/api/orders/{order_id}/ack", json={"status": "cannot_comply"}, headers=MOBILE
    )
    assert missing.status_code == 422
    given = executor.post(
        f"/api/orders/{order_id}/ack",
        json={"status": "cannot_comply", "reason": "на больничном"},
        headers=MOBILE,
    )
    assert given.status_code == 200, given.text


def test_a_forged_order_is_shown_as_rejected_and_cannot_be_acknowledged(
    mobile_app, server, org, clock
):
    """What a compromised server could push down the socket: a well-formed order
    nobody authorised. The client judges it, not the server."""
    executor = phone(mobile_app, "x-101")
    order_id = dispatch(server, org, clock, scenario="TEST.PING", severity="info")
    genuine = wait_for(lambda: executor.get("/api/inbox").json()["orders"])[0]
    assert genuine["accepted"]

    mobile = mobile_app.state.mobile
    session = next(iter(mobile.sessions.values()))
    forged = dict(session.inbox[order_id].envelope)
    forged["payload"] = {
        **forged["payload"],
        "order_id": "00000000-0000-4000-8000-000000000000",
        "seq": forged["payload"]["seq"] + 1,
        "drill": False,
        "scenario": "EVAC.BUILDING",
        "severity": "critical",
    }
    item = mobile.receive(session, forged)
    assert item.accepted is False and item.reasons

    shown = next(
        o
        for o in executor.get("/api/inbox").json()["orders"]
        if o["order_id"] == forged["payload"]["order_id"]
    )
    assert shown["accepted"] is False
    refused = executor.post(
        f"/api/orders/{shown['order_id']}/ack", json={"status": "acknowledged"}, headers=MOBILE
    )
    assert refused.status_code == 409


def test_a_stand_down_marks_the_original_order(mobile_app, server, org, clock):
    executor = phone(mobile_app, "x-101")
    order_id = dispatch(server, org, clock, scenario="TEST.PING", severity="info")
    wait_for(lambda: executor.get("/api/inbox").json()["orders"])

    server.auth = signer_for(org, "p-003", clock)
    original = server.get(f"/v1/orders/{order_id}").json()["payload"]
    cancel = server.post(
        "/v1/proposals",
        json={
            "scenario": original["scenario"],
            "severity": original["severity"],
            "drill": original["drill"],
            "action": "STOP",
            "audience": original["audience"],
            "text": "Отбой",
            "cancels": order_id,
        },
    ).json()
    person = org.person("p-003")
    server.post(
        f"/v1/proposals/{cancel['order_id']}/signatures",
        json={
            "key_id": person.key_id,
            "sig": sign_payload(DOMAIN_ORDER, cancel["payload"], person.private_key),
        },
    ).raise_for_status()

    orders = wait_for(
        lambda: (o := executor.get("/api/inbox").json()["orders"]) and len(o) == 2 and o
    )
    by_id = {o["order_id"]: o for o in orders}
    assert by_id[cancel["order_id"]]["accepted"] is True
    assert by_id[order_id]["cancelled_by"] == cancel["order_id"]


def test_only_executors_log_in(mobile_app):
    client = TestClient(mobile_app)

    def login(person_id: str, passphrase: str = PASSPHRASE) -> int:
        return client.post(
            "/api/login", json={"person_id": person_id, "passphrase": passphrase}, headers=MOBILE
        ).status_code

    assert login("x-101", "wrong") == 401
    assert login("../x-101") == 400
    assert login("p-003") == 403
    assert login("a-001") == 403


def test_a_session_lasts_one_shift(mobile_app, monotonic):
    executor = phone(mobile_app, "x-101")
    monotonic.now += SESSION_LIFETIME_S + 1
    assert executor.get("/api/inbox").status_code == 401
    assert mobile_app.state.mobile.sessions == {}


def test_an_ack_needs_the_app_header(mobile_app, server, org, clock):
    executor = phone(mobile_app, "x-101")
    order_id = dispatch(server, org, clock)
    wait_for(lambda: executor.get("/api/inbox").json()["orders"])
    response = executor.post(f"/api/orders/{order_id}/ack", json={"status": "acknowledged"})
    assert response.status_code == 403


def test_receipt_is_reported_only_once_the_page_has_fetched_the_order(
    mobile_app, server, org, clock
):
    """The stream keeps running after the phone page is closed. A "received" sent
    then would tell the duty officer the handset got an alert it never showed."""
    phone(mobile_app, "x-101")
    session = next(iter(mobile_app.state.mobile.sessions.values()))
    order_id = dispatch(server, org, clock)
    wait_for(lambda: order_id in session.inbox)

    def mine() -> dict[str, Any]:
        people = status_of(server, org, clock, order_id)["people"]
        return next(p for p in people if p["person_id"] == "x-101")

    assert mine()["ack_status"] is None  # delivered to the client, not yet to a page

    page = TestClient(mobile_app)
    page.cookies.update({"alerting_mobile": next(iter(mobile_app.state.mobile.sessions))})
    page.get("/api/inbox")
    assert mine()["ack_status"] == "received"


def test_an_older_unanswered_order_stays_answerable(mobile_app, server, org, clock):
    executor = phone(mobile_app, "x-101")
    first = dispatch(server, org, clock, scenario="MUSTER", severity="warning")
    second = dispatch(server, org, clock, scenario="TEST.PING", severity="info")
    orders = wait_for(
        lambda: (o := executor.get("/api/inbox").json()["orders"]) and len(o) == 2 and o
    )
    assert [o["order_id"] for o in orders] == [second, first]  # newest first, by arrival

    response = executor.post(
        f"/api/orders/{first}/ack", json={"status": "acknowledged"}, headers=MOBILE
    )
    assert response.status_code == 200, response.text
    assert "x-101" not in status_of(server, org, clock, first)["outstanding"]
