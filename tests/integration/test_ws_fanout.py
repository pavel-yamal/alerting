"""WebSocket delivery when the socket and the dispatch are in different processes.

Two complete server apps on one database stand in for two worker processes (or two
nodes): each has its own event loop, its own socket registry and its own LISTEN
connection, exactly as uvicorn's workers do. This is the case that used to record
``ws:failed`` for a phone that was connected to the other process.
"""

from __future__ import annotations

import dataclasses
import time
from collections.abc import Iterator
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient

from alerting.core.clock import FixedClock
from alerting.orgkit import Org
from alerting.server.app import create_app
from alerting.server.config import Settings
from alerting.server.services.bootstrap import publish_org
from tests.integration.conftest import signer_for
from tests.integration.test_e2e_ws import connect_executor, propose, sign


def wait_until(condition: Any, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.02)
    raise AssertionError("condition not met in time")


def node(settings: Settings, clock: FixedClock, node_id: str) -> TestClient:
    app = create_app(dataclasses.replace(settings, node_id=node_id), clock, start_escalation=False)
    return TestClient(app)


@pytest.fixture
def two_nodes(settings: Settings, clock: FixedClock, org: Org) -> Iterator[tuple[Any, Any]]:
    with node(settings, clock, "app-1") as one, node(settings, clock, "app-2") as two:
        publish_org(one.app.state.alerting.repo, org, audit=one.app.state.alerting.audit)
        for client in (one, two):
            client.portal.call(client.app.state.alerting.fanout.wait_listening)
        yield one, two


def dispatch_from(client: TestClient, org: Org, clock: FixedClock, **overrides: Any) -> str:
    """Propose and collect the quorum on ``client``: the dispatch runs in its process."""
    client.auth = signer_for(org, "p-001", clock)
    proposal = propose(client, drill=True, **overrides)
    sign(client, proposal, org.person("p-001"))
    client.auth = signer_for(org, "p-002", clock)
    result = sign(client, proposal, org.person("p-002"))
    assert result["dispatched"], result
    order_id: str = proposal["order_id"]
    return order_id


def ws_attempts(client: TestClient, org: Org, clock: FixedClock, order_id: str, person: str):
    client.auth = signer_for(org, "p-001", clock)
    status = client.get(f"/v1/orders/{order_id}/status").json()
    me = next(p for p in status["people"] if p["person_id"] == person)
    return [c for c in me["channels_attempted"] if c.startswith("ws:")]


def test_an_order_reaches_a_socket_held_by_another_process(two_nodes, org, clock):
    one, two = two_nodes
    socket = connect_executor(one, org, "x-101", clock.now())
    try:
        wait_until(lambda: two.app.state.alerting.fanout.connected_anywhere()[0] == 1)
        order_id = dispatch_from(two, org, clock)

        # Checked before reading the socket: without the hand-off nothing arrives,
        # and a blocking read would hang the test instead of failing it.
        assert ws_attempts(two, org, clock, order_id, "x-101") == ["ws:sent"]
        frame = socket.receive_json()
        assert frame["kind"] == "order"
        assert frame["envelope"]["payload"]["order_id"] == order_id

        repo = two.app.state.alerting.repo
        dispatch = next(
            d
            for d in repo.dispatches(order_id)
            if d["person_id"] == "x-101" and d["channel"] == "ws"
        )
        assert "via app-1:" in dispatch["detail"]
    finally:
        # An open test socket at teardown deadlocks the server's shutdown.
        socket.__exit__(None, None, None)


def test_nobody_connected_anywhere_is_still_failed_and_fast(two_nodes, org, clock):
    """No presence anywhere: no hand-off, no waiting, and no pretend delivery."""
    _, two = two_nodes
    started = time.monotonic()
    order_id = dispatch_from(two, org, clock)
    assert time.monotonic() - started < 1.5
    assert ws_attempts(two, org, clock, order_id, "x-101") == ["ws:failed"]


def test_an_unconfirmed_hand_off_is_failed_not_sent(two_nodes, org, clock):
    """A process that says it holds the socket but never answers -- hung, or its
    listener down -- must not turn into delivery on the duty officer's board."""
    _, two = two_nodes
    repo = two.app.state.alerting.repo
    repo.set_presence("ghost:000000", "x-101", 1, clock.now())
    two.app.state.alerting.fanout.relay_timeout = 0.3

    order_id = dispatch_from(two, org, clock)
    assert ws_attempts(two, org, clock, order_id, "x-101") == ["ws:failed"]
    detail = next(
        d["detail"]
        for d in repo.dispatches(order_id)
        if d["person_id"] == "x-101" and d["channel"] == "ws"
    )
    assert "did not confirm" in detail


def test_presence_follows_the_socket(two_nodes, org, clock):
    one, two = two_nodes
    fanout = two.app.state.alerting.fanout
    socket = connect_executor(one, org, "x-102", clock.now())
    wait_until(lambda: fanout.connected_anywhere() == (1, 1))
    socket.__exit__(None, None, None)
    wait_until(lambda: fanout.connected_anywhere() == (0, 0))


def test_a_stopping_process_withdraws_its_presence(settings, clock, org):
    """A process that shuts down (or restarts for a deploy) must not leave others
    handing it orders it can no longer deliver."""
    with node(settings, clock, "app-1") as one:
        fanout = one.app.state.alerting.fanout
        one.portal.call(fanout.wait_listening)
        # As if a device were attached; a real socket would be closed by shutdown
        # first, which detaches it and hides what this test is about.
        fanout.presence_changed("x-101", 1)
        assert fanout.connected_anywhere() == (1, 1)
    # The app's own pool is closed by now; ask the database directly.
    with psycopg.connect(settings.dsn) as connection:
        left = connection.execute("SELECT COUNT(*) FROM ws_presence").fetchone()
    assert left == (0,)


def test_every_device_gets_it_when_they_are_on_different_processes(two_nodes, org, clock):
    """A phone on one process and a tablet on the other: a local delivery must not
    stop the hand-off, or the second device never hears about the order."""
    one, two = two_nodes
    here = connect_executor(two, org, "x-101", clock.now())
    there = connect_executor(one, org, "x-101", clock.now())
    try:
        wait_until(lambda: two.app.state.alerting.fanout.connected_anywhere() == (1, 2))
        order_id = dispatch_from(two, org, clock)

        assert ws_attempts(two, org, clock, order_id, "x-101") == ["ws:sent"]
        for socket in (here, there):
            assert socket.receive_json()["envelope"]["payload"]["order_id"] == order_id
        detail = next(
            d["detail"]
            for d in two.app.state.alerting.repo.dispatches(order_id)
            if d["person_id"] == "x-101" and d["channel"] == "ws"
        )
        assert detail.startswith("1 device(s) here, 1 device(s) via app-1:")
    finally:
        for socket in (here, there):
            socket.__exit__(None, None, None)


def test_a_silent_process_is_waited_for_once_not_per_recipient(two_nodes, org, clock):
    """A crashed process still listed for many people would otherwise cost the full
    timeout for each of them, delaying every channel after ws."""
    _, two = two_nodes
    repo = two.app.state.alerting.repo
    for person in ("x-101", "x-102"):
        repo.set_presence("ghost:000000", person, 1, clock.now())
    two.app.state.alerting.fanout.relay_timeout = 0.5

    started = time.monotonic()
    order_id = dispatch_from(two, org, clock)
    elapsed = time.monotonic() - started

    assert elapsed < 0.95, f"waited {elapsed:.2f}s: once per recipient, not once in all"
    for person in ("x-101", "x-102"):
        assert ws_attempts(two, org, clock, order_id, person) == ["ws:failed"]


def test_housekeeping_restores_presence_a_failed_write_lost(two_nodes, org, clock):
    one, _ = two_nodes
    fanout = one.app.state.alerting.fanout
    socket = connect_executor(one, org, "x-102", clock.now())
    try:
        wait_until(lambda: fanout.connected_anywhere() == (1, 1))
        # As if the write on attach had failed.
        one.app.state.alerting.repo.clear_presence(fanout.process_id)
        assert fanout.connected_anywhere() == (0, 0)
        fanout._housekeeping()
        assert fanout.connected_anywhere() == (1, 1)
    finally:
        socket.__exit__(None, None, None)
