"""Shutdown order, and readiness as distinct from liveness.

The old lifespan closed the database while socket handlers were still running, so an
ACK arriving during shutdown reached a closed sqlite connection. And a node started
with the wrong configuration created an empty database, answered `healthz: ok` — the
check only counted audit rows, which succeeds on an empty table — and could not
dispatch anything, which a load balancer had no way to see.
"""

from __future__ import annotations

import asyncio
import contextlib

import pytest

from alerting.server.app import AppServices
from alerting.server.channels.websocket import WS_SERVICE_RESTART, ConnectionRegistry
from alerting.server.services.bootstrap import publish_org

pytestmark = pytest.mark.asyncio


class RecordingSink:
    def __init__(self) -> None:
        self.frames: list[dict] = []
        self.closed_with: int | None = None

    async def send_json(self, data: dict) -> None:
        self.frames.append(data)

    async def close(self, code: int) -> None:
        self.closed_with = code


# --- connection registry ---------------------------------------------------


async def test_close_all_closes_every_socket_with_the_restart_code():
    """1012 tells a client to reconnect immediately rather than backing off — which
    matters when the thing reconnecting is an executor's alert stream."""
    registry = ConnectionRegistry()
    sinks = [RecordingSink() for _ in range(3)]
    assert await registry.attach("x-101", sinks[0])
    assert await registry.attach("x-101", sinks[1])
    assert await registry.attach("x-102", sinks[2])

    assert await registry.close_all() == 3
    assert all(sink.closed_with == WS_SERVICE_RESTART for sink in sinks)
    assert registry.connected_people() == []


async def test_close_all_survives_a_socket_that_fails_to_close():
    class Broken(RecordingSink):
        async def close(self, code: int) -> None:
            raise RuntimeError("already gone")

    registry = ConnectionRegistry()
    good = RecordingSink()
    await registry.attach("x-101", Broken())
    await registry.attach("x-102", good)

    assert await registry.close_all() == 1
    assert good.closed_with == WS_SERVICE_RESTART


async def test_the_device_cap_is_enforced():
    registry = ConnectionRegistry(max_devices_per_person=2)
    assert await registry.attach("x-101", RecordingSink())
    assert await registry.attach("x-101", RecordingSink())
    assert await registry.attach("x-101", RecordingSink()) is False


# --- shutdown ordering -----------------------------------------------------


async def test_sockets_close_before_the_database(settings, clock, org, tmp_path):
    """The ordering bug: a handler still running would find a closed connection."""
    settings.db_path = str(tmp_path / "order.db")
    services = AppServices(settings, clock)
    publish_org(services.repo, org, audit=services.audit)

    events: list[str] = []
    sink = RecordingSink()

    async def close(code: int) -> None:
        # The database must still answer at this point.
        services.repo.audit_count()
        events.append("sockets")

    sink.close = close  # type: ignore[method-assign]
    await services.connections.attach("x-101", sink)

    # sqlite3.Connection.close is read-only, so the probe goes on the wrapper.
    original_close = services.close

    def wrapper_close() -> None:
        events.append("database")
        original_close()

    services.close = wrapper_close  # type: ignore[method-assign]

    await services.aclose()
    assert events == ["sockets", "database"]


async def test_a_final_audit_head_is_published_on_the_way_out(settings, clock, org, tmp_path):
    """Without it, everything since the last hourly head stays unpublished until the
    process runs again — and an unpublished head is the window in which a rewritten
    tail cannot be detected."""
    settings.db_path = str(tmp_path / "head.db")
    services = AppServices(settings, clock)
    publish_org(services.repo, org, audit=services.audit)

    tip = services.repo.chain_tip()
    assert tip is not None
    services.db.execute("DELETE FROM audit_heads")

    await services.aclose()

    reopened = AppServices(settings, clock)
    try:
        latest = reopened.repo.latest_head()
        assert latest is not None
        assert latest["idx"] == tip[0]
        assert latest["head"] == tip[1]
    finally:
        reopened.close()


async def test_escalation_is_asked_to_stop_rather_than_cancelled(settings, clock, org, tmp_path):
    """A hard cancel abandons a tick mid-fan-out with the rung already claimed, so no
    later tick retries it."""
    settings.db_path = str(tmp_path / "drain.db")
    services = AppServices(settings, clock)
    publish_org(services.repo, org, audit=services.audit)

    ticks = 0
    finished = 0

    async def slow_tick() -> int:
        nonlocal ticks, finished
        ticks += 1
        await asyncio.sleep(0.05)
        finished += 1
        return 0

    services.escalation.tick = slow_tick  # type: ignore[method-assign]
    services.escalation.start(interval=0.01)
    await asyncio.sleep(0.03)
    assert services.escalation.is_running()

    await services.aclose()
    assert ticks == finished, "an in-flight tick was abandoned"
    assert not services.escalation.is_running()


# --- readiness -------------------------------------------------------------


async def test_a_wired_node_reports_ready(client):
    response = client.get("/v1/readyz")
    assert response.status_code == 200
    body = response.json()
    assert body["ready"] is True
    assert body["checks"] == {
        "database": True,
        "directory": True,
        "policy": True,
        "wordlist": True,
        "escalation": True,
    }


async def test_an_empty_database_is_live_but_not_ready(settings, clock, tmp_path):
    """The exact shape of a misconfigured node: it answers healthz and cannot
    dispatch. A balancer must not send alerts to it."""
    from fastapi.testclient import TestClient

    from alerting.server.app import create_app
    from tests.integration.conftest import API_KEY

    settings.db_path = str(tmp_path / "empty.db")
    app = create_app(settings, clock, start_escalation=False)
    with TestClient(app, headers={"Alerting-Api-Key": API_KEY}) as test_client:
        assert test_client.get("/v1/healthz").json() == {"ok": True}

        response = test_client.get("/v1/readyz")
        assert response.status_code == 503
        body = response.json()
        assert body["ready"] is False
        assert body["checks"]["database"] is True
        assert body["checks"]["directory"] is False, "no bundle published"
        assert body["checks"]["policy"] is False


async def test_a_worker_that_was_never_started_is_not_unready(client):
    """A node can legitimately not be the one climbing the ladder — the test client
    today, and every non-leader once escalation is leader-elected."""
    services = client.app.state.alerting
    assert not services.escalation.is_running()
    assert services.escalation.is_healthy()
    assert client.get("/v1/readyz").json()["checks"]["escalation"] is True


async def test_readiness_notices_a_worker_that_started_and_died(client):
    """A node whose worker died still serves and still records orders, but nothing
    escalates — so nobody is notified when an order goes unacknowledged."""
    services = client.app.state.alerting
    services.escalation.start(interval=0.01)
    await asyncio.sleep(0.02)
    assert services.escalation.is_healthy()

    # Kill the task the way a lost event loop would, bypassing stop() — which is the
    # difference between "this node does not escalate" and "this node should be
    # escalating and is not".
    services.escalation._task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await services.escalation._task

    assert not services.escalation.is_healthy()
    response = client.get("/v1/readyz")
    assert response.status_code == 503
    assert response.json()["checks"]["escalation"] is False


async def test_readiness_is_reachable_without_the_api_key(anon_client):
    """The load balancer has no key."""
    assert anon_client.get("/v1/readyz").status_code in {200, 503}
