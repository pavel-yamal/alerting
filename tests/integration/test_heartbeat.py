"""Channel heartbeats.

These did not exist while four documents described them as working, and the threat
model accepted suppression as a residual risk *on the grounds that heartbeats would
reveal it*. So the tests here are less about the mechanism than about the claim:
does a channel going quiet actually become visible, and does a channel with no
provider behind it stay honest about that?
"""

from __future__ import annotations

from typing import Any

import pytest

from alerting.core.audit_chain import Event
from alerting.server.channels.base import ProbeResult

pytestmark = pytest.mark.asyncio


class FakeSocket:
    """The minimum a ConnectionRegistry sink has to be."""

    def __init__(self) -> None:
        self.frames: list[dict[str, Any]] = []

    async def send_json(self, data: dict[str, Any]) -> None:
        self.frames.append(data)

    async def close(self, code: int) -> None:  # pragma: no cover - not exercised
        pass


def entries(services, event: Event) -> list[dict[str, Any]]:
    return [e for e in services.repo.audit_entries(0, 10_000) if e["event"] == str(event)]


# --- honesty ----------------------------------------------------------------


async def test_a_channel_with_no_provider_never_reports_healthy(services):
    """Same rule as delivery: never report health you do not have.

    Four of five adapters ship without a provider. If their heartbeat answered
    "fine", the duty officer's evidence that the channel is alive would be false --
    which is worse than having no heartbeat at all.
    """
    results = await services.heartbeat.tick()

    for name in ("push", "sms", "voice", "siren"):
        assert results[name].status == "stub"
        assert not results[name].ok

    health = services.heartbeat.health()
    assert [n for n in ("push", "sms", "voice", "siren") if health[n]["healthy"]] == []
    assert set(services.heartbeat.silent_channels()) >= {"push", "sms", "voice", "siren"}


async def test_the_websocket_channel_reports_what_it_can_actually_reach(services):
    """The one probe that measures something. Nobody connected means an order would
    reach nobody over this channel, which is exactly the silence to surface."""
    assert (await services.heartbeat.tick())["ws"].status == "failed"

    await services.connections.attach("x-101", FakeSocket())
    result = (await services.heartbeat.tick())["ws"]

    assert result.ok
    assert "1 device owner" in result.detail
    assert services.heartbeat.health()["ws"]["healthy"] is True


# --- what reaches the audit chain -------------------------------------------


async def test_a_channel_falling_silent_is_recorded_in_the_chain(services):
    socket = FakeSocket()
    await services.connections.attach("x-101", socket)
    await services.heartbeat.tick()
    assert entries(services, Event.CHANNEL_SILENT) == []

    await services.connections.detach("x-101", socket)
    await services.heartbeat.tick()

    silent = entries(services, Event.CHANNEL_SILENT)
    assert len(silent) == 1
    assert silent[0]["data"]["channel"] == "ws"
    assert silent[0]["data"]["node_id"] == services.heartbeat.node_id


async def test_a_channel_coming_back_is_recorded_too(services):
    socket = FakeSocket()
    await services.connections.attach("x-101", socket)
    await services.heartbeat.tick()
    await services.connections.detach("x-101", socket)
    await services.heartbeat.tick()
    await services.connections.attach("x-101", FakeSocket())
    await services.heartbeat.tick()

    assert len(entries(services, Event.CHANNEL_RECOVERED)) == 1


async def test_the_first_observation_is_not_audited(services):
    """A node restarting in a loop against a dead channel would otherwise write an
    entry per restart into a log that can never be pruned."""
    await services.heartbeat.tick()

    assert entries(services, Event.CHANNEL_SILENT) == []
    assert services.repo.heartbeat("ws", services.heartbeat.node_id) is not None


async def test_repeated_probes_do_not_flood_the_chain(services):
    """Probes are not audit events; transitions are. The chain is undeletable, and a
    probe a minute per channel per node would bury an incident under rows saying
    nothing happened."""
    before = services.repo.audit_count()
    for _ in range(20):
        await services.heartbeat.tick()

    assert services.repo.audit_count() == before, "a probe reached the audit chain"


# --- staleness and folding ---------------------------------------------------


async def test_a_record_that_stopped_being_updated_is_not_healthy(services, clock):
    """Worse than a dead channel: the heartbeat itself stopped, so silence no longer
    means anything."""
    await services.connections.attach("x-101", FakeSocket())
    await services.heartbeat.tick()
    assert services.heartbeat.health()["ws"]["healthy"] is True

    clock.advance(services.heartbeat.stale_after_s + 1)
    health = services.heartbeat.health()

    assert health["ws"]["healthy"] is False
    assert health["ws"]["stale"] is True


async def test_health_folds_across_nodes(services, clock):
    """A shared provider reachable from any node is reachable. So is the WebSocket
    channel: an executor connected to any node means that path works."""
    services.repo.record_heartbeat("sms", "node-a", "failed", "timeout", clock.now())
    services.repo.record_heartbeat("sms", "node-b", "ok", "provider answered", clock.now())

    health = services.heartbeat.health()
    assert health["sms"]["healthy"] is True
    assert health["sms"]["nodes"]["node-a"]["status"] == "failed"
    assert health["sms"]["nodes"]["node-b"]["status"] == "ok"


async def test_a_configured_channel_that_was_never_probed_shows_up(services):
    """Absent from the table must not mean absent from the answer: "no heartbeat at
    all" is itself worth seeing."""
    health = services.heartbeat.health()

    assert set(health) == set(services.channels.names())
    assert all(not entry["healthy"] for entry in health.values())


async def test_a_probe_that_raises_is_the_answer_not_a_crash(services, monkeypatch):
    async def explode() -> ProbeResult:
        raise RuntimeError("provider SDK blew up")

    monkeypatch.setattr(services.channels["sms"], "probe", explode)
    results = await services.heartbeat.tick()

    assert results["sms"].status == "failed"
    assert "RuntimeError" in results["sms"].detail
    assert results["push"].status == "stub", "one bad probe stopped the others"


# --- what heartbeats must NOT do --------------------------------------------


async def test_a_dead_channel_does_not_make_the_node_unready(client):
    """Readiness decides whether a balancer sends traffic here. A dead SMS provider
    is not this node's fault and is rarely specific to it; pulling the node out of
    rotation over it would take a working WebSocket path out with it."""
    response = client.get("/v1/readyz")

    assert response.status_code == 200
    assert response.json()["ready"] is True
    assert "channels" not in response.json()["checks"]


async def test_the_health_view_is_behind_the_api_key(anon_client):
    """The list of channels that are not watching right now is a gift to anybody
    planning to suppress one."""
    assert anon_client.get("/v1/channels/health").status_code == 401


async def test_the_health_view_reports_the_silent_channels(client):
    body = client.get("/v1/channels/health").json()

    assert set(body["channels"]) == {"push", "siren", "sms", "voice", "ws"}
    assert set(body["silent"]) == {"push", "siren", "sms", "voice", "ws"}
    assert body["stale_after_s"] > 0
