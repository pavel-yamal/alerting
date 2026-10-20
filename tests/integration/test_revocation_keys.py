"""The fast revocation path, through the server: a revocation key, not the root.

The duty shift holds the revocation key; the root names it in the directory. A list it
signs is verified by the server exactly as by a device, takes effect on the next
request, and can only ever add revocations.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from alerting import orgadmin
from alerting.clients.bundles import PinnedOrg
from alerting.clients.keystore import save_key
from alerting.clients.transport import Api
from alerting.core.audit_chain import Event
from alerting.core.clock import FixedClock
from alerting.core.directory import Directory
from alerting.core.signing import (
    DOMAIN_DIRECTORY,
    DOMAIN_REVOCATIONS,
    generate_keypair,
    key_id,
    public_key_to_b64u,
    sign_payload,
)
from alerting.orgadmin import add_revoker, next_revocations, remove_revoker, verified_current
from alerting.orgkit import Org, sign_bundle
from tests.integration.conftest import signer_for, signing_client
from tests.integration.test_e2e_ws import connect_executor
from tests.integration.test_enrollment import chain, publish
from tests.integration.test_events import dispatch

pytestmark = pytest.mark.asyncio


@pytest.fixture
def client(settings, clock: FixedClock, org: Org):
    with signing_client(settings, clock, org, "p-003") as test_client:
        yield test_client


@pytest.fixture
def revoker(client, org, clock):
    """Name a revocation key in directory v2 and return its private half."""
    private, public = generate_keypair()
    current = verified_current(
        client.get("/v1/directory").json(), public_key_to_b64u(org.root_public_key)
    )
    payload, _ = add_revoker(
        current, public_key=public_key_to_b64u(public), label="смена", issued_at=clock.now()
    )
    publish(client, org, payload)
    return private


def effective(client: TestClient, org: Org) -> Directory:
    return Directory.load(
        client.get("/v1/directory").json(), root_public_key=org.root_public_key,
        org_id=org.org_id,
    ).with_revocations(client.get("/v1/revocations").json() or None)  # fmt: skip


def signed_list(client, org, private, *, person: str, at: int) -> dict[str, Any]:
    latest = client.get("/v1/revocations").json() or None
    payload, _ = next_revocations(
        effective(client, org), latest, signer=key_id(private.public_key()),
        person_id=person, kid=None, at=at, reason="утерян",
    )  # fmt: skip
    raw = payload.to_payload()
    return {"payload": raw, "signature": sign_payload(DOMAIN_REVOCATIONS, raw, private)}


async def test_a_revocation_key_cuts_a_device_off_at_once(client, org, clock, revoker):
    assert client.get("/v1/revocations").json() == {}
    evac = await dispatch(client, org, clock, scenario="EVAC.BUILDING", ttl_s=120, seq=1)
    lost = signer_for(org, "p-002", clock)
    assert client.get("/v1/directory", auth=lost).status_code == 200

    listed = signed_list(client, org, revoker, person="p-002", at=clock.now())
    response = client.post("/v1/bundles", json={"bundle": listed})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["kind"] == "revocations" and result["version"] == 1
    assert evac.order_id in result["invalidated"][0], "the event it co-signed is reported"

    refused = client.get("/v1/directory", auth=lost)
    assert refused.status_code == 403
    assert refused.json()["detail"]["error"] == "unknown or revoked key"
    entry = chain(client, Event.KEY_REVOKED)[-1]
    assert entry["person_id"] == "p-002"
    assert entry["revoked_with"] == key_id(revoker.public_key())
    assert entry["published_by"] == "p-003"


async def test_the_server_checks_the_list_like_a_device(client, org, clock, revoker):
    listed = signed_list(client, org, revoker, person="x-101", at=clock.now())

    stranger, _ = generate_keypair()
    forged = {**listed, "signature": sign_payload(DOMAIN_REVOCATIONS, listed["payload"], stranger)}
    assert client.post("/v1/bundles", json={"bundle": forged}).status_code == 409

    unnamed = dict(listed["payload"], signer=key_id(stranger.public_key()))
    by_stranger = {
        "payload": unnamed,
        "signature": sign_payload(DOMAIN_REVOCATIONS, unnamed, stranger),
    }
    assert client.post("/v1/bundles", json={"bundle": by_stranger}).status_code == 409

    assert client.post("/v1/bundles", json={"bundle": listed}).status_code == 200
    again = client.post("/v1/bundles", json={"bundle": listed})
    assert again.status_code == 409, "the same version twice is a rollback attempt"

    dropped = dict(listed["payload"], version=2, entries=[])
    shrunk = {"payload": dropped, "signature": sign_payload(DOMAIN_REVOCATIONS, dropped, revoker)}
    response = client.post("/v1/bundles", json={"bundle": shrunk})
    assert response.status_code == 409 and "revocations_dropped_entries" in response.text


async def test_executors_cannot_publish_a_list(client, executor_client, org, clock, revoker):
    listed = signed_list(client, org, revoker, person="x-102", at=clock.now())
    assert executor_client.post("/v1/bundles", json={"bundle": listed}).status_code == 403


async def test_an_open_socket_closes_on_a_fast_revocation(client, org, clock, revoker, monkeypatch):
    from starlette.websockets import WebSocketDisconnect

    from alerting.server.api import ws

    monkeypatch.setattr(ws, "KEY_RECHECK_S", 0.05)
    socket = connect_executor(client, org, "x-101", clock.now())
    try:
        listed = signed_list(client, org, revoker, person="x-101", at=clock.now())
        assert client.post("/v1/bundles", json={"bundle": listed}).status_code == 200
        with pytest.raises(WebSocketDisconnect) as closed:
            while True:
                socket.receive_json()
        assert closed.value.code == 4403
    finally:
        socket.__exit__(None, None, None)


async def test_the_root_dropping_a_stolen_revocation_key_ends_its_list(client, org, clock, revoker):
    listed = signed_list(client, org, revoker, person="x-101", at=clock.now())
    assert client.post("/v1/bundles", json={"bundle": listed}).status_code == 200
    victim = signer_for(org, "x-101", clock)
    assert client.get("/v1/directory", auth=victim).status_code == 403

    current = verified_current(
        client.get("/v1/directory").json(), public_key_to_b64u(org.root_public_key)
    )
    payload, _ = remove_revoker(
        current, kid=key_id(revoker.public_key()), absorb=None, issued_at=clock.now()
    )
    publish(client, org, payload)
    assert client.get("/v1/directory", auth=victim).status_code == 200
    assert chain(client, Event.DIRECTORY_PUBLISHED)[-1]["revokers"] == []


async def test_revoke_now_from_the_duty_desk(
    client, org, clock, revoker, tmp_path, monkeypatch, capsys
):
    """`alerting-org revoke-now`, end to end against the real app."""
    home = tmp_path / "p-003"
    PinnedOrg(org.org_id, public_key_to_b64u(org.root_public_key), home).save()
    save_key("revoker", revoker, "смена", role="revoker", directory=tmp_path / "revoker")

    def api(args: Any) -> Api:
        return Api(
            "http://testserver", auth=signer_for(org, "p-003", clock), transport=client._transport
        )

    monkeypatch.setattr(orgadmin, "_api", api)
    code = orgadmin.main([
        "revoke-now", "--for", "x-102", "--reason", "утерян телефон",
        "--server", "http://testserver", "--person", "p-003", "--home", str(home),
        "--passphrase", "x", "--revoker-home", str(tmp_path / "revoker"),
        "--revoker-passphrase", "смена",
    ])  # fmt: skip
    assert code == 0, capsys.readouterr()
    assert "REVOKED x-102" in capsys.readouterr().out
    assert client.get("/v1/directory", auth=signer_for(org, "x-102", clock)).status_code == 403

    wrong = orgadmin.main([
        "revoke-now", "--for", "x-103", "--reason", "r", "--person", "p-003",
        "--home", str(home), "--passphrase", "x", "--revoker-home", str(tmp_path / "revoker"),
        "--revoker-passphrase", "не тот",
    ])  # fmt: skip
    assert wrong == 2


async def test_only_the_root_can_name_a_revocation_key(client, org, clock):
    """A revocation key in a directory the root did not sign never reaches anyone."""
    private, public = generate_keypair()
    current = verified_current(
        client.get("/v1/directory").json(), public_key_to_b64u(org.root_public_key)
    )
    payload, _ = add_revoker(
        current, public_key=public_key_to_b64u(public), label="x", issued_at=clock.now()
    )
    forged = sign_bundle(payload, DOMAIN_DIRECTORY, private)
    assert client.post("/v1/bundles", json={"bundle": forged}).status_code == 409


async def test_concurrent_publications_cannot_overwrite_each_other(client, org, clock, revoker):
    """Both built on version N; only the first may land, the second is told to retry."""
    first = signed_list(client, org, revoker, person="x-101", at=clock.now())
    second = signed_list(client, org, revoker, person="x-102", at=clock.now())
    assert first["payload"]["version"] == second["payload"]["version"] == 1

    repo = client.app.state.alerting.repo
    assert repo.put_bundle_if_latest("revocations", 1, first, clock.now(), expected_latest=0)
    assert not repo.put_bundle_if_latest("revocations", 1, second, clock.now(), expected_latest=0)
    stale = dict(second["payload"], version=2)
    assert not repo.put_bundle_if_latest(
        "revocations", 2, {"payload": stale}, clock.now(), expected_latest=0
    ), "built on N=0 while N is now 1: refused even with a fresh version number"
    assert client.get("/v1/revocations").json() == first
