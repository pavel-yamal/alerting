"""The HTTP surface must not stand open.

Before this gate, anyone who could reach the port could write **permanently
undeletable** audit entries with an attacker-chosen `created_by`, burn `seq` numbers
on the primary stream, dump the roster and read the whole chain. This is an interim
shared key — signed requests keyed to each person's device replace it — so the tests
assert the gate holds, not that it identifies anybody.
"""

from __future__ import annotations

import pytest

from alerting.server.app import AppServices, create_app

pytestmark = pytest.mark.asyncio

WRITE_ROUTES = [
    ("post", "/v1/proposals"),
    ("post", "/v1/acks"),
    ("post", "/v1/audit/head"),
]
READ_ROUTES = [
    ("get", "/v1/audit"),
    ("get", "/v1/roster"),
    ("get", "/v1/orders"),
    ("get", "/v1/directory"),
    ("get", "/v1/policy"),
    ("get", "/v1/statusz"),
]


def call(test_client, method: str, path: str, **kwargs):
    """GET takes no body; POST needs one to get past request parsing."""
    if method == "post":
        kwargs.setdefault("json", {})
    return getattr(test_client, method)(path, **kwargs)


@pytest.mark.parametrize(("method", "path"), WRITE_ROUTES + READ_ROUTES)
async def test_every_route_rejects_a_request_without_the_key(anon_client, method, path):
    response = call(anon_client, method, path)
    assert response.status_code == 401, f"{method.upper()} {path} is open"
    assert "Alerting-Api-Key" in response.text


@pytest.mark.parametrize(("method", "path"), WRITE_ROUTES + READ_ROUTES)
async def test_a_wrong_key_is_rejected(anon_client, method, path):
    response = call(anon_client, method, path, headers={"Alerting-Api-Key": "not-the-key"})
    assert response.status_code == 401


async def test_the_unauthenticated_write_that_mattered_most(anon_client):
    """An audit entry can never be deleted, so an open write endpoint means permanent
    attacker-chosen content in the evidence record."""
    before = anon_client.app.state.alerting.repo.audit_count()
    response = anon_client.post(
        "/v1/proposals",
        json={
            "scenario": "EVAC.BUILDING",
            "severity": "critical",
            "drill": False,
            "audience": {"groups": ["fire-wardens"]},
            "created_by": "attacker",
        },
    )
    assert response.status_code == 401
    assert anon_client.app.state.alerting.repo.audit_count() == before


async def test_liveness_stays_open_for_the_load_balancer(anon_client):
    response = anon_client.get("/v1/healthz")
    assert response.status_code == 200
    assert response.json() == {"ok": True}


async def test_liveness_no_longer_leaks_the_connected_roster(anon_client):
    """It used to return the list of currently connected people to anyone."""
    assert set(anon_client.get("/v1/healthz").json()) == {"ok"}


async def test_statusz_carries_the_detail_and_needs_the_key(client):
    body = client.get("/v1/statusz").json()
    assert "connected" in body
    assert body["channels"]["ws"]["delivers"] is True
    assert body["channels"]["sms"]["delivers"] is False


async def test_a_node_refuses_to_start_without_a_key(settings, clock, tmp_path):
    settings.db_path = str(tmp_path / "nokey.db")
    settings.api_key_file = ""
    settings.allow_unauthenticated = False

    with pytest.raises(RuntimeError, match="ALERTING_API_KEY_FILE"):
        AppServices(settings, clock)


async def test_an_open_surface_must_be_asked_for_explicitly(settings, clock, tmp_path, caplog):
    import logging

    settings.db_path = str(tmp_path / "open.db")
    settings.api_key_file = ""
    settings.allow_unauthenticated = True
    caplog.set_level(logging.WARNING, logger="alerting.server")

    services = AppServices(settings, clock)
    try:
        assert "UNAUTHENTICATED" in caplog.text
    finally:
        services.close()


async def test_a_world_readable_key_file_is_refused(settings, clock, tmp_path, api_key_file):
    """A secret every local user can read is not a secret, and using it anyway is how
    a deployment believes in protection it does not have."""
    api_key_file.chmod(0o644)
    settings.db_path = str(tmp_path / "loose.db")

    with pytest.raises(PermissionError, match="readable by group or others"):
        AppServices(settings, clock)


async def test_paged_listings_are_bounded(client):
    """`?limit=999999999` was a one-request memory-exhaustion primitive."""
    assert client.get("/v1/audit", params={"limit": 999_999_999}).status_code == 422
    assert client.get("/v1/orders", params={"limit": 999_999_999}).status_code == 422
    assert client.get("/v1/audit", params={"limit": 1000}).status_code == 200


async def test_publishing_a_head_does_not_walk_the_whole_chain(client, monkeypatch):
    """It used to call audit_entries(0, 1_000_000) on every request."""
    repo = client.app.state.alerting.repo
    original = repo.audit_entries

    def explode(*args, **kwargs):
        raise AssertionError("publish_head must not load the chain")

    monkeypatch.setattr(repo, "audit_entries", explode)
    try:
        response = client.post("/v1/audit/head")
    finally:
        monkeypatch.setattr(repo, "audit_entries", original)

    assert response.status_code == 200
    assert response.json()["payload"]["head"]


async def test_the_app_still_serves_normally_with_the_key(client):
    assert client.get("/v1/policy").status_code == 200
    assert client.get("/v1/roster").status_code == 200
    assert create_app is not None
