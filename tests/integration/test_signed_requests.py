"""Per-person signed requests: the gate, the replay window, and the role table.

What this replaces was a single shared secret. It closed the door but could not say
who came through it, could not be revoked for one person, and -- the part that
mattered most -- left ``created_by`` on a proposal as a string the client asserted
about itself, written straight into an undeletable audit chain.
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest
from fastapi.testclient import TestClient

from alerting.core.audit_chain import Event
from alerting.core.clock import FixedClock
from alerting.core.directory import DirectoryPayload, Revocation
from alerting.core.http_auth import HEADERS, SIGNATURE_HEADER, TIMESTAMP_HEADER
from alerting.core.signing import DOMAIN_DIRECTORY, DOMAIN_ORDER, sign_payload
from alerting.server.app import create_app
from alerting.server.auth import ROUTE_ROLES
from alerting.server.services.bootstrap import publish_org
from tests.integration.conftest import signer_for, signing_client

pytestmark = pytest.mark.asyncio

#: Reachable without a signature, by design, and restricted by IP in nginx instead.
#: Metrics are here only because they are aggregates: no person_id, no name, no phone
#: number, no roster. `test_metrics.py` holds that to account.
PUBLIC_PATHS = {"/v1/healthz", "/v1/readyz", "/v1/metricsz"}


def guarded_routes(app: Any) -> list[tuple[str, str]]:
    """Every HTTP route that is supposed to be behind the gate, from the app itself.

    Enumerated rather than listed by hand: the old test hard-coded nine routes while
    the server served fifteen, so six were never checked at all. A list written once
    is a list that stops being true.

    Read from the OpenAPI schema rather than by walking ``app.routes``: this FastAPI
    keeps included routers wrapped rather than flattened, so the obvious traversal
    finds nothing at all -- and a test that enumerates nothing passes.
    """
    found = []
    for path, operations in app.openapi()["paths"].items():
        if not path.startswith("/v1/") or path in PUBLIC_PATHS:
            continue
        for method in operations:
            if method.upper() not in {"HEAD", "OPTIONS"}:
                found.append((method.upper(), path))
    return sorted(found)


def sign_once(client: TestClient, method: str, url: str, **kwargs: Any) -> dict[str, str]:
    """Build a request, sign it, and hand back the headers to replay or tamper with.

    Returned lower-cased on purpose. ``dict(request.headers)`` lower-cases keys, so a
    test that then overrode ``"Alerting-Signature"`` would *add* a second header
    rather than replace the first -- and the server, matching case-insensitively,
    would read the untampered one and answer 200. That is a test proving nothing,
    and it is exactly what the first draft of this file did.
    """
    request = client.build_request(method, url, **kwargs)
    signed = next(client.auth.auth_flow(request))
    return {name.lower(): value for name, value in signed.headers.items()}


def call(client: TestClient, method: str, path: str) -> Any:
    concrete = path.replace("{order_id}", "00000000-0000-0000-0000-000000000000")
    return client.request(method, concrete, json={} if method == "POST" else None)


# --- the gate ----------------------------------------------------------------


async def test_every_guarded_route_refuses_an_unsigned_request(anon_client):
    routes = guarded_routes(anon_client.app)
    assert len(routes) >= 15, "route enumeration found suspiciously little"

    for method, path in routes:
        response = call(anon_client, method, path)
        assert response.status_code == 401, f"{method} {path} answered {response.status_code}"
        assert response.json()["detail"]["error"] == "missing signature headers"


async def test_every_guarded_route_has_a_role_mapping(anon_client):
    """Deny by default only helps if somebody notices a route was never classified."""
    routes = guarded_routes(anon_client.app)
    assert len(routes) >= 15, "route enumeration found suspiciously little"
    unmapped = [route for route in routes if route not in ROUTE_ROLES]
    assert unmapped == [], f"nobody decided who may call: {unmapped}"


async def test_the_unauthenticated_write_that_mattered_most(anon_client, services):
    """An open port used to mean anyone could write permanently undeletable entries."""
    before = services.repo.audit_count()
    assert anon_client.post("/v1/audit/head").status_code == 401
    assert services.repo.audit_count() == before


async def test_liveness_and_readiness_stay_open_for_the_load_balancer(anon_client):
    """The balancer has no key, and never will."""
    assert anon_client.get("/v1/healthz").status_code == 200
    assert anon_client.get("/v1/readyz").status_code == 200


async def test_headers_are_all_required(anon_client):
    missing = anon_client.get("/v1/roster").json()["detail"]["headers"]
    assert set(missing) == set(HEADERS)


# --- forgery -----------------------------------------------------------------


async def test_a_tampered_body_is_refused(settings, clock, org):
    """The signature covers a hash of the bytes, so one flipped byte invalidates it."""
    with signing_client(settings, clock, org, "p-001") as client:
        good = {
            "scenario": "EVAC",
            "severity": "warning",
            "drill": False,
            "audience": {"groups": ["fire-wardens"]},
            "text": "a",
        }
        headers = sign_once(client, "POST", "/v1/proposals", json=good)
        client.auth = None
        assert (
            client.post("/v1/proposals", json=dict(good, text="b"), headers=headers).status_code
            == 403
        )


async def test_a_tampered_query_string_is_refused(settings, clock, org):
    """The auditor pages the chain with ?from_idx=…&limit=…; an unsigned query is a
    query an attacker rewrites."""
    with signing_client(settings, clock, org, "a-001") as client:
        headers = sign_once(client, "GET", "/v1/audit", params={"from_idx": 0, "limit": 5})
        client.auth = None
        assert client.get("/v1/audit?from_idx=0&limit=500", headers=headers).status_code == 403


async def test_a_signature_from_another_route_is_refused(settings, clock, org):
    """Method and path are in the signed payload, so a signature cannot be moved."""
    with signing_client(settings, clock, org, "p-001") as client:
        headers = sign_once(client, "GET", "/v1/roster")
        client.auth = None
        assert client.get("/v1/orders", headers=headers).status_code == 403


async def test_a_revoked_key_is_refused(settings, clock, org, services):
    """The 60-second revocation target now covers HTTP as well as the socket."""
    with signing_client(settings, clock, org, "p-001") as client:
        assert client.get("/v1/roster").status_code == 200

        # Republish the directory with this key revoked, signed by the real root.
        # The server re-reads and re-verifies the bundle on every request, which is
        # what gives the 60-second revocation target its teeth.
        payload = DirectoryPayload.model_validate(org.directory_bundle["payload"])
        revoked = payload.model_copy(
            update={
                "version": payload.version + 1,
                "revoked": (Revocation(key_id=org.person("p-001").key_id, revoked_at=clock.now()),),
            }
        ).to_payload()
        client.app.state.alerting.repo.put_bundle(
            "directory",
            revoked["version"],
            {
                "payload": revoked,
                "signature": sign_payload(DOMAIN_DIRECTORY, revoked, org.root_private_key),
            },
            clock.now(),
        )

        response = client.get("/v1/roster")
        assert response.status_code == 403
        assert response.json()["detail"]["error"] == "unknown or revoked key"


async def test_a_malformed_signature_is_a_refusal_not_a_crash(settings, clock, org):
    """Everything in these headers is attacker-controlled, so every step of parsing
    them has to answer "refused", never raise."""
    with signing_client(settings, clock, org, "p-001") as client:
        headers = sign_once(client, "GET", "/v1/roster")
        client.auth = None

        for header, value in (
            (SIGNATURE_HEADER, "!!!not-base64!!!"),
            (SIGNATURE_HEADER, "AAAA"),
            (TIMESTAMP_HEADER, "soon"),
            (TIMESTAMP_HEADER, "1.5"),
        ):
            crafted = dict(headers) | {header.lower(): value}
            response = client.get("/v1/roster", headers=crafted)
            assert response.status_code in (401, 403), (
                f"{header}={value!r} produced {response.status_code}"
            )


# --- replay ------------------------------------------------------------------


async def test_a_replayed_request_is_refused(settings, clock, org):
    with signing_client(settings, clock, org, "p-001") as client:
        headers = sign_once(client, "GET", "/v1/roster")
        client.auth = None

        assert client.get("/v1/roster", headers=headers).status_code == 200
        response = client.get("/v1/roster", headers=headers)
        assert response.status_code == 401
        assert response.json()["detail"]["error"] == "replayed request"


async def test_a_replay_is_refused_by_the_other_process_too(settings, clock, org):
    """The nonce lives in a table, not in a worker's memory -- the unit runs
    `--workers 2`, so a per-process cache would be no cache at all."""
    with signing_client(settings, clock, org, "p-001") as first:
        headers = sign_once(first, "GET", "/v1/roster")
        first.auth = None
        assert first.get("/v1/roster", headers=headers).status_code == 200

        app = create_app(settings, clock, start_escalation=False)
        with TestClient(app) as other:
            assert other.get("/v1/roster", headers=headers).status_code == 401


# --- the clock ---------------------------------------------------------------


async def test_a_skewed_clock_is_told_what_is_wrong(settings, clock, org):
    """Before signed requests a wrong clock on a laptop cost nothing. Now it refuses
    every command, and "stale request" is not something anybody connects to their own
    clock unaided."""
    app = create_app(settings, clock, start_escalation=False)
    publish_org(app.state.alerting.repo, org, audit=app.state.alerting.audit)
    with TestClient(app) as client:
        client.auth = signer_for(org, "p-001", FixedClock(clock.now() + 300))
        response = client.get("/v1/roster")

    assert response.status_code == 401
    detail = response.json()["detail"]
    assert detail["error"] == "stale request"
    assert detail["skew_s"] == 300
    assert detail["server_time"] == clock.now()


# --- roles -------------------------------------------------------------------


async def test_an_executor_device_key_cannot_start_an_order(executor_client):
    """The directory holds executors' device keys, which exist to sign receipts. Two
    of them must not be able to open the dispatch path."""
    response = executor_client.post(
        "/v1/proposals",
        json={
            "scenario": "EVAC",
            "severity": "critical",
            "drill": False,
            "audience": {"groups": ["fire-wardens"]},
        },
    )
    assert response.status_code == 403
    assert "executor may not call" in response.json()["detail"]["error"]


async def test_an_executor_cannot_read_the_roster_or_statusz(executor_client):
    """Both are roster leaks; statusz says so in its own docstring."""
    assert executor_client.get("/v1/roster").status_code == 403
    assert executor_client.get("/v1/statusz").status_code == 403


async def test_an_executor_can_still_do_its_own_job(executor_client):
    assert executor_client.get("/v1/directory").status_code == 200
    assert executor_client.get("/v1/policy").status_code == 200


async def test_an_auditor_reads_the_chain_and_writes_nothing(auditor_client):
    assert auditor_client.get("/v1/audit").status_code == 200
    assert auditor_client.post("/v1/audit/head").status_code == 403


# --- the point of the whole exercise ----------------------------------------


async def test_created_by_comes_from_the_signature_not_the_client(client, services):
    """It used to be whatever the client claimed, written into a chain that can never
    be edited. The signing key decides now."""
    response = client.post(
        "/v1/proposals",
        json={
            "scenario": "EVAC.BUILDING",
            "severity": "warning",
            "drill": False,
            "audience": {"groups": ["fire-wardens"]},
            "created_by": "somebody-else",
        },
    )
    assert response.status_code == 200

    created = [
        entry
        for entry in services.repo.audit_entries(0, 10_000)
        if entry["event"] == str(Event.PROPOSAL_CREATED)
    ]
    assert created[-1]["data"]["created_by"] == "p-001"


async def test_a_signature_submission_records_who_carried_it(client, services, org):
    """Two identities, kept apart: whose signature it is, and who brought it in.
    Requiring them to match would quietly forbid a signature taken offline."""
    proposal = client.post(
        "/v1/proposals",
        json={
            "scenario": "EVAC",
            "severity": "warning",
            "drill": False,
            "audience": {"groups": ["fire-wardens"]},
        },
    ).json()
    person = org.person("p-002")
    client.post(
        f"/v1/proposals/{proposal['order_id']}/signatures",
        json={
            "key_id": person.key_id,
            "sig": sign_payload(DOMAIN_ORDER, proposal["payload"], person.private_key),
        },
    )
    signed = [
        entry
        for entry in services.repo.audit_entries(0, 10_000)
        if entry["event"] == str(Event.PROPOSAL_SIGNED)
    ]
    assert signed[-1]["data"]["key_id"] == person.key_id
    assert signed[-1]["data"]["submitted_by"] == "p-001"


# --- bounds that are not about auth but live on these routes -----------------


async def test_paged_listings_are_bounded(client):
    """Unvalidated, ?limit=999999999 was a one-request memory-exhaustion primitive."""
    assert client.get("/v1/audit", params={"limit": 10_000}).status_code == 422
    assert client.get("/v1/audit", params={"limit": 1000}).status_code == 200


async def test_a_secret_file_readable_by_others_is_still_refused(tmp_path):
    """The shared key is gone, but the guarantee it proved is not: the server key and
    the DSN are still read through the same permission check."""
    from alerting.server.config import read_secret_file

    loose = tmp_path / "loose"
    loose.write_text("x", encoding="utf-8")
    loose.chmod(0o644)
    with pytest.raises(PermissionError, match="readable by group or others"):
        read_secret_file(pathlib.Path(loose), "server key")
