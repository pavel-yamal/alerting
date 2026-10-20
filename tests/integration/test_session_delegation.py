"""A device key delegating HTTP authentication to a short-lived session key.

This is what lets the web panel run without holding anyone's device key: the key
stays in the person's browser and signs a delegation; the panel signs requests with
the session key. Orders still need the device key itself.
"""

from __future__ import annotations

import pytest

from alerting.clients.transport import SignedRequests
from alerting.core.http_auth import MAX_DELEGATION_S, delegation_payload, encode_delegation
from alerting.core.signing import (
    DOMAIN_ORDER,
    DOMAIN_SESSION_DELEGATION,
    generate_keypair,
    public_key_to_b64u,
    sign_payload,
)
from alerting.orgadmin import revoke_keys, verified_current
from alerting.orgkit import Org
from tests.integration.test_enrollment import publish

pytestmark = pytest.mark.asyncio


def delegated(org: Org, person_id: str, clock, *, start=None, length=3600, signer=None):
    """A SignedRequests that signs with a fresh session key, as the panel does."""
    person = org.person(person_id)
    session_private, session_public = generate_keypair()
    begin = clock.now() if start is None else start
    payload = delegation_payload(
        org_id=org.org_id, key_id=person.key_id, person_id=person_id,
        session_key=public_key_to_b64u(session_public), not_before=begin,
        not_after=begin + length,
    )  # fmt: skip
    signature = sign_payload(DOMAIN_SESSION_DELEGATION, payload, signer or person.private_key)
    return SignedRequests(
        org_id=org.org_id, key_id=person.key_id, person_id=person_id,
        private_key=session_private, clock=clock,
        delegation=encode_delegation(payload, signature),
    ), session_private  # fmt: skip


async def test_a_delegated_session_key_authenticates_as_its_person(client, org, clock):
    auth, _ = delegated(org, "p-003", clock)
    assert client.get("/v1/roster", auth=auth).status_code == 200


async def test_a_session_key_without_its_delegation_is_refused(client, org, clock):
    auth, _ = delegated(org, "p-003", clock)
    auth.delegation = None
    assert client.get("/v1/roster", auth=auth).status_code == 403


@pytest.mark.parametrize(
    "case",
    ["expired", "too_long", "future", "forged", "other_person"],
)
async def test_a_bad_delegation_is_refused(client, org, clock, case):
    if case == "expired":
        auth, _ = delegated(org, "p-003", clock, start=clock.now() - 7200, length=3600)
    elif case == "too_long":
        auth, _ = delegated(org, "p-003", clock, length=MAX_DELEGATION_S + 1)
    elif case == "future":
        auth, _ = delegated(org, "p-003", clock, start=clock.now() + 600)
    elif case == "forged":
        stranger, _ = generate_keypair()
        auth, _ = delegated(org, "p-003", clock, signer=stranger)
    else:
        auth, _ = delegated(org, "p-003", clock, signer=org.person("p-001").private_key)
    response = client.get("/v1/roster", auth=auth)
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "bad delegation"


async def test_revoking_the_device_key_ends_its_sessions(client, org, clock):
    auth, _ = delegated(org, "p-002", clock)
    assert client.get("/v1/roster", auth=auth).status_code == 200
    current = verified_current(
        client.get("/v1/directory").json(), public_key_to_b64u(org.root_public_key)
    )
    payload, _ = revoke_keys(current, person_id="p-002", kid=None, at=clock.now(), reason="x")
    publish(client, org, payload)
    assert client.get("/v1/roster", auth=auth).status_code == 403


async def test_a_session_key_cannot_sign_an_order(client, org, clock):
    """Transport only: the order signature is checked against the device key."""
    auth, session_private = delegated(org, "p-001", clock)
    proposal = client.post(
        "/v1/proposals",
        json={"scenario": "EVAC.BUILDING", "severity": "critical", "drill": True,
              "audience": {"groups": ["fire-wardens"]}, "text": "x"},
        auth=auth,
    ).json()  # fmt: skip
    response = client.post(
        f"/v1/proposals/{proposal['order_id']}/signatures",
        json={
            "key_id": org.person("p-001").key_id,
            "sig": sign_payload(DOMAIN_ORDER, proposal["payload"], session_private),
        },
        auth=auth,
    )
    result = response.json()
    assert result["dispatched"] is False and "bad_signature" in result["blocking"]


@pytest.mark.parametrize("garbage", ["!!!", "e30", "bm90IGpzb24"])  # bad b64, {}, "not json"
async def test_a_malformed_delegation_header_is_a_refusal_not_a_crash(client, org, clock, garbage):
    auth, _ = delegated(org, "p-003", clock)
    auth.delegation = garbage
    response = client.get("/v1/roster", auth=auth)
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "bad delegation"
