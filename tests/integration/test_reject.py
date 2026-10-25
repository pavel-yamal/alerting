"""Rejecting a proposal: closed unsigned by one decision-maker, never an order.

A proposal waits for its signatures without a deadline, so one nobody wants has to be
closable rather than left one careless signature away from going out.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from alerting.core.clock import FixedClock
from alerting.core.signing import DOMAIN_ORDER, sign_payload
from alerting.orgkit import Org
from alerting.server.app import create_app
from alerting.server.config import Settings
from alerting.server.services.bootstrap import publish_org
from tests.integration.conftest import signer_for
from tests.integration.test_feed import items


@pytest.fixture
def server(settings: Settings, clock: FixedClock, org: Org) -> Iterator[TestClient]:
    app = create_app(settings, clock, start_escalation=False)
    publish_org(app.state.alerting.repo, org, audit=app.state.alerting.audit)
    with TestClient(app) as client:
        yield client


BODY = {"scenario": "EVAC.BUILDING", "severity": "critical", "drill": False,
        "audience": {"groups": ["fire-wardens"]}}  # fmt: skip


def propose(server: TestClient, org: Org, clock: FixedClock) -> dict[str, Any]:
    server.auth = signer_for(org, "p-001", clock)
    proposal: dict[str, Any] = server.post("/v1/proposals", json=BODY).json()
    return proposal


def sign(server: TestClient, org: Org, clock: FixedClock, proposal: dict, person_id: str):
    person = org.person(person_id)
    server.auth = signer_for(org, person_id, clock)
    return server.post(
        f"/v1/proposals/{proposal['order_id']}/signatures",
        json={
            "key_id": person.key_id,
            "sig": sign_payload(DOMAIN_ORDER, proposal["payload"], person.private_key),
        },
    )


def reject(server: TestClient, org: Org, clock: FixedClock, order_id: str, person_id: str):
    server.auth = signer_for(org, person_id, clock)
    return server.post(f"/v1/proposals/{order_id}/reject", json={})


def test_one_decision_maker_rejects_and_nobody_can_sign_it_after(server, org, clock):
    proposal = propose(server, org, clock)
    order_id = proposal["order_id"]
    assert sign(server, org, clock, proposal, "p-001").json()["dispatched"] is False

    response = reject(server, org, clock, order_id, "p-002")
    assert response.status_code == 200, response.text

    shown = server.get(f"/v1/proposals/{order_id}").json()
    assert shown["status"] == "rejected"
    assert shown["rejected_by"] == "p-002" and shown["rejected_at"] == clock.now()

    late = sign(server, org, clock, proposal, "p-003")
    assert late.status_code == 409
    assert items(server) == []  # never an order, never in the feed

    audit = server.app.state.alerting.repo.audit_entries(0, 1000)
    rejected = [e["data"] for e in audit if e["event"] == "proposal.rejected"]
    assert rejected == [{"order_id": order_id, "rejected_by": "p-002"}]


def test_what_went_out_cannot_be_rejected(server, org, clock):
    proposal = propose(server, org, clock)
    sign(server, org, clock, proposal, "p-001")
    assert sign(server, org, clock, proposal, "p-002").json()["dispatched"] is True
    assert reject(server, org, clock, proposal["order_id"], "p-003").status_code == 409


def test_only_decision_makers_reject(server, org, clock):
    proposal = propose(server, org, clock)
    for person_id in ("p-004", "x-101"):  # the duty officer, an executor
        assert reject(server, org, clock, proposal["order_id"], person_id).status_code == 403
    assert reject(server, org, clock, "no-such-proposal", "p-001").status_code == 404


def test_a_proposal_is_claimed_once_before_it_goes_out(server):
    """The last signature takes the proposal out of 'open' in one statement, so a
    rejection arriving at the same moment cannot be reported done for an order that
    went out anyway -- and of two last signatures, one dispatches."""
    repo = server.app.state.alerting.repo
    repo.create_proposal("o-claim", "primary", 10**6, "{}", 0, "p-001")
    assert repo.claim_proposal("o-claim") is True
    assert repo.claim_proposal("o-claim") is False
    assert repo.reject_proposal("o-claim", "p-002", 1) is False
    assert repo.proposal("o-claim")["status"] == "dispatched"
