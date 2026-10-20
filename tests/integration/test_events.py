"""Events that stay in force until a stand-down, and the policy that says which.

The policy is root-signed and published through the server, which verifies it like
any client would. An event of an ``until_cancelled`` scenario is listed as active and
offered to devices that connect later, until its stand-down is dispatched.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from alerting.core.clock import FixedClock
from alerting.core.envelope import Audience
from alerting.core.policy import PolicyPayload
from alerting.core.signing import DOMAIN_POLICY
from alerting.orgkit import DEFAULT_SCENARIOS, Org, make_order, sign_bundle, sign_order
from alerting.server.app import create_app
from alerting.server.config import Settings
from alerting.server.services.bootstrap import publish_org
from tests.integration.conftest import signer_for
from tests.integration.test_e2e_ws import connect_executor

pytestmark = pytest.mark.asyncio


@pytest.fixture
def client(settings: Settings, clock: FixedClock, org: Org):
    app = create_app(settings, clock, start_escalation=False)
    publish_org(app.state.alerting.repo, org, audit=app.state.alerting.audit)
    with TestClient(app) as test_client:
        test_client.auth = signer_for(org, "p-003", clock)
        yield test_client


async def dispatch(client: TestClient, org: Org, clock: FixedClock, **kwargs: Any):
    order = make_order(
        org, issued_at=clock.now(), audience=Audience(groups=("fire-wardens",)), **kwargs
    )
    signers = (
        [org.person("p-001")]
        if kwargs.get("order_type") == "cancel"
        else [org.person("p-001"), org.person("p-002")]
    )
    result = await client.app.state.alerting.dispatcher.dispatch(sign_order(order, signers))
    assert result.accepted, result.decision.reasons
    return order


def next_policy(org: Org, version: int, **scenario_changes: Any) -> dict[str, Any]:
    raw = dict(org.policy_bundle["payload"])
    raw["version"] = version
    scenarios = {code: rule.to_payload() for code, rule in DEFAULT_SCENARIOS.items()}
    scenarios.update(scenario_changes)
    raw["scenarios"] = scenarios
    return sign_bundle(PolicyPayload.model_validate(raw), DOMAIN_POLICY, org.root_private_key)


async def test_an_until_cancelled_event_stays_active_past_its_window_until_stood_down(
    client, org, clock
):
    evac = await dispatch(client, org, clock, scenario="EVAC.BUILDING", ttl_s=120, seq=1)
    muster = await dispatch(client, org, clock, scenario="MUSTER", ttl_s=120, seq=2)
    clock.advance(3600)

    active = client.get("/v1/events/active").json()["events"]
    assert [e["order_id"] for e in active] == [evac.order_id], "MUSTER lapsed with its window"
    assert active[0]["until_cancelled"] is True

    cancel = await dispatch(
        client, org, clock, scenario="EVAC.BUILDING", seq=3, order_type="cancel",
        cancels=evac.order_id, action="STOP",
    )  # fmt: skip
    assert client.get("/v1/events/active").json()["events"] == []

    listed = {o["order_id"]: o for o in client.get("/v1/orders").json()["orders"]}
    assert listed[evac.order_id]["cancelled_by"] == cancel.order_id
    assert listed[cancel.order_id]["cancels"] == evac.order_id
    assert listed[muster.order_id]["cancelled_by"] is None

    status = client.get(f"/v1/orders/{evac.order_id}/status").json()
    assert status["cancelled_by"] == cancel.order_id and status["until_cancelled"] is True


async def test_a_device_that_connects_later_is_told_what_is_in_force(client, org, clock):
    evac = await dispatch(client, org, clock, scenario="EVAC.BUILDING", ttl_s=120)
    clock.advance(3600)
    socket = connect_executor(client, org, "x-101", clock.now())
    try:
        frame = socket.receive_json()
        assert frame["kind"] == "active"
        assert frame["envelope"]["payload"]["order_id"] == evac.order_id
    finally:
        socket.__exit__(None, None, None)


async def test_a_new_signed_policy_is_published_and_takes_effect(client, org):
    bundle = next_policy(
        org, 2, **{"FLOOD": {"description": "Подтопление", "until_cancelled": True}}
    )
    response = client.post("/v1/bundles", json={"bundle": bundle})
    assert response.status_code == 200, response.text
    assert response.json() == {"kind": "policy", "version": 2}
    served = client.get("/v1/policy").json()
    assert served["payload"]["version"] == 2 and "FLOOD" in served["payload"]["scenarios"]

    again = client.post("/v1/bundles", json={"bundle": bundle})
    assert again.status_code == 409, "the same version twice is a rollback attempt"


async def test_a_bundle_the_root_did_not_sign_is_refused(client, org):
    bundle = next_policy(org, 2)
    bundle["payload"]["scenarios"]["EVIL"] = {"description": "added after signing"}
    response = client.post("/v1/bundles", json={"bundle": bundle})
    assert response.status_code == 409
    assert client.get("/v1/policy").json()["payload"]["version"] == 1


async def test_executors_cannot_publish(client, org, clock):
    client.auth = signer_for(org, "x-101", clock)
    response = client.post("/v1/bundles", json={"bundle": next_policy(org, 2)})
    assert response.status_code == 403


async def test_a_new_policy_does_not_revive_an_event_that_already_ended(client, org, clock):
    """Found on the stand: republishing the codebook with EVAC.BUILDING marked "until
    cancelled" brought back every old evacuation nobody had stood down. The rule in
    force at dispatch governs the event's life."""
    old_rules = {code: rule.to_payload() for code, rule in DEFAULT_SCENARIOS.items()}
    old_rules["MUSTER"].pop("until_cancelled", None)
    muster = await dispatch(client, org, clock, scenario="MUSTER", ttl_s=120)
    clock.advance(3600)
    assert client.get("/v1/events/active").json()["events"] == []

    revised = next_policy(org, 2, MUSTER={**old_rules["MUSTER"], "until_cancelled": True})
    assert client.post("/v1/bundles", json={"bundle": revised}).status_code == 200

    assert client.get("/v1/events/active").json()["events"] == [], (
        f"{muster.order_id} ended under the policy it was dispatched with"
    )


async def test_a_policy_that_would_invalidate_a_running_event_is_refused(client, org, clock):
    """Devices verify with the newest policy and never with an older one offered
    alongside (that would be a downgrade), so a policy that drops a running event's
    scenario would leave everyone joining later unable to verify it."""
    evac = await dispatch(client, org, clock, scenario="EVAC.BUILDING")
    rules = {code: rule.to_payload() for code, rule in DEFAULT_SCENARIOS.items()}

    without = dict(rules)
    del without["EVAC.BUILDING"]
    raw = dict(org.policy_bundle["payload"], version=2, scenarios=without)
    dropping = sign_bundle(PolicyPayload.model_validate(raw), DOMAIN_POLICY, org.root_private_key)
    refused = client.post("/v1/bundles", json={"bundle": dropping})
    assert refused.status_code == 409
    assert evac.order_id in refused.json()["detail"]
    assert client.get("/v1/policy").json()["payload"]["version"] == 1

    keeping = next_policy(org, 2, FLOOD={"description": "Подтопление"})
    assert client.post("/v1/bundles", json={"bundle": keeping}).status_code == 200


async def test_an_event_in_force_is_found_however_many_orders_came_after(client, org, clock):
    """The newest-200 window used to be applied before filtering, so a long-running
    event dropped out once enough later orders accumulated."""
    evac = await dispatch(client, org, clock, scenario="EVAC.BUILDING", ttl_s=120)
    repo = client.app.state.alerting.repo
    stored = repo.order(evac.order_id)
    for i in range(205):
        repo.create_order(
            f"later-{i:03d}",
            {"payload": {"scenario": "MUSTER", "not_valid_after": 0}},
            stored["dispatched_at"] + 1 + i,
            True,
            "warning",
            "MUSTER",
            None,
            "d",
        )
    clock.advance(3600)
    active = client.get("/v1/events/active").json()["events"]
    assert [e["order_id"] for e in active] == [evac.order_id]


async def test_a_reconnecting_device_is_sent_the_stand_down_it_missed(client, org, clock):
    evac = await dispatch(client, org, clock, scenario="EVAC.BUILDING", seq=1)
    cancel = await dispatch(
        client, org, clock, scenario="EVAC.BUILDING", seq=2, order_type="cancel",
        cancels=evac.order_id, action="STOP",
    )  # fmt: skip
    socket = connect_executor(client, org, "x-101", clock.now())
    try:
        frame = socket.receive_json()
        assert frame["kind"] == "active"
        assert frame["envelope"]["payload"]["order_id"] == cancel.order_id
        assert frame["envelope"]["payload"]["cancels"] == evac.order_id
    finally:
        socket.__exit__(None, None, None)
