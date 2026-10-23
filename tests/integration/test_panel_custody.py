"""The duty officer's half of the offline-root loop, through the panel.

Panel prepares the request file, the custodians sign it (``custody.sign_answer``, as
the offline laptop does), the panel publishes the answer. The fast revocation path is
signed with a revocation key the "browser" holds.
"""

from __future__ import annotations

import yaml

from alerting import custody
from alerting.core.signing import (
    DOMAIN_REVOCATIONS,
    generate_keypair,
    key_id,
    public_key_to_b64u,
    sign_payload,
)
from tests.integration.test_panel_device_keys import PANEL, Browser, panel_app, server  # noqa: F401
from tests.unit.test_custody import vault_for


def logged_in(panel_app, org):  # noqa: F811
    director = Browser(panel_app, "p-001", org.person("p-001").private_key)
    assert director.login().status_code == 200
    return director.client


def custodians_sign(org, request, clock):
    vault, private = vault_for(org)
    return custody.sign_answer(request, vault, private, now=clock.now())


def test_enrolment_and_a_new_codebook_go_out_and_come_back(panel_app, org, clock):  # noqa: F811
    panel = logged_in(panel_app, org)
    before = panel.get("/api/directory").json()
    assert before["directory_version"] == 1 and before["revokers"] == []

    _, public = generate_keypair()
    scenarios = yaml.safe_load(before["scenarios_yaml"])
    scenarios["FLOOD"] = {"description": "Подтопление", "until_cancelled": True}
    response = panel.post("/api/custody/request", headers=PANEL, json={"changes": [
        {"op": "add_key", "person_id": "x-110", "name": "Соколов", "role": "executor",
         "public_key": public_key_to_b64u(public)},
        {"op": "policy", "scenarios_yaml": yaml.safe_dump(scenarios, allow_unicode=True)},
    ]})  # fmt: skip
    assert response.status_code == 200, response.text
    request = response.json()
    assert request["type"] == custody.REQUEST_TYPE and request["created_by"] == "p-001"

    answer = custodians_sign(org, request, clock)
    published = panel.post("/api/custody/answer", headers=PANEL, json={"answer": answer})
    assert published.status_code == 200, published.text
    kinds = {r["kind"]: r["version"] for r in published.json()["published"]}
    assert kinds["directory"] == 2 and kinds["policy"] == 2

    after = panel.get("/api/directory").json()
    added = next(p for p in after["people"] if p["person_id"] == "x-110")
    assert added["key_id"] == key_id(public) and added["state"] == "live"
    assert "FLOOD" in after["scenarios_yaml"]

    again = panel.post("/api/custody/answer", headers=PANEL, json={"answer": answer})
    assert again.status_code == 200, "the same answer again is a no-op, not an error"
    assert all(r.get("already") for r in again.json()["published"])


def test_an_answer_interrupted_halfway_finishes_on_retry(panel_app, server, org, clock):  # noqa: F811
    """Directory went out, policy did not: uploading the same file completes it."""
    panel = logged_in(panel_app, org)
    before = panel.get("/api/directory").json()
    request = panel.post("/api/custody/request", headers=PANEL, json={"changes": [
        {"op": "retire", "person_id": "x-103"},
        {"op": "policy", "scenarios_yaml": before["scenarios_yaml"]},
    ]}).json()  # fmt: skip
    answer = custodians_sign(org, request, clock)
    server.post("/v1/bundles", json={"bundle": answer["bundles"]["directory"]}).raise_for_status()

    retried = panel.post("/api/custody/answer", headers=PANEL, json={"answer": answer})
    assert retried.status_code == 200, retried.text
    by_kind = {r["kind"]: r for r in retried.json()["published"]}
    assert by_kind["directory"].get("already") and by_kind["policy"]["version"] == 2


def test_a_broken_codebook_is_caught_at_the_desk(panel_app, org):  # noqa: F811
    panel = logged_in(panel_app, org)
    for text in ["{unclosed", "EVAC: {min_severity: nonsense}"]:
        change = {"op": "policy", "scenarios_yaml": text}
        response = panel.post("/api/custody/request", headers=PANEL, json={"changes": [change]})
        assert response.status_code == 422, response.text


def test_a_migration_answer_is_sent_to_the_server_admin(panel_app, org, clock):  # noqa: F811
    panel = logged_in(panel_app, org)
    request = panel.post("/api/custody/request", headers=PANEL, json={"changes": [
        {"op": "retire", "person_id": "x-103"}]}).json()  # fmt: skip
    vault, _ = custody.create_vault(org.org_id, ("первый-хранитель-1", "второй-хранитель-2"),
                                    ("Иванов", "Петров"))  # fmt: skip
    private = custody.open_vault(vault, ("первый-хранитель-1", "второй-хранитель-2"))
    answer = custody.sign_answer(request, vault, private, now=clock.now(), confirm_migration=True)
    response = panel.post("/api/custody/answer", headers=PANEL, json={"answer": answer})
    assert response.status_code == 409 and "rotate-root" in response.text


def test_the_revocation_key_in_the_browser_revokes_at_once(panel_app, org, clock):  # noqa: F811
    panel = logged_in(panel_app, org)
    revoker, revoker_public = generate_keypair()
    request = panel.post("/api/custody/request", headers=PANEL, json={"changes": [
        {"op": "add_revoker", "public_key": public_key_to_b64u(revoker_public),
         "label": "смена"}]}).json()  # fmt: skip
    answer = custodians_sign(org, request, clock)
    panel.post("/api/custody/answer", headers=PANEL, json={"answer": answer}).raise_for_status()

    victim = org.person("x-101").key_id
    prepared = panel.post("/api/revocations/prepare", headers=PANEL, json={
        "signer": key_id(revoker_public), "reason": "утерян", "key_id": victim}).json()  # fmt: skip
    assert [r["key_id"] for r in prepared["revoking"]] == [victim]
    signature = sign_payload(DOMAIN_REVOCATIONS, prepared["payload"], revoker)
    result = panel.post("/api/revocations/publish", headers=PANEL,
                        json={"payload": prepared["payload"], "signature": signature})  # fmt: skip
    assert result.status_code == 200, result.text

    people = {p["key_id"]: p for p in panel.get("/api/directory").json()["people"]}
    assert people[victim]["state"] == "revoked" and people[victim]["reason"] == "утерян"

    stranger, _ = generate_keypair()
    forged = sign_payload(DOMAIN_REVOCATIONS, prepared["payload"], stranger)
    refused = panel.post("/api/revocations/publish", headers=PANEL,
                         json={"payload": prepared["payload"], "signature": forged})  # fmt: skip
    assert refused.status_code >= 400


def test_contacts_are_set_from_the_panel(panel_app, org):  # noqa: F811
    panel = logged_in(panel_app, org)
    response = panel.post("/api/contacts", headers=PANEL, json={
        "person_id": "x-110", "name": "Соколов", "phone": "+7900", "site": "HQ",
        "groups": ["fire-wardens"], "role": "executor"})  # fmt: skip
    assert response.status_code == 200, response.text
    assert panel.post("/api/contacts/x-110/deactivate", headers=PANEL).status_code == 200
