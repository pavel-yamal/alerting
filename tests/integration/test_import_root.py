"""``alerting-server import-root``: the server moves to the custodians' new root."""

from __future__ import annotations

import dataclasses
import json

import pytest

from alerting import custody
from alerting.core.audit_chain import Event
from alerting.server.cli import _import_root
from alerting.server.db.repo import Repo

PASSES = ("первый-хранитель-1", "второй-хранитель-2")


@pytest.fixture
def migration(services, org, tmp_path):
    vault, _ = custody.create_vault(org.org_id, PASSES, ("Иванов", "Петров"))
    private = custody.open_vault(vault, PASSES)
    request = custody.build_request(
        org_id=org.org_id, root_public_key=services.settings.root_public_key,
        directory=org.directory_bundle, policy=org.policy_bundle, revocations=None,
        changes=[{"op": "retire", "person_id": "x-103"}], created_by="p-003", created_at=1,
    )  # fmt: skip
    answer = custody.sign_answer(request, vault, private, now=2_000_000_000, confirm_migration=True)
    path = tmp_path / "answer.json"
    path.write_text(json.dumps(answer), encoding="utf-8")
    return answer, path


def test_the_server_moves_to_the_new_root(services, settings, migration):
    answer, path = migration
    assert _import_root(settings, path, answer["root_fingerprint"].lower()) == 0
    repo: Repo = services.repo
    stored = repo.latest_bundle("directory")
    assert stored == answer["bundles"]["directory"]
    assert repo.latest_bundle("policy") == answer["bundles"]["policy"]
    events = [e for e in repo.audit_entries(0, 10_000) if e["event"] == Event.ROOT_ROTATED]
    assert events and events[-1]["data"]["fingerprint"] == answer["root_fingerprint"]

    # And a server restarted on the new root serves it.
    from alerting.server.app import AppServices

    moved = AppServices(dataclasses.replace(settings, root_public_key=answer["root_public_key"]))
    try:
        assert (
            moved.state.directory().version == answer["bundles"]["directory"]["payload"]["version"]
        )
    finally:
        moved.close()


def test_a_wrong_fingerprint_stops_everything(services, settings, migration):
    _, path = migration
    assert _import_root(settings, path, "AAAA BBBB CCCC") == 2
    assert services.repo.latest_bundle("directory")["payload"]["version"] == 1


def test_a_tampered_answer_is_refused(services, settings, migration, tmp_path):
    answer, _ = migration
    answer["bundles"]["directory"]["payload"]["keys"][0]["name"] = "Подменён"
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(answer), encoding="utf-8")
    assert _import_root(settings, path, answer["root_fingerprint"]) == 2
