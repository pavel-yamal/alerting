"""The custodians' screen, end to end: create the vault, review and sign a request."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from alerting import custody
from alerting.clients.custodian.app import CSRF_HEADER, create_custodian
from alerting.core.directory import Directory
from alerting.core.signing import generate_keypair, key_id, public_key_from_b64u, public_key_to_b64u
from alerting.orgkit import build_org

H = {CSRF_HEADER: "1"}
PASSES = ["первый-хранитель-1", "второй-хранитель-2"]


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    monkeypatch.setattr(custody, "SCRYPT_N", 2**10)


@pytest.fixture
def screen(tmp_path):
    return TestClient(create_custodian(tmp_path / "usb" / "root-vault.json"))


def test_from_an_empty_laptop_to_a_signed_answer(screen, tmp_path):
    assert screen.get("/api/status").json()["vault"] is None
    assert "script-src 'self'" in screen.get("/").headers["content-security-policy"]

    created = screen.post("/api/vault/create", headers=H, json={
        "org_id": "acme", "names": ["Иванов", "Петров"], "passphrases": PASSES,
    })  # fmt: skip
    assert created.status_code == 200, created.text
    vault = created.json()["vault"]
    assert (
        vault["fingerprint"] and (tmp_path / "usb" / "root-vault.json").stat().st_mode & 0o077 == 0
    )
    again = screen.post("/api/vault/create", headers=H, json={
        "org_id": "acme", "names": ["А", "Б"], "passphrases": PASSES,
    })  # fmt: skip
    assert again.status_code == 409, "an existing root key is never overwritten"

    # Migration of a demo org onto this fresh key, enrolling one person on the way.
    org = build_org(org_id="acme")
    _, public = generate_keypair()
    request = custody.build_request(
        org_id="acme", root_public_key=public_key_to_b64u(org.root_public_key),
        directory=org.directory_bundle, policy=org.policy_bundle, revocations=None,
        changes=[{"op": "add_key", "person_id": "p-010", "name": "Орлова", "role": "lpr",
                  "public_key": public_key_to_b64u(public)}],
        created_by="p-003", created_at=1,
    )  # fmt: skip
    review = screen.post("/api/review", headers=H, json={"request": request}).json()
    assert review["migrating"] is True and review["previous_fingerprint"]
    assert key_id(public) in review["changes"][0]

    bad = [PASSES[0], "не-тот-пароль-2"]
    wrong = screen.post("/api/sign", headers=H, json={
        "request": request, "passphrases": bad, "confirm_migration": True,
    })  # fmt: skip
    assert wrong.status_code == 422 and "пароли" in wrong.text
    unconfirmed = screen.post(
        "/api/sign", headers=H, json={"request": request, "passphrases": PASSES}
    )
    assert unconfirmed.status_code == 422

    answer = screen.post("/api/sign", headers=H, json={
        "request": request, "passphrases": PASSES, "confirm_migration": True,
    }).json()  # fmt: skip
    directory = Directory.load(
        answer["bundles"]["directory"], root_public_key=public_key_from_b64u(vault["public_key"]),
        org_id="acme",
    )  # fmt: skip
    assert directory.lookup(key_id(public)).person_id == "p-010"
    assert answer["root_fingerprint"] == vault["fingerprint"]


def test_requests_need_the_custodian_header(screen):
    assert screen.post("/api/vault/check", json={"passphrases": PASSES}).status_code == 403


def test_a_backup_restores_on_another_laptop(screen, tmp_path):
    screen.post("/api/vault/create", headers=H, json={
        "org_id": "acme", "names": ["Иванов", "Петров"], "passphrases": PASSES,
    })  # fmt: skip
    backup = screen.get("/api/vault/file").json()
    other = TestClient(create_custodian(tmp_path / "second" / "vault.json"))
    assert other.post("/api/vault/restore", headers=H, json={"vault": backup}).status_code == 200
    assert other.post("/api/vault/check", headers=H, json={"passphrases": PASSES}).json() == {
        "ok": True
    }


def test_a_damaged_backup_is_refused_and_nothing_is_written(screen, tmp_path):
    screen.post("/api/vault/create", headers=H, json={
        "org_id": "acme", "names": ["Иванов", "Петров"], "passphrases": PASSES,
    })  # fmt: skip
    good = screen.get("/api/vault/file").json()
    target = tmp_path / "third" / "vault.json"
    other = TestClient(create_custodian(target))
    for broken in [
        {"type": custody.VAULT_TYPE, "v": 1},
        dict(good, public_key="AAAA"),
        dict(good, key_id="ed25519:someone-else"),
        dict(good, salts=[good["salts"][0]]),
    ]:
        response = other.post("/api/vault/restore", headers=H, json={"vault": broken})
        assert response.status_code == 422, response.text
        assert not target.exists()
    assert other.post("/api/vault/restore", headers=H, json={"vault": good}).status_code == 200
