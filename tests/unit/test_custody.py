"""The custodians' side: two-person vault, requests in, signed answers out."""

from __future__ import annotations

import pytest

from alerting import custody
from alerting.core.directory import Directory
from alerting.core.policy import Policy
from alerting.core.signing import (
    DOMAIN_REVOCATIONS,
    generate_keypair,
    key_id,
    public_key_to_b64u,
    sign_payload,
)
from alerting.custody import CustodyError
from alerting.orgadmin import add_revoker, next_revocations, verified_current
from alerting.orgkit import DEFAULT_SCENARIOS, Org, build_org, sign_bundle

NOW = 1_700_100_000
PASSES = ("первый-хранитель-1", "второй-хранитель-2")
NAMES = ("Иванов", "Петров")


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    monkeypatch.setattr(custody, "SCRYPT_N", 2**10)


@pytest.fixture
def org() -> Org:
    return build_org(issued_at=1_700_000_000)


def vault_for(org: Org) -> tuple[dict, object]:
    """A vault holding the org's own root key, as after a completed migration."""
    vault, _ = custody.create_vault(org.org_id, PASSES, NAMES)
    # Swap in the org's root so requests made from its bundles verify directly.
    import os

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from alerting.core.signing import b64u_decode, b64u_encode, private_key_to_b64u

    public = public_key_to_b64u(org.root_public_key)
    salts = tuple(b64u_decode(s) for s in vault["salts"])
    nonce = os.urandom(12)
    sealed = AESGCM(custody._vault_key(PASSES, salts)).encrypt(
        nonce, private_key_to_b64u(org.root_private_key).encode(), custody._aad(org.org_id, public)
    )
    vault.update(public_key=public, key_id=key_id(org.root_public_key),
                 nonce=b64u_encode(nonce), sealed=b64u_encode(sealed))  # fmt: skip
    return vault, org.root_private_key


def request(org: Org, changes: list[dict], *, root=None, revocations=None, directory=None):
    return custody.build_request(
        org_id=org.org_id,
        root_public_key=root or public_key_to_b64u(org.root_public_key),
        directory=directory or org.directory_bundle,
        policy=org.policy_bundle,
        revocations=revocations,
        changes=changes,
        created_by="p-003",
        created_at=NOW,
    )


def test_the_vault_opens_only_with_both_passphrases(org):
    vault, private = custody.create_vault(org.org_id, PASSES, NAMES)
    opened = custody.open_vault(vault, PASSES)
    assert public_key_to_b64u(opened.public_key()) == vault["public_key"]
    for wrong in [(PASSES[0], "не-тот-пароль-22"), ("не-тот-пароль-11", PASSES[1]), PASSES[::-1]]:
        with pytest.raises(CustodyError, match="пароли не подходят"):
            custody.open_vault(vault, wrong)
    assert "sealed" in vault and private_key_text(private) not in str(vault)


def private_key_text(private) -> str:
    from alerting.core.signing import private_key_to_b64u

    return private_key_to_b64u(private)


@pytest.mark.parametrize(
    "passes,names",
    [
        (("short", PASSES[1]), NAMES),
        ((PASSES[0], PASSES[0]), NAMES),
        (PASSES, ("Иванов", "Иванов")),
    ],
)
def test_a_weak_vault_is_refused(org, passes, names):
    with pytest.raises(CustodyError):
        custody.create_vault(org.org_id, passes, names)


def test_an_enrolment_request_becomes_the_next_signed_directory(org):
    vault, private = vault_for(org)
    _, public = generate_keypair()
    enrol = {"op": "add_key", "person_id": "p-010", "name": "Орлова", "role": "lpr",
             "public_key": public_key_to_b64u(public)}  # fmt: skip
    req = request(org, [enrol])
    seen = custody.review(req, vault)
    assert not seen.migrating and "ДОБАВИТЬ p-010" in seen.changes[0]
    assert key_id(public) in seen.changes[0], "custodians compare it with the device"

    answer = custody.sign_answer(req, vault, private, now=NOW)
    assert set(answer["bundles"]) == {"directory"}
    directory = Directory.load(
        answer["bundles"]["directory"], root_public_key=org.root_public_key, org_id=org.org_id,
        min_version=2,
    )  # fmt: skip
    assert directory.lookup(key_id(public)).role == "lpr"


def test_a_tampered_request_is_refused_before_anything_is_shown(org):
    vault, _ = vault_for(org)
    forged = dict(org.directory_bundle, signature=org.policy_bundle["signature"])
    req = request(org, [{"op": "retire", "person_id": "x-101"}], directory=forged)
    with pytest.raises(CustodyError, match="не подписаны"):
        custody.review(req, vault)


def test_another_organisations_request_is_refused(org):
    vault, _ = vault_for(org)
    other = build_org(org_id="other")
    req = request(other, [{"op": "retire", "person_id": "x-101"}])
    with pytest.raises(CustodyError, match="организации"):
        custody.review(req, vault)


def test_migration_carries_everyone_over_to_the_new_root(org):
    vault, _ = custody.create_vault(org.org_id, PASSES, NAMES)
    private = custody.open_vault(vault, PASSES)
    req = request(org, [{"op": "retire", "person_id": "x-103"}])
    seen = custody.review(req, vault)
    assert seen.migrating and seen.previous_root == public_key_to_b64u(org.root_public_key)
    with pytest.raises(CustodyError, match="подтвердите"):
        custody.sign_answer(req, vault, private, now=NOW)

    answer = custody.sign_answer(req, vault, private, now=NOW, confirm_migration=True)
    new_root = private.public_key()
    directory = Directory.load(answer["bundles"]["directory"], root_public_key=new_root,
                               org_id=org.org_id, min_version=2)  # fmt: skip
    old = Directory.load(org.directory_bundle, root_public_key=org.root_public_key,
                         org_id=org.org_id)  # fmt: skip
    assert {e.key_id for e in directory.payload.keys} == {e.key_id for e in old.payload.keys}
    policy = Policy.load(answer["bundles"]["policy"], root_public_key=new_root,
                         org_id=org.org_id, min_version=2)  # fmt: skip
    assert policy.payload.scenarios == old_policy(org).payload.scenarios
    assert answer["migration"] is True and answer["root_public_key"] == vault["public_key"]


def old_policy(org: Org) -> Policy:
    return Policy.load(org.policy_bundle, root_public_key=org.root_public_key, org_id=org.org_id)


def test_a_new_codebook_is_signed_as_the_next_policy(org):
    vault, private = vault_for(org)
    scenarios = {c: r.to_payload() for c, r in DEFAULT_SCENARIOS.items()}
    scenarios["FLOOD"] = {"description": "Подтопление", "until_cancelled": True}
    req = request(org, [{"op": "policy", "scenarios": scenarios}])
    answer = custody.sign_answer(req, vault, private, now=NOW)
    assert set(answer["bundles"]) == {"policy"}
    policy = Policy.load(answer["bundles"]["policy"], root_public_key=org.root_public_key,
                         org_id=org.org_id, min_version=2)  # fmt: skip
    assert "FLOOD" in policy.payload.scenarios
    assert policy.payload.not_valid_after == NOW + 365 * 86400

    broken = request(org, [{"op": "policy", "scenarios": {"X": {"min_severity": "nonsense"}}}])
    with pytest.raises(CustodyError, match="политика"):
        custody.sign_answer(broken, vault, private, now=NOW)


def test_dropping_a_revocation_key_can_keep_its_revocations(org):
    vault, private = vault_for(org)
    revoker_private, revoker_public = generate_keypair()
    current = verified_current(org.directory_bundle, public_key_to_b64u(org.root_public_key))
    with_revoker, _ = add_revoker(current, public_key=public_key_to_b64u(revoker_public),
                                  label="смена", issued_at=NOW)  # fmt: skip
    directory_bundle = sign_bundle(with_revoker, custody.DOMAIN_DIRECTORY, org.root_private_key)
    loaded = Directory.load(
        directory_bundle, root_public_key=org.root_public_key, org_id=org.org_id
    )
    listed, _ = next_revocations(loaded, None, signer=key_id(revoker_public), person_id="x-101",
                                 kid=None, at=NOW, reason="утерян")  # fmt: skip
    raw = listed.to_payload()
    revocations = {
        "payload": raw,
        "signature": sign_payload(DOMAIN_REVOCATIONS, raw, revoker_private),
    }

    drop = {"op": "remove_revoker", "key_id": key_id(revoker_public), "fate": "absorb"}
    req = request(org, [drop], directory=directory_bundle, revocations=revocations)
    answer = custody.sign_answer(req, vault, private, now=NOW)
    directory = Directory.load(answer["bundles"]["directory"], root_public_key=org.root_public_key,
                               org_id=org.org_id)  # fmt: skip
    assert directory.revokers == {}
    assert directory.is_revoked(org.person("x-101").key_id), "kept by the root itself"


def test_a_request_with_an_unknown_or_malformed_change_is_refused(org):
    for bad in [{"op": "make_me_director"}, {"op": "retire"},
                {"op": "add_key", "person_id": "P!", "name": "x", "role": "lpr",
                 "public_key": "x" * 43}]:  # fmt: skip
        with pytest.raises(CustodyError):
            request(org, [bad])
    with pytest.raises(CustodyError, match="нет изменений"):
        request(org, [])


def test_answers_are_shape_checked_on_the_way_back(org):
    with pytest.raises(CustodyError):
        custody.read_answer({"type": "x"}, org_id=org.org_id)
    with pytest.raises(CustodyError):
        custody.read_answer({"type": custody.ANSWER_TYPE, "v": 1, "org_id": "other",
                             "bundles": {"directory": {}}}, org_id=org.org_id)  # fmt: skip
    ok = {"type": custody.ANSWER_TYPE, "v": 1, "org_id": org.org_id, "bundles": {"policy": {}}}
    assert custody.read_answer(ok, org_id=org.org_id) == {"policy": {}}
