"""The codebook and quorum come from YAML, signed offline by the root key.

Not from the server's environment: a phone checks the policy against the root key it
pinned at enrollment, so a list the server could rewrite would be a list an attacker
with the server could rewrite.
"""

from __future__ import annotations

import json
import pathlib

import pytest
import yaml

from alerting.core.directory import Directory
from alerting.core.policy import Policy, PolicyPayload
from alerting.core.signing import (
    DOMAIN_DIRECTORY,
    DOMAIN_POLICY,
    generate_keypair,
    key_id,
    private_key_to_b64u,
    public_key_to_b64u,
    sign_payload,
)
from alerting.orgadmin import (
    add_key,
    build_policy,
    main,
    retire_keys,
    revoke_keys,
    verified_current,
)
from alerting.orgkit import build_org, sign_bundle

CONFIG = pathlib.Path("config")


def example_policy() -> PolicyPayload:
    return build_policy(
        yaml.safe_load((CONFIG / "policy.example.yaml").read_text(encoding="utf-8")),
        scenarios=yaml.safe_load((CONFIG / "scenarios.example.yaml").read_text(encoding="utf-8")),
        version=2,
        issued_at=1_700_000_000,
        ttl_days=365,
    )


def test_the_shipped_examples_build_a_valid_policy():
    payload = example_policy()
    assert payload.version == 2
    assert set(payload.scenarios) >= {"EVAC.BUILDING", "SHELTER.IN.PLACE", "TEST.PING"}
    evac = payload.scenarios["EVAC.BUILDING"]
    assert evac.until_cancelled is True and evac.card
    assert payload.scenarios["TEST.PING"].until_cancelled is None
    assert payload.severities["critical"].launch.m == 2


def test_a_signed_policy_verifies_like_a_client_verifies_it(org):
    bundle = sign_bundle(example_policy(), DOMAIN_POLICY, org.root_private_key)
    policy = Policy.load(bundle, root_public_key=org.root_public_key, org_id="acme", min_version=2)
    assert policy.lasts_until_cancelled("EVAC.BUILDING")
    assert not policy.lasts_until_cancelled("MUSTER")
    assert not policy.lasts_until_cancelled("NO.SUCH")


def test_a_policy_signed_before_the_new_fields_existed_still_verifies(org):
    """card and until_cancelled default to None and canonical form omits None, so a
    bundle signed without them canonicalizes to the bytes it was signed over."""
    raw = example_policy().to_payload()
    for rule in raw["scenarios"].values():
        rule.pop("card", None)
        rule.pop("until_cancelled", None)
    bundle = {"payload": raw, "signature": sign_payload(DOMAIN_POLICY, raw, org.root_private_key)}
    policy = Policy.load(bundle, root_public_key=org.root_public_key, org_id="acme")
    assert not policy.lasts_until_cancelled("EVAC.BUILDING")


def test_a_float_quorum_is_refused_offline_not_by_every_client():
    document = yaml.safe_load((CONFIG / "policy.example.yaml").read_text(encoding="utf-8"))
    document["severities"]["critical"]["launch"]["m"] = 2.0
    with pytest.raises(ValueError):
        build_policy(document, scenarios={"X": {}}, version=2, issued_at=0, ttl_days=1)


def test_a_policy_without_events_is_refused():
    document = yaml.safe_load((CONFIG / "policy.example.yaml").read_text(encoding="utf-8"))
    with pytest.raises(ValueError, match="no scenarios"):
        build_policy(document, scenarios=None, version=2, issued_at=0, ttl_days=1)


def test_sign_policy_command_writes_a_verifiable_bundle(tmp_path, org, capsys):
    key = tmp_path / "root-key.SECRET"
    key.write_text(private_key_to_b64u(org.root_private_key), encoding="utf-8")
    out = tmp_path / "policy.json"
    code = main(
        [
            "sign-policy",
            "--policy", str(CONFIG / "policy.example.yaml"),
            "--scenarios", str(CONFIG / "scenarios.example.yaml"),
            "--root-key", str(key),
            "--version", "3",
            "--out", str(out),
        ]
    )  # fmt: skip
    assert code == 0
    bundle = json.loads(out.read_text(encoding="utf-8"))
    policy = Policy.load(bundle, root_public_key=org.root_public_key, org_id="acme", min_version=3)
    assert policy.version == 3
    assert "[до отбоя]" in capsys.readouterr().out


# --- the key directory: add, retire, revoke -------------------------------------------

NOW = 1_700_100_000


def _org_and_current():
    org = build_org(issued_at=1_700_000_000)
    return org, verified_current(org.directory_bundle, public_key_to_b64u(org.root_public_key))


def _load(org, payload) -> Directory:
    return Directory.load(
        sign_bundle(payload, DOMAIN_DIRECTORY, org.root_private_key),
        root_public_key=org.root_public_key,
        org_id=org.org_id,
        min_version=2,
    )


def test_add_key_enrolls_the_next_version_and_it_signs():
    org, current = _org_and_current()
    _, public = generate_keypair()
    payload, entry = add_key(
        current, person_id="x-104", name="Новиков", role="executor",
        public_key=public_key_to_b64u(public), issued_at=NOW,
    )  # fmt: skip
    assert payload.version == current.version + 1
    assert entry.key_id == key_id(public)
    assert _load(org, payload).signer_status(entry.key_id, NOW + 1) is None


def test_add_key_refuses_a_duplicate_key_and_a_second_role():
    _, current = _org_and_current()
    existing = current.keys[0]
    with pytest.raises(ValueError, match="already in the directory"):
        add_key(current, person_id="z", name="z", role="executor",
                public_key=existing.public_key, issued_at=NOW)  # fmt: skip
    _, public = generate_keypair()
    with pytest.raises(ValueError, match="one person, one role"):
        add_key(current, person_id=existing.person_id, name="z", role="auditor",
                public_key=public_key_to_b64u(public), issued_at=NOW)  # fmt: skip


def test_retire_keeps_earlier_signatures_and_ends_later_ones():
    org, current = _org_and_current()
    kid = org.person("p-002").key_id
    payload, retired = retire_keys(current, person_id="p-002", kid=None, at=NOW)
    assert [e.key_id for e in retired] == [kid]
    directory = _load(org, payload)
    assert directory.signer_status(kid, NOW - 10) is None
    assert directory.signer_status(kid, NOW + 10) is not None


def test_revoke_kills_every_signature_the_key_made():
    org, current = _org_and_current()
    kid = org.person("x-101").key_id
    payload, _ = revoke_keys(current, person_id=None, kid=kid, at=NOW, reason="lost phone")
    directory = _load(org, payload)
    assert directory.signer_status(kid, NOW - 3000) is not None
    with pytest.raises(ValueError, match="no live key"):
        revoke_keys(payload, person_id=None, kid=kid, at=NOW, reason="again")


def test_selecting_needs_exactly_one_of_person_or_key():
    _, current = _org_and_current()
    with pytest.raises(ValueError, match="exactly one"):
        retire_keys(current, person_id=None, kid=None, at=NOW)
    with pytest.raises(ValueError, match="exactly one"):
        retire_keys(current, person_id="p-001", kid="x", at=NOW)


def test_directory_commands_chain_from_file_to_file(tmp_path, capsys):
    org, _ = _org_and_current()
    root = tmp_path / "root.key"
    root.write_text(private_key_to_b64u(org.root_private_key), encoding="utf-8")
    v1 = tmp_path / "v1.json"
    v1.write_text(json.dumps(org.directory_bundle), encoding="utf-8")
    _, public = generate_keypair()

    add = ["directory", "add", "--from", str(v1), "--root-key", str(root),
           "--out", str(tmp_path / "v2.json"), "--person", "x-104", "--name", "Новиков",
           "--role", "executor", "--public-key", public_key_to_b64u(public)]  # fmt: skip
    assert main(add) == 0
    assert main(["directory", "revoke", "--from", str(tmp_path / "v2.json"),
                 "--root-key", str(root), "--out", str(tmp_path / "v3.json"),
                 "--person", "x-101", "--reason", "lost"]) == 0  # fmt: skip
    assert main(["directory", "show", "--file", str(tmp_path / "v3.json")]) == 0
    out = capsys.readouterr().out
    assert key_id(public) in out and "REVOKED" in out and "version 3" in out

    other = build_org()
    (tmp_path / "other.key").write_text(private_key_to_b64u(other.root_private_key), "utf-8")
    retire = ["directory", "retire", "--from", str(v1), "--root-key",
              str(tmp_path / "other.key"), "--out", str(tmp_path / "x.json"),
              "--person", "x-101"]  # fmt: skip
    assert main(retire) == 2, "another org's root must not sign over this one"
