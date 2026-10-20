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

from alerting.core.policy import Policy, PolicyPayload
from alerting.core.signing import DOMAIN_POLICY, private_key_to_b64u, sign_payload
from alerting.orgadmin import build_policy, main
from alerting.orgkit import sign_bundle

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
