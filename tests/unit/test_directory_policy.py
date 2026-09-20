"""Root-signed bundles — the mechanism that makes client-side verification real.

Without pinning the org root key and enforcing version monotonicity, a compromised
server would simply serve a directory containing its own key and a policy of ``m: 1``,
and every "client-side signature check" below would pass.
"""

from __future__ import annotations

import pytest

from alerting.core.directory import (
    STALE_DIRECTORY_S,
    Directory,
    DirectoryPayload,
    DirectoryRejected,
    Revocation,
)
from alerting.core.errors import Reason
from alerting.core.policy import Policy, PolicyPayload, PolicyRejected, QuorumRule
from alerting.core.signing import DOMAIN_DIRECTORY, DOMAIN_POLICY, generate_keypair
from alerting.orgkit import sign_bundle

from tests.conftest import ISSUED_AT


def load_directory(org, bundle=None, **kwargs):
    return Directory.load(
        bundle or org.directory_bundle,
        root_public_key=kwargs.pop("root_public_key", org.root_public_key),
        org_id=kwargs.pop("org_id", org.org_id),
        **kwargs,
    )


def load_policy(org, bundle=None, **kwargs):
    return Policy.load(
        bundle or org.policy_bundle,
        root_public_key=kwargs.pop("root_public_key", org.root_public_key),
        org_id=kwargs.pop("org_id", org.org_id),
        **kwargs,
    )


def test_directory_signed_by_the_root_key_loads(org):
    assert load_directory(org).version == 1


def test_directory_signed_by_anyone_else_is_rejected(org):
    """This is the evil-server case in miniature."""
    attacker, _ = generate_keypair()
    payload = DirectoryPayload.model_validate(org.directory_bundle["payload"])
    forged = sign_bundle(payload, DOMAIN_DIRECTORY, attacker)
    with pytest.raises(DirectoryRejected) as exc:
        load_directory(org, forged)
    assert exc.value.reason is Reason.DIRECTORY_UNSIGNED


def test_directory_version_rollback_is_rejected(org):
    """Rolling a client back to an older directory would resurrect a revoked key."""
    with pytest.raises(DirectoryRejected) as exc:
        load_directory(org, min_version=5)
    assert exc.value.reason is Reason.DIRECTORY_ROLLBACK


def test_directory_for_another_org_is_rejected(org):
    with pytest.raises(DirectoryRejected) as exc:
        load_directory(org, org_id="someone-else")
    assert exc.value.reason is Reason.ORG_MISMATCH


def test_malformed_directory_bundle_is_rejected(org):
    with pytest.raises(DirectoryRejected) as exc:
        load_directory(org, {"payload": "not a dict", "signature": "x"})
    assert exc.value.reason is Reason.MALFORMED


def test_revoked_key_is_reported_as_revoked(org):
    key = org.person("p-002").key_id
    payload = DirectoryPayload.model_validate(org.directory_bundle["payload"])
    updated = payload.model_copy(
        update={"version": 2, "revoked": (Revocation(key_id=key, revoked_at=ISSUED_AT),)}
    )
    directory = load_directory(
        org, sign_bundle(updated, DOMAIN_DIRECTORY, org.root_private_key)
    )
    assert directory.is_revoked(key)
    assert directory.signer_status(key, ISSUED_AT) is Reason.REVOKED_SIGNER


def test_key_outside_its_validity_window_cannot_sign(org):
    directory = load_directory(org)
    key = org.person("p-001").key_id
    assert directory.signer_status(key, ISSUED_AT) is None
    assert directory.signer_status(key, 0) is Reason.REVOKED_SIGNER


def test_unknown_key_is_reported_as_unknown(org):
    assert load_directory(org).signer_status("ed25519:nope", ISSUED_AT) is Reason.UNKNOWN_SIGNER


def test_staleness_is_a_banner_not_a_refusal(org):
    directory = load_directory(org)
    assert not directory.is_stale(ISSUED_AT)
    assert directory.is_stale(ISSUED_AT + STALE_DIRECTORY_S + 1)


def test_duplicate_key_ids_are_rejected_at_construction(org):
    payload = DirectoryPayload.model_validate(org.directory_bundle["payload"])
    doubled = list(payload.keys) + [payload.keys[0]]
    with pytest.raises(ValueError, match="duplicate key_id"):
        payload.model_copy(update={"keys": tuple(doubled)}).model_validate(
            {**payload.to_payload(), "keys": [k.to_payload() for k in doubled]}
        )


def test_policy_signed_by_anyone_else_is_rejected(org):
    attacker, _ = generate_keypair()
    payload = PolicyPayload.model_validate(org.policy_bundle["payload"])
    forged = sign_bundle(payload, DOMAIN_POLICY, attacker)
    with pytest.raises(PolicyRejected) as exc:
        load_policy(org, forged)
    assert exc.value.reason is Reason.POLICY_UNSIGNED


def test_policy_downgraded_to_one_of_n_by_the_server_is_rejected(org):
    """The headline attack: a compromised server sets m=1 and approves its own order."""
    payload = PolicyPayload.model_validate(org.policy_bundle["payload"])
    weakened = payload.model_copy(
        update={
            "severities": {
                **payload.severities,
                "critical": payload.severities["critical"].model_copy(
                    update={"launch": QuorumRule(m=1)}
                ),
            }
        }
    )
    attacker, _ = generate_keypair()
    with pytest.raises(PolicyRejected):
        load_policy(org, sign_bundle(weakened, DOMAIN_POLICY, attacker))


def test_policy_version_rollback_is_rejected(org):
    with pytest.raises(PolicyRejected) as exc:
        load_policy(org, min_version=9)
    assert exc.value.reason is Reason.POLICY_ROLLBACK


def test_policy_expiry(org):
    policy = load_policy(org)
    assert not policy.is_expired(ISSUED_AT)
    assert policy.is_expired(ISSUED_AT + 400 * 24 * 3600)


def test_rule_lookup_distinguishes_launch_from_cancel(org):
    policy = load_policy(org)
    from alerting.core.envelope import Severity

    assert policy.rule_for(Severity.CRITICAL, is_cancel=False).m == 2
    assert policy.rule_for(Severity.CRITICAL, is_cancel=True).m == 1


def test_scenario_lookup(org):
    policy = load_policy(org)
    assert policy.scenario("EVAC.BUILDING") is not None
    assert policy.scenario("NOT.IN.CODEBOOK") is None
