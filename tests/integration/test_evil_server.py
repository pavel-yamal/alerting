"""What a fully compromised server can and cannot do.

This is the test for the single most important architectural decision in the project.
The server holds no approver keys and is not the source of authority: clients pin the
org root public key at enrollment and verify the directory and policy bundles against
it. Without that pinning, every "client-side signature check" elsewhere in this suite
would be theatre — a compromised server would simply serve a directory containing its
own key and a policy of ``m: 1``.

What remains after this defence is stated honestly at the bottom: a compromised server
can still suppress, delay, and lie on a dashboard. That is the accepted residual risk,
and it is why heartbeats, escalation and out-of-band fallback exist.
"""

from __future__ import annotations

import pytest

from alerting.core.directory import Directory, DirectoryPayload, DirectoryRejected, KeyEntry
from alerting.core.envelope import Severity, SignedEnvelope
from alerting.core.errors import Reason
from alerting.core.policy import Policy, PolicyPayload, PolicyRejected, QuorumRule
from alerting.core.replay import ReplayWindow
from alerting.core.signing import (
    DOMAIN_DIRECTORY,
    DOMAIN_POLICY,
    generate_keypair,
    key_id,
    public_key_to_b64u,
)
from alerting.core.verify import verify_envelope
from alerting.orgkit import Person, make_order, sign_bundle, sign_order
from tests.integration.conftest import ISSUED_AT


@pytest.fixture
def attacker():
    """The compromised server's own keypair. It is not in the org directory."""
    private, public = generate_keypair()
    return Person(
        person_id="evil-1",
        name="Компрометированный сервер",
        role="lpr",
        private_key=private,
        key_id=key_id(public),
    ), public


def evil_directory(org, attacker_person, attacker_public, version=99):
    """The server injects its own key and signs the directory with its own root."""
    payload = DirectoryPayload.model_validate(org.directory_bundle["payload"])
    injected = KeyEntry(
        key_id=attacker_person.key_id,
        public_key=public_key_to_b64u(attacker_public),
        person_id=attacker_person.person_id,
        name=attacker_person.name,
        role="lpr",
        valid_from=ISSUED_AT - 3600,
    )
    widened = payload.model_copy(update={"version": version, "keys": (*payload.keys, injected)})
    evil_root, _ = generate_keypair()
    return sign_bundle(widened, DOMAIN_DIRECTORY, evil_root)


def evil_policy(org, version=99):
    """The server downgrades critical launches to a single signature."""
    payload = PolicyPayload.model_validate(org.policy_bundle["payload"])
    weakened = payload.model_copy(
        update={
            "version": version,
            "severities": {
                **payload.severities,
                Severity.CRITICAL: payload.severities[Severity.CRITICAL].model_copy(
                    update={"launch": QuorumRule(m=1)}
                ),
            },
        }
    )
    evil_root, _ = generate_keypair()
    return sign_bundle(weakened, DOMAIN_POLICY, evil_root)


def test_client_rejects_an_injected_directory(client, org, attacker, services):
    """The headline case: a key the org never enrolled, served by the server itself."""
    person, public = attacker
    services.repo.put_bundle("directory", 99, evil_directory(org, person, public), ISSUED_AT)

    with pytest.raises(DirectoryRejected) as exc:
        Directory.load(
            services.repo.latest_bundle("directory"),
            root_public_key=org.root_public_key,
            org_id=org.org_id,
        )
    assert exc.value.reason is Reason.DIRECTORY_UNSIGNED


def test_client_rejects_a_downgraded_policy(client, org, services):
    services.repo.put_bundle("policy", 99, evil_policy(org), ISSUED_AT)

    with pytest.raises(PolicyRejected) as exc:
        Policy.load(
            services.repo.latest_bundle("policy"),
            root_public_key=org.root_public_key,
            org_id=org.org_id,
        )
    assert exc.value.reason is Reason.POLICY_UNSIGNED


def test_an_order_signed_only_by_the_attacker_fails_client_side(org, attacker, clock):
    """Even if the server dispatches it, the executor's device refuses it."""
    person, _ = attacker
    envelope = sign_order(make_order(org), [person])

    decision = verify_envelope(
        envelope,
        directory=Directory.load(
            org.directory_bundle, root_public_key=org.root_public_key, org_id=org.org_id
        ),
        policy=Policy.load(
            org.policy_bundle, root_public_key=org.root_public_key, org_id=org.org_id
        ),
        clock=clock,
        replay=ReplayWindow(),
        org_id=org.org_id,
    )
    assert decision.rejected
    assert Reason.UNKNOWN_SIGNER in decision.reasons


def test_the_server_cannot_roll_a_client_back_past_a_revocation(org):
    """Serving yesterday's directory would resurrect a revoked key, so a client that
    has seen version N refuses anything below it."""
    with pytest.raises(DirectoryRejected) as exc:
        Directory.load(
            org.directory_bundle,
            root_public_key=org.root_public_key,
            org_id=org.org_id,
            min_version=2,
        )
    assert exc.value.reason is Reason.DIRECTORY_ROLLBACK


def test_the_server_cannot_alter_a_dispatched_order(client, org, services, clock):
    """Rewriting stored bytes breaks the signatures the client checks itself."""
    from tests.integration.test_e2e_ws import client_side_verify, propose, sign

    proposal = propose(client)
    sign(client, proposal, org.person("p-001"))
    sign(client, proposal, org.person("p-002"))

    stored = client.get(f"/v1/orders/{proposal['order_id']}").json()
    tampered = {
        **stored,
        "payload": {**stored["payload"], "scenario": "SHELTER.IN.PLACE"},
    }
    decision = client_side_verify(client, org, tampered, clock)
    assert decision.rejected
    assert Reason.BAD_SIGNATURE in decision.reasons


def test_residual_risk_a_compromised_server_can_still_suppress(client, org, services):
    """Documented, not fixed. Suppression is why heartbeats, escalation and the printed
    out-of-band fallback exist — see docs/01-threat-model.md."""
    from tests.integration.test_e2e_ws import propose, sign

    proposal = propose(client)
    sign(client, proposal, org.person("p-001"))
    sign(client, proposal, org.person("p-002"))

    # The server simply declines to fan out. Nothing cryptographic detects this.
    status = client.get(f"/v1/orders/{proposal['order_id']}/status").json()
    assert status["acknowledged"] == 0
    assert status["outstanding"], "escalation is what notices this, not verification"


def test_verification_does_not_depend_on_the_transport(org, clock):
    """The same envelope verifies identically whether it came over the socket or not."""
    envelope_dict = sign_order(
        make_order(org), [org.person("p-001"), org.person("p-002")]
    ).model_dump(mode="json")

    decision = verify_envelope(
        SignedEnvelope.model_validate(envelope_dict),
        directory=Directory.load(
            org.directory_bundle, root_public_key=org.root_public_key, org_id=org.org_id
        ),
        policy=Policy.load(
            org.policy_bundle, root_public_key=org.root_public_key, org_id=org.org_id
        ),
        clock=clock,
        replay=ReplayWindow(),
        org_id=org.org_id,
    )
    assert decision.accepted
