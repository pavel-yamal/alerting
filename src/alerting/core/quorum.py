"""M-of-N quorum evaluation — the two-man rule.

Plain multi-signature, deliberately not a threshold scheme. FROST or MuSig would
aggregate the approvers into one signature and hide *who* signed; here per-approver
attribution is the whole point of the audit trail, so aggregation would destroy the
property we are building.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field

from alerting.core.directory import KeyEntry
from alerting.core.errors import Reason
from alerting.core.policy import QuorumRule


@dataclass(frozen=True)
class QuorumResult:
    met: bool
    reasons: tuple[Reason, ...] = ()
    signer_key_ids: tuple[str, ...] = ()
    signer_person_ids: tuple[str, ...] = ()
    detail: dict[str, object] = field(default_factory=dict)


def evaluate_quorum(
    valid_signers: Sequence[KeyEntry],
    rule: QuorumRule,
    *,
    issued_at: int,
    approver_roles: Collection[str],
    observed_at: Mapping[str, int] | None = None,
) -> QuorumResult:
    """Decide whether these verified signers satisfy the rule.

    A verified signature is not the same thing as authority to approve. The directory
    holds every enrolled key, executors' ACK-signing devices included, so the role
    allowlist is what keeps "this signature is genuine" from silently meaning "this
    person may order an evacuation".

    Args:
        valid_signers: directory entries whose signatures already verified.
        rule: the launch or cancel rule for this severity.
        issued_at: the payload's issue time, shared by every signer.
        approver_roles: roles permitted to approve, from the root-signed policy.
        observed_at: when the server *saw* each signature arrive, keyed by ``key_id``.
            Only the server has this. Signature entries carry no self-asserted
            timestamp (it would be forgeable), so ``max_signature_spread_s`` can only
            be enforced where an independent observation exists. Clients pass ``None``
            and rely on the payload TTL instead; this is documented in
            docs/03-envelope-spec.md rather than silently skipped.

    Returns:
        A ``QuorumResult``. ``met=False`` always carries at least one reason.
    """
    reasons: list[Reason] = []

    permitted = frozenset(approver_roles)
    authorized = [entry for entry in valid_signers if entry.role in permitted]
    # Dropping a non-approver's signature is not fatal on its own — an extra signature
    # does not invalidate an order the real approvers signed — but it never counts
    # toward the quorum, and the operator is told when one was discarded.
    dropped_unauthorized = len(authorized) != len(valid_signers)
    valid_signers = authorized

    key_ids = [entry.key_id for entry in valid_signers]
    if len(set(key_ids)) != len(key_ids):
        reasons.append(Reason.DUPLICATE_SIGNER)

    person_ids: list[str] = []
    for entry in valid_signers:
        if entry.person_id not in person_ids:
            person_ids.append(entry.person_id)

    effective = len(person_ids) if rule.distinct_persons else len(set(key_ids))
    if effective < rule.m:
        reasons.append(Reason.QUORUM_NOT_MET)
        if rule.distinct_persons and len(set(key_ids)) >= rule.m:
            # Enough keys, not enough humans: one person with two devices.
            reasons.append(Reason.NOT_DISTINCT_PERSONS)

    for role, required in rule.min_from_role.items():
        holders = {entry.person_id for entry in valid_signers if entry.role == role}
        if len(holders) < required:
            reasons.append(Reason.ROLE_REQUIREMENT_UNMET)
            break

    if rule.max_signature_spread_s is not None and observed_at:
        times = [observed_at[k] for k in key_ids if k in observed_at]
        if times and max(times) - issued_at > rule.max_signature_spread_s:
            reasons.append(Reason.SIGNATURE_SPREAD_EXCEEDED)

    if dropped_unauthorized and reasons:
        reasons.append(Reason.UNAUTHORIZED_SIGNER_ROLE)

    return QuorumResult(
        met=not reasons,
        reasons=tuple(dict.fromkeys(reasons)),
        signer_key_ids=tuple(key_ids),
        signer_person_ids=tuple(person_ids),
        detail={
            "required": rule.m,
            "effective": effective,
            "dropped_unauthorized": dropped_unauthorized,
        },
    )
