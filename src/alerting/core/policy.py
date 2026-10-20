"""Quorum and scenario policy — also root-signed, also version-monotonic.

A policy that the server could rewrite would let a compromised server set ``m: 1`` and
approve its own orders. So the policy travels the same trust path as the directory.
"""

from __future__ import annotations

from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, StrictBool, StrictInt, StrictStr

from alerting.core.envelope import CanonicalModel, Identifier, Seq, Severity
from alerting.core.errors import Reason
from alerting.core.signing import DOMAIN_POLICY, verify_signature


class QuorumRule(CanonicalModel):
    """How many signatures, from whom, collected how fast."""

    m: StrictInt = Field(ge=1, le=16)

    #: Bounds how long a half-approved proposal may sit collecting its last signature.
    #: Without it, an approver could sign now and the order could fire next month.
    max_signature_spread_s: StrictInt | None = Field(default=None, ge=0, le=86400)

    #: Stops one human with two enrolled devices from satisfying a 2-of-N alone.
    distinct_persons: StrictBool = True

    #: e.g. {"director": 1} — at least one signature from someone in that role.
    min_from_role: dict[str, StrictInt] = Field(default_factory=dict)


class SeverityRules(CanonicalModel):
    launch: QuorumRule
    cancel: QuorumRule


class ScenarioRule(CanonicalModel):
    min_severity: Severity | None = None
    max_severity: Severity | None = None
    description: StrictStr = Field(default="", max_length=500)

    #: What the executor does, shown on their screen beside the order. Root-signed
    #: with the rest of the policy, so the instruction a person acts on cannot be
    #: rewritten by whoever controls the server.
    #:
    #: Both fields below default to ``None``, not ``""``/``False``: canonical form
    #: omits ``None``, so every policy signed before these fields existed still
    #: canonicalizes to the bytes it was signed over.
    card: StrictStr | None = Field(default=None, max_length=1000)

    #: The event stays in force until a stand-down order cancels it, rather than
    #: lapsing when the envelope's delivery window closes. The window itself is
    #: unchanged -- it still bounds when the envelope may first be accepted -- but
    #: escalation keeps going for people who have not answered, and a device that
    #: connects later is shown the event as active. See ADR 0010.
    until_cancelled: StrictBool | None = None


class PolicyPayload(CanonicalModel):
    v: Literal[1]
    type: Literal["policy"]
    org_id: Identifier
    policy_id: Identifier
    version: StrictInt = Field(ge=1)
    issued_at: StrictInt = Field(ge=0)
    not_valid_after: StrictInt = Field(ge=0)

    #: Roles whose signatures may count toward a quorum. REQUIRED and with no default,
    #: for the same reason ``drill`` has none: a policy that does not say who may
    #: approve must be unusable, not permissive.
    #:
    #: Without this, every key in the directory counted — and the directory also holds
    #: executors' device keys, which exist only to sign ACKs. Two executors could
    #: launch a critical evacuation and one could stand it down, silently contradicting
    #: the separation documented in docs/02-trust-and-approval.md.
    approver_roles: Seq[Identifier] = Field(min_length=1)

    severities: dict[Severity, SeverityRules]
    scenarios: dict[str, ScenarioRule]


class Policy:
    """A verified policy."""

    def __init__(self, payload: PolicyPayload) -> None:
        self.payload = payload

    @property
    def policy_id(self) -> str:
        return self.payload.policy_id

    @property
    def approver_roles(self) -> frozenset[str]:
        """Roles allowed to satisfy a quorum. Root-signed, so a compromised server
        cannot widen it."""
        return frozenset(self.payload.approver_roles)

    @property
    def version(self) -> int:
        return self.payload.version

    def rule_for(self, severity: Severity, *, is_cancel: bool) -> QuorumRule | None:
        rules = self.payload.severities.get(severity)
        if rules is None:
            return None
        return rules.cancel if is_cancel else rules.launch

    def scenario(self, code: str) -> ScenarioRule | None:
        return self.payload.scenarios.get(code)

    def lasts_until_cancelled(self, code: str) -> bool:
        """Whether an event of this scenario stays in force until a stand-down."""
        rule = self.payload.scenarios.get(code)
        return bool(rule and rule.until_cancelled)

    def is_expired(self, now: int) -> bool:
        return now > self.payload.not_valid_after

    @classmethod
    def load(
        cls,
        bundle: dict[str, Any],
        *,
        root_public_key: Ed25519PublicKey,
        org_id: str,
        min_version: int = 0,
    ) -> Policy:
        signature = bundle.get("signature")
        payload_raw = bundle.get("payload")
        if not isinstance(payload_raw, dict) or not isinstance(signature, str):
            raise PolicyRejected(Reason.MALFORMED)

        payload = PolicyPayload.model_validate(payload_raw)
        if payload.to_payload() != payload_raw:
            raise PolicyRejected(Reason.NOT_CANONICAL)
        if payload.org_id != org_id:
            raise PolicyRejected(Reason.ORG_MISMATCH)
        if not verify_signature(DOMAIN_POLICY, payload_raw, signature, root_public_key):
            raise PolicyRejected(Reason.POLICY_UNSIGNED)
        if payload.version < min_version:
            raise PolicyRejected(Reason.POLICY_ROLLBACK)
        return cls(payload)


class PolicyRejected(Exception):
    def __init__(self, reason: Reason) -> None:
        super().__init__(reason.value)
        self.reason = reason
