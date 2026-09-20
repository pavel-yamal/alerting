"""Quorum and scenario policy — also root-signed, also version-monotonic.

A policy that the server could rewrite would let a compromised server set ``m: 1`` and
approve its own orders. So the policy travels the same trust path as the directory.
"""

from __future__ import annotations

from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, StrictBool, StrictInt, StrictStr

from alerting.core.envelope import CanonicalModel, Identifier, Severity
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


class PolicyPayload(CanonicalModel):
    v: Literal[1]
    type: Literal["policy"]
    org_id: Identifier
    policy_id: Identifier
    version: StrictInt = Field(ge=1)
    issued_at: StrictInt = Field(ge=0)
    not_valid_after: StrictInt = Field(ge=0)
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
    def version(self) -> int:
        return self.payload.version

    def rule_for(self, severity: Severity, *, is_cancel: bool) -> QuorumRule | None:
        rules = self.payload.severities.get(severity)
        if rules is None:
            return None
        return rules.cancel if is_cancel else rules.launch

    def scenario(self, code: str) -> ScenarioRule | None:
        return self.payload.scenarios.get(code)

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
