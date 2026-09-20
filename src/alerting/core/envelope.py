"""Normative definitions of everything that gets signed.

Three rules that are security controls rather than style:

* ``extra="forbid"`` — an unknown field is a rejection, not something to drop
  quietly. Dropping it would mean the bytes we verified are not the bytes we parsed.
* Strict scalars — ``"seq": "1247"`` must not quietly become ``1247``. Coercion
  changes the canonical bytes and therefore changes what the signature covers. Enums
  still load from their string values, because that round-trips to identical bytes.
  The authoritative guard is the canonical byte comparison in ``verify.verify_envelope``;
  these types make the failure happen earlier and with a clearer message.
* ``drill`` has no default. A forgotten flag must be a malformed envelope, never a
  silently "real" order. This is the single field most likely to hurt someone.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)

from alerting.core.canonical import canonicalize

ENVELOPE_VERSION = 1

_STRICT = ConfigDict(extra="forbid", frozen=True)

Identifier = Annotated[StrictStr, Field(min_length=1, max_length=128)]


def _to_tuple(value: Any) -> Any:
    """JSON has only arrays, and ``strict=True`` will not widen a list into a tuple.

    Accepting the list is safe: both serialize to the same canonical JSON array, so
    this cannot change the bytes a signature covers. Tuples are used internally so the
    models stay genuinely immutable.
    """
    return tuple(value) if isinstance(value, list) else value


def seq_of(item: Any) -> Any:
    """An immutable sequence field that still loads from JSON."""
    return Annotated[tuple[item, ...], BeforeValidator(_to_tuple)]


class Severity(StrEnum):
    """Severity drives the quorum rule and the escalation ladder."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    CATASTROPHIC = "catastrophic"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.WARNING: 1,
    Severity.CRITICAL: 2,
    Severity.CATASTROPHIC: 3,
}


class Action(StrEnum):
    START = "START"
    STOP = "STOP"
    HOLD = "HOLD"


class AckStatus(StrEnum):
    RECEIVED = "received"  # emitted by the device itself
    ACKNOWLEDGED = "acknowledged"  # a human tapped
    EN_ROUTE = "en_route"
    COMPLETED = "completed"
    CANNOT_COMPLY = "cannot_comply"


class CanonicalModel(BaseModel):
    """Base for every signed structure."""

    model_config = _STRICT

    def to_payload(self) -> dict[str, Any]:
        """The dict that gets canonicalized. ``exclude_none`` implements absent-means-absent."""
        return self.model_dump(mode="json", exclude_none=True)

    def canonical_bytes(self) -> bytes:
        return canonicalize(self.to_payload())


class Audience(CanonicalModel):
    """Who the order is addressed to. Empty everywhere means nobody, which is a bug."""

    sites: seq_of(Identifier) = ()
    groups: seq_of(Identifier) = ()
    persons: seq_of(Identifier) = ()

    def is_empty(self) -> bool:
        return not (self.sites or self.groups or self.persons)


class OrderPayload(CanonicalModel):
    """A launch or stand-down order. This is what approvers sign."""

    v: Literal[1]
    type: Literal["order", "cancel"]
    order_id: Identifier
    org_id: Identifier
    stream_id: Identifier
    seq: StrictInt = Field(ge=0)
    nonce: Identifier
    issued_at: StrictInt = Field(ge=0)
    not_valid_after: StrictInt = Field(ge=0)
    severity: Severity
    drill: StrictBool
    scenario: Identifier
    action: Action
    audience: Audience
    text: StrictStr = Field(default="", max_length=2000)
    requires_ack: StrictBool = True
    ack_deadline_s: StrictInt = Field(default=120, ge=0, le=86400)
    policy_id: Identifier
    cancels: Identifier | None = None

    @model_validator(mode="after")
    def _check_shape(self) -> Self:
        if self.not_valid_after <= self.issued_at:
            raise ValueError("not_valid_after must be strictly after issued_at")
        if self.type == "cancel" and self.cancels is None:
            raise ValueError("a cancel must name the order_id it cancels")
        if self.type == "order" and self.cancels is not None:
            raise ValueError("only a cancel may carry 'cancels'")
        if self.type == "cancel" and self.cancels == self.order_id:
            raise ValueError("a cancel cannot cancel itself")
        return self

    @property
    def is_cancel(self) -> bool:
        return self.type == "cancel"


class Signature(CanonicalModel):
    """A detached approver signature.

    Deliberately carries no ``signed_at``: anything outside the signed payload is
    forgeable, and a forgeable timestamp that *looks* authoritative is worse than none.
    Timing evidence lives in the audit chain and in the payload's own ``issued_at``.
    """

    key_id: Identifier
    alg: Literal["Ed25519"]
    sig: Identifier


class SignedEnvelope(BaseModel):
    """Wire format: the payload exactly as received, plus detached signatures.

    The payload is kept as a raw mapping on purpose. Verification re-parses it and
    re-canonicalizes, then asserts the bytes are identical, so a parser that quietly
    normalized something can never widen what a signature appears to cover.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    payload: dict[str, Any]
    signatures: tuple[Signature, ...] = ()

    def parse_payload(self) -> OrderPayload:
        return OrderPayload.model_validate(self.payload)

    def with_signature(self, signature: Signature) -> SignedEnvelope:
        return SignedEnvelope(
            payload=self.payload, signatures=(*self.signatures, signature)
        )


class AckPayload(CanonicalModel):
    """An executor's signed receipt.

    ``order_digest`` is the load-bearing field: it proves which exact order text the
    executor had in front of them.
    """

    v: Literal[1]
    type: Literal["ack"]
    order_id: Identifier
    org_id: Identifier
    person_id: Identifier
    device_key_id: Identifier
    status: AckStatus
    at: StrictInt = Field(ge=0)
    nonce: Identifier
    order_digest: Identifier
    reason: StrictStr | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _reason_required_for_refusal(self) -> Self:
        if self.status is AckStatus.CANNOT_COMPLY and not self.reason:
            raise ValueError("cannot_comply must state a reason")
        return self


class SignedAck(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    payload: dict[str, Any]
    signature: Signature

    def parse_payload(self) -> AckPayload:
        return AckPayload.model_validate(self.payload)
