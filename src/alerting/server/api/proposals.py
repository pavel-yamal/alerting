"""Proposals and signature collection.

A proposal is never actionable. An operator with a stolen password can create one all
day; it becomes an order only when enough approver signatures arrive to satisfy the
root-signed policy. That separation is the point of the endpoint split.
"""

from __future__ import annotations

import secrets
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from alerting.core.audit_chain import Event
from alerting.core.canonical import canonicalize
from alerting.core.envelope import (
    Action,
    Audience,
    OrderPayload,
    Severity,
    Signature,
    SignedEnvelope,
)
from alerting.core.signing import ALG_ED25519, DOMAIN_ORDER, b64u_encode

router = APIRouter(prefix="/v1/proposals", tags=["proposals"])


class ProposalRequest(BaseModel):
    scenario: str
    severity: Severity
    drill: bool  # required here too: no default anywhere in the stack
    action: Action = Action.START
    audience: Audience = Audience()
    text: str = ""
    ttl_s: int = Field(default=900, ge=60, le=86400)
    stream_id: str = "primary"
    requires_ack: bool = True
    ack_deadline_s: int = Field(default=120, ge=0, le=86400)
    created_by: str = "dispatcher"
    cancels: str | None = None


class SignatureRequest(BaseModel):
    key_id: str
    sig: str


@router.post("")
async def create_proposal(body: ProposalRequest, request: Request) -> dict[str, Any]:
    app = request.app.state.alerting
    now = app.clock.now()
    seq = app.repo.next_seq(body.stream_id)
    policy = app.state.policy()

    payload = OrderPayload(
        v=1,
        type="cancel" if body.cancels else "order",
        order_id=str(uuid.uuid4()),
        org_id=app.state.org_id,
        stream_id=body.stream_id,
        seq=seq,
        nonce=secrets.token_urlsafe(16),
        issued_at=now,
        not_valid_after=now + body.ttl_s,
        severity=body.severity,
        drill=body.drill,
        scenario=body.scenario,
        action=body.action,
        audience=body.audience,
        text=body.text,
        requires_ack=body.requires_ack,
        ack_deadline_s=body.ack_deadline_s,
        policy_id=policy.policy_id,
        cancels=body.cancels,
    )
    raw = payload.to_payload()
    app.repo.create_proposal(payload.order_id, body.stream_id, seq, raw, now, body.created_by)
    app.audit.append(
        Event.PROPOSAL_CREATED,
        {
            "order_id": payload.order_id,
            "scenario": payload.scenario,
            "severity": str(payload.severity),
            "drill": payload.drill,
            "created_by": body.created_by,
        },
    )
    rule = policy.rule_for(payload.severity, is_cancel=payload.is_cancel)
    return {
        "order_id": payload.order_id,
        "payload": raw,
        # Exactly what each approver must sign. Returned so a client never has to
        # reimplement canonicalization and risk signing different bytes.
        "signing_input_b64u": b64u_encode(DOMAIN_ORDER + canonicalize(raw)),
        "required_signatures": rule.m if rule else None,
    }


@router.get("/{order_id}")
async def get_proposal(order_id: str, request: Request) -> dict[str, Any]:
    app = request.app.state.alerting
    row = app.repo.proposal(order_id)
    if row is None:
        raise HTTPException(404, "no such proposal")
    import json

    signatures = app.repo.signatures(order_id)
    return {
        "order_id": order_id,
        "status": row["status"],
        "payload": json.loads(row["payload_json"]),
        "signatures": [
            {"key_id": s["key_id"], "observed_at": s["observed_at"]} for s in signatures
        ],
    }


@router.post("/{order_id}/signatures")
async def add_signature(order_id: str, body: SignatureRequest, request: Request) -> dict[str, Any]:
    """Record an approver signature; dispatch automatically once quorum is met."""
    app = request.app.state.alerting
    row = app.repo.proposal(order_id)
    if row is None:
        raise HTTPException(404, "no such proposal")
    if row["status"] != "open":
        raise HTTPException(409, f"proposal is {row['status']}")

    import json

    payload = json.loads(row["payload_json"])
    now = app.clock.now()
    app.repo.add_signature(order_id, body.key_id, body.sig, now)
    app.audit.append(Event.PROPOSAL_SIGNED, {"order_id": order_id, "key_id": body.key_id})

    stored = app.repo.signatures(order_id)
    envelope = SignedEnvelope(
        payload=payload,
        signatures=tuple(
            Signature(key_id=s["key_id"], alg=ALG_ED25519, sig=s["sig"]) for s in stored
        ),
    )
    observed = {s["key_id"]: s["observed_at"] for s in stored}
    decision = app.dispatcher.check(envelope, observed)

    if not decision.accepted:
        return {
            "order_id": order_id,
            "dispatched": False,
            "signatures": len(stored),
            "blocking": [str(r) for r in decision.reasons],
        }

    result = await app.dispatcher.dispatch(envelope, observed_at=observed)
    app.repo.set_proposal_status(order_id, "dispatched")
    return {
        "order_id": order_id,
        "dispatched": result.accepted,
        "signatures": len(stored),
        "recipients": result.recipients,
        "warnings": [str(w) for w in decision.warnings],
    }
