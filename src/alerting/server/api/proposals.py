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

    #: Required, with no empty default. An order addressed to nobody is an operator
    #: error, and it has to be caught here — before approvers spend signatures on it —
    #: rather than surfacing as a successfully dispatched no-op.
    audience: Audience
    text: str = ""
    ttl_s: int = Field(default=900, ge=60, le=86400)
    stream_id: str = "primary"
    requires_ack: bool = True
    ack_deadline_s: int = Field(default=120, ge=0, le=86400)
    cancels: str | None = None

    #: There is deliberately no ``created_by``. It used to be a string the client
    #: asserted about itself, written straight into an undeletable audit chain --
    #: so the one field naming who started an emergency order was the one field
    #: nobody had checked. It now comes from the request signature.


class SignatureRequest(BaseModel):
    key_id: str
    sig: str


@router.post("")
async def create_proposal(body: ProposalRequest, request: Request) -> dict[str, Any]:
    app = request.app.state.alerting
    if body.audience.is_empty():
        raise HTTPException(422, "audience is empty: this order would reach nobody")
    now = app.clock.now()
    # No transaction here any more: `next_seq` is now a single atomic upsert on the
    # `streams` table, so the number is allocated the instant it is handed out. It
    # used to be SELECT MAX(seq) followed, twenty-five lines later, by an insert --
    # a read-modify-write two concurrent proposals on one stream both won.
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
        # Nothing is delivered in RSS-only mode, so there is nothing to acknowledge.
        requires_ack=False if app.settings.rss_only else body.requires_ack,
        ack_deadline_s=0 if app.settings.rss_only else body.ack_deadline_s,
        policy_id=policy.policy_id,
        cancels=body.cancels,
    )
    raw = payload.to_payload()
    created_by = request.state.principal.person_id
    app.repo.create_proposal(payload.order_id, body.stream_id, seq, raw, now, created_by)
    app.audit.append(
        Event.PROPOSAL_CREATED,
        {
            "order_id": payload.order_id,
            "scenario": payload.scenario,
            "severity": str(payload.severity),
            "drill": payload.drill,
            "created_by": created_by,
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


#: How far back the list reaches for proposals that are no longer open. Open ones are
#: listed whatever their age.
RECENT_S = 24 * 3600


@router.get("")
async def list_proposals(request: Request) -> dict[str, Any]:
    """Every open proposal, and the last day's closed ones, for every decision-maker.

    This list used to live in the panel's memory: a proposal was visible only through
    the panel that created it, and lost when that panel restarted -- so the second
    decision-maker, on another device, never saw what was waiting for his signature.
    """
    import json

    app = request.app.state.alerting
    rows = app.repo.recent_proposals(app.clock.now() - RECENT_S)
    signatures = app.repo.signatures_for([row["order_id"] for row in rows])
    return {
        # The panel and the app say "goes to the RSS feed" instead of "everyone gets it".
        "delivery": app.settings.delivery,
        "proposals": [
            {
                "order_id": row["order_id"],
                "status": row["status"],
                "created_at": row["created_at"],
                "payload": json.loads(row["payload_json"]),
                "signatures": [
                    {"key_id": s["key_id"], "observed_at": s["observed_at"]}
                    for s in signatures.get(row["order_id"], [])
                ],
            }
            for row in rows
        ],
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
    # Two identities, recorded separately on purpose. `key_id` is whose signature
    # this is; `submitted_by` is who carried it to the server. They are the same
    # person today, and requiring that would quietly forbid a signature taken offline
    # and brought in by a dispatcher -- a workflow this system should be able to grow
    # into. Recording both keeps the question answerable either way.
    app.audit.append(
        Event.PROPOSAL_SIGNED,
        {
            "order_id": order_id,
            "key_id": body.key_id,
            "submitted_by": request.state.principal.person_id,
        },
    )

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
    warnings = [str(w) for w in decision.warnings]
    if result.reached_nobody:
        warnings.append("reached_nobody")
    return {
        "order_id": order_id,
        "dispatched": result.accepted,
        "signatures": len(stored),
        "recipients": result.recipients,
        # Never let "quorum met" alone read as success: a validly approved order that
        # matched no active contact is the failure this system exists to prevent.
        "reached_nobody": result.reached_nobody,
        "warnings": warnings,
    }
