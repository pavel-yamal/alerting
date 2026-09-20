"""Orders, the acknowledgement dashboard, and ACK submission."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from alerting.core.audit_chain import Event
from alerting.core.envelope import Signature, SignedAck
from alerting.core.receipts import verify_ack

router = APIRouter(prefix="/v1", tags=["orders"])


class AckRequest(BaseModel):
    payload: dict[str, Any]
    signature: Signature


@router.get("/orders")
async def list_orders(request: Request, limit: int = 20) -> dict[str, Any]:
    app = request.app.state.alerting
    return {
        "orders": [
            {
                "order_id": row["order_id"],
                "drill": bool(row["drill"]),
                "severity": row["severity"],
                "scenario": row["scenario"],
                "dispatched_at": row["dispatched_at"],
                "cancels": row["cancels"],
            }
            for row in app.repo.orders(limit)
        ]
    }


@router.get("/orders/{order_id}")
async def get_order(order_id: str, request: Request) -> dict[str, Any]:
    app = request.app.state.alerting
    row = app.repo.order(order_id)
    if row is None:
        raise HTTPException(404, "no such order")
    return json.loads(row["envelope_json"])


@router.get("/orders/{order_id}/status")
async def order_status(order_id: str, request: Request) -> dict[str, Any]:
    """Who has acknowledged. This is what the decision-makers actually watch."""
    app = request.app.state.alerting
    status = app.dispatcher.status(order_id)
    if not status:
        raise HTTPException(404, "no such order")
    return status


@router.post("/acks")
async def submit_ack(body: AckRequest, request: Request) -> dict[str, Any]:
    """Accept a signed receipt.

    An invalid ACK is recorded rather than dropped: it means somebody is trying to pass
    themselves off as an executor, and the dashboard has to show that. It also does not
    count toward acknowledgement, so escalation keeps running.
    """
    app = request.app.state.alerting
    ack = SignedAck(payload=body.payload, signature=body.signature)
    try:
        parsed = ack.parse_payload()
    except Exception as exc:
        raise HTTPException(400, "malformed ack") from exc

    row = app.repo.order(parsed.order_id)
    if row is None:
        raise HTTPException(404, "no such order")

    ok, reasons = verify_ack(
        ack,
        directory=app.state.directory(),
        org_id=app.state.org_id,
        expected_order_digest=row["order_digest"],
    )
    app.repo.record_ack(
        parsed.order_id,
        parsed.person_id,
        parsed.device_key_id,
        str(parsed.status),
        parsed.at,
        ack.model_dump(mode="json"),
        ok,
        [str(r) for r in reasons],
    )
    app.audit.append(
        Event.ACK_RECEIVED if ok else Event.ACK_REJECTED,
        {
            "order_id": parsed.order_id,
            "person_id": parsed.person_id,
            "status": str(parsed.status),
            "valid": ok,
            "reasons": [str(r) for r in reasons],
        },
    )
    return {"accepted": ok, "reasons": [str(r) for r in reasons]}
