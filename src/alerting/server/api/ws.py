"""The executor stream.

The handshake is a challenge-response over the device's Ed25519 key, so the server
knows who it is talking to for routing and ACK attribution.

Worth stating plainly, because it is easy to assume otherwise: **order authenticity
does not depend on this handshake at all.** The client reaches the same verdict about
an envelope whether it arrived over this socket, over push, or on a USB stick. If this
were the only check, a compromised server could fabricate orders freely.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from alerting.core.audit_chain import Event
from alerting.core.clock import TRANSPORT_AUTH_WINDOW_S
from alerting.core.envelope import OrderPayload, Signature, SignedAck
from alerting.core.receipts import verify_ack
from alerting.core.signing import DOMAIN_DEVICE_AUTH, verify_signature

log = logging.getLogger("alerting.api.ws")

router = APIRouter(tags=["stream"])


#: How long an unauthenticated socket may stay open. Without it, anyone could accept
#: a socket and hold it indefinitely without ever proving who they are.
AUTH_FRAME_TIMEOUT_S = 5

#: A signed envelope is a couple of kilobytes; an ACK is smaller. Anything larger is
#: not a client of this protocol.
MAX_FRAME_BYTES = 64 * 1024


class WebSocketSink:
    """Adapts a FastAPI WebSocket to the channel registry's Sink protocol."""

    def __init__(self, websocket: WebSocket) -> None:
        self.websocket = websocket

    async def send_json(self, data: dict[str, Any]) -> None:
        await self.websocket.send_json(data)

    async def close(self, code: int) -> None:
        await self.websocket.close(code=code)


@router.websocket("/v1/stream")
async def stream(websocket: WebSocket) -> None:
    app = websocket.app.state.alerting
    await websocket.accept()

    nonce = secrets.token_urlsafe(16)
    now = app.clock.now()
    await websocket.send_json({"kind": "challenge", "nonce": nonce, "at": now})

    try:
        message = await asyncio.wait_for(_receive_bounded(websocket), AUTH_FRAME_TIMEOUT_S)
    except TimeoutError:
        await websocket.close(code=4408, reason="auth timeout")
        return
    except (WebSocketDisconnect, ValueError):
        return

    person_id = await _authenticate(app, websocket, message, nonce, now)
    if person_id is None:
        return

    sink = WebSocketSink(websocket)
    if not await app.connections.attach(person_id, sink):
        await websocket.close(code=4429, reason="too many devices")
        return
    await websocket.send_json({"kind": "ready", "person_id": person_id, "org_id": app.state.org_id})
    await _send_active_events(app, websocket, person_id)

    try:
        while True:
            frame = await _receive_bounded(websocket)
            await _handle_frame(app, websocket, frame, person_id)
    except FrameTooLarge:
        await websocket.close(code=1009, reason="frame too large")
    except (WebSocketDisconnect, ValueError):
        pass
    finally:
        await app.connections.detach(person_id, sink)


async def _send_active_events(app: Any, websocket: WebSocket, person_id: str) -> None:
    """Tell a device that has just connected which events addressed to it are in force.

    Someone coming on shift, or a phone that was off, would otherwise see nothing
    until the next order. Sent as ``active``, not ``order``: it is a re-statement of
    something already dispatched, and the client verifies it fully but does not
    treat it as a new delivery (no replay rejection for an order it already saw,
    no new alarm for one it already holds).
    """
    try:
        events = app.dispatcher.active_events(app.clock.now())
    except Exception:
        log.warning("could not list active events for %s", person_id, exc_info=True)
        return
    for event in reversed(events):  # oldest first, the order they happened in
        order = OrderPayload.model_validate(event["payload"])
        if any(r.person_id == person_id for r in app.state.recipients_for(order)):
            await websocket.send_json({"kind": "active", "envelope": event["envelope"]})
    # Then the day's signed stand-downs, so a device that missed one while offline
    # can close the event it already holds. A client applies a stand-down only to an
    # event it has; one for an event it never saw is ignored.
    for standdown in app.dispatcher.recent_standdowns(app.clock.now()):
        order = OrderPayload.model_validate(standdown["envelope"]["payload"])
        if any(r.person_id == person_id for r in app.state.recipients_for(order)):
            await websocket.send_json({"kind": "active", "envelope": standdown["envelope"]})


async def _authenticate(
    app: Any, websocket: WebSocket, message: dict[str, Any], nonce: str, now: int
) -> str | None:
    payload = message.get("payload")
    signature = message.get("sig")
    if message.get("kind") != "auth" or not isinstance(payload, dict) or not signature:
        await websocket.close(code=4400, reason="auth expected")
        return None

    # The nonce binds the signature to this connection, so a captured handshake
    # cannot be replayed onto a new socket.
    if payload.get("nonce") != nonce or payload.get("org_id") != app.state.org_id:
        await websocket.close(code=4401, reason="bad auth payload")
        return None
    # `int()` on an attacker-supplied value: a string or a list here used to raise out
    # of the handler rather than close the socket. Everything in this frame is
    # attacker-controlled, so every step of it has to answer "refused", not "crash".
    at = payload.get("at")
    if not isinstance(at, int) or isinstance(at, bool) or abs(at - now) > TRANSPORT_AUTH_WINDOW_S:
        await websocket.close(code=4401, reason="stale auth")
        return None

    key_id = payload.get("key_id")
    directory = app.state.directory()
    if not isinstance(key_id, str) or directory.signer_status(key_id, now) is not None:
        await websocket.close(code=4403, reason="unknown or revoked device")
        return None

    entry = directory.lookup(key_id)
    if entry is None or not verify_signature(
        DOMAIN_DEVICE_AUTH, payload, signature, entry.public()
    ):
        await websocket.close(code=4403, reason="bad device signature")
        return None
    if entry.person_id != payload.get("person_id"):
        await websocket.close(code=4403, reason="person mismatch")
        return None
    return entry.person_id


async def _handle_frame(
    app: Any, websocket: WebSocket, frame: dict[str, Any], person_id: str
) -> None:
    kind = frame.get("kind")
    if kind == "ping":
        await websocket.send_json({"kind": "pong", "at": app.clock.now()})
        return
    if kind != "ack":
        return

    try:
        ack = SignedAck(
            payload=frame["payload"], signature=Signature.model_validate(frame["signature"])
        )
        parsed = ack.parse_payload()
    except Exception:
        await websocket.send_json({"kind": "ack-result", "accepted": False})
        return

    row = app.repo.order(parsed.order_id)
    if row is None:
        await websocket.send_json({"kind": "ack-result", "accepted": False})
        return

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
        },
    )
    await websocket.send_json({"kind": "ack-result", "accepted": ok})


class FrameTooLarge(ValueError):
    """The peer sent more than this protocol ever needs."""


async def _receive_bounded(websocket: WebSocket) -> dict[str, Any]:
    """Read one JSON frame, refusing anything oversized before parsing it.

    ``receive_json`` would happily parse a megabyte first and complain afterwards.
    """
    raw = await websocket.receive_text()
    if len(raw) > MAX_FRAME_BYTES:
        raise FrameTooLarge(f"{len(raw)} bytes")
    return json.loads(raw)  # type: ignore[no-any-return]
