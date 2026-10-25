"""Devices of decision-makers that receive push from the app.

Every route is a signed request from the person whose device it is (ROUTE_ROLES):
a device is registered for whoever signed, never for a person named in the body.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from alerting.server.services.lpr_notify import TEST, mask

router = APIRouter(prefix="/v1/push", tags=["push"])


class TokenForm(BaseModel):
    token: str = Field(min_length=8, max_length=4096)
    platform: str = Field(pattern="^(ios|android)$")
    device_label: str = Field(default="", max_length=120)
    app_version: str = Field(default="", max_length=40)


class TokenRef(BaseModel):
    token: str = Field(min_length=8, max_length=4096)


@router.post("/tokens")
async def register(body: TokenForm, request: Request) -> dict[str, Any]:
    app = request.app.state.alerting
    principal = request.state.principal
    app.repo.save_push_token(
        body.token.strip(),
        principal.person_id,
        principal.key_id,
        body.platform,
        device_label=body.device_label,
        app_version=body.app_version,
        at=app.clock.now(),
    )
    return {
        "token": mask(body.token.strip()),
        # Whether this server can push to this platform at all: an app that
        # registered fine but will never be notified has to be able to say so.
        "configured": app.notifier.push.configured[body.platform],
    }


@router.post("/tokens/remove")
async def remove(body: TokenRef, request: Request) -> dict[str, Any]:
    """Forget a device of the caller's. The same answer whether or not it was there."""
    app = request.app.state.alerting
    app.repo.delete_push_token(body.token.strip(), request.state.principal.person_id)
    return {"ok": True}


@router.post("/test")
async def test(request: Request) -> dict[str, Any]:
    """Send a test notification to every device of the caller's, and say what happened."""
    app = request.app.state.alerting
    person_id = request.state.principal.person_id
    results = await app.notifier.send({person_id}, TEST)
    return {"configured": app.notifier.push.configured, "devices": results}
