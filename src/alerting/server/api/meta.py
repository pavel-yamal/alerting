"""Bundles, roster, audit access and health."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request

from alerting.core.audit_chain import head_of

router = APIRouter(prefix="/v1", tags=["meta"])


@router.get("/directory")
async def directory(request: Request) -> dict[str, Any]:
    """The root-signed key directory. Clients verify it against their pinned root key
    and refuse any version lower than the highest they have seen."""
    app = request.app.state.alerting
    return app.state.directory_bundle


@router.get("/policy")
async def policy(request: Request) -> dict[str, Any]:
    app = request.app.state.alerting
    return app.state.policy_bundle


@router.get("/roster")
async def roster(request: Request) -> dict[str, Any]:
    """Pseudonymous by default. Names and phone numbers are personal data and are not
    served here; see docs/08-personal-data.md."""
    app = request.app.state.alerting
    return {
        "people": [
            {
                "person_id": row["person_id"],
                "role": row["role"],
                "site": row["site"],
                "groups": [g for g in row["groups_csv"].split(",") if g],
            }
            for row in app.repo.contacts()
        ]
    }


@router.get("/audit")
async def audit(request: Request, from_idx: int = 0, limit: int = 200) -> dict[str, Any]:
    app = request.app.state.alerting
    entries = list(app.repo.audit_entries(from_idx, limit))
    return {"entries": entries, "count": app.repo.audit_count(), "heads": app.repo.heads()}


@router.get("/audit/head")
async def audit_head(request: Request) -> dict[str, Any]:
    app = request.app.state.alerting
    row = app.repo.latest_head()
    if row is None:
        raise HTTPException(404, "no head published yet")
    return {"idx": row["idx"], "head": row["head"], "ts": row["ts"], "signature": row["signature"]}


@router.post("/audit/head")
async def publish_head(request: Request) -> dict[str, Any]:
    """Force a head now. Used by the drill runbook at the end of an exercise."""
    app = request.app.state.alerting
    entries = list(app.repo.audit_entries(0, 1_000_000))
    if not entries:
        raise HTTPException(409, "empty chain")
    return app.audit.publish_head(len(entries) - 1, head_of(entries), app.clock.now())


@router.get("/healthz")
async def healthz(request: Request) -> dict[str, Any]:
    app = request.app.state.alerting
    return {
        "ok": True,
        "org": app.state.org_id,
        "audit_entries": app.repo.audit_count(),
        "connected": app.connections.connected_people(),
        "channels": app.channels.names(),
    }
