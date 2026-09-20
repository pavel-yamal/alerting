"""Bundles, roster, audit access and health."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from alerting.wordlist import MIN_WORDLIST_SIZE

log = logging.getLogger("alerting.api.meta")

#: Upper bound on any paged listing.
MAX_PAGE = 1000

router = APIRouter(prefix="/v1", tags=["meta"])

#: Routes that are deliberately reachable without the shared key. Only liveness lives
#: here, and nginx restricts it to the load balancer and localhost anyway.
public_router = APIRouter(prefix="/v1", tags=["public"])


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
async def audit(
    request: Request,
    from_idx: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=MAX_PAGE),
) -> dict[str, Any]:
    """A page of the chain. ``limit`` is bounded: unvalidated, ``?limit=999999999``
    was a one-request memory-exhaustion primitive available to anyone."""
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
    """Force a head now. Used by the drill runbook at the end of an exercise.

    Reads the chain tip rather than loading every entry to recompute it — the old
    version did ``audit_entries(0, 1_000_000)`` on each call, which grew without
    bound and was reachable by anyone.
    """
    app = request.app.state.alerting
    tip = app.repo.chain_tip()
    if tip is None:
        raise HTTPException(409, "empty chain")
    idx, head = tip
    return app.audit.publish_head(idx, head, app.clock.now())


@router.get("/statusz")
async def statusz(request: Request) -> dict[str, Any]:
    """Operational detail. Authenticated, because the connected-person list is a
    roster leak and the channel inventory tells an attacker what is not watching."""
    app = request.app.state.alerting
    return {
        "ok": True,
        "org": app.state.org_id,
        "audit_entries": app.repo.audit_count(),
        "connected": app.connections.connected_people(),
        "channels": {
            name: {"delivers": getattr(app.channels[name], "delivers", False)}
            for name in app.channels.names()
        },
    }


@public_router.get("/readyz")
async def readyz(request: Request) -> dict[str, Any]:
    """Can this node actually dispatch an order? This is what a load balancer wants.

    Liveness is not enough here. Started with the wrong configuration, a node creates
    an empty database, answers ``healthz: ok`` — the old check only counted audit rows,
    which succeeds on an empty table — and is incapable of sending anything. A
    balancer would route alerts to it.
    """
    app = request.app.state.alerting
    checks: dict[str, bool] = {}

    for name, probe in (
        ("database", lambda: app.repo.audit_count() >= 0),
        ("schema", lambda: _schema_ok(app)),
        ("directory", lambda: bool(app.state.directory().payload.keys)),
        ("policy", lambda: bool(app.state.policy().payload.severities)),
        ("wordlist", lambda: len(app.state.wordlist) >= MIN_WORDLIST_SIZE),
        ("escalation", lambda: app.escalation.is_healthy()),
    ):
        try:
            checks[name] = bool(probe())
        except Exception:
            log.warning("readiness check %s failed", name, exc_info=True)
            checks[name] = False

    ready = all(checks.values())
    if not ready:
        failed = sorted(name for name, ok in checks.items() if not ok)
        log.warning("not ready: %s", ", ".join(failed))
    return JSONResponse(  # type: ignore[return-value]
        status_code=200 if ready else 503, content={"ready": ready, "checks": checks}
    )


def _schema_ok(app: Any) -> bool:
    """The database is at the version this build was written against.

    Checked at startup too, but a node can outlive a migration run on a shared
    database: the answer here is what keeps a balancer from sending an alert to a
    node that would fail on the first column it does not have.
    """
    from alerting.server.db import migrate

    with app.pool.connection() as connection:
        migrate.verify(connection)
    return True


@public_router.get("/healthz")
async def healthz(request: Request) -> dict[str, bool]:
    """Liveness for the load balancer, and nothing else.

    It used to return the list of currently connected people to anyone who asked.
    It also used to answer ``ok: True`` unconditionally without testing a thing;
    now it at least touches the database.
    """
    app = request.app.state.alerting
    try:
        app.repo.audit_count()
    except Exception:
        log.exception("healthz: database unreachable")
        return {"ok": False}
    return {"ok": True}
