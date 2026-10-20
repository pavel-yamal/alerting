"""Bundles, roster, audit access and health."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from alerting.core.audit_chain import Event
from alerting.core.directory import Directory, DirectoryRejected
from alerting.core.envelope import SignedEnvelope
from alerting.core.policy import Policy, PolicyRejected
from alerting.core.replay import ReplayWindow
from alerting.core.signing import b64u_decode
from alerting.core.verify import verify_envelope
from alerting.server.metrics import collect, render
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


def _broken_active_events(app: Any, directory: Directory, policy: Policy, now: int) -> list[str]:
    """Events still in force that would not verify under this directory and policy.

    Checked with the same verification the devices run, so whoever publishes learns
    it before publication rather than an executor learning it during the event.
    """
    broken = []
    for event in app.dispatcher.active_events(now):
        decision = verify_envelope(
            SignedEnvelope.model_validate(event["envelope"]),
            directory=directory,
            policy=policy,
            clock=app.clock,
            replay=ReplayWindow(),
            org_id=app.state.org_id,
        )
        if decision.rejected:
            reasons = ", ".join(str(r) for r in decision.reasons)
            broken.append(f"{event['scenario']} {event['order_id']} ({reasons})")
    return broken


def _refuse_if_it_breaks_active_events(app: Any, policy: Policy, now: int) -> None:
    """Refuse a policy under which an event still in force would no longer verify.

    A device verifies with the newest policy it has -- never with an older one the
    server offers alongside, because that is a downgrade: a compromised server pairing
    a forged order with an old, weaker quorum. So a policy that drops a running
    event's scenario, renames the policy line or raises its quorum would make that
    event unverifiable on every device that joins later.

    A directory is different and is not refused: revoking a key that co-signed a
    running event is exactly what has to be possible at once when a phone is stolen.
    Those events are reported back instead (``invalidated``), to be re-issued.
    """
    broken = _broken_active_events(app, app.state.directory(), policy, now)
    if broken:
        raise HTTPException(
            409,
            "the policy would invalidate events still in force: "
            + "; ".join(broken)
            + ". Stand them down first, or keep their scenario, policy_id and quorum.",
        )


def _audit_key_changes(app: Any, old: dict[str, Any] | None, new: Directory, by: Any) -> None:
    """One chain entry per key that came, ended or was revoked. Pseudonym and role
    only: the chain is undeletable and names are personal data."""
    before = {k["key_id"]: k for k in (old or {}).get("keys", [])}
    revoked_before = {r["key_id"] for r in (old or {}).get("revoked", [])}
    for entry in new.payload.keys:
        common = {"person_id": entry.person_id, "key_id": entry.key_id, "role": entry.role}
        if entry.key_id not in before:
            app.audit.append(Event.KEY_ENROLLED, {**common, "published_by": by})
        elif entry.valid_until is not None and before[entry.key_id].get("valid_until") != (
            entry.valid_until
        ):
            app.audit.append(
                Event.KEY_RETIRED, {**common, "valid_until": entry.valid_until, "published_by": by}
            )
    by_id = {e.key_id: e for e in new.payload.keys}
    for revocation in new.payload.revoked:
        if revocation.key_id in revoked_before:
            continue
        owner = by_id.get(revocation.key_id)
        app.audit.append(
            Event.KEY_REVOKED,
            {
                "key_id": revocation.key_id,
                "person_id": owner.person_id if owner else None,
                "role": owner.role if owner else None,
                "revoked_at": revocation.revoked_at,
                "reason": revocation.reason,
                "published_by": by,
            },
        )


class BundleUpload(BaseModel):
    bundle: dict[str, Any]


@router.post("/bundles")
async def publish_bundle(body: BundleUpload, request: Request) -> dict[str, Any]:
    """Publish a new root-signed directory or policy.

    The server is not the authority here and cannot become one through this route:
    the bundle is verified against the pinned root key exactly as every client will
    verify it, and only a higher version is accepted. What a caller can do with it is
    upload something the root custodians already signed -- a new codebook, a changed
    quorum, a revoked key -- without shell access to the database. Signing happens
    offline (``alerting-org sign-policy``); this only carries the result.
    """
    app = request.app.state.alerting
    payload = body.bundle.get("payload")
    kind = payload.get("type") if isinstance(payload, dict) else None
    if kind not in ("directory", "policy"):
        raise HTTPException(422, "bundle payload must have type directory or policy")

    current = app.repo.latest_bundle(kind)
    seen = int(current["payload"]["version"]) if current else 0
    loader = Directory.load if kind == "directory" else Policy.load
    try:
        loaded = loader(
            body.bundle,
            root_public_key=app.state.root_public_key,
            org_id=app.state.org_id,
            min_version=seen + 1,
        )
    except (DirectoryRejected, PolicyRejected) as exc:
        raise HTTPException(409, f"bundle refused: {exc}") from None
    except Exception as exc:
        raise HTTPException(422, f"malformed bundle: {exc}") from None

    now = app.clock.now()
    invalidated: list[str] = []
    if kind == "policy":
        _refuse_if_it_breaks_active_events(app, loaded, now)
    else:
        invalidated = _broken_active_events(app, loaded, app.state.policy(), now)
    app.repo.put_bundle(kind, loaded.version, body.bundle, now)
    principal = getattr(request.state, "principal", None)
    by = principal.person_id if principal else None
    app.audit.append(
        Event.DIRECTORY_PUBLISHED if kind == "directory" else Event.POLICY_PUBLISHED,
        {
            "version": loaded.version,
            "published_by": by,
            **({"policy_id": loaded.policy_id} if kind == "policy" else {}),
            **({"invalidated": invalidated} if invalidated else {}),
        },
    )
    if kind == "directory":
        _audit_key_changes(app, current["payload"] if current else None, loaded, by)
    log.info("published %s version %d", kind, loaded.version)
    if invalidated:
        log.warning("directory %d invalidates active events: %s", loaded.version, invalidated)
    return {"kind": kind, "version": loaded.version, "invalidated": invalidated}


#: Roles a contact may carry. The directory decides what a key may *sign*; this only
#: says how the person is addressed, so it is checked for typos, not for authority.
CONTACT_ROLES = frozenset({"executor", "duty_officer", "deputy", "director", "auditor"})


class ContactUpload(BaseModel):
    person_id: str = Field(pattern=r"^[A-Za-z0-9._:-]{1,64}$")
    name: str = Field(min_length=1, max_length=200)
    phone: str = Field(default="", max_length=32)
    site: str = Field(default="", max_length=64)
    groups: list[str] = Field(default_factory=list, max_length=32)
    role: str = "executor"
    wake_key: str = Field(default="", max_length=64)


@router.post("/contacts")
async def set_contact(body: ContactUpload, request: Request) -> dict[str, Any]:
    """Add or update where to reach a person.

    Personal data, held by the server and deliberately not root-signed: a contact
    decides who an order is *sent* to, never whether an order is genuine -- a device
    still verifies every order against the directory. A compromised operator account
    can misroute, which the audit entry here makes visible; it cannot forge.
    """
    app = request.app.state.alerting
    if body.role not in CONTACT_ROLES:
        raise HTTPException(422, f"unknown role {body.role!r}")
    if any("," in g or not g for g in body.groups):
        raise HTTPException(422, "group names must be non-empty and contain no commas")
    if body.wake_key:
        try:
            if len(b64u_decode(body.wake_key)) != 32:
                raise ValueError
        except Exception:
            raise HTTPException(422, "wake_key must be 32 bytes, base64url") from None
    app.repo.upsert_contact(
        body.person_id,
        name=body.name,
        phone=body.phone,
        site=body.site,
        groups=body.groups,
        wake_key=body.wake_key,
        role=body.role,
    )
    principal = getattr(request.state, "principal", None)
    app.audit.append(
        Event.CONTACT_SET,
        {
            "person_id": body.person_id,
            "role": body.role,
            "site": body.site,
            "groups": body.groups,
            "wake_key_set": bool(body.wake_key),
            "by": principal.person_id if principal else None,
        },
    )
    return {"person_id": body.person_id, "active": True}


@router.post("/contacts/{person_id}/deactivate")
async def deactivate_contact(person_id: str, request: Request) -> dict[str, Any]:
    """Stop sending orders to a person. Their key is untouched: revoke it in the
    directory if the device itself is no longer trusted."""
    app = request.app.state.alerting
    if not app.repo.deactivate_contact(person_id):
        raise HTTPException(404, f"no contact {person_id!r}")
    principal = getattr(request.state, "principal", None)
    app.audit.append(
        Event.CONTACT_DEACTIVATED,
        {"person_id": person_id, "by": principal.person_id if principal else None},
    )
    return {"person_id": person_id, "active": False}


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
        "silent_channels": app.heartbeat.silent_channels(),
    }


@router.get("/channels/health")
async def channels_health(request: Request) -> dict[str, Any]:
    """What each channel last said when asked whether it is still there.

    This is the duty officer's screen, and the whole point of it is that a channel
    which has gone quiet shows up **before** an incident rather than during one --
    the only thing this system has against deliberate suppression short of the
    printed fallback (threat model, attacks 4 and 5).

    Read it as three states, not two. ``healthy`` means some node reached it
    recently. ``stale`` means nothing has been *recorded* recently, which is a
    different and worse problem: the heartbeat itself has stopped. And a channel
    reporting ``stub`` is answering honestly that it has no provider behind it,
    which is not health.

    It is authenticated, like ``statusz``: the list of channels that are not
    watching right now is a gift to anybody planning to suppress one.
    """
    app = request.app.state.alerting
    health = app.heartbeat.health()
    return {
        "node_id": app.settings.node_id,
        "stale_after_s": app.heartbeat.stale_after_s,
        "silent": sorted(name for name, entry in health.items() if not entry["healthy"]),
        "channels": health,
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
        ("writable", lambda: _writable(app)),
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


def _writable(app: Any) -> bool:
    """Is this database accepting writes, or is it a standby?

    Every other readiness probe is a read, so a node pointed at a read-only replica
    passed all of them and reported itself ready -- while being unable to record a
    single order, acknowledgement or audit entry. A balancer would have sent alerts
    to it. That is the same blind spot readiness was introduced to close for an empty
    database, one layer down.

    Asked as a question about the server rather than by attempting a write: a probe
    that wrote would put a row in a table on every scrape.
    """
    with app.pool.connection() as connection:
        row = connection.execute("SELECT pg_is_in_recovery() AS recovering").fetchone()
    return not row["recovering"]


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


@public_router.get("/metricsz", response_class=PlainTextResponse)
async def metricsz(request: Request) -> str:
    """Prometheus exposition. Aggregates only -- never a series per person.

    On the public router with liveness and readiness, and restricted the same way:
    by IP in nginx. That is only defensible because of what is *not* here. There is
    no ``person_id``, no name, no phone number and no roster; ``/v1/statusz``, which
    does name who is currently connected and calls that a roster leak itself, stays
    behind the signature gate. A scraper cannot sign Ed25519 requests, so the choice
    was between an IP allowlist over harmless aggregates and no metrics at all.

    Every value is computed here, from shared state. Nothing is accumulated in the
    process: the unit runs ``--workers 2``, and an in-process counter would answer
    differently depending on which worker was scraped.
    """
    app = request.app.state.alerting
    return render(collect(app))


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
