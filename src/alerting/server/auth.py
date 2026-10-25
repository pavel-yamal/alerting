"""Per-person transport authentication for the HTTP surface.

Every request carries an Ed25519 signature over its own method, path, query string
and body, made with the caller's personal key and verified against the root-signed
directory. That replaces a single shared secret which closed the door but could not
say who came through it and could not be revoked for one person -- rotating it was an
all-or-nothing event for every dispatcher and executor at once.

The concrete win is not convenience. ``created_by`` on a proposal used to be a string
the client asserted about itself, written straight into an undeletable audit chain.
It is now derived from the signature, so the chain names who actually made the call.

**This mirrors the WebSocket handshake in ``api/ws.py`` deliberately**, down to the
order of the checks, because two transport-auth schemes that differ in small ways are
two things to get right instead of one. There is exactly one difference, and it is
forced: the handshake's nonce is minted by the *server* and lives in the handler's
stack frame, so a captured handshake cannot be replayed and nothing is stored. HTTP
has no prior round trip, so the nonce comes from the client and the server has to
remember it -- see ``migrations/0004_http_nonces.sql``.

**``/v1/stream`` is not signed this way and should not be.** Its first frame already
proves the same thing with a server-chosen nonce, which is strictly stronger. Signing
the upgrade as well would authenticate the same key for the same session using the
weaker of the two schemes.

Authentication answers *who*; :data:`ROUTE_ROLES` answers *what they may call*. The
role comes from the directory entry, not from ``policy.approver_roles`` -- the policy
decides whose signature counts toward a quorum, which is a different question from
who may open a connection and ask.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, Request

from alerting.core.clock import TRANSPORT_AUTH_WINDOW_S
from alerting.core.http_auth import (
    DELEGATION_HEADER,
    HEADERS,
    KEY_ID_HEADER,
    NONCE_HEADER,
    PERSON_HEADER,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    DelegationRefused,
    check_delegation,
    request_payload,
)
from alerting.core.signing import DOMAIN_HTTP_REQUEST, b64u_decode, verify_signature

log = logging.getLogger("alerting.auth")

#: Spent nonces are pruned at most this often per process. The work is trivial but
#: doing it on every request would add a write to every read.
PRUNE_EVERY_S = 60.0

#: The decision-makers (ЛПР): the only role that issues orders -- proposes, signs,
#: stands down. Whose signature counts toward a quorum is still the policy's
#: ``approver_roles``; this is who may call the routes at all.
LPR = frozenset({"lpr"})

#: Everyone who runs the operation: the decision-makers, and for now the duty officer,
#: who watches the picture, keeps the directory and contacts, but issues nothing.
OPERATORS = LPR | frozenset({"duty_officer"})

#: Any key the directory knows. Used only where an executor's device genuinely needs
#: the route to do its job.
ENROLLED = frozenset({"*"})

#: Route path template -> roles allowed to call it.
#:
#: **Deny by default.** A route missing from this table refuses everyone and says so,
#: rather than inheriting whatever the last entry happened to be. A new endpoint is
#: then a decision somebody has to make on purpose, which is the only way a table
#: like this stays true a year later.
ROUTE_ROLES: dict[tuple[str, str], frozenset[str]] = {
    # Writes that start or stop an alert: decision-makers only.
    ("POST", "/v1/proposals"): LPR,
    ("POST", "/v1/proposals/{order_id}/signatures"): LPR,
    # Closing a proposal unsigned. One decision-maker is enough: it stops something,
    # and whoever wanted it can propose again.
    ("POST", "/v1/proposals/{order_id}/reject"): LPR,
    # Devices of the decision-makers' app that receive push: each person's own.
    ("POST", "/v1/push/tokens"): LPR,
    ("POST", "/v1/push/tokens/remove"): LPR,
    ("POST", "/v1/push/test"): LPR,
    ("POST", "/v1/audit/head"): OPERATORS,
    # Root-signed and version-checked on the way in, so the role is a second gate,
    # not the first: whoever uploads cannot change a byte of what the root signed.
    ("POST", "/v1/bundles"): OPERATORS,
    # Who orders are sent to. Not who may sign or verify -- that is the directory.
    ("POST", "/v1/contacts"): OPERATORS,
    ("POST", "/v1/contacts/{person_id}/deactivate"): OPERATORS,
    # The operating picture and the audit chain.
    ("GET", "/v1/proposals"): OPERATORS,
    ("GET", "/v1/proposals/{order_id}"): OPERATORS,
    ("GET", "/v1/orders"): OPERATORS,
    ("GET", "/v1/events/active"): OPERATORS,
    ("GET", "/v1/orders/{order_id}/status"): OPERATORS,
    ("GET", "/v1/audit"): OPERATORS,
    ("GET", "/v1/audit/head"): OPERATORS,
    # The roster is personal data and statusz names who is currently connected --
    # its own docstring calls that a roster leak. Executors lose both, which is a
    # tightening: they never needed them.
    ("GET", "/v1/roster"): OPERATORS,
    ("GET", "/v1/statusz"): OPERATORS,
    ("GET", "/v1/channels/health"): OPERATORS,
    # What an executor's device needs: fetch the order it was told about, send the
    # receipt, and keep its pinned bundles current.
    ("GET", "/v1/orders/{order_id}"): ENROLLED,
    ("POST", "/v1/acks"): ENROLLED,
    ("GET", "/v1/directory"): ENROLLED,
    ("GET", "/v1/policy"): ENROLLED,
    ("GET", "/v1/revocations"): ENROLLED,
}


@dataclass(frozen=True)
class Principal:
    """Who made this request, according to the root-signed directory."""

    key_id: str
    person_id: str
    role: str


def _refuse(status: int, error: str, **extra: Any) -> HTTPException:
    return HTTPException(status_code=status, detail={"error": error, **extra})


class _Pruner:
    """Deletes spent nonces now and then, without a worker of its own."""

    def __init__(self) -> None:
        self._last = 0.0

    def maybe(self, repo: Any, now: int) -> None:
        if time.monotonic() - self._last < PRUNE_EVERY_S:
            return
        self._last = time.monotonic()
        try:
            repo.prune_request_nonces(now)
        except Exception:  # pragma: no cover - housekeeping must never fail a request
            log.warning("could not prune spent request nonces", exc_info=True)


_pruner = _Pruner()


async def require_signed_request(request: Request) -> Principal:
    """Verify the signature, reject a replay, and check the caller's role.

    The order of the checks is the same as the WebSocket handshake's, and so is the
    rule that unknown and revoked are answered identically -- a caller learns that
    their key is not usable, not which of the two reasons applies.
    """
    app = request.app.state.alerting
    now = app.clock.now()

    missing = [name for name in HEADERS if not request.headers.get(name)]
    if missing:
        log.warning(
            "unsigned %s %s from %s",
            request.method,
            request.url.path,
            request.client.host if request.client else "unknown",
        )
        raise _refuse(401, "missing signature headers", headers=missing)

    key_id = request.headers[KEY_ID_HEADER]
    person_id = request.headers[PERSON_HEADER]
    nonce = request.headers[NONCE_HEADER]
    signature = request.headers[SIGNATURE_HEADER]

    try:
        at = int(request.headers[TIMESTAMP_HEADER])
    except ValueError:
        raise _refuse(401, "malformed timestamp", server_time=now) from None

    # `server_time` is not a courtesy. Before this, a wrong clock on an approver's
    # laptop cost nothing; now it refuses every command they type, and "stale
    # request" is not something anybody connects to their own clock unaided.
    if abs(at - now) > TRANSPORT_AUTH_WINDOW_S:
        raise _refuse(
            401,
            "stale request",
            server_time=now,
            skew_s=at - now,
            window_s=TRANSPORT_AUTH_WINDOW_S,
        )

    directory = app.state.directory()
    if directory.signer_status(key_id, now) is not None:
        log.warning("refused %s: unknown or revoked key %s", request.url.path, key_id)
        raise _refuse(403, "unknown or revoked key")

    entry = directory.lookup(key_id)
    assert entry is not None  # signer_status already proved it is there

    body = await request.body()
    payload = request_payload(
        org_id=app.state.org_id,
        key_id=key_id,
        person_id=person_id,
        method=request.method,
        path=request.url.path,
        query=request.url.query,
        body=body,
        nonce=nonce,
        at=at,
    )
    # A web panel whose device key lives in the browser signs requests with a session
    # key that the device key delegated to. The delegation is re-verified on every
    # request against the directory as it is *now*, so revoking the device key ends
    # every session it started, at once.
    signer = entry.public()
    delegation = request.headers.get(DELEGATION_HEADER)
    if delegation:
        try:
            try:
                blob = json.loads(b64u_decode(delegation))
                raw, delegation_sig = blob["payload"], blob["sig"]
            except Exception:
                raise DelegationRefused("malformed delegation") from None
            signer = check_delegation(
                raw,
                delegation_sig,
                org_id=app.state.org_id,
                key_id=key_id,
                person_id=person_id,
                device_key=entry.public(),
                now=now,
            )
        except DelegationRefused as exc:
            log.warning("refused %s: %s from %s", request.url.path, exc, key_id)
            raise _refuse(403, "bad delegation", reason=str(exc)) from None
    if not verify_signature(DOMAIN_HTTP_REQUEST, payload, signature, signer):
        log.warning("refused %s: bad signature from %s", request.url.path, key_id)
        raise _refuse(403, "bad request signature")

    if entry.person_id != person_id:
        raise _refuse(403, "person mismatch")

    # Only now, once the signature is known good: an unverified caller must not be
    # able to fill this table.
    _pruner.maybe(app.repo, now)
    if not app.repo.claim_request_nonce(key_id, nonce, at + TRANSPORT_AUTH_WINDOW_S):
        log.warning("refused %s: replayed nonce from %s", request.url.path, key_id)
        raise _refuse(401, "replayed request")

    principal = Principal(key_id=key_id, person_id=person_id, role=entry.role)
    _authorize(request, principal)
    request.state.principal = principal
    return principal


def _authorize(request: Request, principal: Principal) -> None:
    route = request.scope.get("route")
    template = getattr(route, "path", request.url.path)
    allowed = ROUTE_ROLES.get((request.method.upper(), template))

    if allowed is None:
        # Fail closed and loudly. A route nobody classified is a route nobody thought
        # about, and guessing on its behalf is how an endpoint quietly becomes public.
        log.error("no role mapping for %s %s; refusing", request.method, template)
        raise _refuse(403, "no role mapping for this route", route=template)

    if allowed is ENROLLED or principal.role in allowed:
        return

    log.warning(
        "refused %s %s: %s is a %s", request.method, template, principal.person_id, principal.role
    )
    raise _refuse(403, f"role {principal.role} may not call this route", route=template)
