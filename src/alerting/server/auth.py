"""Interim transport authentication for the HTTP surface.

**This is a stopgap, and it is labelled as one.** The design already has per-person
Ed25519 identities in a root-signed directory with a 60-second revocation target, so
the right answer is signed requests: a header carrying method, path, body hash and a
nonce, verified against that same directory, so every audit entry can name the
``key_id`` that made the call. That is a phase of its own.

Until it lands, a single shared key is what stops the box standing open. What it buys,
stated precisely so nobody mistakes it for the real thing:

* it stops an unauthenticated caller writing **permanently undeletable** audit entries
  with an attacker-chosen ``created_by``, burning ``seq`` numbers, and dumping the
  roster and the whole chain;
* it does **not** identify who called, cannot be revoked per person, and is shared by
  every dispatcher, executor and auditor CLI. Rotating it is an all-or-nothing event.

It is deliberately not a substitute for the cryptographic checks underneath: an order
still needs its quorum of approver signatures, and an ACK still needs a valid device
signature. This only decides who may knock on the door.
"""

from __future__ import annotations

import hmac
import logging

from fastapi import HTTPException, Request

log = logging.getLogger("alerting.auth")

HEADER = "Alerting-Api-Key"


async def require_api_key(request: Request) -> None:
    """Reject a request that does not carry the shared key.

    Compared with :func:`hmac.compare_digest` so a wrong key cannot be found one
    character at a time.
    """
    expected: str = request.app.state.alerting.api_key
    if not expected:
        # AppServices refuses to start in this state unless it was waived on purpose,
        # so reaching here means the operator asked for an open surface.
        return

    presented = request.headers.get(HEADER, "")
    if not presented or not hmac.compare_digest(presented, expected):
        log.warning(
            "rejected unauthenticated %s %s from %s",
            request.method,
            request.url.path,
            request.client.host if request.client else "unknown",
        )
        raise HTTPException(
            status_code=401,
            detail=f"missing or invalid {HEADER}",
            headers={"WWW-Authenticate": HEADER},
        )
