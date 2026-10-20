"""The wire format for transport authentication of one HTTP request.

This lives in the core, with no I/O, because **both sides must build the same object
or nothing verifies**. A client that assembles the payload slightly differently from
the server produces signatures that fail for reasons indistinguishable from a wrong
key, and the two implementations would drift the first time either side is edited.
One function, imported by both.

The signature covers method, path, query string and a hash of the body. The query
string is not an afterthought: the auditor pages the chain with
``?from_idx=…&limit=…``, and an unsigned query is a query an attacker can rewrite.
"""

from __future__ import annotations

import hashlib
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, StrictInt

from alerting.core.canonical import canonicalize
from alerting.core.envelope import CanonicalModel, Identifier
from alerting.core.signing import (
    DOMAIN_SESSION_DELEGATION,
    b64u_encode,
    public_key_from_b64u,
    verify_signature,
)

KEY_ID_HEADER = "Alerting-Key-Id"
PERSON_HEADER = "Alerting-Person-Id"
NONCE_HEADER = "Alerting-Nonce"
TIMESTAMP_HEADER = "Alerting-Timestamp"
SIGNATURE_HEADER = "Alerting-Signature"

#: All five are required. A request missing any of them is unsigned, not partly signed.
HEADERS = (KEY_ID_HEADER, PERSON_HEADER, NONCE_HEADER, TIMESTAMP_HEADER, SIGNATURE_HEADER)

#: Optional. Present when the request is signed by a session key the device key
#: delegated to (a web panel whose device key lives in the person's browser).
DELEGATION_HEADER = "Alerting-Delegation"

#: The longest a delegation may run. A panel session idles out long before this; the
#: cap is what bounds a session key that leaks from the panel process.
MAX_DELEGATION_S = 12 * 3600


def request_payload(
    *,
    org_id: str,
    key_id: str,
    person_id: str,
    method: str,
    path: str,
    query: str,
    body: bytes,
    nonce: str,
    at: int,
) -> dict[str, Any]:
    """The object both sides sign.

    ``org_id`` is in the signature so a request signed for one organisation cannot be
    replayed at another that enrolled the same key.

    ``body_sha256`` is **absent** when there is no body rather than null:
    canonicalization refuses null on the "absent means absent" rule, and two spellings
    of "no body" would be two different signed byte strings.

    The hash is over the bytes as they travel, not over a re-canonicalized object.
    The client sends canonical bytes precisely so that both sides hash the same thing.
    """
    payload: dict[str, Any] = {
        "v": 1,
        "type": "http-request",
        "org_id": org_id,
        "key_id": key_id,
        "person_id": person_id,
        "method": method.upper(),
        "path": path,
        "query": query,
        "nonce": nonce,
        "at": at,
    }
    if body:
        payload["body_sha256"] = b64u_encode(hashlib.sha256(body).digest())
    return payload


class SessionDelegation(CanonicalModel):
    """A device key saying: requests signed by ``session_key`` are mine, until then.

    It covers **transport only**. Orders and ACKs are still verified against the
    device key in the directory, so whoever holds a session key -- the panel process,
    or someone who broke into it -- can read and propose, but cannot put this
    person's signature on an order.
    """

    v: Literal[1]
    type: Literal["session-delegation"]
    org_id: Identifier
    key_id: Identifier
    person_id: Identifier
    session_key: Identifier
    not_before: StrictInt = Field(ge=0)
    not_after: StrictInt = Field(ge=0)


class DelegationRefused(ValueError):
    """The delegation header does not authorize this request."""


def encode_delegation(payload: dict[str, Any], signature: str) -> str:
    """Header value: base64url of the canonical ``{"payload", "sig"}`` object."""
    return b64u_encode(canonicalize({"payload": payload, "sig": signature}))


def check_delegation(
    raw: Any,
    signature: Any,
    *,
    org_id: str,
    key_id: str,
    person_id: str,
    device_key: Ed25519PublicKey,
    now: int,
    skew_s: int = 60,
) -> Ed25519PublicKey:
    """Verify a delegation and return the session key it authorizes.

    ``raw`` and ``signature`` come straight from the decoded header (the server does
    the JSON; the core has no I/O). Every field is attacker-controlled, so every
    failure is a ``DelegationRefused``, never another exception.
    """
    try:
        delegation = SessionDelegation.model_validate(raw)
        if delegation.to_payload() != raw or not isinstance(signature, str):
            raise DelegationRefused("delegation is not canonical")
        session_key = public_key_from_b64u(delegation.session_key)
    except DelegationRefused:
        raise
    except Exception:
        raise DelegationRefused("malformed delegation") from None
    if (delegation.org_id, delegation.key_id, delegation.person_id) != (org_id, key_id, person_id):
        raise DelegationRefused("delegation is for another key")
    if delegation.not_after - delegation.not_before > MAX_DELEGATION_S:
        raise DelegationRefused("delegation runs longer than allowed")
    if not delegation.not_before - skew_s <= now <= delegation.not_after:
        raise DelegationRefused("delegation expired or not yet valid")
    if not verify_signature(DOMAIN_SESSION_DELEGATION, raw, signature, device_key):
        raise DelegationRefused("bad delegation signature")
    return session_key


def delegation_payload(
    *, org_id: str, key_id: str, person_id: str, session_key: str, not_before: int, not_after: int
) -> dict[str, Any]:
    """The object the device key signs (domain ``DOMAIN_SESSION_DELEGATION``)."""
    return SessionDelegation(
        v=1,
        type="session-delegation",
        org_id=org_id,
        key_id=key_id,
        person_id=person_id,
        session_key=session_key,
        not_before=not_before,
        not_after=not_after,
    ).to_payload()
