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
from typing import Any

from alerting.core.signing import b64u_encode

KEY_ID_HEADER = "Alerting-Key-Id"
PERSON_HEADER = "Alerting-Person-Id"
NONCE_HEADER = "Alerting-Nonce"
TIMESTAMP_HEADER = "Alerting-Timestamp"
SIGNATURE_HEADER = "Alerting-Signature"

#: All five are required. A request missing any of them is unsigned, not partly signed.
HEADERS = (KEY_ID_HEADER, PERSON_HEADER, NONCE_HEADER, TIMESTAMP_HEADER, SIGNATURE_HEADER)


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
