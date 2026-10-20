"""HTTP and WebSocket plumbing for the CLIs.

Every HTTP request is signed with the caller's personal Ed25519 key. The signing
happens in an :class:`httpx.Auth`, which is the only correct seam: it is handed the
fully built request, with the bytes and the URL exactly as they will go on the wire,
so what is signed and what is sent cannot drift.

**The hash is over the bytes as sent**, which is what makes the encoding irrelevant
to correctness: whatever the client puts on the wire is exactly what the server
hashes. The alternative -- hashing ``canonicalize(body)`` on one side and the received
bytes on the other -- fails on any request with more than one key, because httpx's
``json=`` uses ``separators=(",", ":")`` with no key sorting and no NFC, and that is
not JCS. The failure would look like a key problem rather than an encoding one.

The body is nonetheless *sent* canonical (``content=canonicalize(body)``). Not for
the signature, which no longer cares, but so the bytes on the wire are the same form
everything else in this system signs -- one encoding to reason about in a packet
capture, and one that refuses floats and nulls before they reach the server.
"""

from __future__ import annotations

import secrets
from collections.abc import Generator, Mapping
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from alerting.core.canonical import canonicalize
from alerting.core.clock import Clock, SystemClock
from alerting.core.http_auth import (
    KEY_ID_HEADER,
    NONCE_HEADER,
    PERSON_HEADER,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    request_payload,
)
from alerting.core.signing import DOMAIN_HTTP_REQUEST, sign_payload


class ServerError(RuntimeError):
    pass


class SignedRequests(httpx.Auth):
    """Signs each request over its method, path, query string and body."""

    #: The signature covers the body, so httpx must not stream it past us.
    requires_request_body = True

    def __init__(
        self,
        *,
        org_id: str,
        key_id: str,
        person_id: str,
        private_key: Ed25519PrivateKey,
        clock: Clock | None = None,
    ) -> None:
        self.org_id = org_id
        self.key_id = key_id
        self.person_id = person_id
        self.private_key = private_key
        # Injected like every other clock in this codebase. A signature carries a
        # timestamp the server checks against its own, so a test driving a fixed
        # clock on the server has to be able to drive the same one here.
        self.clock = clock or SystemClock()

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, None, None]:
        nonce = secrets.token_urlsafe(16)
        at = self.clock.now()
        payload = request_payload(
            org_id=self.org_id,
            key_id=self.key_id,
            person_id=self.person_id,
            method=request.method,
            path=request.url.path,
            query=request.url.query.decode("ascii"),
            body=request.content,
            nonce=nonce,
            at=at,
        )
        request.headers[KEY_ID_HEADER] = self.key_id
        request.headers[PERSON_HEADER] = self.person_id
        request.headers[NONCE_HEADER] = nonce
        request.headers[TIMESTAMP_HEADER] = str(at)
        request.headers[SIGNATURE_HEADER] = sign_payload(
            DOMAIN_HTTP_REQUEST, payload, self.private_key
        )
        yield request


class Api:
    def __init__(
        self,
        base_url: str,
        timeout: float = 10.0,
        *,
        auth: httpx.Auth | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        # `transport` lets a test hand in the server's in-process transport, so a
        # client is exercised against the real app rather than a mock of it.
        self._client = httpx.Client(
            base_url=self.base_url, timeout=timeout, auth=auth, transport=transport
        )

    @property
    def ws_url(self) -> str:
        return self.base_url.replace("https://", "wss://").replace("http://", "ws://")

    def get(self, path: str, **params: Any) -> Any:
        response = self._client.get(path, params=params or None)
        return self._unwrap(response)

    def post(self, path: str, body: Mapping[str, Any] | None = None) -> Any:
        if body is None:
            response = self._client.post(path)
        else:
            response = self._client.post(
                path,
                content=canonicalize(body),
                headers={"Content-Type": "application/json"},
            )
        return self._unwrap(response)

    @staticmethod
    def _unwrap(response: httpx.Response) -> Any:
        if response.status_code in (401, 403):
            raise ServerError(_explain(response))
        if response.status_code >= 400:
            raise ServerError(f"{response.status_code}: {response.text}")
        return response.json()

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Api:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _explain(response: httpx.Response) -> str:
    """Turn a refusal into something the person at the keyboard can act on.

    The clock case is why this exists. Before signed requests a wrong clock on an
    approver's laptop cost nothing; now it refuses every command they type, and
    "stale request" is not something anybody connects to their own clock unaided.
    The server sends its own time back for exactly this.
    """
    try:
        detail = response.json().get("detail", {})
    except Exception:
        return f"{response.status_code}: {response.text}"
    if not isinstance(detail, dict):
        return f"{response.status_code}: {detail}"

    error = detail.get("error", "refused")
    if error == "stale request":
        skew = detail.get("skew_s", 0)
        direction = "ahead of" if skew > 0 else "behind"
        return (
            f"401 {error}: your clock is {abs(skew)}s {direction} the server's "
            f"(window {detail.get('window_s')}s). Fix NTP on this machine; nothing "
            "will authenticate until you do."
        )
    if error == "unknown or revoked key":
        return "403: this key is not in the directory, or it has been revoked."
    if error == "missing signature headers":
        return "401: the request was not signed. Pass --person and unlock your key."
    route = detail.get("route")
    return f"{response.status_code} {error}" + (f" ({route})" if route else "")
