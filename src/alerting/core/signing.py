"""Ed25519 signing with domain separation.

Every signature in this system is taken over ``DOMAIN || JCS(payload)``. The domain
prefix is what stops a signature made for one purpose from being replayed as another:
without it, an ACK body crafted to also parse as an order payload would carry a valid
"approval". The domains are distinct, NUL-terminated, and never reused.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from alerting.core.canonical import canonicalize
from alerting.core.errors import CanonicalizationError

DOMAIN_ORDER = b"alerting.order.v1\x00"
DOMAIN_ACK = b"alerting.ack.v1\x00"
DOMAIN_DIRECTORY = b"alerting.directory.v1\x00"
DOMAIN_POLICY = b"alerting.policy.v1\x00"
DOMAIN_REVOCATIONS = b"alerting.revocations.v1\x00"
DOMAIN_AUDIT_HEAD = b"alerting.audit-head.v1\x00"
DOMAIN_WAKE = b"alerting.wake.v1"  # HMAC label, not a signature domain

ALG_ED25519: Literal["Ed25519"] = "Ed25519"


def b64u_encode(raw: bytes) -> str:
    """URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64u_decode(text: str) -> bytes:
    """Inverse of :func:`b64u_encode`; raises ``ValueError`` on malformed input."""
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def key_id(public_key: Ed25519PublicKey) -> str:
    """Stable, collision-resistant identifier for a public key.

    Derived from the key itself so that a directory entry cannot silently point a
    known ``key_id`` at different key material.
    """
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    digest = hashlib.sha256(raw).digest()
    return "ed25519:" + b64u_encode(digest)[:22]


def signing_input(domain: bytes, payload: Mapping[str, Any]) -> bytes:
    """The exact bytes a signature covers."""
    return domain + canonicalize(payload)


def payload_digest(payload: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical payload, base64url.

    Used by ACK receipts to pin *what the executor actually saw*, so a compromised
    server cannot later claim the order said something else.
    """
    return b64u_encode(hashlib.sha256(canonicalize(payload)).digest())


def sign_payload(domain: bytes, payload: Mapping[str, Any], private_key: Ed25519PrivateKey) -> str:
    """Return a detached base64url signature over ``domain || JCS(payload)``."""
    return b64u_encode(private_key.sign(signing_input(domain, payload)))


def verify_signature(
    domain: bytes,
    payload: Mapping[str, Any],
    signature: str,
    public_key: Ed25519PublicKey,
) -> bool:
    """Constant-time-ish verification that never raises on attacker-controlled input.

    The docstring used to say that and the code did not keep the promise: the payload
    goes through ``canonicalize`` inside ``signing_input``, which refuses floats,
    nulls, non-string keys and oversized integers by **raising**
    ``CanonicalizationError``. Any caller handing this an attacker-supplied payload --
    the WebSocket handshake frame, an HTTP signature header -- would get an exception
    where it expected ``False``, which in a request handler means a 500 instead of a
    refusal. A crafted payload must be a failed verification, not a crash.
    """
    try:
        raw = b64u_decode(signature)
    except (ValueError, TypeError):
        return False
    if len(raw) != 64:
        return False
    try:
        message = signing_input(domain, payload)
    except CanonicalizationError:
        return False
    try:
        public_key.verify(raw, message)
    except InvalidSignature:
        return False
    return True


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Fresh Ed25519 keypair. Production keys are generated on the device, not here."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def public_key_from_b64u(text: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(b64u_decode(text))


def public_key_to_b64u(public_key: Ed25519PublicKey) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return b64u_encode(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw))


def private_key_from_b64u(text: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(b64u_decode(text))


def private_key_to_b64u(private_key: Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    return b64u_encode(private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))


#: Device authentication on the WebSocket handshake. Separate from every other domain
#: so a transport-auth signature can never be replayed as an order or an ACK.
DOMAIN_DEVICE_AUTH = b"alerting.device-auth.v1\x00"

#: Transport authentication for one HTTP request. Separate from device-auth so a
#: WebSocket handshake signature can never be replayed as an HTTP call, and separate
#: from the order and ACK domains so neither can ever be replayed as transport auth.
DOMAIN_HTTP_REQUEST = b"alerting.http-request.v1\x00"
