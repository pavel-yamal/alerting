"""Signature mechanics, especially domain separation."""

from __future__ import annotations

import pytest

from alerting.core.signing import (
    DOMAIN_ACK,
    DOMAIN_DIRECTORY,
    DOMAIN_ORDER,
    b64u_decode,
    b64u_encode,
    generate_keypair,
    key_id,
    payload_digest,
    private_key_from_b64u,
    private_key_to_b64u,
    public_key_from_b64u,
    public_key_to_b64u,
    sign_payload,
    signing_input,
    verify_signature,
)

PAYLOAD = {"a": 1, "b": "x"}


@pytest.fixture
def keypair():
    return generate_keypair()


def test_roundtrip(keypair):
    private, public = keypair
    signature = sign_payload(DOMAIN_ORDER, PAYLOAD, private)
    assert verify_signature(DOMAIN_ORDER, PAYLOAD, signature, public)


def test_signature_does_not_transfer_across_domains(keypair):
    """Without domain separation an ACK body that also parses as an order payload
    would carry a valid-looking approval."""
    private, public = keypair
    signature = sign_payload(DOMAIN_ORDER, PAYLOAD, private)
    assert not verify_signature(DOMAIN_ACK, PAYLOAD, signature, public)
    assert not verify_signature(DOMAIN_DIRECTORY, PAYLOAD, signature, public)


def test_tampered_payload_fails(keypair):
    private, public = keypair
    signature = sign_payload(DOMAIN_ORDER, PAYLOAD, private)
    assert not verify_signature(DOMAIN_ORDER, {"a": 2, "b": "x"}, signature, public)


def test_wrong_key_fails(keypair):
    private, _ = keypair
    _, other_public = generate_keypair()
    signature = sign_payload(DOMAIN_ORDER, PAYLOAD, private)
    assert not verify_signature(DOMAIN_ORDER, PAYLOAD, signature, other_public)


@pytest.mark.parametrize("bad", ["", "!!!not base64!!!", "AAAA", "a" * 200])
def test_malformed_signatures_never_raise(keypair, bad):
    """Attacker-controlled input must produce False, not an exception that could
    crash a dispatcher mid-incident."""
    _, public = keypair
    assert verify_signature(DOMAIN_ORDER, PAYLOAD, bad, public) is False


def test_truncated_signature_rejected(keypair):
    private, public = keypair
    signature = sign_payload(DOMAIN_ORDER, PAYLOAD, private)
    truncated = b64u_encode(b64u_decode(signature)[:63])
    assert not verify_signature(DOMAIN_ORDER, PAYLOAD, truncated, public)


def test_key_id_is_derived_from_the_key_material(keypair):
    _, public = keypair
    assert key_id(public).startswith("ed25519:")
    assert key_id(public) == key_id(public_key_from_b64u(public_key_to_b64u(public)))
    _, other = generate_keypair()
    assert key_id(public) != key_id(other)


def test_private_key_serialization_roundtrip(keypair):
    private, public = keypair
    restored = private_key_from_b64u(private_key_to_b64u(private))
    signature = sign_payload(DOMAIN_ORDER, PAYLOAD, restored)
    assert verify_signature(DOMAIN_ORDER, PAYLOAD, signature, public)


def test_signing_input_is_domain_then_canonical_bytes():
    assert signing_input(DOMAIN_ORDER, PAYLOAD) == DOMAIN_ORDER + b'{"a":1,"b":"x"}'


def test_payload_digest_is_stable_and_order_independent():
    assert payload_digest({"a": 1, "b": 2}) == payload_digest({"b": 2, "a": 1})
    assert payload_digest({"a": 1}) != payload_digest({"a": 2})


def test_b64u_roundtrip_without_padding():
    for size in range(1, 40):
        raw = bytes(range(size))
        assert b64u_decode(b64u_encode(raw)) == raw
        assert "=" not in b64u_encode(raw)
