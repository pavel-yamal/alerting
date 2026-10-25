"""The push transport: JWTs Apple and Google accept, and what their answers mean.

Signatures are checked with the public key here, not just compared to a string: a
JWT that merely looks right fails at Apple with a 403 nobody on the stand can read.
"""

from __future__ import annotations

import json

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from alerting.core.signing import b64u_decode
from alerting.server.mobilepush import (
    FCM_TOKEN_URL,
    ApnsConfig,
    MobilePush,
    build_apns_jwt,
    build_fcm_assertion,
    parse_service_account,
)

pytestmark = pytest.mark.asyncio


def pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def parts(jwt: str) -> tuple[dict, dict, bytes, bytes]:
    header, claims, signature = jwt.split(".")
    return (
        json.loads(b64u_decode(header)),
        json.loads(b64u_decode(claims)),
        f"{header}.{claims}".encode(),
        b64u_decode(signature),
    )


@pytest.fixture
def apns_key():
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def apns(apns_key) -> ApnsConfig:
    return ApnsConfig(team_id="TEAM123", key_id="KEY456", private_key_pem=pem(apns_key),
                      topic="me.yamal.alert")  # fmt: skip


@pytest.fixture
def service_account() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return json.dumps({"project_id": "alerting-lpr", "client_email": "push@alerting-lpr.iam",
                       "private_key": pem(key), "private_key_id": "kid-1"})  # fmt: skip


async def test_the_apns_jwt_is_es256_over_the_p8_key(apns, apns_key):
    header, claims, signed, signature = parts(build_apns_jwt(apns, 1_700_000_000))
    assert header == {"alg": "ES256", "kid": "KEY456"}
    assert claims == {"iss": "TEAM123", "iat": 1_700_000_000}
    # JOSE carries r||s, 32 bytes each, not DER.
    assert len(signature) == 64
    der = encode_dss_signature(int.from_bytes(signature[:32]), int.from_bytes(signature[32:]))
    apns_key.public_key().verify(der, signed, ec.ECDSA(hashes.SHA256()))


async def test_an_apns_key_that_is_not_p256_is_refused(apns):
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong = ApnsConfig(apns.team_id, apns.key_id, pem(rsa_key), apns.topic)
    with pytest.raises(ValueError, match="P-256"):
        build_apns_jwt(wrong, 0)


async def test_the_fcm_assertion_is_rs256_for_the_service_account(service_account):
    config = parse_service_account(service_account)
    header, claims, signed, signature = parts(build_fcm_assertion(config, 1_700_000_000))
    assert header == {"alg": "RS256", "typ": "JWT", "kid": "kid-1"}
    assert claims["iss"] == "push@alerting-lpr.iam"
    assert claims["aud"] == FCM_TOKEN_URL
    assert claims["exp"] - claims["iat"] == 3600
    public = serialization.load_pem_private_key(
        config.private_key_pem.encode(), password=None
    ).public_key()
    public.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())


async def test_a_service_account_must_be_complete_and_its_project_can_be_overridden(
    service_account,
):
    assert parse_service_account(service_account, "other").project_id == "other"
    incomplete = json.loads(service_account)
    del incomplete["client_email"]
    with pytest.raises(ValueError, match="client_email"):
        parse_service_account(json.dumps(incomplete))


def apple(answers: list[tuple[int, dict]]):
    """A fake APNs: answers in order, and records what it was asked."""
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        status, body = answers[len(seen) - 1]
        return httpx.Response(status, json=body)

    return seen, httpx.MockTransport(handle)


async def test_apns_delivers_to_the_production_host_with_the_app_as_topic(apns):
    seen, transport = apple([(200, {})])
    push = MobilePush(apns, None, transport=transport)
    result = await push.send_apns("abc123", "production", "T", "B", {"order_id": "o1"})
    assert result.ok and result.apns_env is None
    request = seen[0]
    assert str(request.url) == "https://api.push.apple.com/3/device/abc123"
    assert request.headers["apns-topic"] == "me.yamal.alert"
    assert request.headers["apns-push-type"] == "alert"
    assert request.headers["authorization"].startswith("bearer ")
    body = json.loads(request.content)
    assert body == {"aps": {"alert": {"title": "T", "body": "B"}, "sound": "default"},
                    "order_id": "o1"}  # fmt: skip
    await push.aclose()


async def test_a_sandbox_token_is_found_on_the_other_host_and_reported(apns):
    """A build from Xcode: production says BadDeviceToken, sandbox takes it."""
    seen, transport = apple([(400, {"reason": "BadDeviceToken"}), (200, {})])
    push = MobilePush(apns, None, transport=transport)
    result = await push.send_apns("abc123", "production", "T", "B", {})
    assert result.ok and result.apns_env == "sandbox"
    assert [r.url.host for r in seen] == ["api.push.apple.com", "api.sandbox.push.apple.com"]


async def test_a_transient_failure_on_the_other_host_keeps_the_token(apns):
    """Production says BadDeviceToken, sandbox is busy: the token may be good there,
    and deleting it would silence the phone until its owner signs in again."""
    for answer in ((503, {"reason": "ServiceUnavailable"}), (429, {"reason": "TooManyRequests"})):
        _, transport = apple([(400, {"reason": "BadDeviceToken"}), answer])
        result = await MobilePush(apns, None, transport=transport).send_apns(
            "t", "production", "T", "B", {}
        )
        assert not result.ok and not result.gone
        assert result.error == answer[1]["reason"]


async def test_a_token_neither_host_takes_or_apple_unregistered_is_gone(apns):
    _, transport = apple([(400, {"reason": "BadDeviceToken"})] * 2)
    assert (await MobilePush(apns, None, transport=transport).send_apns("t", "production", "T",
                                                                         "B", {})).gone  # fmt: skip
    _, transport = apple([(410, {"reason": "Unregistered"})])
    result = await MobilePush(apns, None, transport=transport).send_apns(
        "t", "production", "T", "B", {}
    )
    assert result.gone and result.error == "Unregistered"
    _, transport = apple([(429, {"reason": "TooManyRequests"})])
    result = await MobilePush(apns, None, transport=transport).send_apns(
        "t", "production", "T", "B", {}
    )
    assert not result.ok and not result.gone and result.error == "TooManyRequests"


async def test_fcm_exchanges_its_jwt_once_and_then_sends(service_account):
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if str(request.url) == FCM_TOKEN_URL:
            return httpx.Response(200, json={"access_token": "ya29.x", "expires_in": 3600})
        return httpx.Response(200, json={"name": "projects/alerting-lpr/messages/1"})

    push = MobilePush(None, parse_service_account(service_account),
                      transport=httpx.MockTransport(handle))  # fmt: skip
    for _ in range(2):
        assert (await push.send_fcm("tok", "T", "B", {"order_id": "o1", "open": "proposal"})).ok
    urls = [str(r.url) for r in seen]
    assert urls.count(FCM_TOKEN_URL) == 1, "the OAuth2 token is cached for its hour"
    send = seen[1]
    assert str(send.url).endswith("/v1/projects/alerting-lpr/messages:send")
    assert send.headers["authorization"] == "Bearer ya29.x"
    message = json.loads(send.content)["message"]
    assert message["token"] == "tok"
    assert message["data"] == {"order_id": "o1", "open": "proposal"}
    assert message["android"]["notification"]["channel_id"] == "lpr"


async def test_fcm_unregistered_and_404_mean_the_token_is_gone(service_account):
    def answer(status: int, body: dict):
        def handle(request: httpx.Request) -> httpx.Response:
            if str(request.url) == FCM_TOKEN_URL:
                return httpx.Response(200, json={"access_token": "a"})
            return httpx.Response(status, json=body)

        return httpx.MockTransport(handle)

    config = parse_service_account(service_account)
    unregistered = {"error": {"status": "NOT_FOUND", "message": "gone",
                              "details": [{"errorCode": "UNREGISTERED"}]}}  # fmt: skip
    for status, body in ((404, unregistered), (404, {}), (400, unregistered)):
        result = await MobilePush(None, config, transport=answer(status, body)).send_fcm(
            "t", "T", "B", {}
        )
        assert result.gone, (status, body)
    result = await MobilePush(None, config, transport=answer(503, {})).send_fcm("t", "T", "B", {})
    assert not result.ok and not result.gone


async def test_nothing_configured_sends_nothing():
    push = MobilePush(None, None)
    assert push.configured == {"ios": False, "android": False}
    assert (await push.send_apns("t", "production", "T", "B", {})).error == "APNs not configured"
    assert (await push.send_fcm("t", "T", "B", {})).error == "FCM not configured"
