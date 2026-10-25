"""Push to the decision-makers' app: APNs on iOS, FCM on Android.

Transport only -- JWTs and HTTP, no database. Who gets what lives in
``services/lpr_notify.py``.

Why two senders and not Firebase for both: ``@capacitor/push-notifications`` on iOS
registers straight with APNs and hands back an APNs token, so Firebase is not needed
there at all and these notifications do not pass through Google. Android cannot do
without FCM. The same split, for the same reasons, as the organisation's helpdesk
app (``helpdesk: api/app/notifications/mobilepush.py``).

The two differ in three ways:

* APNs is signed **ES256** with the ``.p8`` key and takes the JWT directly;
* FCM is signed **RS256** with a service-account key, and the JWT is exchanged for
  an OAuth2 token that lives an hour -- so it is cached;
* APNs speaks **HTTP/2 only**: over HTTP/1.1 Apple closes the connection without a
  usable answer (hence ``httpx[http2]``).

What a notification may say is decided elsewhere (docs/04-channels.md): it passes
through Apple or Google, so it carries "open the app" and an identifier, never the
order itself.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from alerting.core.signing import b64u_encode

log = logging.getLogger("alerting.mobilepush")

APNS_PRODUCTION = "https://api.push.apple.com"
APNS_SANDBOX = "https://api.sandbox.push.apple.com"
FCM_SCOPE = "https://www.googleapis.com/auth/firebase.messaging"
FCM_TOKEN_URL = "https://oauth2.googleapis.com/token"

#: Apple wants the JWT replaced no more than every 20 minutes and no less than hourly.
APNS_JWT_TTL_S = 30 * 60

#: An undelivered notification is dropped after this long: a day-old "your signature
#: is needed" is noise, and the proposal is in the app's list anyway.
EXPIRY_S = 24 * 3600

#: Same id as PUSH_CHANNEL_ID in apps/approver/src/push.js and the manifest default.
ANDROID_CHANNEL_ID = "lpr"


@dataclass(frozen=True)
class PushResult:
    ok: bool
    status_code: int | None = None
    #: The token is dead (app removed, token replaced): forget it.
    gone: bool = False
    error: str = ""
    #: iOS only: the APNs environment that accepted the token, when it changed.
    apns_env: str | None = None


@dataclass(frozen=True)
class ApnsConfig:
    team_id: str
    key_id: str
    private_key_pem: str
    topic: str

    @property
    def configured(self) -> bool:
        return bool(self.team_id and self.key_id and self.private_key_pem and self.topic)


@dataclass(frozen=True)
class FcmConfig:
    project_id: str
    client_email: str
    private_key_pem: str
    private_key_id: str = ""


def parse_service_account(raw: str, project_id: str = "") -> FcmConfig:
    """``FcmConfig`` from a Firebase service-account JSON. Raises if incomplete.

    ``project_id`` overrides the file's: one service account can serve several
    Firebase projects, and then the file names the wrong one.
    """
    data = json.loads(raw)
    config = FcmConfig(
        project_id=(project_id or data.get("project_id") or "").strip(),
        client_email=(data.get("client_email") or "").strip(),
        private_key_pem=(data.get("private_key") or "").strip(),
        private_key_id=(data.get("private_key_id") or "").strip(),
    )
    if not (config.project_id and config.client_email and config.private_key_pem):
        raise ValueError("the FCM service account lacks project_id, client_email or private_key")
    return config


def _jwt(header: dict[str, Any], claims: dict[str, Any], sign: Any) -> str:
    signing_input = ".".join(
        b64u_encode(json.dumps(part, separators=(",", ":")).encode()) for part in (header, claims)
    )
    return f"{signing_input}.{b64u_encode(sign(signing_input.encode('ascii')))}"


def build_apns_jwt(config: ApnsConfig, now: int) -> str:
    """``authorization: bearer <jwt>`` for APNs: ES256 over P-256, signature as r||s."""
    key = serialization.load_pem_private_key(config.private_key_pem.encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("the APNs key must be the EC P-256 .p8 key from Apple Developer")

    def sign(data: bytes) -> bytes:
        r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    return _jwt({"alg": "ES256", "kid": config.key_id}, {"iss": config.team_id, "iat": now}, sign)


def build_fcm_assertion(config: FcmConfig, now: int) -> str:
    """The RS256 service-account JWT that is exchanged for an OAuth2 token."""
    key = serialization.load_pem_private_key(config.private_key_pem.encode(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("the FCM service account key must be RSA")
    header = {"alg": "RS256", "typ": "JWT"}
    if config.private_key_id:
        header["kid"] = config.private_key_id
    claims = {
        "iss": config.client_email,
        "scope": FCM_SCOPE,
        "aud": FCM_TOKEN_URL,
        "iat": now,
        "exp": now + 3600,
    }
    return _jwt(header, claims, lambda data: key.sign(data, padding.PKCS1v15(), hashes.SHA256()))


def apns_body(title: str, body: str, data: dict[str, str]) -> dict[str, Any]:
    return {"aps": {"alert": {"title": title, "body": body}, "sound": "default"}, **data}


def fcm_message(token: str, title: str, body: str, data: dict[str, str]) -> dict[str, Any]:
    return {
        "message": {
            "token": token,
            "notification": {"title": title, "body": body},
            # FCM data values must be strings, or the request fails INVALID_ARGUMENT.
            "data": {k: str(v) for k, v in data.items()},
            "android": {
                "priority": "high",
                # The channel the app creates (importance HIGH): without it FCM uses
                # its fallback channel, whose notifications do not pop up.
                "notification": {"channel_id": ANDROID_CHANNEL_ID, "default_sound": True},
            },
        }
    }


#: Failures after which the request certainly did not reach Apple whole: safe to
#: retry. Anything else -- a read timeout, a broken response -- may come after Apple
#: accepted it, and APNs has no de-duplication: a retry would show it twice.
_RETRY_SAFE: tuple[type[BaseException], ...] = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.PoolTimeout,
    httpx.WriteError,
    httpx.LocalProtocolError,
)


class MobilePush:
    """Both senders, with their cached credentials and long-lived connections.

    One HTTP/2 connection to Apple per host, kept across notifications. Apple asks
    for exactly that and treats rapid connect/disconnect as a denial-of-service
    attack; the helpdesk lost notifications in bursts before it did the same.
    """

    def __init__(
        self,
        apns: ApnsConfig | None,
        fcm: FcmConfig | None,
        *,
        timeout_s: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.apns = apns if apns and apns.configured else None
        self.fcm = fcm
        self.timeout_s = timeout_s
        self._transport = transport
        self._clients: dict[str, httpx.AsyncClient] = {}
        self._apns_jwt: tuple[str, float] | None = None
        self._fcm_token: tuple[str, float] | None = None
        self._lock = asyncio.Lock()

    @property
    def configured(self) -> dict[str, bool]:
        return {"ios": self.apns is not None, "android": self.fcm is not None}

    def _client(self, key: str, *, http2: bool) -> httpx.AsyncClient:
        client = self._clients.get(key)
        if client is None or client.is_closed:
            client = httpx.AsyncClient(
                http2=http2, timeout=self.timeout_s, transport=self._transport
            )
            self._clients[key] = client
        return client

    async def _drop(self, key: str) -> None:
        client = self._clients.pop(key, None)
        if client is not None:
            await client.aclose()

    async def aclose(self) -> None:
        for key in list(self._clients):
            await self._drop(key)

    # --- APNs ---------------------------------------------------------------------

    def _apns_bearer(self) -> str:
        assert self.apns is not None
        now = time.time()
        if self._apns_jwt is None or self._apns_jwt[1] <= now:
            self._apns_jwt = (build_apns_jwt(self.apns, int(now)), now + APNS_JWT_TTL_S)
        return self._apns_jwt[0]

    async def _apns_once(self, token: str, payload: bytes, *, sandbox: bool) -> PushResult:
        assert self.apns is not None
        host = APNS_SANDBOX if sandbox else APNS_PRODUCTION
        headers = {
            "authorization": f"bearer {self._apns_bearer()}",
            "apns-topic": self.apns.topic,
            "apns-push-type": "alert",
            "apns-priority": "10",
            "apns-expiration": str(int(time.time()) + EXPIRY_S),
        }
        response = None
        failure: BaseException | None = None
        # A long-lived connection Apple has since closed fails at the transport:
        # drop it and try once on a fresh one -- only if the request surely did not go.
        for _ in range(2):
            client = self._client(host, http2=True)
            try:
                response = await client.post(
                    f"{host}/3/device/{token}", content=payload, headers=headers
                )
                break
            except Exception as exc:
                failure = exc
                await self._drop(host)
                if not isinstance(exc, _RETRY_SAFE):
                    break
        if response is None:
            return PushResult(ok=False, error=f"transport error: {failure}")
        if response.status_code == 200:
            return PushResult(ok=True, status_code=200)
        try:
            reason = str((response.json() or {}).get("reason") or "")
        except Exception:
            reason = response.text.strip()[:200]
        return PushResult(
            ok=False,
            status_code=response.status_code,
            gone=response.status_code == 410 or reason == "Unregistered",
            error=reason or f"HTTP {response.status_code}",
        )

    async def send_apns(
        self, token: str, env: str, title: str, body: str, data: dict[str, str]
    ) -> PushResult:
        """``env`` is where this token last worked: "production" or "sandbox".

        A build from Xcode gets a sandbox token, TestFlight and the App Store a
        production one, and the token itself does not say which. Both kinds live at
        once during a rollout, so it is per token: on ``BadDeviceToken`` the other
        host is tried, and the one that worked is reported back to be remembered.
        """
        if self.apns is None:
            return PushResult(ok=False, error="APNs not configured")
        try:
            payload = json.dumps(apns_body(title, body, data), ensure_ascii=False).encode()
            result = await self._apns_once(token, payload, sandbox=env == "sandbox")
            if result.ok or result.error != "BadDeviceToken":
                return result
            other = "production" if env == "sandbox" else "sandbox"
            retry = await self._apns_once(token, payload, sandbox=other == "sandbox")
        except Exception as exc:
            log.warning("APNs send failed: %s", exc)
            return PushResult(ok=False, error=str(exc))
        if retry.ok:
            return PushResult(ok=True, status_code=200, apns_env=other)
        if retry.gone or retry.error == "BadDeviceToken":
            # Neither host takes it: the token is garbage.
            return PushResult(ok=False, status_code=retry.status_code, gone=True, error=retry.error)
        # The other host failed for its own reasons (a timeout, 429, 503): the token
        # may well be good there. Keep it, and report what actually happened.
        return retry

    # --- FCM ----------------------------------------------------------------------

    async def _fcm_access_token(self) -> str:
        assert self.fcm is not None
        async with self._lock:
            now = time.time()
            if self._fcm_token is not None and self._fcm_token[1] > now:
                return self._fcm_token[0]
            response = await self._client("oauth", http2=False).post(
                FCM_TOKEN_URL,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": build_fcm_assertion(self.fcm, int(now)),
                },
            )
            if response.status_code != 200:
                raise RuntimeError(
                    f"FCM token exchange failed: HTTP {response.status_code}: {response.text[:300]}"
                )
            data = response.json()
            token = str(data.get("access_token") or "")
            if not token:
                raise RuntimeError("FCM token exchange returned no access_token")
            # A minute's margin, so a token does not expire in flight.
            lifetime = max(int(data.get("expires_in") or 3600) - 60, 60)
            self._fcm_token = (token, now + lifetime)
            return token

    async def send_fcm(self, token: str, title: str, body: str, data: dict[str, str]) -> PushResult:
        if self.fcm is None:
            return PushResult(ok=False, error="FCM not configured")
        try:
            access = await self._fcm_access_token()
            response = await self._client("fcm", http2=False).post(
                f"https://fcm.googleapis.com/v1/projects/{self.fcm.project_id}/messages:send",
                json=fcm_message(token, title, body, data),
                headers={"Authorization": f"Bearer {access}"},
            )
        except Exception as exc:
            log.warning("FCM send failed: %s", exc)
            return PushResult(ok=False, error=f"transport error: {exc}")
        if response.status_code == 200:
            return PushResult(ok=True, status_code=200)
        code, detail = "", ""
        try:
            error = (response.json() or {}).get("error") or {}
            detail = str(error.get("message") or "")[:300]
            code = next(
                (d["errorCode"] for d in error.get("details") or [] if d.get("errorCode")),
                str(error.get("status") or ""),
            )
        except Exception:
            detail = response.text.strip()[:300]
        return PushResult(
            ok=False,
            status_code=response.status_code,
            # UNREGISTERED: the app is gone or the token replaced; 404 means the same.
            gone=code == "UNREGISTERED" or response.status_code == 404,
            error=f"{code}: {detail}" if code else (detail or f"HTTP {response.status_code}"),
        )
