"""Executor client with a phone-sized web page.

The same standing as ``alerting-executor listen``: it holds the executor's device
key, keeps the order stream open, and decides whether an order is genuine **against
the pinned org root key** -- with the same ``verify_one`` the CLI uses, never with
the server's opinion. The page on the phone shows the verdict and sends the
person's acknowledgement back, signed with that key.

What this is not, and the page says so: verification here runs in this process, not
on the handset. On the stand that process sits beside the server, because the demo
keys are there. A native app moves exactly this logic onto the phone, with the key in
the platform keystore and push to wake it; until then this is the demonstration of
the flow, not the security boundary a phone would be.

An executor's key signs receipts, never orders, so the session is not idle-timed like
the duty officer's panel: listening for hours is the job. It has an absolute lifetime
of one shift instead.
"""

from __future__ import annotations

import contextlib
import json
import logging
import pathlib
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx
from cryptography.exceptions import InvalidTag
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from alerting.clients.bundles import BundleCache, PinnedOrg
from alerting.clients.executor_cli import describe, verify_one
from alerting.clients.keystore import StoredKey, load_key
from alerting.clients.transport import Api, ServerError, SignedRequests
from alerting.core.clock import Clock, SystemClock
from alerting.core.directory import Directory
from alerting.core.envelope import AckStatus, OrderPayload
from alerting.core.policy import Policy
from alerting.core.receipts import build_ack
from alerting.core.signing import DOMAIN_DEVICE_AUTH, sign_payload
from alerting.core.wordcode import bucket_for, wake_code
from alerting.wordlist import load_wordlist

log = logging.getLogger("alerting.mobile")

COOKIE = "alerting_mobile"
CSRF_HEADER = "X-Alerting-Mobile"

#: One shift. After that the person logs in again and the key is unlocked afresh.
SESSION_LIFETIME_S = 12 * 3600

#: Reconnect delay bounds for the order stream.
RECONNECT_MIN_S = 1.0
RECONNECT_MAX_S = 30.0

PERSON_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
STATIC_DIR = pathlib.Path(__file__).parent / "static"

#: The statuses a person can send. ``received`` is sent by the client itself the
#: moment an order verifies, so the operator sees "reached the device" at once.
HUMAN_STATUSES = {"acknowledged", "en_route", "completed", "cannot_comply"}


class Socket(Protocol):
    def recv(self) -> str: ...
    def send(self, text: str) -> None: ...
    def close(self) -> None: ...


#: Opens the order stream. Production uses the websockets client; tests hand in the
#: server app's own in-process socket.
Connector = Callable[[str], Socket]


def websockets_connector(url: str) -> Socket:
    from websockets.sync.client import connect

    return connect(url, open_timeout=10)


@dataclass
class InboxItem:
    envelope: dict[str, Any]
    accepted: bool
    reasons: list[str]
    warnings: list[str]
    signers: list[str]
    received_at: int
    payload: OrderPayload | None
    my_ack: str | None = None
    cancelled_by: str | None = None


@dataclass
class Session:
    stored: StoredKey
    pin: PinnedOrg
    cache: BundleCache
    api: Api
    name: str
    home: pathlib.Path
    started: float
    inbox: dict[str, InboxItem] = field(default_factory=dict)
    connected: bool = False
    last_error: str = ""
    stop: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)
    #: The open stream, so ending the session can close it: the listener is blocked
    #: in ``recv`` and would otherwise keep the key in use until the server hangs up.
    socket: Socket | None = None
    thread: threading.Thread | None = None

    @property
    def directory(self) -> Directory:
        return self.cache.directory()

    @property
    def policy(self) -> Policy:
        return self.cache.policy()


class LoginRequest(BaseModel):
    person_id: str
    passphrase: str


class AckForm(BaseModel):
    status: str
    reason: str | None = Field(default=None, max_length=500)


class Mobile:
    def __init__(
        self,
        *,
        homes: pathlib.Path,
        server_url: str,
        wordlist: pathlib.Path | None,
        transport: httpx.BaseTransport | None = None,
        connector: Connector = websockets_connector,
        clock: Clock | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.homes = homes
        self.server_url = server_url.rstrip("/")
        self.transport = transport
        self.connector = connector
        self.clock = clock or SystemClock()
        self.monotonic = monotonic
        self.wordlist = load_wordlist(wordlist, required=False) if wordlist else []
        self.sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    # --- sessions -------------------------------------------------------------
    def login(self, person_id: str, passphrase: str) -> tuple[str, Session]:
        if not PERSON_ID.match(person_id):
            raise HTTPException(400, "некорректный идентификатор")
        home = self.homes / person_id
        try:
            stored = load_key(person_id, passphrase, directory=home)
            pin = PinnedOrg.load(home)
        except (FileNotFoundError, InvalidTag):
            raise HTTPException(401, "неверный идентификатор или пароль") from None

        api = Api(
            self.server_url,
            auth=SignedRequests(
                org_id=pin.org_id,
                key_id=stored.key_id,
                person_id=stored.person_id,
                private_key=stored.private_key,
                clock=self.clock,
            ),
            transport=self.transport,
        )
        cache = BundleCache(pin)
        try:
            directory = cache.accept("directory", api.get("/v1/directory"))
            cache.accept("policy", api.get("/v1/policy"))
        except ServerError as exc:
            api.close()
            raise HTTPException(502, f"сервер отказал: {exc}") from None
        except Exception as exc:
            api.close()
            raise HTTPException(502, f"справочник или политика не прошли проверку: {exc}") from None

        assert isinstance(directory, Directory)
        entry = directory.lookup(stored.key_id)
        if entry is None or directory.is_revoked(stored.key_id):
            api.close()
            raise HTTPException(403, "ключ отсутствует в справочнике или отозван")
        if entry.role != "executor":
            api.close()
            raise HTTPException(403, "это приложение исполнителя; дежурные и ЛПР — в панели")

        session = Session(stored, pin, cache, api, entry.name, home, started=self.monotonic())
        token = secrets.token_urlsafe(32)
        with self._lock:
            # One listener per person: a second login replaces the first rather
            # than opening a second stream for the same device key.
            for old_token, old in list(self.sessions.items()):
                if old.stored.person_id == person_id:
                    self._drop(old_token)
            self.sessions[token] = session
        session.thread = threading.Thread(
            target=self._listen, args=(session,), name=f"stream-{person_id}", daemon=True
        )
        session.thread.start()
        log.info("mobile login: %s", person_id)
        return token, session

    def session(self, token: str | None) -> Session:
        with self._lock:
            session = self.sessions.get(token or "")
            if session is None:
                raise HTTPException(401, "войдите")
            if self.monotonic() - session.started > SESSION_LIFETIME_S:
                self._drop(token or "")
                raise HTTPException(401, "смена закончилась, войдите снова")
            return session

    def _drop(self, token: str) -> None:
        session = self.sessions.pop(token, None)
        if session is not None:
            session.stop.set()
            socket, session.socket = session.socket, None
            if socket is not None:
                with contextlib.suppress(Exception):
                    socket.close()
            session.api.close()

    def shutdown(self, timeout: float = 5.0) -> None:
        """End every session and wait for its listener to let go of the stream."""
        with self._lock:
            sessions = list(self.sessions.values())
            for token in list(self.sessions):
                self._drop(token)
        for session in sessions:
            if session.thread is not None:
                session.thread.join(timeout)

    def logout(self, token: str | None) -> None:
        with self._lock:
            self._drop(token or "")

    # --- the order stream -----------------------------------------------------
    def _listen(self, session: Session) -> None:
        url = self.server_url.replace("https://", "wss://").replace("http://", "ws://")
        delay = RECONNECT_MIN_S
        while not session.stop.is_set():
            socket: Socket | None = None
            try:
                socket = self.connector(f"{url}/v1/stream")
                session.socket = socket
                if session.stop.is_set():
                    break
                self._authenticate(session, socket)
                session.connected, session.last_error = True, ""
                delay = RECONNECT_MIN_S
                while not session.stop.is_set():
                    frame = json.loads(socket.recv())
                    if frame.get("kind") == "order":
                        self.receive(session, frame["envelope"])
            except Exception as exc:
                if session.stop.is_set():
                    break
                session.connected = False
                session.last_error = str(exc) or exc.__class__.__name__
                log.warning("stream for %s dropped: %s", session.stored.person_id, exc)
            finally:
                session.connected = False
                session.socket = None
                if socket is not None:
                    with contextlib.suppress(Exception):
                        socket.close()
            session.stop.wait(delay)
            delay = min(delay * 2, RECONNECT_MAX_S)

    def _authenticate(self, session: Session, socket: Socket) -> None:
        challenge = json.loads(socket.recv())
        payload = {
            "v": 1,
            "type": "device-auth",
            "org_id": session.pin.org_id,
            "person_id": session.stored.person_id,
            "key_id": session.stored.key_id,
            "nonce": challenge["nonce"],
            "at": self.clock.now(),
        }
        socket.send(
            json.dumps(
                {
                    "kind": "auth",
                    "payload": payload,
                    "sig": sign_payload(DOMAIN_DEVICE_AUTH, payload, session.stored.private_key),
                }
            )
        )
        ready = json.loads(socket.recv())
        if ready.get("kind") != "ready":
            raise RuntimeError(f"сервер не принял устройство: {ready}")

    def receive(self, session: Session, envelope: dict[str, Any]) -> InboxItem:
        """Verify one delivered order on this client and file it in the inbox."""
        raw = envelope.get("payload", {})
        order_id = str(raw.get("order_id", ""))
        with session.lock:
            target_id = raw.get("cancels")
            target = session.inbox.get(target_id) if target_id else None
            decision = verify_one(
                session.cache,
                envelope,
                cancel_target=target.payload if target else None,
                clock=self.clock,
            )
            directory = session.directory
            names = {e.person_id: e.name for e in directory.payload.keys}
            item = InboxItem(
                envelope=envelope,
                accepted=decision.accepted,
                reasons=[describe(r) for r in decision.reasons],
                warnings=[describe(w) for w in decision.warnings],
                signers=[names.get(p, p) for p in decision.signer_persons],
                received_at=self.clock.now(),
                payload=decision.payload,
            )
            if order_id and order_id not in session.inbox:
                session.inbox[order_id] = item
            if decision.accepted and target is not None:
                target.cancelled_by = order_id

        if decision.accepted and decision.payload is not None:
            # Automatic, like the CLI: tells the operator the order reached a device
            # and verified there. The person's own acknowledgement is a separate tap.
            try:
                self.send_ack(session, order_id, AckStatus.RECEIVED)
            except Exception as exc:
                log.warning("received-ack for %s failed: %s", order_id, exc)
        return item

    def send_ack(
        self, session: Session, order_id: str, status: AckStatus, reason: str | None = None
    ) -> bool:
        item = session.inbox.get(order_id)
        if item is None or not item.accepted or item.payload is None:
            raise HTTPException(409, "подтверждать можно только проверенный подлинный приказ")
        ack = build_ack(
            order=item.payload,
            order_payload_raw=item.envelope["payload"],
            person_id=session.stored.person_id,
            device_key_id=session.stored.key_id,
            status=status,
            at=self.clock.now(),
            nonce=secrets.token_urlsafe(12),
            private_key=session.stored.private_key,
            reason=reason,
        )
        result = session.api.post(
            "/v1/acks",
            {"payload": ack.payload, "signature": ack.signature.model_dump(mode="json")},
        )
        accepted = bool(result.get("accepted"))
        if accepted and status != AckStatus.RECEIVED:
            item.my_ack = str(status)
        return accepted

    # --- rendering ------------------------------------------------------------
    def wake_words(self, session: Session, payload: OrderPayload) -> list[str] | None:
        path = session.home / "wake_key.hex"
        if not self.wordlist or not path.exists():
            return None
        return wake_code(
            bytes.fromhex(path.read_text(encoding="utf-8").strip()),
            org_id=payload.org_id,
            order_id=payload.order_id,
            bucket=bucket_for(payload.issued_at),
            wordlist=self.wordlist,
        )

    def view(self, session: Session, order_id: str, item: InboxItem) -> dict[str, Any]:
        raw = item.envelope.get("payload", {})
        scenario = session.policy.scenario(str(raw.get("scenario", "")))
        return {
            "order_id": order_id,
            "accepted": item.accepted,
            "reasons": item.reasons,
            "warnings": item.warnings,
            "drill": raw.get("drill"),
            "scenario": raw.get("scenario"),
            "description": scenario.description if scenario else "",
            "severity": raw.get("severity"),
            "action": raw.get("action"),
            "text": raw.get("text", ""),
            "cancels": raw.get("cancels"),
            "cancelled_by": item.cancelled_by,
            "signers": item.signers,
            "issued_at": raw.get("issued_at"),
            "not_valid_after": raw.get("not_valid_after"),
            "received_at": item.received_at,
            "requires_ack": bool(raw.get("requires_ack")),
            "my_ack": item.my_ack,
            "wake_words": self.wake_words(session, item.payload) if item.payload else None,
        }


def create_mobile(
    *,
    homes: pathlib.Path,
    server_url: str,
    wordlist: pathlib.Path | None = None,
    transport: httpx.BaseTransport | None = None,
    connector: Connector = websockets_connector,
    clock: Clock | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> FastAPI:
    mobile = Mobile(
        homes=homes,
        server_url=server_url,
        wordlist=wordlist,
        transport=transport,
        connector=connector,
        clock=clock,
        monotonic=monotonic,
    )
    app = FastAPI(title="alerting mobile", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.mobile = mobile

    def current(request: Request) -> Session:
        return mobile.session(request.cookies.get(COOKIE))

    def guarded(request: Request) -> Session:
        if request.headers.get(CSRF_HEADER) != "1":
            raise HTTPException(403, "запрос не из приложения")
        return current(request)

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/manifest.webmanifest", include_in_schema=False)
    def manifest() -> FileResponse:
        return FileResponse(
            STATIC_DIR / "manifest.webmanifest", media_type="application/manifest+json"
        )

    @app.get("/sw.js", include_in_schema=False)
    def service_worker() -> FileResponse:
        return FileResponse(STATIC_DIR / "sw.js", media_type="text/javascript")

    @app.get("/icon.svg", include_in_schema=False)
    def icon() -> FileResponse:
        return FileResponse(STATIC_DIR / "icon.svg", media_type="image/svg+xml")

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/api/login")
    def login(body: LoginRequest, request: Request, response: Response) -> dict[str, Any]:
        if request.headers.get(CSRF_HEADER) != "1":
            raise HTTPException(403, "запрос не из приложения")
        token, session = mobile.login(body.person_id.strip(), body.passphrase)
        response.set_cookie(COOKIE, token, httponly=True, samesite="strict", path="/")
        return {"person_id": session.stored.person_id, "name": session.name}

    @app.post("/api/logout")
    def logout(request: Request, response: Response) -> dict[str, bool]:
        mobile.logout(request.cookies.get(COOKIE))
        response.delete_cookie(COOKIE, path="/")
        return {"ok": True}

    @app.get("/api/inbox")
    def inbox(session: Session = Depends(current)) -> dict[str, Any]:
        with session.lock:
            items = sorted(session.inbox.items(), key=lambda kv: kv[1].received_at, reverse=True)
            views = [mobile.view(session, order_id, item) for order_id, item in items]
        return {
            "person_id": session.stored.person_id,
            "name": session.name,
            "connected": session.connected,
            "last_error": session.last_error,
            "now": mobile.clock.now(),
            "orders": views,
        }

    @app.post("/api/orders/{order_id}/ack")
    def ack(order_id: str, body: AckForm, session: Session = Depends(guarded)) -> dict[str, Any]:
        if body.status not in HUMAN_STATUSES:
            raise HTTPException(422, "неизвестный статус")
        if body.status == "cannot_comply" and not (body.reason or "").strip():
            raise HTTPException(422, "укажите причину")
        try:
            accepted = mobile.send_ack(session, order_id, AckStatus(body.status), body.reason)
        except ServerError as exc:
            raise HTTPException(502, str(exc)) from None
        if not accepted:
            raise HTTPException(409, "сервер не принял подтверждение")
        return {"accepted": True}

    return app
