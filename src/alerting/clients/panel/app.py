"""Web panel for the duty officer and the decision-makers.

Two ways to sign in, and they differ in where the person's key lives.

**Device key (the real one).** The key is created in the person's browser -- phone,
iPad, workstation -- and never leaves it (docs/adr/0012). At login the browser signs a
short-lived *delegation* handing HTTP authentication to a session key this process
generates; the panel signs requests with that. Orders are signed **in the browser**,
over the payload the page itself renders. So this process, and whoever breaks into
it, can read and propose but cannot put anyone's signature on an order.

**Server-held demo keys.** Keys under ``--homes``, unlocked here with a passphrase --
how the Docker stand shows the flow with no enrolment at all. Whoever learns two
passphrases, or controls this process, can sign. Off unless enabled.

Either way the panel re-derives what is signed from the payload itself and refuses
unless the person approved *those* bytes (see :func:`sign_proposal`), and the server
never sees a device key.
"""

from __future__ import annotations

import hashlib
import logging
import pathlib
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx
import yaml
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from alerting import custody
from alerting.clients.approver_cli import KNOWN_PAYLOAD_FIELDS
from alerting.clients.bundles import BundleCache, PinnedOrg
from alerting.clients.keystore import load_key
from alerting.clients.transport import Api, ServerError, SignedRequests
from alerting.core.canonical import canonicalize
from alerting.core.clock import Clock, SystemClock
from alerting.core.directory import Directory
from alerting.core.envelope import Severity
from alerting.core.http_auth import MAX_DELEGATION_S, delegation_payload, encode_delegation
from alerting.core.policy import Policy
from alerting.core.signing import (
    DOMAIN_ORDER,
    generate_keypair,
    public_key_to_b64u,
    sign_payload,
    verify_signature,
)
from alerting.orgadmin import next_revocations
from alerting.server.auth import OPERATORS

log = logging.getLogger("alerting.panel")

COOKIE = "alerting_panel"

#: Mutating requests must carry this header. A cross-site form or image cannot set a
#: custom header without a CORS preflight, and this app answers no preflight -- so a
#: page on another origin cannot make the panel sign on the operator's behalf.
CSRF_HEADER = "X-Alerting-Panel"

#: An unattended panel with an unlocked key is a signing machine for whoever walks
#: past. Fifteen minutes of inactivity ends the session; the key is dropped with it.
IDLE_TIMEOUT_S = 15 * 60

#: Sent by the page on requests a person caused (a click, a submit). Only those count
#: as activity. The page also polls every few seconds, and if polling counted, a tab
#: left open on an unattended desk would keep its key unlocked forever.
ACTIVITY_HEADER = "X-Alerting-Activity"

#: How often expired sessions are swept even if nobody calls the panel at all -- a
#: closed tab never sends the request that would have noticed its session expired.
SWEEP_INTERVAL_S = 30

#: Person ids become path components of the key store. Anything else is refused
#: before it gets near the filesystem.
PERSON_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
KEY_ID = re.compile(r"^ed25519:[A-Za-z0-9_-]{22}$")

#: How long a browser has to sign the delegation it was handed.
CHALLENGE_TTL_S = 120

#: The delegation's own lifetime. The session idles out after 15 minutes anyway and
#: drops the session key; this caps what a key leaked from this process is worth.
DELEGATION_S = MAX_DELEGATION_S

STATIC_DIR = pathlib.Path(__file__).parent / "static"


@dataclass
class Session:
    person_id: str
    key_id: str
    #: The device key, when it is held here (demo mode). ``None`` when it lives in the
    #: person's browser, which then signs orders itself.
    signer: Ed25519PrivateKey | None
    pin: PinnedOrg
    cache: BundleCache
    api: Api
    name: str
    role: str
    #: Whether this person's signature counts toward a quorum. Distinct from being
    #: allowed in at all: the server lets every operator create and watch proposals,
    #: and an organisation may keep duty officers out of ``approver_roles`` on purpose.
    can_sign: bool
    last_seen: float

    @property
    def directory(self) -> Directory:
        return self.cache.directory()

    @property
    def policy(self) -> Policy:
        return self.cache.policy()


class LoginRequest(BaseModel):
    person_id: str
    passphrase: str


class ProposalForm(BaseModel):
    scenario: str
    severity: Severity
    #: Required and without a default, as everywhere else in the stack. The form
    #: offers no preselected choice either: the operator has to click one.
    drill: bool
    groups: list[str] = Field(default_factory=list)
    sites: list[str] = Field(default_factory=list)
    persons: list[str] = Field(default_factory=list)
    text: str = Field(default="", max_length=1000)
    ttl_s: int = Field(default=900, ge=60, le=86400)


class SignForm(BaseModel):
    #: The digest of the payload the person was shown. Signing proceeds only if the
    #: payload the server holds *now* has the same digest.
    digest: str
    #: The order signature made in the browser by the device key. Required, and the
    #: only way to sign, when the key lives there.
    sig: str | None = None


class CustodyForm(BaseModel):
    changes: list[dict[str, Any]] = Field(min_length=1, max_length=100)


class AnswerForm(BaseModel):
    answer: dict[str, Any]


class ContactForm(BaseModel):
    person_id: str
    name: str
    phone: str = ""
    site: str = ""
    groups: list[str] = Field(default_factory=list)
    role: str = "executor"


class RevokeForm(BaseModel):
    signer: str
    reason: str = Field(min_length=1, max_length=500)
    person_id: str | None = None
    key_id: str | None = None


class SignedList(BaseModel):
    payload: dict[str, Any]
    signature: str


class DeviceBegin(BaseModel):
    person_id: str
    key_id: str


class DeviceFinish(BaseModel):
    challenge: str
    signature: str


@dataclass
class Challenge:
    person_id: str
    key_id: str
    payload: dict[str, Any]
    session_key: Ed25519PrivateKey
    created: float


class CancelForm(BaseModel):
    text: str = Field(default="", max_length=1000)


def payload_digest(payload: dict[str, Any]) -> str:
    """What a person approves: the exact bytes the order signature will cover."""
    return hashlib.sha256(DOMAIN_ORDER + canonicalize(payload)).hexdigest()


def describe_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Every field the signature covers, for the review screen.

    The same rule as ``show_payload`` in the CLI: a correct signature over content
    nobody looked at is how a compromised server would widen an audience or flip
    START to STOP. So the whole payload is rendered, not a headline.
    """
    audience = payload.get("audience", {})
    return {
        "drill": payload["drill"],
        "scenario": payload["scenario"],
        "severity": payload["severity"],
        "action": payload["action"],
        "audience": {
            "sites": list(audience.get("sites") or []),
            "groups": list(audience.get("groups") or []),
            "persons": list(audience.get("persons") or []),
        },
        "text": payload.get("text", ""),
        "issued_at": payload["issued_at"],
        "not_valid_after": payload["not_valid_after"],
        "stream": f"{payload['stream_id']}#{payload['seq']}",
        "requires_ack": bool(payload.get("requires_ack")),
        "ack_deadline_s": payload.get("ack_deadline_s"),
        "cancels": payload.get("cancels"),
        "org_id": payload["org_id"],
        "policy_id": payload["policy_id"],
        "unexpected_fields": sorted(set(payload) - KNOWN_PAYLOAD_FIELDS),
    }


class Panel:
    """Sessions, and the proposals this panel has seen."""

    def __init__(
        self,
        *,
        homes: pathlib.Path | None,
        server_url: str,
        transport: httpx.BaseTransport | None = None,
        clock: Clock | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        org_id: str | None = None,
        root_public_key: str | None = None,
        state_dir: pathlib.Path | None = None,
        server_keys: bool = True,
    ) -> None:
        self.homes = homes
        self.server_url = server_url
        self.transport = transport
        self.clock = clock or SystemClock()
        # Idle time is measured on a monotonic clock, injected so a test can advance it.
        self.monotonic = monotonic
        self.sessions: dict[str, Session] = {}
        self.challenges: dict[str, Challenge] = {}
        # Device-key sessions verify bundles against the root key configured here --
        # pinned by whoever installed the panel, never fetched from the server.
        self.pin: PinnedOrg | None = None
        if org_id and root_public_key:
            home = state_dir or pathlib.Path("var/panel")
            home.mkdir(parents=True, exist_ok=True)
            self.pin = PinnedOrg(org_id, root_public_key, home)
            self.pin.save()
        self.server_keys = server_keys and homes is not None
        # The server has no "list open proposals" route, so the panel remembers the
        # ones created or opened through it. Every person using this panel sees them,
        # which is the point: the second signer finds the first one's proposal here.
        self.proposal_ids: list[str] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()

    @property
    def device_login(self) -> bool:
        return self.pin is not None

    def remember(self, order_id: str) -> None:
        with self._lock:
            if order_id in self.proposal_ids:
                self.proposal_ids.remove(order_id)
            self.proposal_ids.insert(0, order_id)
            del self.proposal_ids[50:]

    def login(self, person_id: str, passphrase: str) -> tuple[str, Session]:
        """Demo mode: unlock a key held under ``--homes``."""
        if not self.server_keys or self.homes is None:
            raise HTTPException(
                404, "вход по ключам на сервере отключён — войдите ключом устройства"
            )
        if not PERSON_ID.match(person_id):
            raise HTTPException(400, "некорректный идентификатор")
        home = self.homes / person_id
        try:
            stored = load_key(person_id, passphrase, directory=home)
            pin = PinnedOrg.load(home)
        except (FileNotFoundError, InvalidTag):
            # One message for both: which person ids exist is not the panel's to say.
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
        return self._open(api, pin, stored.person_id, stored.key_id, stored.private_key)

    def begin_device_login(self, person_id: str, key_id: str) -> tuple[str, dict[str, Any]]:
        """Hand the browser a delegation to sign for a session key made here."""
        if self.pin is None:
            raise HTTPException(404, "вход ключом устройства не настроен на этой панели")
        if not PERSON_ID.match(person_id) or not KEY_ID.match(key_id):
            raise HTTPException(400, "некорректный идентификатор или ключ")
        session_key, session_public = generate_keypair()
        now = self.clock.now()
        payload = delegation_payload(
            org_id=self.pin.org_id,
            key_id=key_id,
            person_id=person_id,
            session_key=public_key_to_b64u(session_public),
            not_before=now,
            not_after=now + DELEGATION_S,
        )
        challenge = secrets.token_urlsafe(24)
        with self._lock:
            cutoff = self.monotonic() - CHALLENGE_TTL_S
            for stale in [c for c, v in self.challenges.items() if v.created < cutoff]:
                del self.challenges[stale]
            self.challenges[challenge] = Challenge(
                person_id, key_id, payload, session_key, self.monotonic()
            )
        return challenge, payload

    def finish_device_login(self, challenge: str, signature: str) -> tuple[str, Session]:
        with self._lock:
            pending = self.challenges.pop(challenge, None)
        if pending is None or self.monotonic() - pending.created > CHALLENGE_TTL_S:
            raise HTTPException(401, "вход устарел — начните заново")
        assert self.pin is not None
        api = Api(
            self.server_url,
            auth=SignedRequests(
                org_id=self.pin.org_id,
                key_id=pending.key_id,
                person_id=pending.person_id,
                private_key=pending.session_key,
                clock=self.clock,
                delegation=encode_delegation(pending.payload, signature),
            ),
            transport=self.transport,
        )
        return self._open(api, self.pin, pending.person_id, pending.key_id, None)

    def _open(
        self,
        api: Api,
        pin: PinnedOrg,
        person_id: str,
        key_id: str,
        signer: Ed25519PrivateKey | None,
    ) -> tuple[str, Session]:
        # Verified against the pinned root key, with rollback protection, before the
        # panel trusts a single name, role or scenario from the server. For a device
        # login this first request is also where the server checks the delegation.
        cache = BundleCache(pin)
        try:
            cache.accept("directory", api.get("/v1/directory"))
            directory = cache.accept("revocations", api.get("/v1/revocations"))
            policy = cache.accept("policy", api.get("/v1/policy"))
        except ServerError as exc:
            api.close()
            if "403" in str(exc) or "401" in str(exc):
                raise HTTPException(401, f"ключ не принят сервером: {exc}") from None
            raise HTTPException(502, f"сервер отказал: {exc}") from None
        except Exception as exc:
            api.close()
            log.warning("bundle rejected for %s: %s", person_id, exc)
            raise HTTPException(502, f"справочник или политика не прошли проверку: {exc}") from None

        assert isinstance(directory, Directory) and isinstance(policy, Policy)
        entry = directory.lookup(key_id)
        if entry is None or directory.is_revoked(key_id) or entry.person_id != person_id:
            api.close()
            raise HTTPException(403, "ключ отсутствует в справочнике или отозван")
        # The same gate the server applies to creating proposals, not the quorum
        # roles: who may use the panel and whose signature counts are different
        # questions, and the policy answers only the second.
        if entry.role not in OPERATORS:
            api.close()
            raise HTTPException(
                403, "панель — для дежурных и ЛПР; исполнители работают в своём приложении"
            )

        token = secrets.token_urlsafe(32)
        session = Session(
            person_id,
            key_id,
            signer,
            pin,
            cache,
            api,
            entry.name,
            entry.role,
            can_sign=entry.role in policy.approver_roles,
            last_seen=self.monotonic(),
        )
        with self._lock:
            self.sessions[token] = session
        log.info(
            "panel login: %s (%s, %s)",
            person_id,
            entry.role,
            "server-held key" if signer else "device key",
        )
        return token, session

    def session(self, token: str | None, *, activity: bool) -> Session:
        """The live session for ``token``. Only ``activity`` extends it."""
        self.sweep()
        with self._lock:
            session = self.sessions.get(token or "")
            if session is None:
                raise HTTPException(401, "сессия истекла или не начата — войдите")
            if activity:
                session.last_seen = self.monotonic()
            return session

    def sweep(self) -> None:
        """Drop every session idle past the timeout, and its unlocked key with it."""
        now = self.monotonic()
        with self._lock:
            expired = [t for t, s in self.sessions.items() if now - s.last_seen > IDLE_TIMEOUT_S]
            dropped = [self.sessions.pop(t) for t in expired]
        for session in dropped:
            session.api.close()
            log.info("panel session expired: %s", session.person_id)

    def start_sweeper(self) -> None:
        def run() -> None:
            while not self._stop.wait(SWEEP_INTERVAL_S):
                self.sweep()

        threading.Thread(target=run, name="panel-session-sweeper", daemon=True).start()

    def logout(self, token: str | None) -> None:
        with self._lock:
            session = self.sessions.pop(token or "", None)
        if session is not None:
            session.api.close()


def _server(call: Any, *args: Any, **kwargs: Any) -> Any:
    """Call the server, turning its refusals into something the page can show."""
    try:
        return call(*args, **kwargs)
    except ServerError as exc:
        text = str(exc)
        status = 404 if text.startswith("404") else 409 if text.startswith("409") else 502
        raise HTTPException(status, text) from None


def create_panel(
    *,
    homes: pathlib.Path | None,
    server_url: str,
    transport: httpx.BaseTransport | None = None,
    clock: Clock | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    org_id: str | None = None,
    root_public_key: str | None = None,
    state_dir: pathlib.Path | None = None,
    server_keys: bool = True,
) -> FastAPI:
    panel = Panel(
        homes=homes,
        server_url=server_url,
        transport=transport,
        clock=clock,
        monotonic=monotonic,
        org_id=org_id,
        root_public_key=root_public_key,
        state_dir=state_dir,
        server_keys=server_keys,
    )
    panel.start_sweeper()
    app = FastAPI(title="alerting panel", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.panel = panel

    def current(request: Request) -> Session:
        return panel.session(
            request.cookies.get(COOKIE), activity=request.headers.get(ACTIVITY_HEADER) == "1"
        )

    def guarded(request: Request) -> Session:
        if request.headers.get(CSRF_HEADER) != "1":
            raise HTTPException(403, "запрос не из панели")
        # A state-changing request is always a person acting.
        return panel.session(request.cookies.get(COOKIE), activity=True)

    def names(session: Session) -> dict[str, str]:
        return {entry.person_id: entry.name for entry in session.directory.payload.keys}

    def signer_names(session: Session, signatures: list[dict[str, Any]]) -> list[str]:
        directory = session.directory
        result = []
        for signature in signatures:
            entry = directory.lookup(signature["key_id"])
            result.append(f"{entry.name} ({entry.role})" if entry else signature["key_id"])
        return result

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Response:
        """Scripts only from this origin, and never in a frame.

        With the key in the browser, script injection is the attack that matters:
        injected code could ask the unlocked key to sign. So no inline script, no
        foreign script, no ``eval`` -- the page's code is the two files below.
        """
        response: Response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/panel.js", include_in_schema=False)
    def panel_js() -> FileResponse:
        return FileResponse(STATIC_DIR / "panel.js", media_type="text/javascript")

    @app.get("/devicekey.js", include_in_schema=False)
    def devicekey_js() -> FileResponse:
        return FileResponse(STATIC_DIR / "devicekey.js", media_type="text/javascript")

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, bool]:
        return {"ok": True}

    def who(session: Session) -> dict[str, Any]:
        return {
            "person_id": session.person_id,
            "key_id": session.key_id,
            "name": session.name,
            "role": session.role,
            "can_sign": session.can_sign,
            # The page signs orders itself when the key lives in the browser.
            "device_key": session.signer is None,
        }

    def require_csrf(request: Request) -> None:
        if request.headers.get(CSRF_HEADER) != "1":
            raise HTTPException(403, "запрос не из панели")

    @app.get("/api/config")
    def config() -> dict[str, Any]:
        """What the login page needs before anyone is signed in. Nothing secret."""
        return {
            "org_id": panel.pin.org_id if panel.pin else None,
            "device_login": panel.device_login,
            "server_keys": panel.server_keys,
        }

    @app.post("/api/login")
    def login(body: LoginRequest, request: Request, response: Response) -> dict[str, Any]:
        require_csrf(request)
        token, session = panel.login(body.person_id.strip(), body.passphrase)
        response.set_cookie(COOKIE, token, httponly=True, samesite="strict", path="/")
        return who(session)

    @app.post("/api/device/begin")
    def device_begin(body: DeviceBegin, request: Request) -> dict[str, Any]:
        require_csrf(request)
        challenge, payload = panel.begin_device_login(body.person_id.strip(), body.key_id)
        return {"challenge": challenge, "delegation": payload}

    @app.post("/api/device/finish")
    def device_finish(body: DeviceFinish, request: Request, response: Response) -> dict[str, Any]:
        require_csrf(request)
        token, session = panel.finish_device_login(body.challenge, body.signature)
        response.set_cookie(COOKIE, token, httponly=True, samesite="strict", path="/")
        return who(session)

    @app.post("/api/logout")
    def logout(request: Request, response: Response) -> dict[str, bool]:
        panel.logout(request.cookies.get(COOKIE))
        response.delete_cookie(COOKIE, path="/")
        return {"ok": True}

    @app.get("/api/me")
    def me(session: Session = Depends(current)) -> dict[str, Any]:
        return who(session)

    @app.get("/api/meta")
    def meta(session: Session = Depends(current)) -> dict[str, Any]:
        # Re-synced here rather than trusted from login: a newly published policy --
        # a new event in the codebook, a changed quorum -- shows up without anyone
        # logging out. Verified and version-checked like at login.
        try:
            session.cache.accept("directory", session.api.get("/v1/directory"))
            session.cache.accept("revocations", session.api.get("/v1/revocations"))
            session.cache.accept("policy", session.api.get("/v1/policy"))
        except Exception as exc:
            log.warning("bundle refresh failed for %s: %s", session.person_id, exc)
        policy = session.policy.payload
        roster = _server(session.api.get, "/v1/roster")["people"]
        return {
            "org_id": session.pin.org_id,
            "scenarios": [
                {
                    "code": code,
                    "description": rule.description,
                    "min_severity": rule.min_severity,
                    "max_severity": rule.max_severity,
                    "card": rule.card or "",
                    "until_cancelled": bool(rule.until_cancelled),
                }
                for code, rule in sorted(policy.scenarios.items())
                if code != "CANARY"
            ],
            "severities": {
                str(level): {
                    "launch": rules.launch.m,
                    "distinct_persons": rules.launch.distinct_persons,
                    "min_from_role": dict(rules.launch.min_from_role),
                    "spread_s": rules.launch.max_signature_spread_s,
                    "cancel": rules.cancel.m,
                }
                for level, rules in policy.severities.items()
            },
            "groups": sorted({g for person in roster for g in person["groups"]}),
            "sites": sorted({person["site"] for person in roster if person["site"]}),
        }

    @app.post("/api/proposals")
    def propose(body: ProposalForm, session: Session = Depends(guarded)) -> dict[str, Any]:
        audience = {
            key: value
            for key, value in (
                ("sites", body.sites),
                ("groups", body.groups),
                ("persons", body.persons),
            )
            if value
        }
        result = _server(
            session.api.post,
            "/v1/proposals",
            {
                "scenario": body.scenario,
                "severity": str(body.severity),
                "drill": body.drill,
                "action": "START",
                "audience": audience,
                "text": body.text,
                "ttl_s": body.ttl_s,
            },
        )
        panel.remember(result["order_id"])
        return {"order_id": result["order_id"], "required": result["required_signatures"]}

    @app.get("/api/proposals")
    def proposals(session: Session = Depends(current)) -> dict[str, Any]:
        items = []
        for order_id in list(panel.proposal_ids):
            try:
                proposal = session.api.get(f"/v1/proposals/{order_id}")
            except ServerError:
                continue
            payload = proposal["payload"]
            items.append(
                {
                    "order_id": order_id,
                    "status": proposal["status"],
                    "drill": payload["drill"],
                    "scenario": payload["scenario"],
                    "severity": payload["severity"],
                    "cancels": payload.get("cancels"),
                    "not_valid_after": payload["not_valid_after"],
                    "signed_by": signer_names(session, proposal["signatures"]),
                }
            )
        return {"proposals": items, "now": session_now(panel)}

    @app.get("/api/proposals/{order_id}")
    def review(order_id: str, session: Session = Depends(current)) -> dict[str, Any]:
        proposal = _server(session.api.get, f"/v1/proposals/{order_id}")
        payload = proposal["payload"]
        panel.remember(order_id)
        rule = session.policy.rule_for(
            Severity(payload["severity"]), is_cancel=bool(payload.get("cancels"))
        )
        return {
            "order_id": order_id,
            "status": proposal["status"],
            "fields": describe_payload(payload),
            # The raw payload, for a page that signs in the browser: it renders the
            # review from this very object and signs the same object, so what the
            # person reads is what the device key signs.
            "payload": payload,
            "digest": payload_digest(payload),
            "required": rule.m if rule else None,
            "signed_by": signer_names(session, proposal["signatures"]),
            "can_sign": session.can_sign,
            "signed_by_me": any(s["key_id"] == session.key_id for s in proposal["signatures"]),
            "now": session_now(panel),
        }

    @app.post("/api/proposals/{order_id}/sign")
    def sign_proposal(
        order_id: str, body: SignForm, session: Session = Depends(guarded)
    ) -> dict[str, Any]:
        """Sign only what the person was shown.

        The payload is fetched again here, its digest recomputed from the payload
        itself (never from anything the server offers as "the bytes to sign"), and
        compared with the digest the review screen displayed. If the server changed
        anything in between, nothing is signed and the person reviews again.
        """
        if not session.can_sign:
            raise HTTPException(403, "ваша подпись не засчитывается в кворум по политике")
        proposal = _server(session.api.get, f"/v1/proposals/{order_id}")
        payload = proposal["payload"]
        if payload_digest(payload) != body.digest:
            raise HTTPException(409, "приказ изменился после просмотра — проверьте заново")
        unexpected = set(payload) - KNOWN_PAYLOAD_FIELDS
        if unexpected:
            raise HTTPException(
                409, f"в приказе поля, которые панель не показала: {sorted(unexpected)}"
            )
        if payload.get("org_id") != session.pin.org_id:
            raise HTTPException(409, "приказ другой организации")

        if session.signer is not None:
            signature = sign_payload(DOMAIN_ORDER, payload, session.signer)
        else:
            # Signed in the browser. Checked here against the device key in the
            # directory before it goes anywhere: a signature over anything but this
            # payload is a page and a panel that disagree, and nothing is sent.
            entry = session.directory.lookup(session.key_id)
            if not body.sig or entry is None:
                raise HTTPException(400, "подпись не получена от устройства")
            if not verify_signature(DOMAIN_ORDER, payload, body.sig, entry.public()):
                raise HTTPException(
                    409, "подпись устройства не сходится с приказом — проверьте заново"
                )
            signature = body.sig
        result = _server(
            session.api.post,
            f"/v1/proposals/{order_id}/signatures",
            {"key_id": session.key_id, "sig": signature},
        )
        log.info("panel: %s signed %s", session.person_id, order_id)
        return {
            "dispatched": bool(result.get("dispatched")),
            "recipients": len(result.get("recipients") or []),
            "blocking": result.get("blocking", []),
            "warnings": result.get("warnings", []),
        }

    @app.get("/api/orders")
    def orders(session: Session = Depends(current)) -> dict[str, Any]:
        listed = _server(session.api.get, "/v1/orders", limit=20)
        return {
            "orders": [o for o in listed["orders"] if o["scenario"] != "CANARY"],
            "now": session_now(panel),
        }

    @app.get("/api/events/active")
    def active(session: Session = Depends(current)) -> dict[str, Any]:
        listed = _server(session.api.get, "/v1/events/active")
        return {
            "events": [e for e in listed["events"] if e["scenario"] != "CANARY"],
            "now": session_now(panel),
        }

    @app.get("/api/orders/{order_id}")
    def order_status(order_id: str, session: Session = Depends(current)) -> dict[str, Any]:
        status = _server(session.api.get, f"/v1/orders/{order_id}/status")
        known = names(session)
        for person in status["people"]:
            person["name"] = known.get(person["person_id"], "")
        status["now"] = session_now(panel)
        return status

    @app.post("/api/orders/{order_id}/cancel")
    def cancel(
        order_id: str, body: CancelForm, session: Session = Depends(guarded)
    ) -> dict[str, Any]:
        """Create the stand-down proposal. Signing it is the same review-and-sign step
        as any other order -- a cancel is an order too."""
        order = _server(session.api.get, f"/v1/orders/{order_id}")
        payload = order["payload"]
        proposal = _server(
            session.api.post,
            "/v1/proposals",
            {
                "scenario": payload["scenario"],
                "severity": payload["severity"],
                # Must match the target, or the server refuses: a drill envelope can
                # never stand down a real order.
                "drill": payload["drill"],
                "action": "STOP",
                "audience": payload["audience"],
                "text": body.text or "Отбой",
                "cancels": order_id,
            },
        )
        panel.remember(proposal["order_id"])
        return {"order_id": proposal["order_id"]}

    # --- the directory, and what goes to the custodians ------------------------------
    #
    # The panel never holds the root key. It shows who is enrolled, prepares a request
    # file for the custodians' offline laptop, and publishes the signed answer they
    # bring back -- which the server verifies against the root it trusts. A revocation
    # in a hurry is signed in the browser with the duty shift's revocation key.

    def fresh(session: Session) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
        """Current bundles from the server, verified and version-checked here first."""
        directory = _server(session.api.get, "/v1/directory")
        policy = _server(session.api.get, "/v1/policy")
        revocations = _server(session.api.get, "/v1/revocations") or None
        try:
            session.cache.accept("directory", directory)
            session.cache.accept("revocations", revocations or {})
            session.cache.accept("policy", policy)
        except Exception as exc:
            raise HTTPException(502, f"справочник или политика не прошли проверку: {exc}") from None
        return directory, policy, revocations

    @app.get("/api/directory")
    def directory_view(session: Session = Depends(current)) -> dict[str, Any]:
        fresh(session)
        directory = session.directory
        now = panel.clock.now()
        people = []
        for entry in sorted(directory.payload.keys, key=lambda e: (e.person_id, e.valid_from)):
            revocation = directory.revocation(entry.key_id)
            state = (
                "revoked"
                if revocation
                else "retired"
                if entry.valid_until is not None and entry.valid_until <= now
                else "live"
            )
            people.append(
                {
                    "person_id": entry.person_id,
                    "name": entry.name,
                    "role": entry.role,
                    "key_id": entry.key_id,
                    "state": state,
                    "valid_until": entry.valid_until,
                    "reason": revocation.reason if revocation else "",
                }
            )
        return {
            "org_id": session.pin.org_id,
            "directory_version": directory.version,
            "policy_version": session.policy.version,
            "revocations_version": directory.revocations.version if directory.revocations else 0,
            "revokers": [{"key_id": k, "label": r.label} for k, r in directory.revokers.items()],
            "people": people,
            "scenarios_yaml": yaml.safe_dump(
                {c: r.to_payload() for c, r in session.policy.payload.scenarios.items()},
                allow_unicode=True,
                sort_keys=True,
            ),
            "policy_not_valid_after": session.policy.payload.not_valid_after,
        }

    @app.post("/api/custody/request")
    def custody_request(body: CustodyForm, session: Session = Depends(guarded)) -> dict[str, Any]:
        directory, policy, revocations = fresh(session)
        changes = []
        for change in body.changes:
            if change.get("op") == "policy" and isinstance(change.get("scenarios_yaml"), str):
                try:
                    scenarios = yaml.safe_load(change["scenarios_yaml"])
                except yaml.YAMLError as exc:
                    raise HTTPException(422, f"кодовая книга не читается: {exc}") from None
                change = {k: v for k, v in change.items() if k != "scenarios_yaml"}
                change["scenarios"] = scenarios
            changes.append(change)
        try:
            request = custody.build_request(
                org_id=session.pin.org_id,
                root_public_key=session.pin.root_public_key_b64u,
                directory=directory,
                policy=policy,
                revocations=revocations,
                changes=changes,
                created_by=session.person_id,
                created_at=panel.clock.now(),
            )
            # Checked here as the custodians will check it, so a typo is caught at the
            # desk rather than in the safe room.
            for parsed in custody.parse_changes(request["changes"]):
                if isinstance(parsed, custody.PolicyChange):
                    custody._next_policy(session.policy.payload, parsed, panel.clock.now())
        except custody.CustodyError as exc:
            raise HTTPException(422, str(exc)) from None
        log.info("panel: %s prepared a custody request: %s", session.person_id, changes)
        return request

    @app.post("/api/custody/answer")
    def custody_answer(body: AnswerForm, session: Session = Depends(guarded)) -> dict[str, Any]:
        try:
            bundles = custody.read_answer(body.answer, org_id=session.pin.org_id)
        except custody.CustodyError as exc:
            raise HTTPException(422, str(exc)) from None
        if body.answer.get("root_public_key") != session.pin.root_public_key_b64u:
            raise HTTPException(
                409,
                "ответ подписан другим корневым ключом (отпечаток "
                f"{body.answer.get('root_fingerprint', '?')}): это перенос организации. "
                "Его применяет администратор сервера: ./docker/rotate-root.sh <файл ответа>",
            )
        published = []
        for kind in ("directory", "policy"):
            if kind not in bundles:
                continue
            # The two bundles are published one after the other. If the first went
            # out and the second failed, uploading the same answer again must finish
            # the job, not stop at "version already seen" on the first.
            if _server(session.api.get, f"/v1/{kind}") == bundles[kind]:
                version = bundles[kind]["payload"]["version"]
                published.append({"kind": kind, "version": version, "already": True})
                continue
            result = _server(session.api.post, "/v1/bundles", {"bundle": bundles[kind]})
            published.append(result)
        fresh(session)
        log.info("panel: %s published custody answer %s", session.person_id, published)
        return {"published": published, "summary": body.answer.get("summary", [])}

    @app.post("/api/contacts")
    def set_contact(body: ContactForm, session: Session = Depends(guarded)) -> dict[str, Any]:
        result: dict[str, Any] = _server(
            session.api.post, "/v1/contacts", body.model_dump(exclude_none=True)
        )
        return result

    @app.post("/api/contacts/{person_id}/deactivate")
    def deactivate_contact(person_id: str, session: Session = Depends(guarded)) -> dict[str, Any]:
        result: dict[str, Any] = _server(session.api.post, f"/v1/contacts/{person_id}/deactivate")
        return result

    @app.post("/api/revocations/prepare")
    def prepare_revocation(body: RevokeForm, session: Session = Depends(guarded)) -> dict[str, Any]:
        """The next revocation list, for the browser's revocation key to sign."""
        _, _, latest = fresh(session)
        directory = session.directory
        try:
            payload, chosen = next_revocations(
                directory,
                latest,
                signer=body.signer,
                person_id=body.person_id,
                kid=body.key_id,
                at=panel.clock.now(),
                reason=body.reason,
            )
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        return {
            "payload": payload.to_payload(),
            "previous": [r["key_id"] for r in (latest or {}).get("payload", {}).get("entries", [])],
            # The signed list it builds on, so the browser can check the baseline
            # itself rather than take this response's word for it.
            "latest": latest,
            "revoking": [
                {"person_id": e.person_id, "name": e.name, "role": e.role, "key_id": e.key_id}
                for e in chosen
            ],
        }

    @app.post("/api/revocations/publish")
    def publish_revocation(body: SignedList, session: Session = Depends(guarded)) -> dict[str, Any]:
        result: dict[str, Any] = _server(
            session.api.post,
            "/v1/bundles",
            {"bundle": {"payload": body.payload, "signature": body.signature}},
        )
        fresh(session)
        log.warning("panel: %s published revocation list %s", session.person_id, result)
        return result

    return app


def session_now(panel: Panel) -> int:
    """The panel's clock, so the page shows expiry against the same clock that signs."""
    return panel.clock.now()
