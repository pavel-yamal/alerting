"""Web panel for the duty officer and the decision-makers.

**This is a client, not part of the server.** It holds the person's unlocked key for
the length of a session and signs every request with it, exactly as
``alerting-approver`` does from a terminal. The server still never sees a private
key, and still cannot make anyone sign anything: the panel re-derives the bytes it
signs from the payload itself and refuses to sign unless the person approved *those*
bytes (see :func:`sign_proposal`).

Where it runs follows from that. On a real installation it belongs on the operator's
workstation, next to their key, not on the alerting server. On the Docker stand it
runs in its own container beside the server, because there the demo keys already
live in a shared volume.

What the browser talks to is this process, same-origin, behind a session cookie. The
browser never sees a key, a passphrase after login, or the server's address.
"""

from __future__ import annotations

import hashlib
import logging
import pathlib
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
from cryptography.exceptions import InvalidTag
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from alerting.clients.approver_cli import KNOWN_PAYLOAD_FIELDS
from alerting.clients.bundles import BundleCache, PinnedOrg
from alerting.clients.keystore import StoredKey, load_key
from alerting.clients.transport import Api, ServerError, SignedRequests
from alerting.core.canonical import canonicalize
from alerting.core.clock import Clock, SystemClock
from alerting.core.directory import Directory
from alerting.core.envelope import Severity
from alerting.core.policy import Policy
from alerting.core.signing import DOMAIN_ORDER, sign_payload

log = logging.getLogger("alerting.panel")

COOKIE = "alerting_panel"

#: Mutating requests must carry this header. A cross-site form or image cannot set a
#: custom header without a CORS preflight, and this app answers no preflight -- so a
#: page on another origin cannot make the panel sign on the operator's behalf.
CSRF_HEADER = "X-Alerting-Panel"

#: An unattended panel with an unlocked key is a signing machine for whoever walks
#: past. Fifteen minutes of inactivity ends the session; the key is dropped with it.
IDLE_TIMEOUT_S = 15 * 60

#: Person ids become path components of the key store. Anything else is refused
#: before it gets near the filesystem.
PERSON_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")

STATIC_DIR = pathlib.Path(__file__).parent / "static"


@dataclass
class Session:
    stored: StoredKey
    pin: PinnedOrg
    cache: BundleCache
    api: Api
    name: str
    role: str
    last_seen: float = field(default_factory=time.monotonic)

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
        homes: pathlib.Path,
        server_url: str,
        transport: httpx.BaseTransport | None = None,
        clock: Clock | None = None,
    ) -> None:
        self.homes = homes
        self.server_url = server_url
        self.transport = transport
        self.clock = clock or SystemClock()
        self.sessions: dict[str, Session] = {}
        # The server has no "list open proposals" route, so the panel remembers the
        # ones created or opened through it. Every person using this panel sees them,
        # which is the point: the second signer finds the first one's proposal here.
        self.proposal_ids: list[str] = []
        self._lock = threading.Lock()

    def remember(self, order_id: str) -> None:
        with self._lock:
            if order_id in self.proposal_ids:
                self.proposal_ids.remove(order_id)
            self.proposal_ids.insert(0, order_id)
            del self.proposal_ids[50:]

    def login(self, person_id: str, passphrase: str) -> tuple[str, Session]:
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

        # Verified against the pinned root key, with rollback protection, before the
        # panel trusts a single name, role or scenario from the server.
        cache = BundleCache(pin)
        try:
            directory = cache.accept("directory", api.get("/v1/directory"))
            policy = cache.accept("policy", api.get("/v1/policy"))
        except ServerError as exc:
            api.close()
            raise HTTPException(502, f"сервер отказал: {exc}") from None
        except Exception as exc:
            api.close()
            log.warning("bundle rejected for %s: %s", person_id, exc)
            raise HTTPException(502, f"справочник или политика не прошли проверку: {exc}") from None

        assert isinstance(directory, Directory) and isinstance(policy, Policy)
        entry = directory.lookup(stored.key_id)
        if entry is None or directory.is_revoked(stored.key_id):
            api.close()
            raise HTTPException(403, "ключ отсутствует в справочнике или отозван")
        if entry.role not in policy.approver_roles:
            api.close()
            raise HTTPException(
                403, "панель — для дежурных и ЛПР; исполнители работают в своём приложении"
            )

        token = secrets.token_urlsafe(32)
        session = Session(stored, pin, cache, api, entry.name, entry.role)
        with self._lock:
            self.sessions[token] = session
        log.info("panel login: %s (%s)", person_id, entry.role)
        return token, session

    def session(self, token: str | None) -> Session:
        with self._lock:
            session = self.sessions.get(token or "")
            if session is None:
                raise HTTPException(401, "войдите в панель")
            if time.monotonic() - session.last_seen > IDLE_TIMEOUT_S:
                del self.sessions[token or ""]
                session.api.close()
                raise HTTPException(401, "сессия истекла, войдите снова")
            session.last_seen = time.monotonic()
            return session

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
    homes: pathlib.Path,
    server_url: str,
    transport: httpx.BaseTransport | None = None,
    clock: Clock | None = None,
) -> FastAPI:
    panel = Panel(homes=homes, server_url=server_url, transport=transport, clock=clock)
    app = FastAPI(title="alerting panel", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.panel = panel

    def current(request: Request) -> Session:
        return panel.session(request.cookies.get(COOKIE))

    def guarded(request: Request) -> Session:
        if request.headers.get(CSRF_HEADER) != "1":
            raise HTTPException(403, "запрос не из панели")
        return current(request)

    def names(session: Session) -> dict[str, str]:
        return {entry.person_id: entry.name for entry in session.directory.payload.keys}

    def signer_names(session: Session, signatures: list[dict[str, Any]]) -> list[str]:
        directory = session.directory
        result = []
        for signature in signatures:
            entry = directory.lookup(signature["key_id"])
            result.append(f"{entry.name} ({entry.role})" if entry else signature["key_id"])
        return result

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/api/login")
    def login(body: LoginRequest, request: Request, response: Response) -> dict[str, Any]:
        if request.headers.get(CSRF_HEADER) != "1":
            raise HTTPException(403, "запрос не из панели")
        token, session = panel.login(body.person_id.strip(), body.passphrase)
        response.set_cookie(COOKIE, token, httponly=True, samesite="strict", path="/")
        return {"person_id": session.stored.person_id, "name": session.name, "role": session.role}

    @app.post("/api/logout")
    def logout(request: Request, response: Response) -> dict[str, bool]:
        panel.logout(request.cookies.get(COOKIE))
        response.delete_cookie(COOKIE, path="/")
        return {"ok": True}

    @app.get("/api/me")
    def me(session: Session = Depends(current)) -> dict[str, Any]:
        return {"person_id": session.stored.person_id, "name": session.name, "role": session.role}

    @app.get("/api/meta")
    def meta(session: Session = Depends(current)) -> dict[str, Any]:
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
            "digest": payload_digest(payload),
            "required": rule.m if rule else None,
            "signed_by": signer_names(session, proposal["signatures"]),
            "signed_by_me": any(
                s["key_id"] == session.stored.key_id for s in proposal["signatures"]
            ),
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

        result = _server(
            session.api.post,
            f"/v1/proposals/{order_id}/signatures",
            {
                "key_id": session.stored.key_id,
                "sig": sign_payload(DOMAIN_ORDER, payload, session.stored.private_key),
            },
        )
        log.info("panel: %s signed %s", session.stored.person_id, order_id)
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

    return app


def session_now(panel: Panel) -> int:
    """The panel's clock, so the page shows expiry against the same clock that signs."""
    return panel.clock.now()
