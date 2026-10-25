"""Self-service enrolment for a demonstration stand -- the App Store reviewer's way in.

docs/adr/0016, "Демо-стенд для ревью". On a real installation a device key reaches the
directory only through the custodians and the offline root key (ADR 0013): somebody
checks, in person, whose key it is. A reviewer from Apple has nobody to meet. So a
*demonstration* panel may be given the demo organisation's root key, and then it
enrols any app key that asks, as a decision-maker of the demo organisation:

* it is off unless the panel is started with ``--demo-enroll-root-key``; the root key
  must match the root the panel pins, or the panel refuses to start;
* that root key exists only on a demo stand (``org-init`` writes it); a real
  installation's root lives offline with the custodians and is never on a server, so
  the flag cannot be turned on there by accident;
* enrolled keys are named ``demo-NNN``, role ``lpr``, valid for ``DEMO_KEY_DAYS``, and
  there are at most ``DEMO_ENROLL_LIMIT`` of them;
* the directory change is published with a server-held demo key (``--demo-enroll-as``),
  the same way the custodians' answer is carried by a person signed in to the panel.

The app learns about it from ``/api/config`` (``demo: true``) and shows a
"демо-стенд" banner on every screen.
"""

from __future__ import annotations

import logging
import pathlib
import re
import threading
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from alerting.clients.keystore import load_key
from alerting.clients.transport import Api, ServerError, SignedRequests
from alerting.core.signing import (
    DOMAIN_DIRECTORY,
    private_key_from_b64u,
    public_key_from_b64u,
    public_key_to_b64u,
)
from alerting.orgadmin import add_key, verified_current
from alerting.orgkit import sign_bundle

log = logging.getLogger("alerting.panel.demo")

DEMO_PERSON = re.compile(r"^demo-(\d{3,})$")
DEMO_KEY_DAYS = 30
DEMO_ENROLL_LIMIT = 200


@dataclass
class DemoEnroll:
    """What a demonstration panel needs to enrol keys by itself."""

    root_key: Ed25519PrivateKey
    #: A person with a server-held key under ``--homes`` who may publish bundles.
    publisher: str
    passphrase: str
    lock: threading.Lock = field(default_factory=threading.Lock)

    @classmethod
    def from_file(cls, path: pathlib.Path, publisher: str, passphrase: str) -> DemoEnroll:
        return cls(
            private_key_from_b64u(path.read_text(encoding="utf-8").strip()), publisher, passphrase
        )

    @property
    def root_public_b64u(self) -> str:
        return public_key_to_b64u(self.root_key.public_key())


class DemoEnrollForm(BaseModel):
    public_key: str = Field(min_length=43, max_length=43)


def add_demo_routes(app: FastAPI, panel: Any, demo: DemoEnroll, csrf_header: str) -> None:
    """``POST /api/demo/enroll``: put this app key into the demo directory."""
    if panel.pin is None or panel.homes is None:
        raise ValueError("demo enrolment needs device-key login (--org, --root-key) and --homes")
    if demo.root_public_b64u != panel.pin.root_public_key_b64u:
        raise ValueError("the demo root key does not match the root this panel pins")

    def publisher_api() -> Api:
        home = panel.homes / demo.publisher
        stored = load_key(demo.publisher, demo.passphrase, directory=home)
        auth = SignedRequests(
            org_id=panel.pin.org_id,
            key_id=stored.key_id,
            person_id=stored.person_id,
            private_key=stored.private_key,
            clock=panel.clock,
        )
        return Api(panel.server_url, auth=auth, transport=panel.transport)

    @app.post("/api/demo/enroll")
    def demo_enroll(body: DemoEnrollForm, request: Request) -> dict[str, Any]:
        if request.headers.get(csrf_header) != "1":
            raise HTTPException(403, "запрос не из панели")
        try:
            public_key_from_b64u(body.public_key)
        except Exception:
            raise HTTPException(400, "это не публичный ключ Ed25519") from None
        with demo.lock:
            try:
                api = publisher_api()
                current = verified_current(api.get("/v1/directory"), demo.root_public_b64u)
            except (FileNotFoundError, ServerError) as exc:
                log.warning("demo enrolment: cannot read the directory: %s", exc)
                raise HTTPException(503, "демо-стенд не может прочитать справочник") from None
            taken = [int(m.group(1)) for e in current.keys if (m := DEMO_PERSON.match(e.person_id))]
            if len(set(taken)) >= DEMO_ENROLL_LIMIT:
                raise HTTPException(429, "на демо-стенде исчерпан лимит регистраций")
            number = max(taken, default=0) + 1
            person_id = f"demo-{number:03d}"
            name = f"Демо-ЛПР {number}"
            try:
                payload, entry = add_key(
                    current,
                    person_id=person_id,
                    name=name,
                    role="lpr",
                    public_key=body.public_key,
                    issued_at=panel.clock.now(),
                    valid_days=DEMO_KEY_DAYS,
                )
            except ValueError as exc:
                raise HTTPException(409, str(exc)) from None
            try:
                api.post(
                    "/v1/bundles", {"bundle": sign_bundle(payload, DOMAIN_DIRECTORY, demo.root_key)}
                )
            except ServerError as exc:
                log.warning("demo enrolment: publish refused: %s", exc)
                raise HTTPException(502, "сервер не принял справочник") from None
        log.info("demo enrolment: %s as %s", entry.key_id, person_id)
        return {"person_id": person_id, "name": name, "key_id": entry.key_id, "role": "lpr"}
