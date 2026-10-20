"""The custodians' screen: run on the offline laptop, opened in its browser.

It binds to localhost only and has no notion of a network: requests arrive as files
the custodians pick from a USB stick, answers leave the same way. The root key is
opened for one signature at a time -- both passphrases with every signing -- and
dropped as soon as it is done; nothing but the sealed vault is ever written.
"""

from __future__ import annotations

import json
import logging
import os
import pathlib
import time
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from alerting import custody
from alerting.custody import CustodyError

log = logging.getLogger("alerting.custodian")

CSRF_HEADER = "X-Alerting-Custodian"
STATIC_DIR = pathlib.Path(__file__).parent / "static"


class CreateForm(BaseModel):
    org_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    names: tuple[str, str]
    passphrases: tuple[str, str]


class RestoreForm(BaseModel):
    vault: dict[str, Any]


class UnlockForm(BaseModel):
    passphrases: tuple[str, str]


class ReviewForm(BaseModel):
    request: dict[str, Any]


class SignForm(BaseModel):
    request: dict[str, Any]
    passphrases: tuple[str, str]
    confirm_migration: bool = False


def _write_vault(path: pathlib.Path, vault: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(vault, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def create_custodian(vault_path: pathlib.Path) -> FastAPI:
    app = FastAPI(title="alerting custodian", docs_url=None, redoc_url=None, openapi_url=None)

    def vault() -> dict[str, Any] | None:
        if not vault_path.exists():
            return None
        blob: dict[str, Any] = json.loads(vault_path.read_text(encoding="utf-8"))
        return blob

    def require_vault() -> dict[str, Any]:
        found = vault()
        if found is None:
            raise HTTPException(409, "корневого ключа ещё нет — создайте его")
        return found

    def require_csrf(request: Request) -> None:
        if request.headers.get(CSRF_HEADER) != "1":
            raise HTTPException(403, "запрос не из окна хранителей")

    def refuse(exc: CustodyError) -> HTTPException:
        return HTTPException(422, str(exc))

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/custodian.js", include_in_schema=False)
    def script() -> FileResponse:
        return FileResponse(STATIC_DIR / "custodian.js", media_type="text/javascript")

    @app.get("/api/status")
    def status() -> dict[str, Any]:
        found = vault()
        if found is None:
            return {"vault": None, "path": str(vault_path)}
        return {
            "path": str(vault_path),
            "vault": {
                "org_id": found["org_id"],
                "public_key": found["public_key"],
                "key_id": found["key_id"],
                "fingerprint": custody.fingerprint(found["public_key"]),
                "custodians": found["custodians"],
                "created_at": found["created_at"],
            },
        }

    @app.post("/api/vault/create")
    def create(body: CreateForm, request: Request) -> dict[str, Any]:
        require_csrf(request)
        if vault_path.exists():
            raise HTTPException(409, f"корневой ключ уже есть: {vault_path}")
        try:
            sealed, _ = custody.create_vault(body.org_id, body.passphrases, body.names)
        except CustodyError as exc:
            raise refuse(exc) from None
        _write_vault(vault_path, sealed)
        log.info("root vault created for %s at %s", body.org_id, vault_path)
        return status()

    @app.post("/api/vault/restore")
    def restore(body: RestoreForm, request: Request) -> dict[str, Any]:
        require_csrf(request)
        if vault_path.exists():
            raise HTTPException(409, f"корневой ключ уже есть: {vault_path}")
        if body.vault.get("type") != custody.VAULT_TYPE:
            raise HTTPException(422, "это не резервная копия корневого ключа")
        _write_vault(vault_path, body.vault)
        return status()

    @app.get("/api/vault/file")
    def backup() -> Response:
        """The sealed vault, for the second safe. Useless without both passphrases."""
        found = require_vault()
        return Response(
            json.dumps(found, ensure_ascii=False, indent=2),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="root-vault-{found["org_id"]}.json"'
            },
        )

    @app.post("/api/vault/check")
    def check(body: UnlockForm, request: Request) -> dict[str, bool]:
        """Both passphrases still open the vault -- for the yearly drill."""
        require_csrf(request)
        try:
            custody.open_vault(require_vault(), body.passphrases)
        except CustodyError as exc:
            raise refuse(exc) from None
        return {"ok": True}

    @app.post("/api/review")
    def review(body: ReviewForm, request: Request) -> dict[str, Any]:
        require_csrf(request)
        found = require_vault()
        try:
            seen = custody.review(body.request, found)
        except CustodyError as exc:
            raise refuse(exc) from None
        return {
            "org_id": seen.org_id,
            "migrating": seen.migrating,
            "previous_fingerprint": (
                custody.fingerprint(seen.previous_root) if seen.previous_root else None
            ),
            "directory_version": seen.directory_version,
            "policy_version": seen.policy_version,
            "created_by": seen.created_by,
            "created_at": seen.created_at,
            "changes": seen.changes,
            "people": seen.people,
        }

    @app.post("/api/sign")
    def sign(body: SignForm, request: Request) -> dict[str, Any]:
        require_csrf(request)
        found = require_vault()
        try:
            private = custody.open_vault(found, body.passphrases)
            answer = custody.sign_answer(
                body.request,
                found,
                private,
                now=int(time.time()),
                confirm_migration=body.confirm_migration,
            )
        except CustodyError as exc:
            raise refuse(exc) from None
        # The unlocked key goes out of scope with this call; it is never stored.
        log.info("signed an answer for %s: %s", found["org_id"], answer["summary"])
        return answer

    return app
