"""Ending a client session by an administrator.

Sessions in the panel and the executor's app have no lifetime: a person stays signed
in until they log out, their key is revoked, or an administrator ends the session.
The last is this module -- for when the key itself is fine and only the session has
to go (a phone left logged in, a person moved off the shift).

The administrator is whoever can run a command on the client's host: the process
writes a fresh random token to ``admin.token`` in its state directory at start, 0600,
and the admin routes answer only a request carrying it. Someone who can read that
file can already read the process's memory, so the token adds no new trust, and
nothing reachable from the network alone can end a session.
"""

from __future__ import annotations

import argparse
import datetime
import hmac
import os
import pathlib
import secrets
import sys
from collections.abc import Callable
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

ADMIN_HEADER = "X-Alerting-Admin"
TOKEN_FILE = "admin.token"


class EndForm(BaseModel):
    #: The person whose sessions end. ``None`` with ``all`` ends every session.
    person_id: str | None = None
    all: bool = False


def issue_token(state_dir: pathlib.Path) -> str:
    """A new token for this process, replacing the one a previous run left."""
    state_dir.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)
    path = state_dir / TOKEN_FILE
    tmp = path.with_suffix(".tmp")
    tmp.unlink(missing_ok=True)
    # Created 0600 rather than chmod-ed after: never readable by others, even briefly.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        out.write(token)
    os.replace(tmp, path)
    return token


def add_admin_routes(
    app: FastAPI,
    token: str,
    *,
    list_sessions: Callable[[], list[dict[str, Any]]],
    end_sessions: Callable[[str | None], int],
) -> None:
    """``GET /admin/sessions`` and ``POST /admin/sessions/end``, behind the token.

    ``end_sessions(None)`` ends every session; otherwise those of one person. It
    returns how many ended.
    """

    def require(request: Request) -> None:
        given = request.headers.get(ADMIN_HEADER, "")
        if not hmac.compare_digest(given.encode(), token.encode()):
            raise HTTPException(403, "нужен токен администратора")

    @app.get("/admin/sessions", include_in_schema=False)
    def sessions(request: Request) -> dict[str, Any]:
        require(request)
        return {"sessions": list_sessions()}

    @app.post("/admin/sessions/end", include_in_schema=False)
    def end(body: EndForm, request: Request) -> dict[str, int]:
        require(request)
        if body.all == (body.person_id is not None):
            raise HTTPException(422, "укажите person_id или all, но не оба")
        return {"ended": end_sessions(None if body.all else body.person_id)}


def add_admin_commands(sub: Any) -> None:
    """The ``sessions`` and ``end-session`` subcommands of a client's CLI."""
    sub.add_parser("sessions", help="list who is signed in (administrator)")
    end = sub.add_parser("end-session", help="sign a person out (administrator)")
    who = end.add_mutually_exclusive_group(required=True)
    who.add_argument("person_id", nargs="?", help="whose sessions to end")
    who.add_argument("--all", action="store_true", help="end every session")


def run_admin_command(args: argparse.Namespace, state_dir: pathlib.Path, port: int) -> int:
    """Call the running process on this host with the token it wrote."""
    try:
        token = (state_dir / TOKEN_FILE).read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        print(f"нет {state_dir / TOKEN_FILE}: процесс не запущен с этим --state", file=sys.stderr)
        return 1
    with httpx.Client(
        base_url=f"http://127.0.0.1:{port}", headers={ADMIN_HEADER: token}, timeout=10
    ) as client:
        if args.command == "sessions":
            response = client.get("/admin/sessions")
        else:
            body = {"all": True} if args.all else {"person_id": args.person_id}
            response = client.post("/admin/sessions/end", json=body)
    if response.status_code != 200:
        print(f"отказ: {response.status_code} {response.text}", file=sys.stderr)
        return 1
    data = response.json()
    if args.command == "sessions":
        rows = data["sessions"]
        for row in rows:
            since = datetime.datetime.fromtimestamp(row["since"]).isoformat(timespec="seconds")
            print("\t".join((row["person_id"], row["name"], row["role"], since, row["kind"])))
        if not rows:
            print("никто не вошёл")
    else:
        print(f"завершено сессий: {data['ended']}")
    return 0
