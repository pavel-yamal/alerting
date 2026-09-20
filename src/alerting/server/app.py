"""Application factory."""

from __future__ import annotations

import contextlib
import logging
import pathlib
from collections.abc import AsyncIterator
from typing import Any

import yaml
from fastapi import FastAPI

from alerting.core.clock import Clock, SystemClock
from alerting.core.signing import public_key_from_b64u
from alerting.server.api import meta, orders, proposals, ws
from alerting.server.channels.registry import default_registry
from alerting.server.channels.websocket import ConnectionRegistry
from alerting.server.config import Settings
from alerting.server.db.connection import connect, migrate
from alerting.server.db.repo import Repo
from alerting.server.services.audit_service import AuditService
from alerting.server.services.dispatcher import Dispatcher
from alerting.server.services.escalation import DEFAULT_PLAN, EscalationPlan, EscalationWorker
from alerting.server.services.registry import OrgState, load_wordlist

log = logging.getLogger("alerting.server")


class AppServices:
    """Everything the routes reach for, assembled once."""

    def __init__(self, settings: Settings, clock: Clock | None = None) -> None:
        self.settings = settings
        self.clock = clock or SystemClock()

        pathlib.Path(settings.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.db = connect(settings.db_path)
        migrate(self.db)
        self.repo = Repo(self.db)

        if not settings.root_public_key:
            raise RuntimeError(
                "no org root public key configured; the server cannot verify its own "
                "bundles and must not start"
            )

        self.state = OrgState(
            self.repo,
            org_id=settings.org_id,
            root_public_key=public_key_from_b64u(settings.root_public_key),
            wordlist=load_wordlist(pathlib.Path(settings.wordlist_path)),
            drill_enabled_sites=settings.drill_enabled_sites,
        )
        self.connections = ConnectionRegistry()
        self.channels = default_registry(self.connections, settings.org_label)
        self.audit = AuditService(
            self.repo,
            self.clock,
            spool_dir=settings.spool_dir,
            heads_dir=settings.heads_dir,
        )
        self.dispatcher = Dispatcher(self.repo, self.state, self.channels, self.audit, self.clock)
        self.escalation = EscalationWorker(
            self.repo, self.dispatcher, self.audit, self.clock, _load_plan(settings)
        )

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.db.close()


def _load_plan(settings: Settings) -> EscalationPlan:
    path = pathlib.Path(settings.escalation_config)
    if not path.exists():
        return DEFAULT_PLAN
    return EscalationPlan.from_config(yaml.safe_load(path.read_text(encoding="utf-8")))


def create_app(
    settings: Settings | None = None,
    clock: Clock | None = None,
    *,
    start_escalation: bool = True,
) -> FastAPI:
    resolved = settings or Settings.from_env()
    services = AppServices(resolved, clock)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if start_escalation:
            services.escalation.start(resolved.escalation_interval_s)
        try:
            yield
        finally:
            await services.escalation.stop()
            services.close()

    app = FastAPI(
        title="alerting",
        summary="Verifiable emergency order dispatch",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.alerting = services
    for module in (proposals, orders, meta, ws):
        app.include_router(module.router)
    return app


def app_from_env() -> Any:  # pragma: no cover - uvicorn entry point
    return create_app()
