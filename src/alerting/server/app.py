"""Application factory."""

from __future__ import annotations

import contextlib
import logging
import pathlib
from collections.abc import AsyncIterator

import yaml
from fastapi import Depends, FastAPI

from alerting.core.clock import Clock, SystemClock
from alerting.core.signing import private_key_from_b64u, public_key_from_b64u
from alerting.server.api import meta, orders, proposals, ws
from alerting.server.auth import require_api_key
from alerting.server.channels.registry import ChannelRegistry, default_registry
from alerting.server.channels.websocket import ConnectionRegistry
from alerting.server.config import Settings
from alerting.server.db import migrate
from alerting.server.db.leader import LeaderLock
from alerting.server.db.pool import open_pool
from alerting.server.db.repo import Repo
from alerting.server.logging_config import configure as configure_logging
from alerting.server.services.audit_service import AuditService
from alerting.server.services.dispatcher import Dispatcher
from alerting.server.services.escalation import DEFAULT_PLAN, EscalationPlan, EscalationWorker
from alerting.server.services.registry import OrgState
from alerting.wordlist import load_wordlist

log = logging.getLogger("alerting.server")


class AppServices:
    """Everything the routes reach for, assembled once."""

    def __init__(self, settings: Settings, clock: Clock | None = None) -> None:
        self.settings = settings
        self.clock = clock or SystemClock()

        self.pool = open_pool(settings.load_dsn())
        # Everything from here on can refuse to start, and a refusal that leaked the
        # pool would leave server-side connections behind on every restart loop --
        # and `Restart=always` with `StartLimitIntervalSec=0` means this node retries
        # forever by design.
        try:
            self._build(settings)
        except BaseException:
            with contextlib.suppress(Exception):
                self.pool.close()
            raise

    def _build(self, settings: Settings) -> None:
        # Migrations are NOT applied here. They are `alerting-server migrate`, run by
        # the owner role from a oneshot unit. An application that migrates on boot
        # runs two migrations at once the day two nodes restart together, and has to
        # hold schema-changing privileges for its whole life to do it. What it does
        # instead is refuse to run against a schema it was not built for.
        with self.pool.connection() as connection:
            migrate.verify(connection)
        self.repo = Repo(self.pool)

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
        self.channels = default_registry(self.connections, self.repo, settings.org_label)
        self.escalation_plan = _load_plan(settings)
        _require_deliverable_channels(
            self.channels, self.escalation_plan, allow_stubs=settings.allow_stub_channels
        )

        self.api_key = settings.load_api_key()
        if not self.api_key and not settings.allow_unauthenticated:
            raise RuntimeError(
                "no ALERTING_API_KEY_FILE configured. Without it every route is open: "
                "anyone who reaches the port can write permanently undeletable audit "
                "entries, burn seq numbers and dump the roster. Set the key file, or "
                "ALERTING_ALLOW_UNAUTHENTICATED=1 if this is a closed-network demo."
            )
        if not self.api_key:
            log.warning(
                "HTTP surface is UNAUTHENTICATED because ALERTING_ALLOW_UNAUTHENTICATED "
                "is set; anything that can reach the port can write to the audit chain"
            )

        raw_server_key = settings.load_server_key()
        server_key = private_key_from_b64u(raw_server_key) if raw_server_key else None
        if server_key is None:
            log.warning(
                "no ALERTING_SERVER_KEY_FILE configured: audit heads will be published "
                "UNSIGNED, so they cannot be verified and give no tamper-evidence "
                "against anyone who can rewrite the database"
            )
        self.audit = AuditService(
            self.repo,
            self.clock,
            server_key=server_key,
            spool_dir=settings.spool_dir,
            heads_dir=settings.heads_dir,
        )
        self.dispatcher = Dispatcher(self.repo, self.state, self.channels, self.audit, self.clock)
        # The leader lock keeps one process climbing ladders. It takes a connection
        # of its own because the lock is session scoped: one from the pool is handed
        # back after each statement, which would release it immediately.
        self.escalation = EscalationWorker(
            self.repo,
            self.dispatcher,
            self.audit,
            self.clock,
            self.escalation_plan,
            leader=LeaderLock(settings.load_dsn()),
        )

    def close(self) -> None:
        """Synchronous teardown. Prefer :meth:`aclose`, which orders it correctly."""
        # The leader lock holds a connection of its own, outside the pool, so closing
        # the pool does not touch it. Left behind, it keeps the escalation lock until
        # the server eventually reaps the connection -- and every other node sits
        # idle, not climbing ladders, for as long as that takes.
        if self.escalation.leader is not None:
            with contextlib.suppress(Exception):
                self.escalation.leader.release()
        with contextlib.suppress(Exception):
            self.pool.close()

    async def aclose(self) -> None:
        """Shut down in the order that does not lose anything.

        The order is the point, and the old version had it wrong: it stopped
        escalation and closed the database while socket handlers were still running,
        so an ACK arriving during shutdown reached a closed connection.

        1. Close the sockets, so no handler reaches for ``repo`` afterwards.
        2. Stop escalation, letting the current tick finish rather than abandoning a
           fan-out half-done with the rung already claimed.
        3. Publish a final audit head, so the entries since the last one are covered
           instead of waiting for the next start.
        4. Only now close the pool.

        Steps 3 and 4 are in a ``finally``: they are the two that must happen even
        when the shutdown is itself cancelled.
        """
        try:
            with contextlib.suppress(Exception):
                closed = await self.connections.close_all()
                if closed:
                    log.info("closed %d executor socket(s) for restart", closed)

            with contextlib.suppress(Exception):
                await self.escalation.stop()
        finally:
            # Steps 3 and 4 run even if the shutdown itself is cancelled. Both of the
            # awaits above can raise CancelledError, which is a BaseException and so
            # passes through `suppress(Exception)` untouched -- and skipping these two
            # is expensive in a specific way: an unpublished head is exactly the window
            # in which a rewritten tail cannot be detected, and a leaked pool outlives
            # a node whose unit restarts it forever by design.
            with contextlib.suppress(Exception):
                self._publish_final_head()

            self.close()

    def _publish_final_head(self) -> None:
        """Sign the chain tip on the way out.

        Without it, everything since the last hourly head stays unpublished until the
        process runs again — and an unpublished head is exactly the window in which a
        rewritten tail cannot be detected.
        """
        tip = self.repo.chain_tip()
        if tip is None:
            return
        idx, head = tip
        if (latest := self.repo.latest_head()) is not None and latest["idx"] >= idx:
            return
        self.audit.publish_head(idx, head, self.clock.now())
        log.info("published final audit head idx=%d", idx)


#: The one value an operator may pass to mean "yes, really use the hardcoded ladder".
BUILTIN_PLAN = "builtin"


def _load_plan(settings: Settings) -> EscalationPlan:
    """Load the escalation ladder, refusing to silently substitute a different one.

    This used to return ``DEFAULT_PLAN`` whenever the file was missing, which meant a
    node could run a different ladder than the operator had configured — different
    channels, different timings — with no log line saying so. A missing file is now a
    startup failure; the built-in ladder has to be asked for by name.
    """
    if settings.escalation_config == BUILTIN_PLAN:
        log.warning("using the built-in escalation ladder, as explicitly configured")
        return DEFAULT_PLAN

    path = pathlib.Path(settings.escalation_config)
    if not path.exists():
        raise RuntimeError(
            f"escalation ladder not found: {path}. Set ALERTING_ESCALATION_CONFIG to a "
            f"real file, or to the literal {BUILTIN_PLAN!r} to use the built-in one."
        )
    return EscalationPlan.from_config(yaml.safe_load(path.read_text(encoding="utf-8")))


def _require_deliverable_channels(
    channels: ChannelRegistry, plan: EscalationPlan, *, allow_stubs: bool
) -> None:
    """Refuse to start a node whose escalation ladder names a channel that cannot send.

    Same posture as the missing root key above. Four of five adapters ship without a
    provider, and a node that boots with them quietly reports delivery it never made —
    so an operator would have no way to learn that push, SMS, voice and the siren did
    nothing.
    """
    named = {name for rungs in plan.ladders.values() for rung in rungs for name in rung.channels}
    stubs = sorted(
        name
        for name in named
        if (channel := channels.get(name)) is not None and not getattr(channel, "delivers", False)
    )
    if not stubs:
        return
    if allow_stubs:
        log.warning(
            "channels %s have no provider configured and will NOT deliver; "
            "running anyway because ALERTING_ALLOW_STUB_CHANNELS is set",
            ", ".join(stubs),
        )
        return
    raise RuntimeError(
        f"escalation ladder names channels with no provider: {', '.join(stubs)}. "
        "They would report delivery without sending anything. Configure providers, or "
        "set ALERTING_ALLOW_STUB_CHANNELS=1 to accept that (never in production)."
    )


def create_app(
    settings: Settings | None = None,
    clock: Clock | None = None,
    *,
    start_escalation: bool = True,
) -> FastAPI:
    resolved = settings or Settings.from_env()
    configure_logging(resolved.log_level, json_output=resolved.log_json)
    services = AppServices(resolved, clock)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if start_escalation:
            services.escalation.start(resolved.escalation_interval_s)
        try:
            yield
        finally:
            await services.aclose()

    app = FastAPI(
        title="alerting",
        summary="Verifiable emergency order dispatch",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.alerting = services

    # Every route behind the shared key, except liveness, which nginx restricts to
    # the load balancer. The WebSocket carries its own Ed25519 challenge-response and
    # is authenticated more strongly than this gate, so it is not double-gated —
    # executors have a device key, not the shared secret.
    guarded = [Depends(require_api_key)]
    for module in (proposals, orders, meta):
        app.include_router(module.router, dependencies=guarded)
    app.include_router(meta.public_router)
    app.include_router(ws.router)
    return app
