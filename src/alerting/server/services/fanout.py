"""WebSocket delivery across processes and nodes.

A socket lives in the memory of the process that accepted it, but the order is
dispatched by whichever process received the last signature -- or by the escalation
leader. With ``--workers 2``, and with two nodes behind nginx, those are usually
different processes, and the dispatching one used to look only at its own sockets
and record ``ws:failed`` for a phone that was connected next door.

The hand-off goes through PostgreSQL, which every process already shares:

1. Each process keeps ``ws_presence`` current for the people it holds sockets for.
2. A dispatching process that has no socket for a person, but sees one in presence
   elsewhere, writes a ``ws_relay`` row and announces it with ``NOTIFY``.
3. The process holding the socket delivers the order it reads from ``orders`` and
   writes how many devices it reached to ``ws_relay_result``.
4. Only a result with devices reached turns the attempt into ``sent``. A hand-off
   nobody confirms within the timeout is ``failed`` and says why: this project does
   not record delivery it cannot show, and escalation keeps running.

The order travels by id, not in the notification: ``NOTIFY`` payloads are capped at
8000 bytes, and the order row is already committed before fan-out starts.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import secrets
from typing import Any

import psycopg

from alerting.core.clock import Clock
from alerting.server.db.repo import Repo

log = logging.getLogger("alerting.fanout")

CHANNEL = "alerting_ws_relay"

#: How long a dispatching process waits for another process to confirm delivery.
#: A healthy hand-off answers in milliseconds; this bounds the case where the
#: process holding the socket is hung, so one stuck node cannot stall a fan-out.
RELAY_TIMEOUT_S = 2.0
RELAY_POLL_S = 0.02

#: Presence is refreshed this often, and a row older than ``PRESENCE_STALE_S`` is
#: ignored -- the process that wrote it has stopped refreshing, which is what a crash
#: looks like from here.
PRESENCE_REFRESH_S = 15.0
PRESENCE_STALE_S = 60

#: Hand-offs and abandoned presence are pruned past this age.
PRUNE_AFTER_S = 3600


def new_process_id(node_id: str) -> str:
    """Unique per process, readable per node: ``app-1:3f9c2a``."""
    return f"{node_id}:{secrets.token_hex(3)}"


class Fanout:
    def __init__(
        self,
        repo: Repo,
        clock: Clock,
        *,
        dsn: str,
        process_id: str,
        relay_timeout: float = RELAY_TIMEOUT_S,
    ) -> None:
        self.repo = repo
        self.clock = clock
        self.dsn = dsn
        self.process_id = process_id
        self.relay_timeout = relay_timeout
        self.registry: Any = None  # ConnectionRegistry; set by attach_registry
        self._task: asyncio.Task[None] | None = None
        self._listening = asyncio.Event()

    def attach_registry(self, registry: Any) -> None:
        self.registry = registry

    # --- presence ---------------------------------------------------------------
    def presence_changed(self, person_id: str, devices: int) -> None:
        """Called by the registry on every attach and detach."""
        try:
            self.repo.set_presence(self.process_id, person_id, devices, self.clock.now())
        except Exception:
            # Losing presence degrades delivery from other processes to this one; it
            # must not refuse the socket. The next refresh writes it again.
            log.warning("could not record presence for %s", person_id, exc_info=True)

    def connected_anywhere(self) -> tuple[int, int]:
        """(people, processes) with a fresh socket anywhere in the cluster."""
        row = self.repo.presence_summary(self.clock.now() - PRESENCE_STALE_S)
        return (int(row["people"]), int(row["processes"])) if row else (0, 0)

    # --- sending ------------------------------------------------------------------
    async def relay(self, person_id: str, order_id: str) -> tuple[int, str]:
        """Hand an order to whichever processes hold this person's sockets.

        Returns (devices reached, detail). Zero is the honest answer when nobody
        confirms; the caller records ``failed`` and escalation carries on.
        """
        now = self.clock.now()
        holders = self.repo.present_elsewhere(person_id, self.process_id, now - PRESENCE_STALE_S)
        if not holders:
            return 0, "offline"

        relay_id = self.repo.create_relay(order_id, person_id, self.process_id, now)
        self.repo.notify(CHANNEL, str(relay_id))

        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.relay_timeout
        while True:
            results = self.repo.relay_results(relay_id)
            delivered = sum(int(r["delivered"]) for r in results)
            if delivered or len(results) >= len(holders) or loop.time() >= deadline:
                break
            await asyncio.sleep(RELAY_POLL_S)

        if delivered:
            via = ", ".join(sorted(r["process_id"] for r in results if r["delivered"]))
            return delivered, f"{delivered} device(s) via {via}"
        if results:
            return 0, "relayed, but the holding process reached no device"
        waited = f"{self.relay_timeout:g}s"
        return 0, f"connected via {', '.join(holders)}, but no confirmation in {waited}"

    # --- receiving ------------------------------------------------------------------
    async def handle(self, relay_id: int) -> None:
        """Deliver one hand-off if this process holds a socket for its person."""
        if self.registry is None:
            return
        row = self.repo.relay(relay_id)
        if row is None or row["origin"] == self.process_id:
            return
        person_id = row["person_id"]
        if not self.registry.online(person_id):
            # Not ours. Saying nothing lets the dispatcher wait for the process that
            # does hold it, instead of stopping early on our zero.
            return
        frame = {"kind": "order", "envelope": json.loads(row["envelope_json"])}
        delivered = await self.registry.deliver(person_id, frame)
        self.repo.record_relay_result(relay_id, self.process_id, delivered, self.clock.now())
        log.info("relay %s: %s reached on %d device(s)", relay_id, person_id, delivered)

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.get_running_loop().create_task(self._run(), name="ws-fanout")

    async def wait_listening(self, timeout: float = 5.0) -> None:
        """For tests and startup checks: until LISTEN is in effect."""
        await asyncio.wait_for(self._listening.wait(), timeout)

    async def _run(self) -> None:
        delay = 1.0
        while True:
            try:
                connection = await psycopg.AsyncConnection.connect(self.dsn, autocommit=True)
                async with connection:
                    await connection.execute(f"LISTEN {CHANNEL}")
                    self._listening.set()
                    delay = 1.0
                    self._housekeeping()
                    while True:
                        async for note in connection.notifies(timeout=PRESENCE_REFRESH_S):
                            with contextlib.suppress(ValueError):
                                await self._safe_handle(int(note.payload))
                        self._housekeeping()
            except asyncio.CancelledError:
                raise
            except Exception:
                self._listening.clear()
                log.warning("fan-out listener lost its connection; retrying", exc_info=True)
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30.0)

    async def _safe_handle(self, relay_id: int) -> None:
        try:
            await self.handle(relay_id)
        except Exception:
            log.warning("relay %s could not be handled", relay_id, exc_info=True)

    def _housekeeping(self) -> None:
        now = self.clock.now()
        try:
            self.repo.refresh_presence(self.process_id, now)
            self.repo.prune_relays(now - PRUNE_AFTER_S)
            self.repo.prune_presence(now - PRUNE_AFTER_S)
        except Exception:
            log.warning("fan-out housekeeping failed", exc_info=True)

    async def stop(self) -> None:
        """Stop listening and withdraw this process's presence."""
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
            self._task = None
        with contextlib.suppress(Exception):
            self.repo.clear_presence(self.process_id)
