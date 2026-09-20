"""Channel heartbeats: make a silent channel visible before the emergency.

**This did not exist, and four documents said it did.** The threat model names it as
the measure against attack 4 (a suppressed order) and attack 5 (a fully compromised
server), and it accepts suppression as a residual risk explicitly *because*
heartbeats would reveal it. An accepted risk resting on a control that is not there
is worse than a missing feature: it is a wrong answer to "are we covered?".

What it does is deliberately small. Every interval each channel is asked one
question -- are you still there? -- and the answer is written down per node. Nothing
is sent to a person, nothing is retried, and a failing channel does not change what
the node does with an order. It only becomes visible.

Three decisions worth stating, because each could plausibly have gone the other way:

* **A stub is not healthy.** An adapter with no provider behind it reports ``stub``,
  which never satisfies a check. Same rule as delivery: never report health you do
  not have.
* **Probes do not enter the audit chain, transitions do.** The chain is append-only
  and undeletable; a probe a minute per channel per node would bury an incident
  under rows saying nothing happened. A channel falling silent or coming back is one
  entry each.
* **A dead channel does not fail readiness.** Readiness answers "can this node
  dispatch an order", and it decides whether a load balancer sends traffic here. A
  dead SMS provider is not this node's fault, is usually not specific to this node,
  and pulling the node out of rotation over it would remove a working WebSocket path
  as well. It belongs on the duty officer's screen, not in the balancer's decision.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

from alerting.core.audit_chain import Event
from alerting.core.clock import Clock
from alerting.server.channels.base import ProbeResult
from alerting.server.channels.registry import ChannelRegistry
from alerting.server.db.repo import Repo
from alerting.server.services.audit_service import AuditService

log = logging.getLogger("alerting.heartbeat")

#: How often each channel is asked. A minute is frequent enough that a channel
#: going quiet is noticed within the time it takes to walk to the duty desk, and
#: rare enough that it costs nothing.
DEFAULT_INTERVAL_S = 60.0

#: A record older than this means the heartbeat itself stopped -- the worker died,
#: or the node did. Three missed intervals rather than one, so a slow tick is not
#: reported as a dead channel.
STALE_AFTER_S = 3


class HeartbeatService:
    def __init__(
        self,
        repo: Repo,
        channels: ChannelRegistry,
        audit: AuditService,
        clock: Clock,
        *,
        node_id: str,
        interval: float = DEFAULT_INTERVAL_S,
    ) -> None:
        self.repo = repo
        self.channels = channels
        self.audit = audit
        self.clock = clock
        self.node_id = node_id
        self.interval = interval
        self._task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()

    @property
    def stale_after_s(self) -> int:
        return int(self.interval * STALE_AFTER_S)

    async def tick(self) -> dict[str, ProbeResult]:
        """Probe every channel once. Returns what each said, which makes it testable."""
        now = self.clock.now()
        results: dict[str, ProbeResult] = {}
        for name in self.channels.names():
            channel = self.channels[name]
            try:
                result = await channel.probe()
            except Exception as exc:
                # A probe that raises is itself the answer.
                log.warning("probe of channel %s raised", name, exc_info=True)
                result = ProbeResult("failed", f"probe raised: {type(exc).__name__}")
            results[name] = result
            self._record(name, result, now)
        return results

    def _record(self, channel: str, result: ProbeResult, now: int) -> None:
        previous = self.repo.heartbeat(channel, self.node_id)
        self.repo.record_heartbeat(channel, self.node_id, result.status, result.detail, now)

        # Only a transition between two OBSERVED states is audited. The first
        # observation after a restart is written to the table but not to the chain,
        # or a node in a restart loop against a dead channel would write an entry per
        # restart into a log that can never be pruned.
        if previous is None or previous["status"] == result.status:
            return
        was_ok, is_ok = previous["status"] == "ok", result.ok
        if was_ok and not is_ok:
            log.error("channel %s went silent on %s: %s", channel, self.node_id, result.detail)
            self.audit.append(
                Event.CHANNEL_SILENT,
                {
                    "channel": channel,
                    "node_id": self.node_id,
                    "status": result.status,
                    "detail": result.detail,
                },
            )
        elif is_ok and not was_ok:
            log.info("channel %s is answering again on %s", channel, self.node_id)
            self.audit.append(
                Event.CHANNEL_RECOVERED,
                {"channel": channel, "node_id": self.node_id, "detail": result.detail},
            )

    def health(self) -> dict[str, Any]:
        """Per-channel health, folded across nodes.

        A channel counts as healthy when **any** node reached it recently. That is
        the right fold for a shared provider, and it is also right for the WebSocket
        channel: an executor connected to any node means that path works.
        """
        now = self.clock.now()
        stale_after = self.stale_after_s
        by_channel: dict[str, dict[str, Any]] = {}

        for row in self.repo.heartbeats():
            channel = row["channel"]
            entry = by_channel.setdefault(
                channel,
                {"healthy": False, "stale": True, "nodes": {}, "last_ok_at": None},
            )
            age = now - int(row["last_at"])
            stale = age > stale_after
            entry["nodes"][row["node_id"]] = {
                "status": row["status"],
                "detail": row["detail"],
                "age_s": age,
                "stale": stale,
                "consecutive_failures": int(row["consecutive_failures"]),
            }
            if row["status"] == "ok" and not stale:
                entry["healthy"] = True
            if not stale:
                entry["stale"] = False
            last_ok = row["last_ok_at"]
            if last_ok is not None:
                previous = entry["last_ok_at"]
                entry["last_ok_at"] = max(int(last_ok), previous or 0)

        # A configured channel that has never been probed is not silently absent from
        # the answer: "no heartbeat recorded" is itself the thing worth seeing.
        for name in self.channels.names():
            by_channel.setdefault(
                name, {"healthy": False, "stale": True, "nodes": {}, "last_ok_at": None}
            )
        return by_channel

    def silent_channels(self) -> list[str]:
        """Channels no node has reached recently -- the duty officer's list."""
        return sorted(name for name, entry in self.health().items() if not entry["healthy"])

    # --- worker lifecycle -----------------------------------------------------
    async def run(self) -> None:
        while not self._stopping.is_set():
            try:
                await self.tick()
            except Exception:
                log.exception("heartbeat tick failed")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stopping.wait(), self.interval)

    def start(self) -> None:
        self._stopping.clear()
        self._task = asyncio.create_task(self.run())

    async def stop(self, drain_timeout: float = 5.0) -> None:
        if self._task is None:
            return
        self._stopping.set()
        try:
            if self._task.done():
                with contextlib.suppress(BaseException):
                    self._task.result()
                return
            await asyncio.wait_for(self._task, drain_timeout)
        except TimeoutError:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        except asyncio.CancelledError:
            current = asyncio.current_task()
            if current is not None and current.cancelling() > 0:
                raise
        finally:
            self._task = None
