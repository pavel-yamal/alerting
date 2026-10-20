"""The escalation ladder.

Day to day this is worth more than the signatures. The realistic failure is not a
forged order — it is a real one that nobody saw because a phone was on silent, a push
token had expired, or an SMS gateway was rate-limiting. So escalation degrades open at
every step: when in doubt, notify more people.

Rungs are idempotent and recorded, so a restart mid-incident does not re-sound a siren
or re-call someone who was already called.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass, field
from typing import Any

from alerting.core.audit_chain import Event
from alerting.core.clock import Clock
from alerting.core.envelope import OrderPayload, SignedEnvelope
from alerting.server.channels.base import Recipient
from alerting.server.db.leader import LeaderLock
from alerting.server.db.repo import Repo
from alerting.server.services.audit_service import AuditService
from alerting.server.services.dispatcher import Dispatcher

log = logging.getLogger("alerting.escalation")

#: How long shutdown waits for an in-flight tick before cancelling it.
DRAIN_TIMEOUT_S = 10.0


@dataclass(frozen=True)
class Rung:
    at_s: int
    channels: tuple[str, ...] = ()
    notify_role: str | None = None
    reassign_to_group: str | None = None


@dataclass
class EscalationPlan:
    """Per-severity ladders, plus the default used when a severity is unlisted."""

    ladders: dict[str, list[Rung]] = field(default_factory=dict)

    def for_severity(self, severity: str) -> list[Rung]:
        return self.ladders.get(severity, self.ladders.get("default", []))

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> EscalationPlan:
        ladders: dict[str, list[Rung]] = {}
        for severity, rungs in config.items():
            ladders[severity] = [
                Rung(
                    at_s=int(rung["at_s"]),
                    channels=tuple(rung.get("channels", ())),
                    notify_role=rung.get("notify_role"),
                    reassign_to_group=rung.get("reassign_to_group"),
                )
                for rung in sorted(rungs, key=lambda r: int(r["at_s"]))
            ]
        return cls(ladders)


DEFAULT_PLAN = EscalationPlan.from_config(
    {
        "default": [
            {"at_s": 0, "channels": ["ws", "push"]},
            {"at_s": 120, "channels": ["sms"]},
        ],
        "critical": [
            {"at_s": 0, "channels": ["ws", "push"]},
            {"at_s": 60, "channels": ["sms"]},
            {"at_s": 180, "channels": ["voice"]},
            {"at_s": 300, "notify_role": "duty_officer"},
            {"at_s": 420, "reassign_to_group": "alternates"},
            {"at_s": 600, "channels": ["siren"]},
        ],
        "catastrophic": [
            {"at_s": 0, "channels": ["ws", "push", "sms"]},
            {"at_s": 60, "channels": ["voice"]},
            {"at_s": 120, "channels": ["siren"]},
            {"at_s": 240, "notify_role": "director"},
        ],
    }
)


class EscalationWorker:
    def __init__(
        self,
        repo: Repo,
        dispatcher: Dispatcher,
        audit: AuditService,
        clock: Clock,
        plan: EscalationPlan = DEFAULT_PLAN,
        leader: LeaderLock | None = None,
    ) -> None:
        self.repo = repo
        self.dispatcher = dispatcher
        self.audit = audit
        self.clock = clock
        self.plan = plan
        #: When set, only the process holding this lock climbs ladders. Without it
        #: every process climbs, which the claims below survive but which means every
        #: rung is a race. None means "climb unconditionally" -- the single-process
        #: case and what the tests drive.
        self.leader = leader
        self._task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()
        self._started = False

    async def tick(self) -> int:
        """One pass. Returns how many rungs fired, which makes it easy to test."""
        import json

        # Asked every tick rather than once at startup: that is what makes failover
        # automatic. When the holder dies its connection goes with it, PostgreSQL
        # drops the session lock, and whichever process asks next takes over.
        if self.leader is not None and not self.leader.acquire():
            return 0

        now = self.clock.now()
        cancelled = self.repo.cancelled_order_ids()
        fired = 0

        for row in self.repo.orders(200):
            order_id = row["order_id"]
            if order_id in cancelled:
                continue
            stored = json.loads(row["envelope_json"])
            envelope = SignedEnvelope.model_validate(stored)
            try:
                order = OrderPayload.model_validate(stored["payload"])
            except Exception:
                continue
            if order.is_cancel or not order.requires_ack:
                continue
            # An event that lasts until a stand-down keeps escalating to the people
            # who have not answered, however long ago its delivery window closed;
            # the ladder itself is finite, so this ends when the last rung has fired.
            if now > order.not_valid_after and not row["until_cancelled"]:
                continue

            acknowledged = self.repo.acknowledged_person_ids(order_id)
            outstanding = [
                r
                for r in self.dispatcher.state.recipients_for(order)
                if r.person_id not in acknowledged
            ]
            if not outstanding:
                continue

            elapsed = now - row["dispatched_at"]
            for index, rung in enumerate(self.plan.for_severity(row["severity"])):
                if elapsed < rung.at_s:
                    break
                fired += await self._fire(rung, index, order, envelope, outstanding, now)
        return fired

    async def _fire(
        self,
        rung: Rung,
        index: int,
        order: OrderPayload,
        envelope: SignedEnvelope,
        outstanding: list[Recipient],
        now: int,
    ) -> int:
        targets = [
            r for r in outstanding if self.repo.mark_rung(order.order_id, r.person_id, index, now)
        ]
        if not targets:
            return 0

        if rung.channels:
            await self.dispatcher.fan_out(order, envelope, targets, rung.channels)

        # The role and group notifications hanging off a rung need a claim of their
        # own. `mark_rung` latches per person, so two climbers claim different
        # subsets of the outstanding people, both end up with a non-empty `targets`,
        # and both then call the duty officer and page the alternates. Leader
        # election makes that rare; this makes it impossible.
        extra: list[Recipient] = []
        if rung.notify_role and self.repo.claim_escalation_extra(
            order.order_id, index, f"role:{rung.notify_role}", now
        ):
            extra += self._people_with_role(rung.notify_role)
        if rung.reassign_to_group and self.repo.claim_escalation_extra(
            order.order_id, index, f"group:{rung.reassign_to_group}", now
        ):
            extra += self._people_in_group(rung.reassign_to_group)
        if extra:
            await self.dispatcher.fan_out(order, envelope, extra, ("ws", "push", "sms"))

        self.audit.append(
            Event.ESCALATION_RUNG_FIRED,
            {
                "order_id": order.order_id,
                "rung": index,
                "at_s": rung.at_s,
                "channels": list(rung.channels),
                "notify_role": rung.notify_role,
                "person_ids": [r.person_id for r in targets],
            },
        )
        log.info("escalation rung %d for %s -> %d people", index, order.order_id, len(targets))
        return 1

    def _people_with_role(self, role: str) -> list[Recipient]:
        return [self._recipient(row) for row in self.repo.contacts() if row["role"] == role]

    def _people_in_group(self, group: str) -> list[Recipient]:
        return [
            self._recipient(row)
            for row in self.repo.contacts()
            if group in row["groups_csv"].split(",")
        ]

    @staticmethod
    def _recipient(row: Any) -> Recipient:
        from alerting.core.signing import b64u_decode

        return Recipient(
            person_id=row["person_id"],
            name=row["name"],
            phone=row["phone"],
            site=row["site"],
            groups=tuple(g for g in row["groups_csv"].split(",") if g),
            wake_key=b64u_decode(row["wake_key"]) if row["wake_key"] else b"",
        )

    def is_running(self) -> bool:
        """True when the ladder is actually being climbed right now."""
        return self._task is not None and not self._task.done()

    def is_healthy(self) -> bool:
        """False only when this worker was started and has since died.

        A node whose worker died still serves HTTP and still records orders, but
        nothing escalates — so nobody is notified when an order goes unacknowledged,
        and readiness has to see that.

        A worker that was never started is *not* unhealthy: a node can legitimately
        not be the one climbing the ladder. That is the case for the test client, and
        it is the case for every non-leader once escalation is leader-elected.
        """
        if not self._started:
            return True
        return self.is_running()

    async def run(self, interval: float = 1.0) -> None:
        while not self._stopping.is_set():
            try:
                await self.tick()
            except Exception:
                log.exception("escalation tick failed")
            # Sleep, but wake immediately on a stop request so shutdown does not wait
            # out a full interval.
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stopping.wait(), interval)

    def start(self, interval: float = 1.0) -> None:
        self._started = True
        self._stopping.clear()
        self._task = asyncio.create_task(self.run(interval))

    async def stop(self, drain_timeout: float = DRAIN_TIMEOUT_S) -> None:
        """Ask the worker to stop and give the current tick time to finish.

        A hard cancel would abandon a tick mid-fan-out: some recipients of a rung
        notified, the rest not, and the rung already claimed in ``escalation_state``
        so no later tick retries it. So the loop is asked to exit and awaited; cancel
        is the fallback for a tick that has genuinely wedged.
        """
        if self._task is None:
            return
        self._stopping.set()
        try:
            if self._task.done():
                # Already finished, or cancelled by something else. There is nothing
                # to drain, and awaiting a cancelled task here would raise
                # CancelledError out of the whole shutdown -- which is a BaseException
                # and so passes straight through the caller's `suppress(Exception)`,
                # skipping the final audit head and leaving the pool open. Collect the
                # outcome instead, so it is not reported as never retrieved.
                with contextlib.suppress(BaseException):
                    self._task.result()
                return
            await asyncio.wait_for(self._task, drain_timeout)
        except TimeoutError:
            log.warning("escalation tick did not finish in %ss; cancelling", drain_timeout)
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        except asyncio.CancelledError:
            # The worker was cancelled while we waited. Re-raise only if *we* are the
            # ones being cancelled -- swallowing that would break the caller's own
            # cancellation. `cancelling()` is the sanctioned way to tell the two
            # apart; the task's own `cancelled()` flag cannot, because `wait_for`
            # cancels it in both cases.
            current = asyncio.current_task()
            if current is not None and current.cancelling() > 0:
                raise
            log.warning("escalation worker was cancelled during shutdown")
        finally:
            self._task = None
            self._started = False
            # Give the lock up now rather than when the connection eventually times
            # out: a restarting node that held it in the meantime leaves every other
            # node idle, which is the whole ladder not being climbed.
            if self.leader is not None:
                self.leader.release()
