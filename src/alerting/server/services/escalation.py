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
from alerting.server.db.repo import Repo
from alerting.server.services.audit_service import AuditService
from alerting.server.services.dispatcher import Dispatcher

log = logging.getLogger("alerting.escalation")


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
    ) -> None:
        self.repo = repo
        self.dispatcher = dispatcher
        self.audit = audit
        self.clock = clock
        self.plan = plan
        self._task: asyncio.Task[None] | None = None

    async def tick(self) -> int:
        """One pass. Returns how many rungs fired, which makes it easy to test."""
        import json

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
            except Exception:  # noqa: BLE001
                continue
            if order.is_cancel or not order.requires_ack:
                continue
            if now > order.not_valid_after:
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
            r
            for r in outstanding
            if self.repo.mark_rung(order.order_id, r.person_id, index, now)
        ]
        if not targets:
            return 0

        if rung.channels:
            await self.dispatcher.fan_out(order, envelope, targets, rung.channels)

        extra: list[Recipient] = []
        if rung.notify_role:
            extra += self._people_with_role(rung.notify_role)
        if rung.reassign_to_group:
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
        log.info(
            "escalation rung %d for %s -> %d people", index, order.order_id, len(targets)
        )
        return 1

    def _people_with_role(self, role: str) -> list[Recipient]:
        return [
            self._recipient(row) for row in self.repo.contacts() if row["role"] == role
        ]

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

    async def run(self, interval: float = 1.0) -> None:
        while True:
            try:
                await self.tick()
            except Exception:  # noqa: BLE001 - the worker must not die mid-incident
                log.exception("escalation tick failed")
            await asyncio.sleep(interval)

    def start(self, interval: float = 1.0) -> None:
        self._task = asyncio.create_task(self.run(interval))

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
