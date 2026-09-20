"""Verify, record, and fan out.

The server verifies before dispatching even though the clients verify again. That is
not redundancy for its own sake: it stops a malformed or under-signed proposal from
ever reaching a siren relay, which has no client to protect it.

The server also enforces ``max_signature_spread_s``, which clients structurally
cannot: signature entries carry no self-asserted timestamp, so the only non-forgeable
timing evidence is when the server observed each signature arrive.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass
from typing import Any

from alerting.core.audit_chain import Event
from alerting.core.clock import Clock
from alerting.core.envelope import OrderPayload, SignedEnvelope
from alerting.core.errors import Reason
from alerting.core.quorum import evaluate_quorum
from alerting.core.signing import payload_digest
from alerting.core.verify import Decision, verify_envelope
from alerting.server.channels.base import (
    DELIVERED_STATUSES,
    DeliveryReceipt,
    DispatchContext,
    Recipient,
)
from alerting.server.channels.registry import ChannelRegistry
from alerting.server.db.repo import Repo
from alerting.server.services.audit_service import AuditService
from alerting.server.services.registry import OrgState
from alerting.server.services.replay_store import DatabaseReplayWindow, KnownOrders

log = logging.getLogger("alerting.dispatcher")

DEFAULT_FIRST_CHANNELS = ("ws", "push")


@dataclass
class DispatchResult:
    decision: Decision
    receipts: list[DeliveryReceipt]
    recipients: list[str]

    #: True when a correctly signed order resolved to nobody. The order is still
    #: recorded — it was validly approved — but this is never reported as an ordinary
    #: success: a valid emergency order that reaches zero people is the exact failure
    #: this system exists to prevent, and silence is indistinguishable from no
    #: emergency. The operator has to see it immediately.
    reached_nobody: bool = False

    @property
    def accepted(self) -> bool:
        return self.decision.accepted


class Dispatcher:
    def __init__(
        self,
        repo: Repo,
        state: OrgState,
        channels: ChannelRegistry,
        audit: AuditService,
        clock: Clock,
    ) -> None:
        self.repo = repo
        self.state = state
        self.channels = channels
        self.audit = audit
        self.clock = clock
        self.replay = DatabaseReplayWindow(repo)
        self.known_orders = KnownOrders(repo)

    def check(self, envelope: SignedEnvelope, observed_at: dict[str, int]) -> Decision:
        """Full verification plus the server-only signature-spread rule."""
        cancel_target = self._cancel_target(envelope)
        decision = verify_envelope(
            envelope,
            directory=self.state.directory(),
            policy=self.state.policy(),
            clock=self.clock,
            replay=self.replay,
            org_id=self.state.org_id,
            seen_order_ids=self.known_orders,
            cancel_target=cancel_target,
        )
        if not decision.accepted or decision.payload is None:
            return decision

        rule = self.state.policy().rule_for(
            decision.payload.severity, is_cancel=decision.payload.is_cancel
        )
        if rule is None or rule.max_signature_spread_s is None:
            return decision

        directory = self.state.directory()
        entries = [
            entry
            for entry in (directory.lookup(kid) for kid in decision.valid_signers)
            if entry is not None
        ]
        spread = evaluate_quorum(
            entries,
            rule,
            issued_at=decision.payload.issued_at,
            approver_roles=self.state.policy().approver_roles,
            observed_at=observed_at,
        )
        if spread.met:
            return decision
        return Decision(
            accepted=False,
            reasons=spread.reasons,
            warnings=decision.warnings,
            valid_signers=decision.valid_signers,
            signer_persons=decision.signer_persons,
            is_drill=decision.is_drill,
            payload=decision.payload,
            quorum=spread,
        )

    def _cancel_target(self, envelope: SignedEnvelope) -> OrderPayload | None:
        target_id = envelope.payload.get("cancels")
        if not isinstance(target_id, str):
            return None
        row = self.repo.order(target_id)
        if row is None:
            return None
        import json

        stored = json.loads(row["envelope_json"])
        try:
            return OrderPayload.model_validate(stored["payload"])
        except Exception:
            return None

    async def dispatch(
        self,
        envelope: SignedEnvelope,
        *,
        observed_at: dict[str, int] | None = None,
        channels: tuple[str, ...] = DEFAULT_FIRST_CHANNELS,
    ) -> DispatchResult:
        """Verify and, if it holds, send to every matching recipient."""
        decision = self.check(envelope, observed_at or {})
        if not decision.accepted or decision.payload is None:
            self.audit.append(
                Event.ORDER_DISPATCHED,
                {
                    "order_id": envelope.payload.get("order_id"),
                    "accepted": False,
                    "reasons": [str(r) for r in decision.reasons],
                },
            )
            return DispatchResult(decision, [], [])

        order = decision.payload
        now = self.clock.now()

        # THIS is the anti-replay decision; the check inside `verify_envelope` only
        # reported what it saw. Between that check and this line another process can
        # dispatch the same sequence number, and only an atomic claim can tell us we
        # lost the race. A rejection here is rare and always worth a loud entry:
        # it means two orders carried the same number on one stream.
        if not self.replay.claim(order.stream_id, order.seq, order.order_id, now):
            replayed = Decision(
                accepted=False,
                reasons=(*decision.reasons, Reason.REPLAYED),
                warnings=decision.warnings,
                valid_signers=decision.valid_signers,
                signer_persons=decision.signer_persons,
                is_drill=decision.is_drill,
            )
            self.audit.append(
                Event.ORDER_DISPATCHED,
                {
                    "order_id": order.order_id,
                    "accepted": False,
                    "reasons": [str(r) for r in replayed.reasons],
                },
            )
            return DispatchResult(replayed, [], [])

        # The order row and the two entries that prove it was authorised go in as
        # one unit, so a crash between them cannot leave a dispatched order with no
        # record of the quorum that authorised it.
        #
        # This does not override the audit spool: `AuditService.append` still catches
        # a failed write, rolls back to its own savepoint and lets the dispatch
        # proceed. Alerting outranks the log, and the spooled entry is the record.
        #
        # The fan-out stays outside: it awaits SMS, voice and socket sends, and a
        # transaction held across that would pin a pooled connection and the audit
        # chain lock for the length of a phone call.
        with self.repo.tx():
            self.repo.create_order(
                order.order_id,
                envelope.model_dump(mode="json"),
                now,
                order.drill,
                str(order.severity),
                order.scenario,
                order.cancels,
                payload_digest(envelope.payload),
            )
            self.audit.append(
                Event.QUORUM_MET,
                {
                    "order_id": order.order_id,
                    "signers": list(decision.signer_persons),
                    "severity": str(order.severity),
                    "drill": order.drill,
                },
            )
            self.audit.append(
                Event.CANCEL_ISSUED if order.is_cancel else Event.ORDER_DISPATCHED,
                {
                    "order_id": order.order_id,
                    "scenario": order.scenario,
                    "drill": order.drill,
                    "cancels": order.cancels,
                    "warnings": [str(w) for w in decision.warnings],
                },
            )

        recipients = self.state.recipients_for(order)
        if not recipients:
            # Degrading closed here would lose nothing (there is nobody to warn), but
            # returning a bare success would hide it. Record it loudly instead.
            log.error(
                "ORDER %s RESOLVED TO NOBODY — audience %s matches no active contact",
                order.order_id,
                order.audience.model_dump(mode="json"),
            )
            self.audit.append(
                Event.DISPATCH_NO_RECIPIENTS,
                {
                    "order_id": order.order_id,
                    "scenario": order.scenario,
                    "drill": order.drill,
                    "audience": order.audience.model_dump(mode="json"),
                },
            )
            return DispatchResult(decision, [], [], reached_nobody=True)

        receipts = await self.fan_out(order, envelope, recipients, channels)
        return DispatchResult(decision, receipts, [r.person_id for r in recipients])

    async def fan_out(
        self,
        order: OrderPayload,
        envelope: SignedEnvelope,
        recipients: list[Recipient],
        channels: tuple[str, ...],
    ) -> list[DeliveryReceipt]:
        """Try each named channel for each recipient. A failing channel never stops
        the others — over-notifying is the safe direction."""
        context = DispatchContext(
            envelope=envelope.model_dump(mode="json"),
            order=order,
            wordlist=self.state.wordlist,
            drill_enabled_sites=self.state.drill_enabled_sites,
        )
        receipts: list[DeliveryReceipt] = []
        for name in channels:
            channel = self.channels.get(name)
            if channel is None:
                log.warning("unknown channel %s", name)
                continue
            for recipient in recipients:
                try:
                    receipt = await channel.send(recipient, context)
                except Exception as exc:
                    log.exception("channel %s failed for %s", name, recipient.person_id)
                    receipt = DeliveryReceipt(name, recipient.person_id, "failed", str(exc))
                receipts.append(receipt)
                self.repo.record_dispatch(
                    order.order_id,
                    recipient.person_id,
                    name,
                    self.clock.now(),
                    receipt.status,
                    receipt.detail,
                )
                self.audit.append(
                    Event.CHANNEL_ATTEMPTED,
                    {
                        "order_id": order.order_id,
                        "person_id": recipient.person_id,  # pseudonym, no name or phone
                        "channel": name,
                        "status": receipt.status,
                    },
                )
        return receipts

    def status(self, order_id: str) -> dict[str, Any]:
        """The dashboard the decision-makers watch: did the order actually land?"""
        row = self.repo.order(order_id)
        if row is None:
            return {}
        acked = {a["person_id"]: a for a in self.repo.acks(order_id)}
        people: list[dict[str, Any]] = []
        attempted: dict[str, list[str]] = {}
        for dispatch in self.repo.dispatches(order_id):
            attempted.setdefault(dispatch["person_id"], []).append(
                f"{dispatch['channel']}:{dispatch['status']}"
            )
        for person_id, channels in sorted(attempted.items()):
            ack = acked.get(person_id)
            people.append(
                {
                    "person_id": person_id,
                    "channels_attempted": channels,
                    # True only if something actually left the machine for this person.
                    # A "stub" attempt is not delivery, and must not read like one.
                    "delivered": any(
                        entry.split(":", 1)[1] in DELIVERED_STATUSES for entry in channels
                    ),
                    "ack_status": ack["status"] if ack else None,
                    "ack_at": ack["at"] if ack else None,
                    # Shown prominently: an invalid ACK means somebody is
                    # impersonating an executor, which is worse than silence.
                    "ack_valid": bool(ack["valid"]) if ack else None,
                }
            )
        valid = self.repo.acknowledged_person_ids(order_id)
        by_status = Counter(row["status"] for row in self.repo.dispatches(order_id))
        return {
            "order_id": order_id,
            "drill": bool(row["drill"]),
            "severity": row["severity"],
            "scenario": row["scenario"],
            "dispatched_at": row["dispatched_at"],
            "people": people,
            "acknowledged": len(valid),
            "outstanding": [p["person_id"] for p in people if p["person_id"] not in valid],
            "delivery": dict(by_status),
            # Counted and surfaced separately: these attempts sent nothing at all, and
            # an operator reading a green dashboard has to be able to see that.
            "stub_attempts": by_status.get("stub", 0),
            "reached_nobody": not people,
        }


REASON_LABELS: dict[Reason, str] = {
    Reason.QUORUM_NOT_MET: "недостаточно подписей",
    Reason.BAD_SIGNATURE: "неверная подпись",
    Reason.REVOKED_SIGNER: "ключ отозван",
    Reason.UNKNOWN_SIGNER: "неизвестный подписант",
    Reason.REPLAYED: "повтор ранее полученного приказа",
    Reason.DRILL_MISMATCH: "учебный/боевой признак не совпадает",
}
