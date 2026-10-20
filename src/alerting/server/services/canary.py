"""The delivery canary: prove the path works before there is an emergency.

Readiness answers "does this node have what it needs". The canary answers the harder
question -- "would an order actually go out right now" -- by sending one, hourly, to
a recipient that exists for no other purpose.

**What it does not test, said first so nobody assumes otherwise.** It does not go
through the approval path: the server holds no approver keys by design (ADR 0004), and
a canary that needed M-of-N human signatures would not be a canary. It also does not
acknowledge on anybody's behalf, because that would need an executor's device key on
the node. Quorum is tested by the monthly drills in ``docs/07-drills-and-training.md``
and by the test suite; acknowledgement by real people is tested by those drills and
measured by the main metric.

**Why it goes in the audit chain when heartbeats do not.** Phase 5 kept channel probes
out of the chain because a probe a minute per channel per node would bury an incident
under millions of rows saying nothing happened. A canary is different in kind: it is an
*order*, and an order that dispatched and left nothing behind is the one state this
system must never reach. Hourly is also three orders of magnitude cheaper -- tens of
thousands of rows a year, which is nothing for a table, against millions.

One node runs it, elected by its own advisory lock. Not the escalation lock: climbing
a ladder and probing the delivery path are different jobs, and coupling them would
mean a node unfit for one is automatically excluded from the other.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import uuid

from alerting.core.audit_chain import Event
from alerting.core.clock import Clock
from alerting.core.envelope import Audience, OrderPayload, Severity
from alerting.server.channels.base import DELIVERED_STATUSES, Recipient
from alerting.server.db.leader import LeaderLock
from alerting.server.db.repo import Repo
from alerting.server.services.audit_service import AuditService
from alerting.server.services.dispatcher import Dispatcher

log = logging.getLogger("alerting.canary")

#: Hourly. Frequent enough that a broken delivery path is found the same working day,
#: rare enough that the audit chain stays a record of events rather than of probes.
DEFAULT_INTERVAL_S = 3600.0

#: The synthetic recipient. A contact with this id exists so the canary has somebody
#: to be addressed to; it is not a person and never appears in a real audience.
CANARY_PERSON_ID = "c-000"

#: How long a canary order stays valid. Short: nothing should act on it, and a long
#: window would leave a stream of harmless-but-live orders lying around.
TTL_S = 300


class CanaryService:
    def __init__(
        self,
        repo: Repo,
        dispatcher: Dispatcher,
        audit: AuditService,
        clock: Clock,
        *,
        node_id: str,
        interval: float = DEFAULT_INTERVAL_S,
        leader: LeaderLock | None = None,
    ) -> None:
        self.repo = repo
        self.dispatcher = dispatcher
        self.audit = audit
        self.clock = clock
        self.node_id = node_id
        self.interval = interval
        self.leader = leader
        self._task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()

    def recipient(self) -> Recipient | None:
        """The canary contact, or None when the organisation has not got one."""
        row = self.repo.contact(CANARY_PERSON_ID)
        if row is None or not row["active"]:
            return None
        return Recipient(
            person_id=row["person_id"],
            name=row["name"],
            phone=row["phone"],
            site=row["site"],
            groups=tuple(g for g in row["groups_csv"].split(",") if g),
        )

    def _order(self, recipient: Recipient) -> OrderPayload:
        now = self.clock.now()
        return OrderPayload(
            v=1,
            type="order",
            order_id=str(uuid.uuid4()),
            org_id=self.dispatcher.state.org_id,
            stream_id="canary",
            seq=self.repo.next_seq("canary"),
            nonce=secrets.token_urlsafe(16),
            issued_at=now,
            not_valid_after=now + TTL_S,
            severity=Severity.INFO,
            # Never a default anywhere in this system, and not here either.
            drill=True,
            scenario=Dispatcher.CANARY_SCENARIO,
            action="HOLD",
            audience=Audience(persons=(recipient.person_id,)),
            text="",
            # False on purpose, twice over: nobody is meant to answer, and it is what
            # keeps the escalation sweep from ever picking a canary up.
            requires_ack=False,
            ack_deadline_s=0,
            policy_id=self.dispatcher.state.policy().policy_id,
        )

    async def tick(self) -> bool:
        """Run one canary. Returns whether it delivered."""
        if self.leader is not None and not self.leader.acquire():
            return False

        started = self.clock.now()
        recipient = self.recipient()
        if recipient is None:
            self._record(started, ok=False, delivered=0, detail="no canary contact configured")
            return False

        # Built before dispatching so the run can be recorded against its order id
        # whether the dispatch succeeded or threw.
        order = self._order(recipient)
        try:
            receipts = await self.dispatcher.dispatch_canary(order, recipient)
        except Exception as exc:
            log.exception("canary dispatch failed")
            self._record(
                started,
                ok=False,
                delivered=0,
                detail=f"{type(exc).__name__}: {exc}",
                order_id=order.order_id,
            )
            return False

        delivered = sum(1 for r in receipts if r.status in DELIVERED_STATUSES)
        self._record(
            started,
            ok=delivered > 0,
            delivered=delivered,
            detail=", ".join(f"{r.channel}:{r.status}" for r in receipts),
            order_id=order.order_id,
        )
        return delivered > 0

    def _record(
        self,
        started: int,
        *,
        ok: bool,
        delivered: int,
        detail: str,
        order_id: str | None = None,
    ) -> None:
        previous = self.repo.latest_canary_run()
        self.repo.record_canary_run(
            node_id=self.node_id,
            started_at=started,
            finished_at=self.clock.now(),
            ok=ok,
            delivered=delivered,
            detail=detail,
            order_id=order_id,
        )
        self.repo.prune_canary_runs()

        # Transitions only, as with heartbeats: the run itself is already recorded in
        # the chain as an order, and a second entry per run would say nothing new.
        if previous is None or bool(previous["ok"]) == ok:
            return
        if ok:
            log.info("canary is delivering again: %s", detail)
            self.audit.append(Event.CANARY_RECOVERED, {"node_id": self.node_id, "detail": detail})
        else:
            log.error("CANARY FAILED to deliver: %s", detail)
            self.audit.append(Event.CANARY_FAILED, {"node_id": self.node_id, "detail": detail})

    # --- worker lifecycle -----------------------------------------------------
    async def run(self) -> None:
        while not self._stopping.is_set():
            try:
                await self.tick()
            except Exception:
                log.exception("canary tick failed")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stopping.wait(), self.interval)

    def start(self) -> None:
        self._stopping.clear()
        self._task = asyncio.create_task(self.run())

    async def stop(self, drain_timeout: float = 10.0) -> None:
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
            if self.leader is not None:
                self.leader.release()
