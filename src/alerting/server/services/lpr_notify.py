"""Push to the decision-makers' app: a proposal waits for a signature, an order went
out, a proposal was rejected.

What a notification may say is docs/04-channels.md: it passes through Apple or
Google, who can read it, so it says what kind of thing happened and "open the app",
and carries the order id for the app to open. Never the scenario, never drill or
real, never the text: those the app shows from the verified payload.

Never in an order's way. Sending runs as a background task after the request that
caused it, every failure is logged and swallowed, and with no keys configured
nothing is attempted at all. A decision-maker who misses a push still finds the
proposal in the app's list.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from alerting.core.clock import Clock
from alerting.server.db.repo import Repo
from alerting.server.mobilepush import MobilePush, PushResult
from alerting.server.services.registry import OrgState

log = logging.getLogger("alerting.lpr_notify")

#: This many failures in a row and a token is dropped even without an explicit
#: "unregistered" -- the same threshold the helpdesk uses, for the same reasons.
MAX_FAILURES = 10


@dataclass(frozen=True)
class Notice:
    title: str
    body: str
    #: What the app opens on a tap: the proposal's review, or the order's status.
    opens: str


PROPOSAL = Notice(
    "Нужна ваша подпись", "Предложение ждёт подписи. Откройте приложение.", "proposal"
)
DISPATCHED = Notice("Приказ вышел", "Обе подписи собраны. Откройте приложение.", "order")
REJECTED = Notice("Предложение отклонено", "Откройте приложение.", "proposal")
TEST = Notice("Проверка уведомлений", "Уведомления на этом телефоне работают.", "")


def mask(token: str) -> str:
    """The token is a secret: logs and API answers carry only its tail."""
    return f"…{token[-6:]}" if len(token) > 6 else "…"


class LprNotifier:
    def __init__(self, repo: Repo, state: OrgState, push: MobilePush, clock: Clock) -> None:
        self.repo = repo
        self.state = state
        self.push = push
        self.clock = clock
        self._tasks: set[asyncio.Task[Any]] = set()

    @property
    def enabled(self) -> bool:
        return any(self.push.configured.values())

    def decision_makers(self) -> set[str]:
        """Who may sign, by the root-signed directory and policy, right now.

        A revoked key stops its holder's notifications at once, whatever tokens are
        still on file: a lost phone must not keep announcing proposals.
        """
        directory = self.state.directory()
        roles = set(self.state.policy().approver_roles)
        now = self.clock.now()
        return {
            entry.person_id
            for entry in directory.payload.keys
            if entry.role in roles and directory.signer_status(entry.key_id, now) is None
        }

    def notify(
        self,
        notice: Notice,
        order_id: str,
        *,
        exclude: Iterable[str] = (),
        only: Iterable[str] | None = None,
    ) -> None:
        """Send in the background to the decision-makers, minus ``exclude``."""
        if not self.enabled:
            return
        task = asyncio.create_task(self._notify(notice, order_id, set(exclude), only))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _notify(
        self, notice: Notice, order_id: str, exclude: set[str], only: Iterable[str] | None
    ) -> None:
        try:
            people = self.decision_makers() - exclude
            if only is not None:
                people &= set(only)
            await self.send(people, notice, order_id)
        except Exception:
            log.warning("push for %s %s failed", notice.opens, order_id, exc_info=True)

    async def send(
        self, people: Iterable[str], notice: Notice, order_id: str = ""
    ) -> list[dict[str, Any]]:
        """Send to every device of ``people`` now; one result per device."""
        rows = self.repo.push_tokens_for(sorted(set(people)))
        data = {"order_id": order_id, "open": notice.opens}
        results = await asyncio.gather(*(self._deliver(row, notice, data) for row in rows))
        return [
            {
                "platform": row["platform"],
                "device": row["device_label"] or mask(row["token"]),
                "ok": result.ok,
                "error": result.error,
            }
            for row, result in zip(rows, results, strict=True)
        ]

    async def _deliver(self, row: Any, notice: Notice, data: dict[str, str]) -> PushResult:
        token = row["token"]
        try:
            if row["platform"] == "ios":
                result = await self.push.send_apns(
                    token, row["apns_env"] or "production", notice.title, notice.body, data
                )
            else:
                result = await self.push.send_fcm(token, notice.title, notice.body, data)
        except Exception as exc:
            result = PushResult(ok=False, error=str(exc))

        if result.ok:
            self.repo.push_delivered(token, self.clock.now(), result.apns_env)
        elif result.gone:
            self.repo.delete_push_token(token)
            log.info("push token %s of %s is gone: %s", mask(token), row["person_id"], result.error)
        elif self.repo.push_failed(token, result.error) >= MAX_FAILURES:
            self.repo.delete_push_token(token)
            log.warning("push token %s dropped after %d failures", mask(token), MAX_FAILURES)
        else:
            log.warning("push to %s failed: %s", mask(token), result.error)
        return result

    async def aclose(self) -> None:
        """Let notifications already under way finish, briefly; then close."""
        if self._tasks:
            with contextlib.suppress(Exception):
                await asyncio.wait(set(self._tasks), timeout=5)
        for task in set(self._tasks):
            task.cancel()
        await self.push.aclose()
