"""One interface for every delivery path, and the rules each path must obey.

The channels differ in how much authenticity the *receiver* can check, and that is
what decides what each is allowed to carry:

============  ======================  ==========================================
Channel       Receiver can verify     Therefore may carry
============  ======================  ==========================================
ws / push     full signature chain    the order itself
sms / voice   a per-person wake code  "open the app" and nothing else
siren / PA    nothing at all          attention only; meaning comes from training
============  ======================  ==========================================

An adapter that carried instructions over a channel whose receiver cannot authenticate
them would silently undo the whole design, so the SMS and siren adapters refuse to
render order content at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from alerting.core.envelope import OrderPayload

#: ``stub`` is the load-bearing addition. An adapter with no provider behind it used
#: to return ``sent``, so the ACK dashboard and the escalation ladder both believed
#: delivery had succeeded — a lie at the exact moment the truth matters most. A stub
#: now says so, and it never counts as delivered anywhere.
DeliveryStatus = Literal["sent", "failed", "queued", "refused", "stub"]

#: Statuses that mean something actually left the machine.
DELIVERED_STATUSES: frozenset[str] = frozenset({"sent", "queued"})


class NoWakeCode(RuntimeError):
    """This recipient's wake code cannot be derived, so nothing may be sent.

    Lives here rather than in one adapter because SMS and voice both depend on it and
    both must refuse for the same reason: the training line is "a genuine message
    always carries your code", and a codeless message makes that line false.
    """


@dataclass(frozen=True)
class Recipient:
    """A person to reach. Holds personal data, so it never enters the audit chain."""

    person_id: str
    name: str = ""
    phone: str = ""
    site: str = ""
    groups: tuple[str, ...] = ()
    wake_key: bytes = b""


@dataclass(frozen=True)
class DeliveryReceipt:
    channel: str
    person_id: str
    status: DeliveryStatus
    detail: str = ""
    rendered: str = ""  # what was actually put on the wire, for the audit trail


#: What a heartbeat probe can conclude. ``stub`` exists for the same reason it does
#: in ``DeliveryStatus``: an adapter with no provider behind it must never be able to
#: report health it does not have. A stub is not ``ok`` and never satisfies a check.
ProbeStatus = Literal["ok", "failed", "stub"]


@dataclass(frozen=True)
class ProbeResult:
    """The answer to "is this channel still there?".

    Deliberately separate from a delivery receipt. A probe is about the channel; a
    receipt is about one person. Conflating them is how a system ends up reporting a
    channel healthy because the last person it tried happened to be reachable.
    """

    status: ProbeStatus
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"


@dataclass
class DispatchContext:
    """Everything an adapter may need that is not the order itself."""

    envelope: dict[str, Any]
    order: OrderPayload
    wordlist: list[str] = field(default_factory=list)
    drill_enabled_sites: frozenset[str] = frozenset()


class Channel(Protocol):
    name: str

    async def send(self, recipient: Recipient, context: DispatchContext) -> DeliveryReceipt: ...

    async def probe(self) -> ProbeResult:
        """Is this channel still there, asked without an emergency to ask it for.

        Every adapter implements it. The point is that a channel which has gone
        quiet becomes visible *before* an incident rather than during one, which is
        the only thing this system has against deliberate suppression short of the
        printed fallback (threat model, attacks 4 and 5).
        """
        ...


def mask_phone(phone: str) -> str:
    """Log-safe rendering of a phone number.

    Adapters log what they did, and those logs are usually less protected than the
    database. A number is personal data (docs/08-personal-data.md), so only the last
    two digits go to the log — enough to correlate with a delivery receipt, not enough
    to be a roster.
    """
    if len(phone) <= 2:
        return "***"
    return "*" * (len(phone) - 2) + phone[-2:]
