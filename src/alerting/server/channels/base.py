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

DeliveryStatus = Literal["sent", "failed", "queued", "refused"]


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
