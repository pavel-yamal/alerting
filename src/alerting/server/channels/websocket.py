"""The primary channel: the full signed envelope, verified by the client itself.

Transport authentication exists here for routing and ACK attribution only. Order
authenticity does not depend on it: the client would reach the same verdict about an
envelope handed to it on a USB stick.
"""

from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from typing import Any, Protocol

from alerting.server.channels.base import DeliveryReceipt, DispatchContext, Recipient


class Sink(Protocol):
    """Anything that can take a JSON frame to one connected device."""

    async def send_json(self, data: dict[str, Any]) -> None: ...


#: A person carries a phone and maybe a tablet. More than this is either a bug or
#: somebody opening sockets in a loop.
MAX_DEVICES_PER_PERSON = 5


class ConnectionRegistry:
    """Which devices are currently connected, per person.

    A person may have several devices; all of them get the order. Absence from this
    registry is not an error, it is the normal case that escalation exists for.
    """

    def __init__(self, max_devices_per_person: int = MAX_DEVICES_PER_PERSON) -> None:
        self._sinks: dict[str, list[Sink]] = defaultdict(list)
        self._lock = asyncio.Lock()
        self._max_devices = max_devices_per_person

    async def attach(self, person_id: str, sink: Sink) -> bool:
        """Register a device. False when this person already has too many open."""
        async with self._lock:
            if len(self._sinks[person_id]) >= self._max_devices:
                return False
            self._sinks[person_id].append(sink)
            return True

    async def detach(self, person_id: str, sink: Sink) -> None:
        async with self._lock:
            if sink in self._sinks.get(person_id, []):
                self._sinks[person_id].remove(sink)
            if not self._sinks.get(person_id):
                self._sinks.pop(person_id, None)

    def online(self, person_id: str) -> bool:
        return bool(self._sinks.get(person_id))

    def connected_people(self) -> list[str]:
        return sorted(self._sinks)

    async def deliver(self, person_id: str, frame: dict[str, Any]) -> int:
        """Send to every device of this person; returns how many accepted it."""
        delivered = 0
        for sink in list(self._sinks.get(person_id, [])):
            try:
                await sink.send_json(frame)
                delivered += 1
            except Exception:
                await self.detach(person_id, sink)
        return delivered

    async def broadcast(self, frame: dict[str, Any]) -> int:
        total = 0
        for person_id in self.connected_people():
            total += await self.deliver(person_id, frame)
        return total


class WebSocketChannel:
    """Carries the complete signed envelope. The only adapter that really delivers."""

    name = "ws"
    delivers = True

    def __init__(self, registry: ConnectionRegistry) -> None:
        self.registry = registry

    async def send(self, recipient: Recipient, context: DispatchContext) -> DeliveryReceipt:
        frame = {"kind": "order", "envelope": context.envelope}
        delivered = await self.registry.deliver(recipient.person_id, frame)
        if delivered:
            return DeliveryReceipt(
                self.name,
                recipient.person_id,
                "sent",
                f"{delivered} device(s)",
                rendered=json.dumps(frame, ensure_ascii=False)[:200],
            )
        return DeliveryReceipt(self.name, recipient.person_id, "failed", "offline")
