"""The primary channel: the full signed envelope, verified by the client itself.

Transport authentication exists here for routing and ACK attribution only. Order
authenticity does not depend on it: the client would reach the same verdict about an
envelope handed to it on a USB stick.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Protocol

from alerting.server.channels.base import DeliveryReceipt, DispatchContext, ProbeResult, Recipient

if TYPE_CHECKING:
    from alerting.server.services.fanout import Fanout

log = logging.getLogger("alerting.channel.ws")


#: RFC 6455 "service restart": the client should reconnect immediately, not back off.
WS_SERVICE_RESTART = 1012


class Sink(Protocol):
    """Anything that can take a JSON frame to one connected device."""

    async def send_json(self, data: dict[str, Any]) -> None: ...

    async def close(self, code: int) -> None: ...


#: A person carries a phone and maybe a tablet. More than this is either a bug or
#: somebody opening sockets in a loop.
MAX_DEVICES_PER_PERSON = 5


class ConnectionRegistry:
    """Which devices are currently connected, per person.

    A person may have several devices; all of them get the order. Absence from this
    registry is not an error, it is the normal case that escalation exists for.
    """

    def __init__(
        self,
        max_devices_per_person: int = MAX_DEVICES_PER_PERSON,
        *,
        on_change: Callable[[str, int], None] | None = None,
    ) -> None:
        self._sinks: dict[str, list[Sink]] = defaultdict(list)
        self._lock = asyncio.Lock()
        self._max_devices = max_devices_per_person
        #: Told the device count for a person after every attach and detach, so other
        #: processes can learn where a person's sockets are (see services/fanout.py).
        self._on_change = on_change

    async def attach(self, person_id: str, sink: Sink) -> bool:
        """Register a device. False when this person already has too many open."""
        async with self._lock:
            if len(self._sinks[person_id]) >= self._max_devices:
                return False
            self._sinks[person_id].append(sink)
            count = len(self._sinks[person_id])
        if self._on_change is not None:
            self._on_change(person_id, count)
        return True

    async def detach(self, person_id: str, sink: Sink) -> None:
        async with self._lock:
            if sink in self._sinks.get(person_id, []):
                self._sinks[person_id].remove(sink)
            count = len(self._sinks.get(person_id, []))
            if not count:
                self._sinks.pop(person_id, None)
        if self._on_change is not None:
            self._on_change(person_id, count)

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

    async def close_all(self, code: int = WS_SERVICE_RESTART) -> int:
        """Close every open socket and empty the registry. Returns how many.

        Called first during shutdown, before the database closes, because a socket
        handler that is still running will reach for ``repo`` to record an incoming
        ACK — and would find a closed connection.

        Code 1012 ("service restart") is what tells a client to reconnect straight
        away rather than backing off, which matters when the thing reconnecting is an
        executor's alert stream.
        """
        async with self._lock:
            sinks = [(person, sink) for person, group in self._sinks.items() for sink in group]
            self._sinks.clear()

        closed = 0
        for person_id, sink in sinks:
            closer = getattr(sink, "close", None)
            if closer is None:
                continue
            try:
                await closer(code)
                closed += 1
            except Exception:
                log.debug("could not close socket for %s", person_id, exc_info=True)
        return closed


class WebSocketChannel:
    """Carries the complete signed envelope. The only adapter that really delivers."""

    name = "ws"
    delivers = True

    def __init__(self, registry: ConnectionRegistry, fanout: Fanout | None = None) -> None:
        self.registry = registry
        self.fanout = fanout

    async def send(self, recipient: Recipient, context: DispatchContext) -> DeliveryReceipt:
        frame = {"kind": "order", "envelope": context.envelope}
        rendered = json.dumps(frame, ensure_ascii=False)[:200]
        delivered = await self.registry.deliver(recipient.person_id, frame)
        if delivered:
            return DeliveryReceipt(
                self.name, recipient.person_id, "sent", f"{delivered} device(s)", rendered=rendered
            )
        if self.fanout is None:
            return DeliveryReceipt(self.name, recipient.person_id, "failed", "offline")
        # Not connected to this process. Another one may hold the socket; only its
        # confirmation counts as delivery.
        delivered, detail = await self.fanout.relay(recipient.person_id, context.order.order_id)
        status = "sent" if delivered else "failed"
        return DeliveryReceipt(
            self.name, recipient.person_id, status, detail, rendered=rendered if delivered else ""
        )

    async def probe(self) -> ProbeResult:
        """The one probe that measures something real.

        This adapter has no provider to ping -- it *is* the provider -- so the
        question worth asking is the one an operator actually cares about: would an
        order reach anybody over this channel right now? Zero connected devices is
        reported as a failure, because that is precisely the silent state the
        heartbeat exists to surface. It is not the node being broken; it is the
        channel being empty, and the duty officer needs to know which.
        """
        local = len(self.registry.connected_people())
        if self.fanout is not None:
            # Any process can deliver to a socket held by any other, so the question
            # "would an order reach anybody" is answered cluster-wide; this node's own
            # share is reported alongside.
            people, processes = self.fanout.connected_anywhere()
            if not people:
                return ProbeResult("failed", "no executor devices connected anywhere")
            return ProbeResult(
                "ok",
                f"{people} device owner(s) connected across {processes} process(es), {local} here",
            )
        if not local:
            return ProbeResult("failed", "no executor devices connected")
        return ProbeResult("ok", f"{local} device owner(s) connected")
