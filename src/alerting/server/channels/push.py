"""Push notifications: a wake-up that may carry a title, with the order fetched after.

Push payloads pass through a third-party service (FCM/APNs) that we do not control, so
this adapter treats push exactly like SMS in what it is allowed to say. The device
fetches the signed envelope over the authenticated channel and verifies it there.
"""

from __future__ import annotations

import logging

from alerting.server.channels.base import DeliveryReceipt, DispatchContext, ProbeResult, Recipient

log = logging.getLogger("alerting.channel.push")


class PushChannel:
    name = "push"

    #: No FCM/APNs credentials behind this yet.
    delivers = False

    def __init__(self) -> None:
        self.sent: list[tuple[str, dict[str, str]]] = []

    async def send(self, recipient: Recipient, context: DispatchContext) -> DeliveryReceipt:
        order = context.order
        payload = {
            "title": "УЧЕНИЕ · Оповещение" if order.drill else "Оповещение",
            "body": "Откройте приложение",
            "order_id": order.order_id,  # an identifier, not content
        }
        self.sent.append((recipient.person_id, payload))
        log.info("PUSH -> %s", recipient.person_id)
        return DeliveryReceipt(
            self.name,
            recipient.person_id,
            "sent" if self.delivers else "stub",
            "delivered" if self.delivers else "no provider configured",
            rendered=str(payload),
        )

    async def probe(self) -> ProbeResult:
        """Nothing to probe: there is no provider behind this adapter.

        It reports ``stub`` rather than ``ok`` for the same reason ``send`` does.
        A heartbeat that answered "fine" for a channel that cannot send anything
        would be worse than no heartbeat at all -- it is the duty officer's evidence
        that the channel is alive, and it would be false.
        """
        return ProbeResult("stub", "no provider configured")
