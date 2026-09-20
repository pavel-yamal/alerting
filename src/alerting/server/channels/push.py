"""Push notifications: a wake-up that may carry a title, with the order fetched after.

Push payloads pass through a third-party service (FCM/APNs) that we do not control, so
this adapter treats push exactly like SMS in what it is allowed to say. The device
fetches the signed envelope over the authenticated channel and verifies it there.
"""

from __future__ import annotations

import logging

from alerting.server.channels.base import DeliveryReceipt, DispatchContext, Recipient

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
