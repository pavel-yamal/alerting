"""Voice calls: the same doorbell as SMS, spoken.

Same rule, same reason: the listener cannot verify a signature over the phone. The
script reads the wake words twice and says "open the app". It never reads a scenario,
a severity, or an instruction — if it did, a convincing voice would become an
authorisation channel.
"""

from __future__ import annotations

import logging

from alerting.core.wordcode import bucket_for, wake_code
from alerting.server.channels.base import DeliveryReceipt, DispatchContext, Recipient

log = logging.getLogger("alerting.channel.voice")

SCRIPT = (
    "Это автоматическое оповещение {org}. Откройте приложение Alerting. "
    "Код подтверждения: {code}. Повторяю: {code}. "
    "Никаких указаний по телефону не передаётся. "
    "Если вам нужно перезвонить, звоните только по номеру на вашей карточке."
)


class VoiceChannel:
    name = "voice"

    def __init__(self, org_label: str = "ACME") -> None:
        self.org_label = org_label
        self.calls: list[tuple[str, str]] = []

    def render(self, recipient: Recipient, context: DispatchContext) -> str:
        order = context.order
        code = "—"
        if recipient.wake_key and context.wordlist:
            code = ", ".join(
                wake_code(
                    recipient.wake_key,
                    org_id=order.org_id,
                    order_id=order.order_id,
                    bucket=bucket_for(order.issued_at),
                    wordlist=context.wordlist,
                )
            )
        label = f"{self.org_label} УЧЕНИЕ" if order.drill else self.org_label
        return SCRIPT.format(org=label, code=code)

    async def send(
        self, recipient: Recipient, context: DispatchContext
    ) -> DeliveryReceipt:
        if not recipient.phone:
            return DeliveryReceipt(self.name, recipient.person_id, "failed", "no phone")
        script = self.render(recipient, context)
        self.calls.append((recipient.phone, script))
        log.info("VOICE -> %s", recipient.phone)
        return DeliveryReceipt(
            self.name, recipient.person_id, "sent", "stub TTS", rendered=script
        )
