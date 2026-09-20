"""SMS: a doorbell, never an order.

A recipient cannot check a signature in a text message, so this adapter refuses to put
anything actionable in one. What it does carry is a per-person wake code, which is the
one thing SMS can achieve on its own: letting the reader tell a genuine "open the app"
from a phishing "open this link".

Three properties the rendered message must keep, because the executor is trained on
exactly them:

1. No link, ever. The training line "we never send links" is only true if it is true.
2. A word code only this recipient could receive.
3. Callback, if any, to the number printed on their card — never one in the message.

This is a stub. ``_transmit`` is the seam for a real provider (SMPP, Twilio); note that
the provider becomes a processor of phone numbers and needs the paperwork in
docs/08-personal-data.md.
"""

from __future__ import annotations

import logging

from alerting.core.wordcode import bucket_for, wake_code
from alerting.server.channels.base import (
    DeliveryReceipt,
    DispatchContext,
    NoWakeCode,
    Recipient,
    mask_phone,
)

log = logging.getLogger("alerting.channel.sms")

TEMPLATE = (
    "{org} ALERT. Откройте приложение Alerting.\n"
    "Код: {code}   ({time})\n"
    "Ссылок не присылаем. Не переходите по ссылкам."
)
DRILL_TEMPLATE = (
    "{org} УЧЕНИЕ. Откройте приложение Alerting.\n"
    "Код: {code}   ({time})\n"
    "Ссылок не присылаем. Не переходите по ссылкам."
)


class SmsChannel:
    name = "sms"

    #: No gateway behind ``_transmit`` yet. Flip to True in the subclass or wiring
    #: that implements a real provider.
    delivers = False

    def __init__(self, org_label: str = "ACME") -> None:
        self.org_label = org_label
        self.sent: list[tuple[str, str]] = []  # (phone, text) — inspected by tests

    def render(self, recipient: Recipient, context: DispatchContext) -> str:
        """Build the message. Deliberately contains no scenario, no severity, no text.

        Raises:
            NoWakeCode: when this recipient's code cannot be derived. Callers must let
                this propagate into a failed receipt rather than sending anything.
        """
        order = context.order
        if not recipient.wake_key or not context.wordlist:
            raise NoWakeCode(
                "no wake key for this person" if not recipient.wake_key else "wordlist not loaded"
            )
        code = "-".join(
            wake_code(
                recipient.wake_key,
                org_id=order.org_id,
                order_id=order.order_id,
                bucket=bucket_for(order.issued_at),
                wordlist=context.wordlist,
            )
        )
        template = DRILL_TEMPLATE if order.drill else TEMPLATE
        minute = order.issued_at % 86400 // 60
        return template.format(
            org=self.org_label, code=code, time=f"{minute // 60:02d}:{minute % 60:02d}"
        )

    async def send(self, recipient: Recipient, context: DispatchContext) -> DeliveryReceipt:
        if not recipient.phone:
            return DeliveryReceipt(self.name, recipient.person_id, "failed", "no phone")
        try:
            text = self.render(recipient, context)
        except NoWakeCode as exc:
            # Never send a codeless message. The training line is "a genuine message
            # always carries your code"; sending one without teaches people to accept
            # codeless SMS, which is exactly the phishing hole the code exists to close.
            log.error(
                "SMS NOT SENT to %s: %s — a codeless message would falsify the training",
                mask_phone(recipient.phone),
                exc,
            )
            return DeliveryReceipt(self.name, recipient.person_id, "failed", f"no wake code: {exc}")
        await self._transmit(recipient.phone, text)
        return DeliveryReceipt(
            self.name,
            recipient.person_id,
            "sent" if self.delivers else "stub",
            "delivered" if self.delivers else "no provider configured",
            rendered=text,
        )

    async def _transmit(self, phone: str, text: str) -> None:
        """Replace with a real gateway. Kept separate so tests can assert on content."""
        self.sent.append((phone, text))
        # Neither the number nor the body goes to the log. The number is personal data
        # and the wake code IS the secret that authenticates the message — and these
        # logs are, as this module's own comment says, less protected than the
        # database. The body stays on the receipt, which is where tests and the audit
        # trail read it from.
        log.info("SMS -> %s (%d chars)", mask_phone(phone), len(text))
