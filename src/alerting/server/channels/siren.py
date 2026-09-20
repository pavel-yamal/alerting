"""Sirens and public address: an attention signal, and nothing more.

A siren is one-way. Nobody standing in the yard can authenticate it, and no amount of
cryptography changes that. So its meaning is established by prior training, never by
the transmission: it means "look at your phone / go to your muster point", and the
instruction itself arrives over a channel the recipient can verify.

The one real safety control here is the drill guard. A drill that emits the live siren
pattern produces a real evacuation, with real stampede risk, on a day nobody is
expecting one. So a drill order may only ever sound the drill pattern, and only at a
site that has been explicitly enabled for drills that day.

Activation is privileged and rate-limited server-side: it happens only for an order
that already satisfied quorum. The manual panel in the security room stays a separate,
independent path — deliberately not interlocked with this software, because it is the
channel that has to work when the software is the thing that is broken.
"""

from __future__ import annotations

import logging

from alerting.server.channels.base import DeliveryReceipt, DispatchContext, Recipient

log = logging.getLogger("alerting.channel.siren")

PATTERN_REAL = "continuous-3min"
PATTERN_DRILL = "short-short-long"

#: Never sound the same site more often than this, whatever the dispatcher does.
MIN_INTERVAL_S = 30


class SirenChannel:
    """Site-scoped: one activation per site, not per person.

    Only the actuation is stubbed. The drill guard, the per-order dedupe and the rate
    limit below are real logic and run for every dispatch.
    """

    name = "siren"

    #: No relay or PA driver behind the activation yet.
    delivers = False

    def __init__(self) -> None:
        self.activations: list[tuple[str, str, str]] = []  # (site, pattern, order_id)
        self._last_fired: dict[str, int] = {}
        self._fired_for_order: set[tuple[str, str]] = set()

    async def send(self, recipient: Recipient, context: DispatchContext) -> DeliveryReceipt:
        order = context.order
        site = recipient.site or "unknown"

        if (site, order.order_id) in self._fired_for_order:
            return DeliveryReceipt(
                self.name,
                recipient.person_id,
                "sent" if self.delivers else "stub",
                "already sounded for this order",
            )

        if order.drill:
            if site not in context.drill_enabled_sites:
                # The important refusal: a drill must not produce a real evacuation.
                log.warning("siren refused: drill at non-drill-enabled site %s", site)
                return DeliveryReceipt(
                    self.name,
                    recipient.person_id,
                    "refused",
                    f"drill not enabled for site {site}",
                )
            pattern = PATTERN_DRILL
        else:
            pattern = PATTERN_REAL

        last = self._last_fired.get(site)
        if last is not None and order.issued_at - last < MIN_INTERVAL_S:
            return DeliveryReceipt(self.name, recipient.person_id, "refused", "rate limited")

        self._last_fired[site] = order.issued_at
        self._fired_for_order.add((site, order.order_id))
        self.activations.append((site, pattern, order.order_id))
        log.info("SIREN %s at %s for %s", pattern, site, order.order_id)
        return DeliveryReceipt(
            self.name,
            recipient.person_id,
            "sent" if self.delivers else "stub",
            f"site={site}" if self.delivers else f"site={site}, no relay configured",
            rendered=pattern,
        )
