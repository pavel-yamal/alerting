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

from alerting.server.channels.base import DeliveryReceipt, DispatchContext, ProbeResult, Recipient
from alerting.server.db.repo import Repo

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

    def __init__(self, repo: Repo) -> None:
        self.repo = repo

    @property
    def activations(self) -> list[tuple[str, str, str]]:
        """Every activation recorded, for tests and the status view."""
        return [
            (row["site"], row["pattern"], row["order_id"])
            for row in self.repo.all_siren_activations()
        ]

    async def send(self, recipient: Recipient, context: DispatchContext) -> DeliveryReceipt:
        order = context.order
        site = recipient.site or "unknown"

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

        # Dedupe and rate limit both read the database rather than this object's
        # memory. They used to be a set and a dict per process, which meant two
        # workers sounded the same site twice for one order -- and nobody standing in
        # the yard can tell a repeat from a second emergency.
        #
        # The rate limit ignores this order's own activation, so the two questions
        # stay independent: "has another order sounded here recently?" and "have we
        # already sounded for this one?" each get their own answer. Without the
        # exclusion the second recipient at a site is told "rate limited" when the
        # truthful answer is "already sounded for this order".
        last = self.repo.siren_last_fired(site, exclude_order_id=order.order_id)
        if last is not None and 0 <= order.issued_at - last < MIN_INTERVAL_S:
            return DeliveryReceipt(self.name, recipient.person_id, "refused", "rate limited")

        # The claim is atomic, so exactly one caller gets True however many race. It
        # is also what makes this idempotent across a restart mid-incident.
        if not self.repo.claim_siren(site, order.order_id, pattern, order.issued_at):
            return DeliveryReceipt(
                self.name,
                recipient.person_id,
                "sent" if self.delivers else "stub",
                "already sounded for this order",
            )
        log.info("SIREN %s at %s for %s", pattern, site, order.order_id)
        return DeliveryReceipt(
            self.name,
            recipient.person_id,
            "sent" if self.delivers else "stub",
            f"site={site}" if self.delivers else f"site={site}, no relay configured",
            rendered=pattern,
        )

    async def probe(self) -> ProbeResult:
        """No relay driver, so nothing to ping.

        Worth saying explicitly: even with a relay, a probe here can only confirm the
        controller answers, never that a siren in a yard made a sound. That gap is
        why the manual panel in the security room is deliberately not interlocked
        with this software.
        """
        return ProbeResult("stub", "no relay controller configured")
