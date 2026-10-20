"""The metric the documents call the main one, finally computed.

``docs/07-drills-and-training.md`` §2 states it plainly -- "**медиана времени от
`quorum.met` до 90 % подтверждений**… Растёт от учения к учению — система гниёт" --
and tells the reader to get it from ``alerting-auditor report``. ``docs/06-runbook.md``
§9 repeats it as the main duty check. Nothing computed it. The duty officer was told
to watch a number the tool did not print, and to judge whether the system was rotting
by it.

It lives in the core because it is arithmetic over the audit chain and nothing else:
no clock, no database, no network. One implementation with two callers -- the auditor's
report and the metrics endpoint -- because a metric computed two ways is two metrics.

**What it measures, precisely.** The clock starts when the quorum was met, not when
somebody typed the proposal: the waiting that matters begins the moment the order is
authorised. It stops when the given share of *recipients* have acknowledged -- so the
denominator is how many people the order actually went to, which is why
``order.dispatched`` had to start recording that count. Only acknowledgements that
mean a human is dealing with it are counted; ``received`` is emitted by a device and
``cannot_comply`` is a refusal, and treating either as an answer would flatter the
number exactly where honesty matters.

Timestamps are whole Unix seconds throughout this system. For a median measured in
tens of seconds that is enough resolution, and it is the unit the documents already
use.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

#: Acknowledgement statuses that mean a person is dealing with the order.
#:
#: Mirrors ``Repo.UNHANDLED_ACK_STATUSES`` and must keep mirroring it: ``received`` is
#: the device saying the bytes arrived, and ``cannot_comply`` is a refusal that keeps
#: the escalation ladder climbing. Counting either here would make the number look
#: better than the situation.
HANDLED_ACK_STATUSES = frozenset({"acknowledged", "en_route", "completed"})

#: The share the main metric is quoted at. Named rather than inlined because it is a
#: statement about the organisation, not a detail of the arithmetic.
MAIN_METRIC_SHARE = 0.9


@dataclass(frozen=True)
class AckTiming:
    """How long an order took to be acknowledged, and by how many.

    ``median_s`` and ``share_s`` are ``None`` when the answer is not known rather
    than zero: an order with no recorded recipient count, or one that not enough
    people have answered yet, has no median-to-90% -- and reporting 0 for "we cannot
    tell" is how a rotting system looks healthy.
    """

    order_id: str
    quorum_at: int | None = None
    dispatched_at: int | None = None
    #: How many people the order went to. ``None`` for an order dispatched before
    #: this count was recorded -- older chains simply cannot answer.
    recipients: int | None = None
    #: Seconds from quorum to each counted acknowledgement, in order.
    ack_delays_s: tuple[int, ...] = ()
    median_s: int | None = None
    #: Seconds until ``share`` of recipients had acknowledged, or None if they have
    #: not. This is the main metric.
    share_s: int | None = None
    share: float = MAIN_METRIC_SHARE
    drill: bool | None = None

    @property
    def acknowledged(self) -> int:
        return len(self.ack_delays_s)

    @property
    def outstanding(self) -> int | None:
        if self.recipients is None:
            return None
        return max(self.recipients - self.acknowledged, 0)

    @property
    def known(self) -> bool:
        """True when there is enough in the chain to quote the main metric."""
        return self.share_s is not None


def _median(values: Sequence[int]) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    # Integer seconds in, integer seconds out: the inputs have one-second resolution,
    # so a half-second in the answer would be precision this data does not have.
    return (ordered[middle - 1] + ordered[middle]) // 2


def ack_timing(
    entries: Iterable[Mapping[str, Any]],
    order_id: str,
    *,
    share: float = MAIN_METRIC_SHARE,
) -> AckTiming:
    """Compute the timing for one order from audit-chain entries."""
    quorum_at: int | None = None
    dispatched_at: int | None = None
    recipients: int | None = None
    drill: bool | None = None
    acks: dict[str, int] = {}

    for entry in entries:
        data = entry.get("data") or {}
        if data.get("order_id") != order_id:
            continue
        event = entry.get("event")
        ts = entry.get("ts")
        if not isinstance(ts, int):
            continue

        if event == "quorum.met":
            quorum_at = ts if quorum_at is None else min(quorum_at, ts)
            if isinstance(data.get("drill"), bool):
                drill = data["drill"]
        elif event == "order.dispatched" and data.get("accepted") is not False:
            dispatched_at = ts if dispatched_at is None else min(dispatched_at, ts)
            count = data.get("recipients")
            if isinstance(count, int) and not isinstance(count, bool):
                recipients = count
            if isinstance(data.get("drill"), bool):
                drill = data["drill"]
        elif event == "ack.received" and data.get("valid") is not False:
            if str(data.get("status")) not in HANDLED_ACK_STATUSES:
                continue
            person = data.get("person_id")
            if not isinstance(person, str):
                continue
            # First counted answer per person. A second one is the same human saying
            # more, not another person answering.
            acks.setdefault(person, ts)

    start = quorum_at if quorum_at is not None else dispatched_at
    if start is None:
        return AckTiming(order_id=order_id, recipients=recipients, share=share, drill=drill)

    delays = tuple(sorted(max(at - start, 0) for at in acks.values()))
    return AckTiming(
        order_id=order_id,
        quorum_at=quorum_at,
        dispatched_at=dispatched_at,
        recipients=recipients,
        ack_delays_s=delays,
        median_s=_median(delays),
        share_s=_share_delay(delays, recipients, share),
        share=share,
        drill=drill,
    )


def _share_delay(delays: Sequence[int], recipients: int | None, share: float) -> int | None:
    """Seconds until ``share`` of recipients had acknowledged.

    ``None`` when the chain cannot say: no recipient count recorded, nobody to notify,
    or not enough people have answered yet. Each of those is a different kind of "not
    known", and none of them is a number.
    """
    if recipients is None or recipients <= 0:
        return None

    # Integer hundredths rather than `math.ceil(recipients * share)`. The float form
    # agrees with this for every count that matters, so this is not a bug fix -- it
    # keeps a float out of a core module whose canonicalization refuses floats
    # outright, and keeps `core`'s deliberately short list of allowed imports short.
    percent = round(share * 100)
    needed = (recipients * percent + 99) // 100
    if needed <= 0 or len(delays) < needed:
        return None
    return delays[needed - 1]


def order_ids(entries: Iterable[Mapping[str, Any]], *, drills_only: bool = False) -> list[str]:
    """Order ids that reached dispatch, oldest first."""
    found: list[str] = []
    for entry in entries:
        if entry.get("event") != "order.dispatched":
            continue
        data = entry.get("data") or {}
        if data.get("accepted") is False:
            continue
        if drills_only and not data.get("drill"):
            continue
        order_id = data.get("order_id")
        if isinstance(order_id, str) and order_id not in found:
            found.append(order_id)
    return found
