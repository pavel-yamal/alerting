"""The main metric: arithmetic over the chain, checked against hand-computed answers.

Two documents call this the metric that matters, and nothing computed it. So these
tests are less about the code than about pinning what the number means -- especially
the cases where the honest answer is "not known" rather than a number.
"""

from __future__ import annotations

from alerting.core.metrics import MAIN_METRIC_SHARE, ack_timing, order_ids


def chain(*entries: dict) -> list[dict]:
    """Chain entries in the shape ``audit_entries`` yields them."""
    return [dict(entry, idx=index) for index, entry in enumerate(entries)]


def quorum(order_id: str, ts: int, drill: bool = True) -> dict:
    return {"ts": ts, "event": "quorum.met", "data": {"order_id": order_id, "drill": drill}}


def dispatched(order_id: str, ts: int, recipients: int | None = None, drill: bool = True) -> dict:
    data: dict = {"order_id": order_id, "drill": drill, "scenario": "MUSTER"}
    if recipients is not None:
        data["recipients"] = recipients
    return {"ts": ts, "event": "order.dispatched", "data": data}


def ack(order_id: str, person: str, ts: int, status: str = "acknowledged", valid: bool = True):
    return {
        "ts": ts,
        "event": "ack.received",
        "data": {"order_id": order_id, "person_id": person, "status": status, "valid": valid},
    }


def test_the_median_and_the_main_metric_are_computed_from_the_chain():
    """Ten recipients, acknowledging 5,10,15,…,50 seconds after quorum.

    Median of those ten delays is (25+30)//2 = 27. The main metric is the ninth
    answer, because ceil(10 * 0.9) = 9, which lands at 45 s.
    """
    entries = chain(
        quorum("o1", 1000),
        dispatched("o1", 1001, recipients=10),
        *[ack("o1", f"x-{n}", 1000 + 5 * n) for n in range(1, 11)],
    )
    timing = ack_timing(entries, "o1")

    assert timing.quorum_at == 1000
    assert timing.recipients == 10
    assert timing.acknowledged == 10
    assert timing.outstanding == 0
    assert timing.median_s == 27
    assert timing.share_s == 45
    assert timing.known is True


def test_the_clock_starts_at_quorum_not_at_dispatch():
    """The waiting that matters begins when the order was authorised."""
    entries = chain(
        quorum("o1", 1000),
        dispatched("o1", 1030, recipients=1),
        ack("o1", "x-1", 1100),
    )
    assert ack_timing(entries, "o1").median_s == 100


def test_an_order_with_no_recipient_count_says_it_does_not_know():
    """An older chain, written before the count was recorded, cannot answer. Zero
    would be a lie that makes a rotting system look instant."""
    entries = chain(quorum("o1", 1000), dispatched("o1", 1001), ack("o1", "x-1", 1010))
    timing = ack_timing(entries, "o1")

    assert timing.recipients is None
    assert timing.outstanding is None
    assert timing.share_s is None
    assert timing.known is False
    # The median of what did arrive is still real and still reported.
    assert timing.median_s == 10


def test_not_enough_answers_yet_is_not_a_number_either():
    entries = chain(
        quorum("o1", 1000),
        dispatched("o1", 1001, recipients=10),
        ack("o1", "x-1", 1005),
    )
    timing = ack_timing(entries, "o1")

    assert timing.acknowledged == 1
    assert timing.outstanding == 9
    assert timing.share_s is None, "one answer out of ten is not 90%"


def test_device_receipts_and_refusals_are_not_answers():
    """`received` comes from a device, not a person; `cannot_comply` is a refusal that
    keeps the ladder climbing. Counting either would flatter the number."""
    entries = chain(
        quorum("o1", 1000),
        dispatched("o1", 1001, recipients=2),
        ack("o1", "x-1", 1002, status="received"),
        ack("o1", "x-2", 1003, status="cannot_comply"),
    )
    timing = ack_timing(entries, "o1")

    assert timing.acknowledged == 0
    assert timing.median_s is None
    assert timing.share_s is None


def test_an_invalid_acknowledgement_does_not_count():
    """An invalid ACK means somebody is impersonating an executor."""
    entries = chain(
        quorum("o1", 1000),
        dispatched("o1", 1001, recipients=1),
        ack("o1", "x-1", 1002, valid=False),
    )
    assert ack_timing(entries, "o1").acknowledged == 0


def test_one_person_answering_twice_is_still_one_person():
    entries = chain(
        quorum("o1", 1000),
        dispatched("o1", 1001, recipients=2),
        ack("o1", "x-1", 1010),
        ack("o1", "x-1", 1050, status="completed"),
    )
    timing = ack_timing(entries, "o1")

    assert timing.acknowledged == 1
    assert timing.ack_delays_s == (10,), "the first answer is when they answered"


def test_other_orders_do_not_bleed_in():
    entries = chain(
        quorum("o1", 1000),
        dispatched("o1", 1001, recipients=1),
        quorum("o2", 1000),
        dispatched("o2", 1001, recipients=1),
        ack("o2", "x-9", 1999),
        ack("o1", "x-1", 1005),
    )
    assert ack_timing(entries, "o1").median_s == 5


def test_a_rejected_dispatch_is_not_a_dispatch():
    """`order.dispatched` with accepted=False is a refusal being recorded."""
    entries = chain(
        {
            "ts": 1000,
            "event": "order.dispatched",
            "data": {"order_id": "o1", "accepted": False, "reasons": ["replayed"]},
        }
    )
    assert order_ids(entries) == []
    assert ack_timing(entries, "o1").quorum_at is None


def test_order_ids_lists_dispatches_oldest_first():
    entries = chain(
        dispatched("o1", 1000, recipients=1, drill=True),
        dispatched("o2", 2000, recipients=1, drill=False),
    )
    assert order_ids(entries) == ["o1", "o2"]
    assert order_ids(entries, drills_only=True) == ["o1"]


def test_the_share_is_ninety_percent_unless_asked_otherwise():
    entries = chain(
        quorum("o1", 1000),
        dispatched("o1", 1001, recipients=4),
        *[ack("o1", f"x-{n}", 1000 + 10 * n) for n in range(1, 5)],
    )
    assert MAIN_METRIC_SHARE == 0.9
    # ceil(4 * 0.9) = 4 -> the last answer, at 40s.
    assert ack_timing(entries, "o1").share_s == 40
    # ceil(4 * 0.5) = 2 -> the second, at 20s.
    assert ack_timing(entries, "o1", share=0.5).share_s == 20
