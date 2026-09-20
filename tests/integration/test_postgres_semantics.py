"""Properties the move to PostgreSQL either gained or could quietly have lost.

Each test here corresponds to a specific way the port could have been wrong while
every other test still passed.
"""

from __future__ import annotations

import concurrent.futures

import psycopg
import pytest

from alerting.core.audit_chain import verify_chain
from alerting.core.clock import FixedClock
from alerting.core.envelope import Audience
from alerting.orgkit import make_order, sign_order
from alerting.server.services.audit_service import AuditService

pytestmark = pytest.mark.asyncio


# --- the hash chain under concurrency --------------------------------------


async def test_concurrent_appenders_produce_one_unbroken_chain(services, clock):
    """Two writers, one chain.

    The old code read the next index and the previous hash as two separate
    autocommitted statements and then inserted. Two appenders racing there compute
    their entry from the same tip: one loses the primary key and its entry is spooled
    instead of chained, and with any other index allocation they would both commit
    and the chain would fork. A forked chain verifies as broken and proves nothing,
    which is worse than having no chain at all -- because it is believed.

    Remove the advisory lock in ``Repo.audit_chain_head`` and this test fails.
    """
    writers, per_writer = 4, 15

    def append_many(worker: int) -> int:
        audit = AuditService(services.repo, clock)
        written = 0
        for n in range(per_writer):
            if audit.append("test.concurrent", {"worker": worker, "n": n}) is not None:
                written += 1
        return written

    with concurrent.futures.ThreadPoolExecutor(max_workers=writers) as pool:
        written = sum(pool.map(append_many, range(writers)))

    assert written == writers * per_writer, "an append was spooled instead of chained"

    entries = list(services.repo.audit_entries(0, 10_000))
    assert [e["idx"] for e in entries] == list(range(len(entries))), "gap or duplicate index"
    assert verify_chain(entries).ok, "the chain forked"


# --- deterministic ordering ------------------------------------------------


async def test_orders_come_back_in_a_stable_order_on_one_timestamp(services, org, clock):
    """``dispatched_at`` is in whole seconds, so a burst of orders shares one value.

    SQLite broke the tie by rowid and happened to be deterministic; PostgreSQL makes
    no such promise. This result feeds the escalation sweep and the replay-detection
    set, so an ambiguous ``ORDER BY ... LIMIT`` means a different set of orders each
    time -- including, eventually, one that lets a replayed order through.
    """
    for seq in range(12):
        order = make_order(
            org,
            issued_at=clock.now(),
            seq=seq + 1,
            audience=Audience(groups=("fire-wardens",)),
        )
        await services.dispatcher.dispatch(
            sign_order(order, [org.person("p-001"), org.person("p-002")]), channels=("ws",)
        )

    stamps = {row["dispatched_at"] for row in services.repo.orders(50)}
    assert len(stamps) == 1, "the premise of this test is that the timestamps tie"

    readings = [[row["order_id"] for row in services.repo.orders(5)] for _ in range(8)]
    assert all(reading == readings[0] for reading in readings), "LIMIT chose different rows"


async def test_acknowledgements_in_the_same_second_keep_their_arrival_order(services, org, clock):
    """The dashboard keeps the last ack per person, so tie order decides what an
    operator is shown about somebody who answered twice."""
    order = make_order(org, issued_at=clock.now(), audience=Audience(groups=("fire-wardens",)))
    await services.dispatcher.dispatch(
        sign_order(order, [org.person("p-001"), org.person("p-002")]), channels=("ws",)
    )
    for n in range(10):
        services.repo.record_ack(
            order.order_id, "p-010", "k", "acknowledged", clock.now(), {"n": n}, valid=True
        )

    readings = [[row["ack_json"] for row in services.repo.acks(order.order_id)] for _ in range(5)]
    assert all(reading == readings[0] for reading in readings)


# --- the escalation latch --------------------------------------------------


async def test_a_rung_can_only_be_claimed_once(services):
    """``mark_rung`` decides whether a siren sounds again after a restart. It rests
    entirely on ``ON CONFLICT DO NOTHING`` reporting zero affected rows, which is a
    different mechanism from the ``INSERT OR IGNORE`` row count it replaced."""
    services.repo.create_order("o-1", {}, 1, False, "critical", "X", None, "d")

    claims = [services.repo.mark_rung("o-1", "p-001", 3, 100) for _ in range(5)]
    assert claims == [True, False, False, False, False]


async def test_concurrent_claims_on_one_rung_elect_exactly_one_winner(services):
    services.repo.create_order("o-2", {}, 1, False, "critical", "X", None, "d")

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(lambda _: services.repo.mark_rung("o-2", "p-001", 0, 100), range(8))
        )
    assert sum(results) == 1, "a rung was claimed twice; the siren would sound again"


# --- types --------------------------------------------------------------------


async def test_timestamps_survive_past_2038(services):
    """PostgreSQL's ``integer`` is four bytes where SQLite's was eight. Porting the
    column types literally would have worked until January 2038 and then started
    refusing orders, which is not a failure anybody would catch in review.

    This goes through ``Repo`` rather than a dispatch on purpose: the question is
    what the columns can hold, and a signed order dated 2049 would be rejected by
    envelope verification long before it reached one.
    """
    far_future = 2_500_000_000  # 2049

    services.repo.create_order("o-2049", {}, far_future, False, "critical", "X", None, "d")
    stored = services.repo.order("o-2049")
    assert stored is not None
    assert stored["dispatched_at"] == far_future

    # The audit chain carries its own timestamps, and they are the ones that have to
    # still be readable decades from now.
    services.audit.clock = FixedClock(far_future)
    idx = services.audit.append("test.future", {"order_id": "o-2049"})
    assert idx is not None
    assert next(iter(services.repo.audit_entries(idx, 1)))["ts"] == far_future


async def test_boolean_columns_are_real_booleans(services, org, clock):
    """``drill`` and ``valid`` were integers compared against ``= 1``. A half-finished
    conversion fails silently on ``valid``, which is the "somebody is impersonating an
    executor" flag."""
    order = make_order(
        org, issued_at=clock.now(), drill=True, audience=Audience(groups=("fire-wardens",))
    )
    await services.dispatcher.dispatch(
        sign_order(order, [org.person("p-001"), org.person("p-002")]), channels=("ws",)
    )
    stored = services.repo.order(order.order_id)
    assert stored is not None
    assert stored["drill"] is True

    services.repo.record_ack(
        order.order_id, "p-010", "k", "acknowledged", clock.now(), {}, valid=False
    )
    row = services.repo.acks(order.order_id)[0]
    assert row["valid"] is False
    assert "p-010" not in services.repo.acknowledged_person_ids(order.order_id)


# --- foreign keys are no longer optional --------------------------------------


async def test_foreign_keys_are_enforced_without_being_asked(services):
    """Under SQLite these clauses only applied because every connection re-issued
    ``PRAGMA foreign_keys = ON``; one connection opened without it and they were
    decoration."""
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        services.repo.record_dispatch("no-such-order", "p-001", "ws", 1, "sent")
