"""What breaks when a second process exists.

Every test here pairs with a piece of state that used to live in one process's
memory. They all run two independent ``AppServices`` over the same database, which
is exactly what ``--workers 2`` in a unit file produces, and what a second node will
produce later.
"""

from __future__ import annotations

import concurrent.futures

import pytest

from alerting.core.envelope import Audience
from alerting.core.errors import Reason
from alerting.orgkit import make_order, sign_order
from alerting.server.app import AppServices
from alerting.server.db.leader import LeaderLock
from alerting.server.services.escalation import EscalationPlan

pytestmark = pytest.mark.asyncio


@pytest.fixture
def second_node(settings, clock, org):
    """A second server process against the same database."""
    node = AppServices(settings, clock)
    yield node
    node.close()


# --- anti-replay ------------------------------------------------------------


async def test_a_replayed_order_is_refused_by_the_other_process(services, second_node, org, clock):
    """The security-critical one.

    The replay window used to be a dict in the dispatcher. Each worker held its own,
    so the same replayed order was rejected by the worker that had seen it and
    accepted by the one that had not -- and anyone who could influence which worker
    answered got replay for free, with nothing in the logs to say so.
    """
    order = make_order(org, issued_at=clock.now(), audience=Audience(groups=("fire-wardens",)))
    envelope = sign_order(order, [org.person("p-001"), org.person("p-002")])

    first = await services.dispatcher.dispatch(envelope, channels=("ws",))
    assert first.accepted

    # Byte-for-byte the same order, replayed at the other process.
    second = await second_node.dispatcher.dispatch(envelope, channels=("ws",))
    assert not second.accepted
    assert Reason.REPLAYED in second.decision.reasons


async def test_a_different_order_reusing_a_sequence_number_is_refused(
    services, second_node, org, clock
):
    """Not just the identical envelope: the number itself is what is claimed."""
    first_order = make_order(
        org, issued_at=clock.now(), seq=7, audience=Audience(groups=("fire-wardens",))
    )
    await services.dispatcher.dispatch(
        sign_order(first_order, [org.person("p-001"), org.person("p-002")]), channels=("ws",)
    )

    impostor = make_order(
        org, issued_at=clock.now(), seq=7, audience=Audience(groups=("fire-wardens",))
    )
    assert impostor.order_id != first_order.order_id
    result = await second_node.dispatcher.dispatch(
        sign_order(impostor, [org.person("p-001"), org.person("p-002")]), channels=("ws",)
    )
    assert not result.accepted
    assert Reason.REPLAYED in result.decision.reasons


async def test_claiming_the_same_sequence_for_the_same_order_twice_is_allowed(services):
    """A retry must not be punished as a replay.

    A process that crashed between claiming a number and recording the order would
    otherwise burn that number for good, and the retry would be refused -- a genuine
    emergency order rejected because of a crash.
    """
    assert services.dispatcher.replay.claim("primary", 3, "order-a", 100) is True
    assert services.dispatcher.replay.claim("primary", 3, "order-a", 101) is True
    assert services.dispatcher.replay.claim("primary", 3, "order-b", 102) is False


async def test_a_duplicate_order_id_is_caught_however_old_it_is(services, second_node, org, clock):
    """Duplicate suppression used to be a set built from the last thousand orders,
    so it stopped working once a thousand orders had gone by. It is an indexed
    lookup now, and this checks the path is wired to it."""
    order = make_order(org, issued_at=clock.now(), audience=Audience(groups=("fire-wardens",)))
    await services.dispatcher.dispatch(
        sign_order(order, [org.person("p-001"), org.person("p-002")]), channels=("ws",)
    )
    assert order.order_id in second_node.dispatcher.known_orders
    assert "no-such-order" not in second_node.dispatcher.known_orders


# --- sequence allocation -----------------------------------------------------


async def test_concurrent_proposals_on_one_stream_get_distinct_numbers(services):
    """`next_seq` was SELECT MAX(seq) followed, twenty-five lines later, by an
    insert. Two proposals racing on one stream both won the read."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        allocated = list(pool.map(lambda _: services.repo.next_seq("primary"), range(40)))

    assert len(set(allocated)) == len(allocated), "a sequence number was handed out twice"
    assert sorted(allocated) == list(range(1, 41)), "the sequence has a gap"


# --- the siren ---------------------------------------------------------------


async def test_the_siren_sounds_once_per_order_across_processes(services, second_node, org, clock):
    """Nobody standing in the yard can tell a repeat from a second emergency.

    The assertion is on the *receipt*, not on a row count. The dedupe used to be a
    set in the channel object, so the second process had no idea the siren had
    already sounded and reported a fresh activation; the row it would have written
    is deduplicated by the primary key either way, which is exactly why counting
    rows would prove nothing here.
    """
    order = make_order(
        org,
        issued_at=clock.now(),
        severity="catastrophic",
        audience=Audience(sites=("hq",)),
    )
    envelope = sign_order(order, [org.person("p-001"), org.person("p-002"), org.person("p-003")])
    first = await services.dispatcher.dispatch(envelope, channels=("siren",))
    assert first.accepted
    sounded = [r for r in first.receipts if r.channel == "siren"]
    # The siren is site-scoped, so within one dispatch the first person at a site
    # sounds it and everyone else there is told it is already sounding. Exactly one
    # genuine activation is what "sounded once" means.
    fresh = [r for r in sounded if "already sounded" not in r.detail]
    assert len(fresh) == 1, f"expected one activation, got {[r.detail for r in sounded]}"

    recipients = services.state.recipients_for(order)
    again = await second_node.dispatcher.fan_out(order, envelope, recipients, ("siren",))

    assert again, "the second process produced no receipts at all"
    assert all("already sounded for this order" in r.detail for r in again), (
        "the other process sounded the siren a second time for one order"
    )
    assert len(services.repo.siren_activations(order.order_id)) == 1


# --- the escalation ladder ---------------------------------------------------


async def test_a_role_rung_notifies_once_even_with_two_climbers(services, second_node, org, clock):
    """`escalation_state` latches per person, which is not enough: two climbers
    claim different subsets of the outstanding people, both end up with work to do,
    and both then call the duty officer."""
    plan = EscalationPlan.from_config({"default": [{"at_s": 0, "notify_role": "duty_officer"}]})
    services.escalation.plan = plan
    second_node.escalation.plan = plan
    # Neither worker is the leader here: the point is that the claim holds even when
    # election has failed or has not happened yet.
    services.escalation.leader = None
    second_node.escalation.leader = None

    order = make_order(org, issued_at=clock.now(), audience=Audience(groups=("fire-wardens",)))
    await services.dispatcher.dispatch(
        sign_order(order, [org.person("p-001"), org.person("p-002")]), channels=("ws",)
    )
    clock.advance(10)

    fired = await services.escalation.tick() + await second_node.escalation.tick()
    assert fired == 1, "the rung fired on both climbers"

    claimed = services.repo.claim_escalation_extra(order.order_id, 0, "role:duty_officer", 0)
    assert claimed is False, "the role notification was never claimed"


# --- leader election ---------------------------------------------------------


async def test_only_one_process_holds_the_escalation_lock(app_dsn):
    first, second = LeaderLock(app_dsn), LeaderLock(app_dsn)
    try:
        assert first.acquire() is True
        assert second.acquire() is False, "two processes both think they lead"
        assert first.acquire() is True, "re-asking should not drop the lock"
    finally:
        first.release()
        second.release()


async def test_the_lock_moves_when_the_holder_lets_go(app_dsn):
    """Failover. A leader that dies takes its connection with it and PostgreSQL
    drops the lock; releasing explicitly is the orderly version of the same thing."""
    first, second = LeaderLock(app_dsn), LeaderLock(app_dsn)
    try:
        assert first.acquire() is True
        assert second.acquire() is False
        first.release()
        assert second.acquire() is True, "the lock was not handed over"
    finally:
        first.release()
        second.release()


async def test_a_worker_that_does_not_lead_does_not_climb(services, second_node, org, clock):
    order = make_order(org, issued_at=clock.now(), audience=Audience(groups=("fire-wardens",)))
    await services.dispatcher.dispatch(
        sign_order(order, [org.person("p-001"), org.person("p-002")]), channels=("ws",)
    )
    clock.advance(10)

    assert services.escalation.leader is not None
    assert second_node.escalation.leader is not None

    led = await services.escalation.tick()
    followed = await second_node.escalation.tick()
    assert led > 0, "the leader did not climb"
    assert followed == 0, "a follower climbed the ladder"
