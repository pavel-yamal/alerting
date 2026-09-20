"""The chain across a real incident, and the rule that it never blocks an alert."""

from __future__ import annotations

import pytest

from alerting.core.audit_chain import head_of, verify_chain
from alerting.core.envelope import Audience
from alerting.orgkit import make_order, sign_order

pytestmark = pytest.mark.asyncio


async def run_incident(services, org, clock):
    order = make_order(org, issued_at=clock.now(), audience=Audience(groups=("fire-wardens",)))
    await services.dispatcher.dispatch(
        sign_order(order, [org.person("p-001"), org.person("p-002")]),
        channels=("ws", "sms"),
    )
    return order


async def test_the_chain_verifies_after_a_full_incident(services, org, clock):
    await run_incident(services, org, clock)
    clock.advance(70)
    await services.escalation.tick()
    assert services.audit.verify().ok


async def test_every_stage_is_recorded(services, org, clock):
    order = await run_incident(services, org, clock)
    events = {e["event"] for e in services.repo.audit_entries(0, 1000)}
    assert {
        "directory.published",
        "policy.published",
        "key.enrolled",
        "quorum.met",
        "order.dispatched",
        "channel.attempted",
    } <= events
    assert any(
        e["data"].get("order_id") == order.order_id for e in services.repo.audit_entries(0, 1000)
    )


async def test_tampering_with_a_stored_entry_is_detected(services, org, clock):
    """The triggers stop a careless admin; this is what stops someone with real
    database access."""
    await run_incident(services, org, clock)
    entries = list(services.repo.audit_entries(0, 1000))
    entries[2]["data"]["order_id"] = "substituted"
    verdict = verify_chain(entries)
    assert not verdict.ok
    assert verdict.failed_index == 2


async def test_truncating_the_chain_is_caught_by_a_published_head(services, org, clock):
    await run_incident(services, org, clock)
    entries = list(services.repo.audit_entries(0, 1000))
    services.audit.publish_head(len(entries) - 1, head_of(entries), clock.now())

    verdict = verify_chain(entries[:3], expected_heads=services.repo.heads())
    assert not verdict.ok
    assert "published head" in (verdict.problem or "")


async def test_the_audit_log_rejects_updates_and_deletes(services, org, clock):
    await run_incident(services, org, clock)
    for statement in ("UPDATE audit_log SET ts = 0", "DELETE FROM audit_log"):
        with pytest.raises(Exception, match="append-only"):
            services.db.execute(statement)


async def test_an_audit_failure_never_blocks_the_alert(services, org, clock, monkeypatch):
    """A system that refuses to warn people because it could not write a log line has
    chosen the wrong failure."""

    def explode(*args, **kwargs):
        raise RuntimeError("disk full")

    monkeypatch.setattr(services.repo, "append_audit", explode)

    order = await run_incident(services, org, clock)
    assert services.repo.order(order.order_id) is not None, "dispatch still happened"
    assert services.channels["sms"].sent, "people were still warned"

    spool = services.settings.spool_dir / "audit-spool.jsonl"
    assert spool.exists(), "the lost entries were spooled for later"
    assert "order.dispatched" in spool.read_text(encoding="utf-8")


async def test_no_personal_data_reaches_the_chain(services, org, clock):
    """The chain is deliberately undeletable, which collides head-on with erasure.
    Pseudonyms only."""
    await run_incident(services, org, clock)
    blob = str(list(services.repo.audit_entries(0, 1000)))
    for person in org.people.values():
        assert person.name not in blob
        assert person.phone not in blob


async def test_erasing_a_contact_leaves_the_chain_verifiable(services, org, clock):
    await run_incident(services, org, clock)
    services.repo.forget_contact("x-101")
    assert services.repo.contact("x-101") is None
    assert services.audit.verify().ok
