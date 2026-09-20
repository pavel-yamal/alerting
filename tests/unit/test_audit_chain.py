"""Hash chaining: what it detects, and what only a published head can detect."""

from __future__ import annotations

import copy

from alerting.core.audit_chain import (
    GENESIS_PREV,
    Event,
    chain_entry,
    head_of,
    verify_chain,
)


def build(n: int = 5):
    entries, prev = [], GENESIS_PREV
    for i in range(n):
        entry, prev = chain_entry(
            i, prev, Event.PROPOSAL_SIGNED, 1_700_000_000 + i, {"order_id": f"o{i}"}
        )
        entries.append(entry)
    return entries


def test_clean_chain_verifies():
    verdict = verify_chain(build())
    assert verdict.ok and verdict.checked == 5


def test_empty_chain_verifies():
    assert verify_chain([]).ok


def test_altered_entry_is_named():
    entries = build()
    entries[2]["data"]["order_id"] = "forged"
    verdict = verify_chain(entries)
    assert not verdict.ok
    assert verdict.failed_index == 2


def test_altered_timestamp_is_caught():
    entries = build()
    entries[1]["ts"] = 999
    assert not verify_chain(entries).ok


def test_reordering_is_caught():
    entries = build()
    entries[1], entries[2] = entries[2], entries[1]
    verdict = verify_chain(entries)
    assert not verdict.ok
    assert "index gap" in (verdict.problem or "")


def test_deleting_an_entry_is_caught():
    entries = build()
    del entries[2]
    assert not verify_chain(entries).ok


def test_altering_the_last_entry_needs_a_published_head():
    """Stated plainly because it matters in a review: the chain alone cannot
    contradict its own tail. Heads are what close that gap."""
    entries = build()
    heads = {len(entries) - 1: head_of(entries)}
    tampered = copy.deepcopy(entries)
    tampered[-1]["data"]["order_id"] = "forged"

    assert verify_chain(tampered).ok, "no following link to contradict it"
    verdict = verify_chain(tampered, expected_heads=heads)
    assert not verdict.ok
    assert "published head" in (verdict.problem or "")


def test_truncating_the_tail_is_caught_by_a_published_head():
    entries = build()
    heads = {len(entries) - 1: head_of(entries)}
    verdict = verify_chain(entries[:3], expected_heads=heads)
    assert not verdict.ok
    assert "shorter than a published head" in (verdict.problem or "")


def test_extra_keys_in_an_entry_are_rejected():
    entries = build()
    entries[1]["smuggled"] = True
    verdict = verify_chain(entries)
    assert not verdict.ok
    assert "shape" in (verdict.problem or "")


def test_head_changes_with_every_append():
    entries = build(3)
    first = head_of(entries)
    entry, _ = chain_entry(3, GENESIS_PREV, Event.ACK_RECEIVED, 1, {})
    assert head_of([*entries, entry]) != first


def test_genesis_links_to_zero():
    entry, _ = chain_entry(0, GENESIS_PREV, Event.PROPOSAL_CREATED, 1, {})
    assert entry["prev"] == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
