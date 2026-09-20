"""Wake codes: the only thing an SMS has to achieve on its own."""

from __future__ import annotations

import secrets

import pytest

from alerting.core.wordcode import (
    WORDLIST_SIZE,
    bucket_for,
    verify_wake_code,
    wake_code,
)

WORDS = [f"СЛОВО{i:04d}" for i in range(WORDLIST_SIZE)]


@pytest.fixture
def key() -> bytes:
    return secrets.token_bytes(32)


def test_deterministic(key):
    args = dict(org_id="acme", order_id="o1", bucket=100, wordlist=WORDS)
    assert wake_code(key, **args) == wake_code(key, **args)


def test_three_words_from_the_wordlist(key):
    code = wake_code(key, org_id="acme", order_id="o1", bucket=1, wordlist=WORDS)
    assert len(code) == 3
    assert all(word in WORDS for word in code)


def test_each_person_gets_a_different_code(key):
    """Intercepting Ivanov's SMS must say nothing about Petrova's code."""
    other = secrets.token_bytes(32)
    args = dict(org_id="acme", order_id="o1", bucket=1, wordlist=WORDS)
    assert wake_code(key, **args) != wake_code(other, **args)


def test_code_is_bound_to_the_order(key):
    base = dict(org_id="acme", bucket=1, wordlist=WORDS)
    assert wake_code(key, order_id="o1", **base) != wake_code(key, order_id="o2", **base)


def test_code_is_bound_to_the_minute(key):
    """A code copied from a drill six months ago must not verify today."""
    base = dict(org_id="acme", order_id="o1", wordlist=WORDS)
    assert wake_code(key, bucket=1, **base) != wake_code(key, bucket=2, **base)


def test_code_is_bound_to_the_org(key):
    base = dict(order_id="o1", bucket=1, wordlist=WORDS)
    assert wake_code(key, org_id="acme", **base) != wake_code(key, org_id="other", **base)


def test_bucket_derives_from_the_orders_own_issue_time():
    aligned = 1_700_000_000 // 60 * 60
    assert bucket_for(aligned + 59) == bucket_for(aligned)
    assert bucket_for(aligned + 60) != bucket_for(aligned)


def test_verify_accepts_the_right_code_case_insensitively(key):
    args = dict(org_id="acme", order_id="o1", bucket=7, wordlist=WORDS)
    code = wake_code(key, **args)
    assert verify_wake_code(code, key, **args)
    assert verify_wake_code([w.lower() for w in code], key, **args)
    assert verify_wake_code([f"  {w} " for w in code], key, **args)


def test_verify_rejects_a_wrong_code(key):
    args = dict(org_id="acme", order_id="o1", bucket=7, wordlist=WORDS)
    assert not verify_wake_code(["НЕТ", "НЕТ", "НЕТ"], key, **args)


def test_short_wordlist_is_refused(key):
    with pytest.raises(ValueError, match="at least"):
        wake_code(key, org_id="a", order_id="o", bucket=1, wordlist=WORDS[:10])


@pytest.mark.parametrize("words", [0, 7])
def test_word_count_bounds(key, words):
    with pytest.raises(ValueError, match="between"):
        wake_code(key, org_id="a", order_id="o", bucket=1, wordlist=WORDS, words=words)
