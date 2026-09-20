"""Wake codes for SMS and voice.

SMS cannot carry a signature a human can check, so in this system **SMS and voice are
never orders** — they are a doorbell that says "open the app". The only thing they must
achieve on their own is letting the recipient tell a genuine doorbell from a phishing
one.

A per-executor HMAC over the order identity, rendered as three words:

* The key is **per person**. Intercepting Ivanov's SMS tells an attacker nothing about
  the code Petrova will receive.
* The minute bucket binds the code to this order's issue time, so a code copied from a
  drill six months ago is stale.
* Words, not digits: people compare words reliably and digits blur together.
* 30 bits ≈ one in a billion per guess, against a few SMS per person per year.

Crucially, matching words are not authorisation either. They only mean the doorbell is
real. Acting still requires opening the app and verifying signatures there.
"""

from __future__ import annotations

import hashlib
import hmac
import unicodedata
from collections.abc import Sequence

from alerting.core.signing import DOMAIN_WAKE

WORD_BITS = 10
DEFAULT_WORDS = 3
WORDLIST_SIZE = 1 << WORD_BITS  # 1024


def bucket_for(issued_at: int) -> int:
    """Minute bucket, taken from the order's own issue time so both sides agree."""
    return issued_at // 60


def wake_code(
    shared_key: bytes,
    *,
    org_id: str,
    order_id: str,
    bucket: int,
    wordlist: Sequence[str],
    words: int = DEFAULT_WORDS,
) -> list[str]:
    """Derive this recipient's wake words for this order."""
    if len(wordlist) < WORDLIST_SIZE:
        raise ValueError(f"wordlist must hold at least {WORDLIST_SIZE} words")
    if not 1 <= words <= 6:
        raise ValueError("words must be between 1 and 6")

    message = f"{DOMAIN_WAKE.decode()}|{org_id}|{order_id}|{bucket}".encode()
    digest = hmac.new(shared_key, message, hashlib.sha256).digest()
    value = int.from_bytes(digest[:8], "big")

    out: list[str] = []
    for index in range(words):
        shift = 64 - WORD_BITS * (index + 1)
        out.append(wordlist[(value >> shift) & (WORDLIST_SIZE - 1)])
    return out


def verify_wake_code(
    candidate: Sequence[str],
    shared_key: bytes,
    *,
    org_id: str,
    order_id: str,
    bucket: int,
    wordlist: Sequence[str],
) -> bool:
    """Compare in constant time; the words are low-entropy and worth not leaking."""
    expected = wake_code(
        shared_key,
        org_id=org_id,
        order_id=order_id,
        bucket=bucket,
        wordlist=wordlist,
        words=len(candidate),
    )
    # compare_digest refuses non-ASCII str, and the wordlist is Russian, so compare
    # the NFC-normalized UTF-8 bytes instead.
    return hmac.compare_digest(_normalize(expected), _normalize(candidate))


def _normalize(words: Sequence[str]) -> bytes:
    return b"\x00".join(
        unicodedata.normalize("NFC", word.strip()).upper().encode("utf-8")
        for word in words
    )
