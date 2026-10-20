"""Hash-chained, append-only audit log.

Each entry carries the hash of the previous one, so an edit, a reorder, or a deletion
anywhere in the history invalidates everything after it. That gives tamper-*evidence*.
Tamper-*proofing* against someone with database access comes from publishing the chain
head out of band (see ``docs/05-audit-spec.md``): once a head is in three auditors'
inboxes, a rewritten history can no longer reach it.

**Personal data must not go into chain entries.** The chain is deliberately
undeletable, which collides head-on with erasure obligations. Entries carry pseudonymous
``person_id`` values only; the mapping to real identities lives in a separate, deletable
table. This is cheap now and very expensive to retrofit.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from alerting.core.canonical import canonicalize
from alerting.core.signing import b64u_encode

DOMAIN_AUDIT = b"alerting.audit.v1\x00"
GENESIS_PREV = b"\x00" * 32


class Event(StrEnum):
    """Everything that has to be reconstructable after an incident."""

    PROPOSAL_CREATED = "proposal.created"
    PROPOSAL_SIGNED = "proposal.signed"
    QUORUM_MET = "quorum.met"
    ORDER_DISPATCHED = "order.dispatched"
    DISPATCH_NO_RECIPIENTS = "dispatch.no_recipients"
    CHANNEL_ATTEMPTED = "channel.attempted"
    CHANNEL_RECEIPT = "channel.receipt"
    ACK_RECEIVED = "ack.received"
    ACK_REJECTED = "ack.rejected"
    CANCEL_ISSUED = "cancel.issued"
    ESCALATION_RUNG_FIRED = "escalation.rung_fired"
    DIRECTORY_PUBLISHED = "directory.published"
    POLICY_PUBLISHED = "policy.published"
    KEY_ENROLLED = "key.enrolled"
    KEY_REVOKED = "key.revoked"
    #: A channel that was answering has stopped. This is the anti-suppression
    #: signal: only *transitions* are recorded, never the probes themselves, because
    #: the chain is undeletable and a probe a minute would bury an incident.
    CHANNEL_SILENT = "channel.silent"
    CHANNEL_RECOVERED = "channel.recovered"
    #: The delivery canary stopped or resumed delivering. Transitions only, for the
    #: same reason as the channel events above: the canary order itself is already in
    #: the chain, and a second entry per run would say nothing new.
    CANARY_FAILED = "canary.failed"
    CANARY_RECOVERED = "canary.recovered"
    DRILL_WINDOW_OPENED = "drill.window.opened"
    MANUAL_BACKFILL = "manual.backfill"
    AUDIT_HEAD_PUBLISHED = "audit.head_published"


def entry_hash(entry: Mapping[str, Any]) -> bytes:
    return hashlib.sha256(DOMAIN_AUDIT + canonicalize(entry)).digest()


def chain_entry(
    idx: int, prev_hash: bytes, event: str, ts: int, data: Mapping[str, Any]
) -> tuple[dict[str, Any], bytes]:
    """Build entry ``idx`` and return it together with its hash.

    ``data`` is stored verbatim — signatures and ACK bodies included — so the chain is
    self-contained evidence rather than a pointer into mutable rows.
    """
    entry: dict[str, Any] = {
        "idx": idx,
        "ts": ts,
        "prev": b64u_encode(prev_hash),
        "event": str(event),
        "data": dict(data),
    }
    return entry, entry_hash(entry)


@dataclass(frozen=True)
class ChainVerdict:
    ok: bool
    checked: int = 0
    failed_index: int | None = None
    problem: str | None = None

    def __bool__(self) -> bool:
        return self.ok


def verify_chain(
    entries: Iterable[Mapping[str, Any]], *, expected_heads: Mapping[int, str] = {}
) -> ChainVerdict:
    """Recompute the chain and report the first index that does not hold.

    What this can and cannot detect, stated plainly because the difference matters in
    an incident review:

    * An altered or reordered entry is caught by the *next* entry's ``prev``. So the
      verdict names the altered entry, not the one whose link failed.
    * A truncated tail, or an alteration of the **last** entry, is invisible to the
      chain alone — there is no following link to contradict it. That is exactly what
      published heads are for, so pass ``expected_heads`` whenever you have them.

    Args:
        entries: the log in index order.
        expected_heads: ``{idx: head_b64u}`` from previously published heads.
    """
    prev = GENESIS_PREV
    count = 0
    for expected_idx, entry in enumerate(entries):
        idx = entry.get("idx")
        if idx != expected_idx:
            return ChainVerdict(False, count, expected_idx, f"index gap: found {idx!r}")

        # Catches extra or missing top-level keys; the content itself is attested by
        # the next entry's prev link, not by this rebuild.
        rebuilt, _ = chain_entry(
            expected_idx,
            prev,
            str(entry.get("event", "")),
            int(entry.get("ts", 0)),
            entry.get("data", {}),
        )
        if set(rebuilt) != set(entry):
            return ChainVerdict(False, count, expected_idx, "unexpected entry shape")
        if entry.get("prev") != b64u_encode(prev):
            return ChainVerdict(
                False,
                count,
                max(expected_idx - 1, 0),
                f"entry {expected_idx - 1} was altered, or entry {expected_idx}.prev was rewritten",
            )

        head = b64u_encode(entry_hash(entry))
        if expected_idx in expected_heads and expected_heads[expected_idx] != head:
            return ChainVerdict(False, count, expected_idx, "does not match the published head")

        prev = entry_hash(entry)
        count += 1

    missing = [i for i in expected_heads if i >= count]
    if missing:
        return ChainVerdict(False, count, min(missing), "chain is shorter than a published head")
    return ChainVerdict(True, count)


def head_of(entries: Iterable[Mapping[str, Any]]) -> str:
    """base64url hash of the last entry, or of genesis for an empty chain."""
    prev = GENESIS_PREV
    for entry in entries:
        prev = entry_hash(entry)
    return b64u_encode(prev)
