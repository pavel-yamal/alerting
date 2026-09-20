"""Append to the hash chain, and publish heads out of band.

One rule dominates this module: **the logger never blocks the alert.** If the audit
write fails during an incident, the dispatch still goes out, the entry is spooled to
disk, and operations gets a loud error. A system that refuses to warn people because it
could not write a log line has chosen the wrong failure.
"""

from __future__ import annotations

import json
import logging
import pathlib
from collections.abc import Mapping
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from alerting.core.audit_chain import (
    GENESIS_PREV,
    Event,
    chain_entry,
    verify_chain,
)
from alerting.core.clock import Clock
from alerting.core.signing import (
    DOMAIN_AUDIT_HEAD,
    b64u_decode,
    b64u_encode,
    sign_payload,
)
from alerting.server.db.repo import Repo

log = logging.getLogger("alerting.audit")

#: How often a head is signed and published. Both bounds apply.
HEAD_EVERY_N = 100
HEAD_EVERY_S = 3600


class AuditService:
    def __init__(
        self,
        repo: Repo,
        clock: Clock,
        *,
        server_key: Ed25519PrivateKey | None = None,
        spool_dir: pathlib.Path | None = None,
        heads_dir: pathlib.Path | None = None,
    ) -> None:
        self.repo = repo
        self.clock = clock
        self.server_key = server_key
        self.spool_dir = spool_dir
        self.heads_dir = heads_dir
        self._last_head_at = 0

    def append(self, event: Event | str, data: Mapping[str, Any]) -> int | None:
        """Append one entry. Returns its index, or ``None`` if it had to be spooled.

        ``data`` must carry pseudonymous ``person_id`` values only — never names or
        phone numbers. The chain cannot be edited later, so anything personal put in
        here can never be erased.
        """
        now = self.clock.now()
        data = _prune(data)
        try:
            # One transaction, and inside it an advisory lock every appender
            # serializes on. Reading the index and the previous hash as separate
            # autocommitted statements -- which is what this used to do -- lets two
            # appenders compute the same link from the same tip, and a hash chain
            # that forks is not evidence of anything.
            with self.repo.tx():
                idx, last = self.repo.audit_chain_head()
                prev = b64u_decode(last) if last else GENESIS_PREV
                entry, digest = chain_entry(idx, prev, str(event), now, data)
                head = b64u_encode(digest)
                self.repo.append_audit(idx, now, entry["prev"], entry["event"], entry["data"], head)
            # Outside the transaction on purpose: a head must never be published for
            # an entry that has not committed, and signing plus a file write has no
            # business holding the chain lock.
            self._maybe_publish_head(idx, head, now)
            return idx
        except Exception:
            log.exception("AUDIT WRITE FAILED — dispatch continues, entry spooled")
            self._spool(event, data, now)
            return None

    def _spool(self, event: Event | str, data: Mapping[str, Any], now: int) -> None:
        if self.spool_dir is None:
            return
        try:
            self.spool_dir.mkdir(parents=True, exist_ok=True)
            line = json.dumps(
                {"ts": now, "event": str(event), "data": dict(data)}, ensure_ascii=False
            )
            with (self.spool_dir / "audit-spool.jsonl").open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except Exception:
            log.exception("audit spool also failed")

    def _maybe_publish_head(self, idx: int, head: str, now: int) -> None:
        due = (idx + 1) % HEAD_EVERY_N == 0 or now - self._last_head_at >= HEAD_EVERY_S
        if not due:
            return
        self.publish_head(idx, head, now)

    def publish_head(self, idx: int, head: str, now: int) -> dict[str, Any]:
        """Sign ``{idx, head, ts}`` and emit it.

        In production this goes to auditors' inboxes and an internal channel, and
        optionally to an RFC 3161 timestamp authority. Here it is a file, which is
        enough to demonstrate that a rewritten history can no longer reach it.
        """
        payload = {"idx": idx, "head": head, "ts": now}
        signature = (
            sign_payload(DOMAIN_AUDIT_HEAD, payload, self.server_key) if self.server_key else ""
        )
        self.repo.put_head(idx, head, now, signature)
        self._last_head_at = now
        if self.heads_dir is not None:
            try:
                self.heads_dir.mkdir(parents=True, exist_ok=True)
                (self.heads_dir / f"head-{idx:08d}.json").write_text(
                    json.dumps({"payload": payload, "signature": signature}, ensure_ascii=False),
                    encoding="utf-8",
                )
            except Exception:
                log.exception("could not write head file")
        log.info("published audit head idx=%d", idx)
        return {"payload": payload, "signature": signature}

    def verify(self) -> Any:
        """Recompute the whole chain against every head we published."""
        return verify_chain(
            list(self.repo.audit_entries(0, 1_000_000)),
            expected_heads=self.repo.heads(),
        )


def _prune(value: Any) -> Any:
    """Drop ``None`` values so callers can pass optional fields straight through.

    Canonicalization refuses null because ``{"a": null}`` and ``{}`` are different
    signed bytes. Applying absent-means-absent here rather than at every call site
    stops one forgotten optional field (``cancels`` on a non-cancel order, say) from
    sending an entry to the spool during an incident.
    """
    if isinstance(value, Mapping):
        return {k: _prune(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_prune(v) for v in value if v is not None]
    return value
