"""Explicit SQL. There is deliberately no update or delete path for ``audit_log``."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from typing import Any


class Repo:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.db = connection

    # --- bundles -------------------------------------------------------------
    def put_bundle(self, kind: str, version: int, bundle: Mapping[str, Any], at: int) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO bundles (kind, version, bundle_json, published_at)"
            " VALUES (?, ?, ?, ?)",
            (kind, version, json.dumps(bundle, ensure_ascii=False), at),
        )

    def latest_bundle(self, kind: str) -> dict[str, Any] | None:
        row = self.db.execute(
            "SELECT bundle_json FROM bundles WHERE kind = ? ORDER BY version DESC LIMIT 1",
            (kind,),
        ).fetchone()
        return json.loads(row["bundle_json"]) if row else None

    # --- contacts (personal data; never enters the audit chain) --------------
    def upsert_contact(
        self,
        person_id: str,
        *,
        name: str,
        phone: str = "",
        site: str = "",
        groups: Sequence[str] = (),
        wake_key: str = "",
        role: str = "executor",
    ) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO contacts"
            " (person_id, name, phone, site, groups_csv, wake_key, role, active)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
            (person_id, name, phone, site, ",".join(groups), wake_key, role),
        )

    def contact(self, person_id: str) -> sqlite3.Row | None:
        return self.db.execute(
            "SELECT * FROM contacts WHERE person_id = ?", (person_id,)
        ).fetchone()

    def contacts(self) -> list[sqlite3.Row]:
        return list(self.db.execute("SELECT * FROM contacts WHERE active = 1"))

    def forget_contact(self, person_id: str) -> None:
        """Erasure of personal data. The audit chain, holding only the pseudonym,
        is untouched and stays verifiable."""
        self.db.execute("DELETE FROM contacts WHERE person_id = ?", (person_id,))

    # --- proposals and signatures -------------------------------------------
    def next_seq(self, stream_id: str) -> int:
        row = self.db.execute(
            "SELECT MAX(seq) AS s FROM proposals WHERE stream_id = ?", (stream_id,)
        ).fetchone()
        return int(row["s"] or 0) + 1

    def create_proposal(
        self, order_id: str, stream_id: str, seq: int, payload: Mapping[str, Any],
        created_at: int, created_by: str,
    ) -> None:
        self.db.execute(
            "INSERT INTO proposals (order_id, stream_id, seq, payload_json, created_at,"
            " created_by) VALUES (?, ?, ?, ?, ?, ?)",
            (order_id, stream_id, seq, json.dumps(payload, ensure_ascii=False),
             created_at, created_by),
        )

    def proposal(self, order_id: str) -> sqlite3.Row | None:
        return self.db.execute(
            "SELECT * FROM proposals WHERE order_id = ?", (order_id,)
        ).fetchone()

    def open_proposals(self) -> list[sqlite3.Row]:
        return list(self.db.execute("SELECT * FROM proposals WHERE status = 'open'"))

    def set_proposal_status(self, order_id: str, status: str) -> None:
        self.db.execute(
            "UPDATE proposals SET status = ? WHERE order_id = ?", (status, order_id)
        )

    def add_signature(self, order_id: str, key_id: str, sig: str, observed_at: int) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO signatures (order_id, key_id, sig, observed_at)"
            " VALUES (?, ?, ?, ?)",
            (order_id, key_id, sig, observed_at),
        )

    def signatures(self, order_id: str) -> list[sqlite3.Row]:
        return list(
            self.db.execute(
                "SELECT * FROM signatures WHERE order_id = ? ORDER BY observed_at",
                (order_id,),
            )
        )

    # --- orders --------------------------------------------------------------
    def create_order(
        self, order_id: str, envelope: Mapping[str, Any], dispatched_at: int,
        drill: bool, severity: str, scenario: str, cancels: str | None, digest: str,
    ) -> None:
        self.db.execute(
            "INSERT INTO orders (order_id, envelope_json, dispatched_at, drill,"
            " severity, scenario, cancels, order_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (order_id, json.dumps(envelope, ensure_ascii=False), dispatched_at,
             int(drill), severity, scenario, cancels, digest),
        )

    def order(self, order_id: str) -> sqlite3.Row | None:
        return self.db.execute(
            "SELECT * FROM orders WHERE order_id = ?", (order_id,)
        ).fetchone()

    def orders(self, limit: int = 50) -> list[sqlite3.Row]:
        return list(
            self.db.execute(
                "SELECT * FROM orders ORDER BY dispatched_at DESC LIMIT ?", (limit,)
            )
        )

    def cancelled_order_ids(self) -> set[str]:
        return {
            row["cancels"]
            for row in self.db.execute(
                "SELECT cancels FROM orders WHERE cancels IS NOT NULL"
            )
        }

    # --- dispatch and acknowledgement ---------------------------------------
    def record_dispatch(
        self, order_id: str, person_id: str, channel: str, at: int, status: str,
        detail: str = "",
    ) -> None:
        self.db.execute(
            "INSERT INTO dispatches (order_id, person_id, channel, attempted_at,"
            " status, detail) VALUES (?, ?, ?, ?, ?, ?)",
            (order_id, person_id, channel, at, status, detail),
        )

    def dispatches(self, order_id: str) -> list[sqlite3.Row]:
        return list(
            self.db.execute(
                "SELECT * FROM dispatches WHERE order_id = ? ORDER BY attempted_at",
                (order_id,),
            )
        )

    def record_ack(
        self, order_id: str, person_id: str, device_key_id: str, status: str, at: int,
        ack: Mapping[str, Any], valid: bool, reasons: Sequence[str] = (),
    ) -> None:
        self.db.execute(
            "INSERT INTO acks (order_id, person_id, device_key_id, status, at,"
            " ack_json, valid, reasons) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (order_id, person_id, device_key_id, status, at,
             json.dumps(ack, ensure_ascii=False), int(valid), ",".join(reasons)),
        )

    def acks(self, order_id: str) -> list[sqlite3.Row]:
        return list(
            self.db.execute(
                "SELECT * FROM acks WHERE order_id = ? ORDER BY at", (order_id,)
            )
        )

    def acknowledged_person_ids(self, order_id: str) -> set[str]:
        """Only *valid* acks count. An invalid one means somebody is impersonating an
        executor, which is worse than silence and must not stop escalation."""
        return {
            row["person_id"]
            for row in self.db.execute(
                "SELECT person_id FROM acks WHERE order_id = ? AND valid = 1"
                " AND status <> 'received'",
                (order_id,),
            )
        }

    # --- escalation ----------------------------------------------------------
    def rung_fired(self, order_id: str, person_id: str, rung: int) -> bool:
        return (
            self.db.execute(
                "SELECT 1 FROM escalation_state WHERE order_id = ? AND person_id = ?"
                " AND rung = ?",
                (order_id, person_id, rung),
            ).fetchone()
            is not None
        )

    def mark_rung(self, order_id: str, person_id: str, rung: int, at: int) -> bool:
        """Returns True if this call is the one that claimed the rung."""
        cursor = self.db.execute(
            "INSERT OR IGNORE INTO escalation_state (order_id, person_id, rung, fired_at)"
            " VALUES (?, ?, ?, ?)",
            (order_id, person_id, rung, at),
        )
        return cursor.rowcount > 0

    # --- audit ---------------------------------------------------------------
    def append_audit(
        self, idx: int, ts: int, prev: str, event: str, data: Mapping[str, Any],
        entry_hash: str,
    ) -> None:
        self.db.execute(
            "INSERT INTO audit_log (idx, ts, prev, event, data_json, entry_hash)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (idx, ts, prev, event, json.dumps(data, ensure_ascii=False), entry_hash),
        )

    def audit_count(self) -> int:
        return int(self.db.execute("SELECT COUNT(*) AS c FROM audit_log").fetchone()["c"])

    def last_audit_hash(self) -> str | None:
        row = self.db.execute(
            "SELECT entry_hash FROM audit_log ORDER BY idx DESC LIMIT 1"
        ).fetchone()
        return row["entry_hash"] if row else None

    def audit_entries(self, from_idx: int = 0, limit: int = 1000) -> Iterator[dict[str, Any]]:
        for row in self.db.execute(
            "SELECT * FROM audit_log WHERE idx >= ? ORDER BY idx LIMIT ?",
            (from_idx, limit),
        ):
            yield {
                "idx": row["idx"],
                "ts": row["ts"],
                "prev": row["prev"],
                "event": row["event"],
                "data": json.loads(row["data_json"]),
            }

    def put_head(self, idx: int, head: str, ts: int, signature: str = "") -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO audit_heads (idx, head, ts, signature)"
            " VALUES (?, ?, ?, ?)",
            (idx, head, ts, signature),
        )

    def heads(self) -> dict[int, str]:
        return {
            row["idx"]: row["head"]
            for row in self.db.execute("SELECT idx, head FROM audit_heads ORDER BY idx")
        }

    def latest_head(self) -> sqlite3.Row | None:
        return self.db.execute(
            "SELECT * FROM audit_heads ORDER BY idx DESC LIMIT 1"
        ).fetchone()
