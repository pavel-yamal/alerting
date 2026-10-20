"""Explicit SQL. There is deliberately no update or delete path for ``audit_log``.

Every method takes a connection from the pool for the length of one statement, unless
it is running inside :meth:`Repo.tx` -- in which case it joins that transaction. The
binding is a :class:`~contextvars.ContextVar` rather than an attribute because the
escalation worker and the HTTP handlers run as separate tasks on one event loop: an
attribute would leak one task's transaction into another's query at the first
``await``.

Two conventions worth knowing before reading the SQL below:

* **Every ``ORDER BY`` ends in a unique column.** The timestamps here are Unix
  seconds and ties are common -- routine in production, universal in tests, which run
  on a fixed clock. SQLite broke ties by rowid, so insertion order came out by
  accident; PostgreSQL makes no such promise, and two of these queries decide which
  orders get escalated and which are checked for replay.
* **Booleans are booleans.** They were integers compared against ``= 1``.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

from psycopg import Connection
from psycopg_pool import ConnectionPool

from alerting.server.db import locks

Row = dict[str, Any]

#: The connection bound to the current task by an open :meth:`Repo.tx` block.
_bound: ContextVar[Connection[Any] | None] = ContextVar("alerting_db_conn", default=None)


class Repo:
    def __init__(self, pool: ConnectionPool[Any]) -> None:
        self.pool = pool

    # --- connection and transaction handling ---------------------------------
    @contextmanager
    def _conn(self) -> Iterator[Connection[Any]]:
        bound = _bound.get()
        if bound is not None:
            yield bound
            return
        with self.pool.connection() as connection:
            yield connection

    @contextmanager
    def tx(self) -> Iterator[Connection[Any]]:
        """Run several statements as one unit.

        Used in exactly three places -- appending an audit entry, allocating a
        proposal's sequence number, and recording a dispatched order alongside its
        audit entries. Everything else is a single statement and runs in autocommit,
        which is what keeps a failed audit write from poisoning the dispatch that
        follows it.

        Nesting is allowed and becomes a savepoint.
        """
        bound = _bound.get()
        if bound is not None:
            with bound.transaction():
                yield bound
            return
        with self.pool.connection() as connection:
            token = _bound.set(connection)
            try:
                with connection.transaction():
                    yield connection
            finally:
                _bound.reset(token)

    def _execute(self, sql: str, params: Sequence[Any] = ()) -> int:
        """Run a statement, return the number of rows it affected."""
        with self._conn() as connection, connection.cursor() as cursor:
            cursor.execute(sql, params)
            return cursor.rowcount

    def _one(self, sql: str, params: Sequence[Any] = ()) -> Row | None:
        with self._conn() as connection, connection.cursor() as cursor:
            cursor.execute(sql, params)
            row: Row | None = cursor.fetchone()
            return row

    def _all(self, sql: str, params: Sequence[Any] = ()) -> list[Row]:
        with self._conn() as connection, connection.cursor() as cursor:
            cursor.execute(sql, params)
            rows: list[Row] = cursor.fetchall()
            return rows

    # --- bundles -------------------------------------------------------------
    def put_bundle(self, kind: str, version: int, bundle: Mapping[str, Any], at: int) -> None:
        self._execute(
            "INSERT INTO bundles (kind, version, bundle_json, published_at)"
            " VALUES (%s, %s, %s, %s)"
            " ON CONFLICT (kind, version) DO UPDATE SET"
            " bundle_json = EXCLUDED.bundle_json, published_at = EXCLUDED.published_at",
            (kind, version, json.dumps(bundle, ensure_ascii=False), at),
        )

    def latest_bundle(self, kind: str) -> dict[str, Any] | None:
        row = self._one(
            "SELECT bundle_json FROM bundles WHERE kind = %s ORDER BY version DESC LIMIT 1",
            (kind,),
        )
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
        self._execute(
            "INSERT INTO contacts"
            " (person_id, name, phone, site, groups_csv, wake_key, role, active)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, true)"
            " ON CONFLICT (person_id) DO UPDATE SET"
            " name = EXCLUDED.name, phone = EXCLUDED.phone, site = EXCLUDED.site,"
            " groups_csv = EXCLUDED.groups_csv, wake_key = EXCLUDED.wake_key,"
            " role = EXCLUDED.role, active = true",
            (person_id, name, phone, site, ",".join(groups), wake_key, role),
        )

    def contact(self, person_id: str) -> Row | None:
        return self._one("SELECT * FROM contacts WHERE person_id = %s", (person_id,))

    def contacts(self) -> list[Row]:
        return self._all("SELECT * FROM contacts WHERE active ORDER BY person_id")

    def forget_contact(self, person_id: str) -> None:
        """Erasure of personal data. The audit chain, holding only the pseudonym,
        is untouched and stays verifiable."""
        self._execute("DELETE FROM contacts WHERE person_id = %s", (person_id,))

    # --- proposals and signatures -------------------------------------------
    def next_seq(self, stream_id: str) -> int:
        """Allocate the next sequence number for a stream, atomically.

        One statement. It used to be ``SELECT MAX(seq)`` followed, twenty-five lines
        later, by an insert -- a read-modify-write that two concurrent proposals on
        one stream both won, leaving the loser with an integrity error and a bare 500.
        The upsert makes the allocation itself the atom, so no transaction has to be
        held open across the payload building in between.
        """
        row = self._one(
            "INSERT INTO streams (stream_id, next_seq) VALUES (%s, 1)"
            " ON CONFLICT (stream_id) DO UPDATE SET next_seq = streams.next_seq + 1"
            " RETURNING next_seq",
            (stream_id,),
        )
        assert row is not None  # RETURNING on an upsert always yields a row
        return int(row["next_seq"])

    def create_proposal(
        self,
        order_id: str,
        stream_id: str,
        seq: int,
        payload: Mapping[str, Any],
        created_at: int,
        created_by: str,
    ) -> None:
        self._execute(
            "INSERT INTO proposals (order_id, stream_id, seq, payload_json, created_at,"
            " created_by) VALUES (%s, %s, %s, %s, %s, %s)",
            (
                order_id,
                stream_id,
                seq,
                json.dumps(payload, ensure_ascii=False),
                created_at,
                created_by,
            ),
        )

    def proposal(self, order_id: str) -> Row | None:
        return self._one("SELECT * FROM proposals WHERE order_id = %s", (order_id,))

    def set_proposal_status(self, order_id: str, status: str) -> None:
        self._execute("UPDATE proposals SET status = %s WHERE order_id = %s", (status, order_id))

    def add_signature(self, order_id: str, key_id: str, sig: str, observed_at: int) -> None:
        self._execute(
            "INSERT INTO signatures (order_id, key_id, sig, observed_at)"
            " VALUES (%s, %s, %s, %s) ON CONFLICT (order_id, key_id) DO NOTHING",
            (order_id, key_id, sig, observed_at),
        )

    def signatures(self, order_id: str) -> list[Row]:
        return self._all(
            "SELECT * FROM signatures WHERE order_id = %s ORDER BY observed_at, key_id",
            (order_id,),
        )

    # --- orders --------------------------------------------------------------
    def create_order(
        self,
        order_id: str,
        envelope: Mapping[str, Any],
        dispatched_at: int,
        drill: bool,
        severity: str,
        scenario: str,
        cancels: str | None,
        digest: str,
        canary: bool = False,
        until_cancelled: bool = False,
    ) -> None:
        self._execute(
            "INSERT INTO orders (order_id, envelope_json, dispatched_at, drill,"
            " severity, scenario, cancels, order_digest, canary, until_cancelled)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                order_id,
                json.dumps(envelope, ensure_ascii=False),
                dispatched_at,
                bool(drill),
                severity,
                scenario,
                cancels,
                digest,
                bool(canary),
                bool(until_cancelled),
            ),
        )

    def order(self, order_id: str) -> Row | None:
        return self._one("SELECT * FROM orders WHERE order_id = %s", (order_id,))

    def orders(self, limit: int = 50) -> list[Row]:
        """Most recent orders first.

        The ``order_id`` tie-break is not cosmetic. ``dispatched_at`` is in whole
        seconds, so a burst of orders shares one value; this result feeds both the
        escalation sweep and the replay-detection set, and a ``LIMIT`` over an
        ambiguous sort would silently choose a different set of rows each time.
        """
        return self._all(
            "SELECT * FROM orders WHERE NOT canary"
            " ORDER BY dispatched_at DESC, order_id DESC LIMIT %s",
            (limit,),
        )

    def active_candidates(self, finite_since: int) -> list[Row]:
        """Orders that may still be in force, with no row limit.

        Filtered in SQL before anything is limited: an event that lasts until a
        stand-down stays in force however many orders came after it, so "the newest
        200, then filter" would drop exactly the long-running ones. Finite orders
        dispatched before ``finite_since`` are past any possible delivery window.
        """
        return self._all(
            "SELECT * FROM orders o WHERE NOT o.canary AND o.cancels IS NULL"
            " AND NOT EXISTS (SELECT 1 FROM orders c WHERE c.cancels = o.order_id)"
            " AND (o.until_cancelled OR o.dispatched_at >= %s)"
            " ORDER BY o.dispatched_at DESC, o.order_id DESC",
            (finite_since,),
        )

    def recent_standdowns(self, since: int) -> list[Row]:
        return self._all(
            "SELECT * FROM orders WHERE cancels IS NOT NULL AND NOT canary"
            " AND dispatched_at >= %s ORDER BY dispatched_at, order_id",
            (since,),
        )

    def cancellations(self) -> dict[str, str]:
        """Cancelled order id -> the stand-down that cancelled it (the first one)."""
        result: dict[str, str] = {}
        for row in self._all(
            "SELECT order_id, cancels FROM orders WHERE cancels IS NOT NULL"
            " ORDER BY dispatched_at, order_id"
        ):
            result.setdefault(row["cancels"], row["order_id"])
        return result

    def cancelled_order_ids(self) -> set[str]:
        return {
            row["cancels"]
            for row in self._all("SELECT cancels FROM orders WHERE cancels IS NOT NULL")
        }

    # --- dispatch and acknowledgement ---------------------------------------
    def record_dispatch(
        self,
        order_id: str,
        person_id: str,
        channel: str,
        at: int,
        status: str,
        detail: str = "",
    ) -> None:
        self._execute(
            "INSERT INTO dispatches (order_id, person_id, channel, attempted_at,"
            " status, detail) VALUES (%s, %s, %s, %s, %s, %s)",
            (order_id, person_id, channel, at, status, detail),
        )

    def dispatches(self, order_id: str) -> list[Row]:
        return self._all(
            "SELECT * FROM dispatches WHERE order_id = %s ORDER BY attempted_at, id",
            (order_id,),
        )

    def record_ack(
        self,
        order_id: str,
        person_id: str,
        device_key_id: str,
        status: str,
        at: int,
        ack: Mapping[str, Any],
        valid: bool,
        reasons: Sequence[str] = (),
    ) -> None:
        self._execute(
            "INSERT INTO acks (order_id, person_id, device_key_id, status, at,"
            " ack_json, valid, reasons) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                order_id,
                person_id,
                device_key_id,
                status,
                at,
                json.dumps(ack, ensure_ascii=False),
                bool(valid),
                ",".join(reasons),
            ),
        )

    def acks(self, order_id: str) -> list[Row]:
        """Every acknowledgement for an order, oldest first.

        The ``id`` tie-break decides which of two acknowledgements sent in the same
        second the dashboard shows, because the caller keeps the last one per person.
        """
        return self._all("SELECT * FROM acks WHERE order_id = %s ORDER BY at, id", (order_id,))

    #: Statuses that do NOT mean the order is being handled by that person.
    #:
    #: ``received`` is emitted by the device, not a human. ``cannot_comply`` is the
    #: one that is easy to get wrong: it is a *refusal*, and treating it as handled
    #: would retire that person from the outstanding set and stop the ladder exactly
    #: at the duty-officer, alternate-group and siren rungs that exist to reassign
    #: their task. A refusal has to keep escalation alive, not end it.
    UNHANDLED_ACK_STATUSES = ("received", "cannot_comply")

    def acknowledged_person_ids(self, order_id: str) -> set[str]:
        """People whose order is genuinely being dealt with.

        Only *valid* acks count: an invalid one means somebody is impersonating an
        executor, which is worse than silence and must not stop escalation.
        """
        return {
            row["person_id"]
            for row in self._all(
                "SELECT person_id FROM acks WHERE order_id = %s AND valid AND status <> ALL(%s)",
                (order_id, list(self.UNHANDLED_ACK_STATUSES)),
            )
        }

    def refused_person_ids(self, order_id: str) -> set[str]:
        """People who reported they cannot comply -- the reassignment list."""
        return {
            row["person_id"]
            for row in self._all(
                "SELECT person_id FROM acks WHERE order_id = %s AND valid"
                " AND status = 'cannot_comply'",
                (order_id,),
            )
        }

    # --- escalation ----------------------------------------------------------
    def mark_rung(self, order_id: str, person_id: str, rung: int, at: int) -> bool:
        """Returns True if this call is the one that claimed the rung.

        This is the latch that stops a restart mid-incident from re-sounding a siren
        or re-calling somebody who was already called, so the row count has to mean
        exactly "I inserted it" and not "a row with these values exists".
        """
        return (
            self._execute(
                "INSERT INTO escalation_state (order_id, person_id, rung, fired_at)"
                " VALUES (%s, %s, %s, %s) ON CONFLICT (order_id, person_id, rung) DO NOTHING",
                (order_id, person_id, rung, at),
            )
            > 0
        )

    # --- anti-replay, by primary key -----------------------------------------
    def stream_high(self, stream_id: str) -> int | None:
        """Highest sequence number ever dispatched on a stream, or None."""
        row = self._one("SELECT MAX(seq) AS s FROM stream_seq WHERE stream_id = %s", (stream_id,))
        value = row["s"] if row else None
        return int(value) if value is not None else None

    def stream_seq_seen(self, stream_id: str, seq: int) -> bool:
        return (
            self._one(
                "SELECT 1 FROM stream_seq WHERE stream_id = %s AND seq = %s", (stream_id, seq)
            )
            is not None
        )

    def claim_stream_seq(self, stream_id: str, seq: int, order_id: str, at: int) -> str | None:
        """Claim ``(stream_id, seq)`` for ``order_id``.

        Returns ``None`` when this call made the claim, or the ``order_id`` that
        already holds it. That distinction is the point: the same order arriving
        twice is a retry and may proceed, while a *different* order carrying a number
        already used is a replay.

        ``DO UPDATE`` with a self-assignment rather than ``DO NOTHING`` so that
        RETURNING still fires on a conflict; ``xmax = 0`` is how PostgreSQL lets a
        caller tell an insert from an update in the same statement.
        """
        row = self._one(
            "INSERT INTO stream_seq (stream_id, seq, order_id, seen_at)"
            " VALUES (%s, %s, %s, %s)"
            " ON CONFLICT (stream_id, seq) DO UPDATE SET order_id = stream_seq.order_id"
            " RETURNING order_id, (xmax = 0) AS inserted",
            (stream_id, seq, order_id, at),
        )
        assert row is not None
        return None if row["inserted"] else str(row["order_id"])

    def order_exists(self, order_id: str) -> bool:
        """Indexed existence check, replacing a scan of the last thousand orders."""
        return self._one("SELECT 1 FROM orders WHERE order_id = %s", (order_id,)) is not None

    # --- siren claims ---------------------------------------------------------
    def claim_siren(self, site: str, order_id: str, pattern: str, at: int) -> bool:
        """True when this call is the one that sounded the siren at this site.

        A siren that sounds twice for one order is not cosmetic: nobody standing
        outside can tell a repeat from a second emergency.
        """
        return (
            self._execute(
                "INSERT INTO siren_activations (site, order_id, pattern, fired_at)"
                " VALUES (%s, %s, %s, %s) ON CONFLICT (site, order_id) DO NOTHING",
                (site, order_id, pattern, at),
            )
            > 0
        )

    def siren_last_fired(self, site: str, *, exclude_order_id: str = "") -> int | None:
        """When this site last sounded, ignoring one order.

        The exclusion is what lets the rate limit and the per-order dedupe be asked
        independently. Without it the second recipient at a site would be told
        "rate limited" -- because the order's own activation is the most recent one --
        when the truthful answer is "already sounded for this order".
        """
        row = self._one(
            "SELECT MAX(fired_at) AS t FROM siren_activations WHERE site = %s AND order_id <> %s",
            (site, exclude_order_id),
        )
        value = row["t"] if row else None
        return int(value) if value is not None else None

    def siren_activations(self, order_id: str) -> list[Row]:
        return self._all(
            "SELECT * FROM siren_activations WHERE order_id = %s ORDER BY site", (order_id,)
        )

    def all_siren_activations(self) -> list[Row]:
        return self._all("SELECT * FROM siren_activations ORDER BY fired_at, site, order_id")

    # --- escalation claims for role and group rungs ---------------------------
    def claim_escalation_extra(self, order_id: str, rung: int, target: str, at: int) -> bool:
        """True when this call claimed the role/group notification for this rung.

        ``escalation_state`` latches per person, which is not enough: two climbers
        claim different subsets of the outstanding people and then both run the role
        and group notifications hanging off the same rung.
        """
        return (
            self._execute(
                "INSERT INTO escalation_extra (order_id, rung, target, fired_at)"
                " VALUES (%s, %s, %s, %s) ON CONFLICT (order_id, rung, target) DO NOTHING",
                (order_id, rung, target, at),
            )
            > 0
        )

    # --- audit ---------------------------------------------------------------
    def audit_chain_head(self) -> tuple[int, str | None]:
        """``(next index, previous entry hash)`` -- the whole link, in one step.

        **Call this inside :meth:`tx`.** It takes a transaction-scoped advisory lock,
        so every appender serializes here and the index and ``prev`` it returns are
        still the tip when the caller inserts. Reading them as two separate
        autocommitted statements is how a hash chain quietly forks.
        """
        with self._conn() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(%s)", (locks.AUDIT_CHAIN,))
            cursor.execute(
                "SELECT COALESCE(MAX(idx) + 1, 0) AS next_idx,"
                " (SELECT entry_hash FROM audit_log ORDER BY idx DESC LIMIT 1) AS prev"
                " FROM audit_log"
            )
            row = cursor.fetchone()
            assert row is not None  # an aggregate always returns one row
            return int(row["next_idx"]), row["prev"]

    def append_audit(
        self,
        idx: int,
        ts: int,
        prev: str,
        event: str,
        data: Mapping[str, Any],
        entry_hash: str,
    ) -> None:
        self._execute(
            "INSERT INTO audit_log (idx, ts, prev, event, data_json, entry_hash)"
            " VALUES (%s, %s, %s, %s, %s, %s)",
            (idx, ts, prev, event, json.dumps(data, ensure_ascii=False), entry_hash),
        )

    def audit_count(self) -> int:
        row = self._one("SELECT COUNT(*) AS c FROM audit_log")
        return int(row["c"]) if row else 0

    def chain_tip(self) -> tuple[int, str] | None:
        """``(idx, entry_hash)`` of the last entry, or None for an empty chain.

        Lets a head be published without loading the chain to recompute its hash.
        """
        row = self._one("SELECT idx, entry_hash FROM audit_log ORDER BY idx DESC LIMIT 1")
        return (int(row["idx"]), row["entry_hash"]) if row else None

    def last_audit_hash(self) -> str | None:
        row = self._one("SELECT entry_hash FROM audit_log ORDER BY idx DESC LIMIT 1")
        return row["entry_hash"] if row else None

    def audit_entries(self, from_idx: int = 0, limit: int = 1000) -> Iterator[dict[str, Any]]:
        rows = self._all(
            "SELECT idx, ts, prev, event, data_json FROM audit_log"
            " WHERE idx >= %s ORDER BY idx LIMIT %s",
            (from_idx, limit),
        )
        for row in rows:
            yield {
                "idx": int(row["idx"]),
                "ts": int(row["ts"]),
                "prev": row["prev"],
                "event": row["event"],
                "data": json.loads(row["data_json"]),
            }

    def put_head(self, idx: int, head: str, ts: int, signature: str = "") -> None:
        self._execute(
            "INSERT INTO audit_heads (idx, head, ts, signature) VALUES (%s, %s, %s, %s)"
            " ON CONFLICT (idx) DO UPDATE SET"
            " head = EXCLUDED.head, ts = EXCLUDED.ts, signature = EXCLUDED.signature",
            (idx, head, ts, signature),
        )

    def heads(self) -> dict[int, str]:
        return {
            int(row["idx"]): row["head"]
            for row in self._all("SELECT idx, head FROM audit_heads ORDER BY idx")
        }

    def latest_head(self) -> Row | None:
        return self._one("SELECT * FROM audit_heads ORDER BY idx DESC LIMIT 1")

    # --- channel heartbeats ---------------------------------------------------
    def heartbeat(self, channel: str, node_id: str) -> Row | None:
        return self._one(
            "SELECT * FROM channel_heartbeats WHERE channel = %s AND node_id = %s",
            (channel, node_id),
        )

    def record_heartbeat(
        self, channel: str, node_id: str, status: str, detail: str, at: int
    ) -> None:
        """Upsert one node's view of one channel.

        Only this node ever writes its own row, so no lock is needed. The failure
        counter is reset by a success and incremented by anything else -- a ``stub``
        counts as a failure here, because a channel with no provider behind it is
        exactly as silent as one whose provider is down.
        """
        self._execute(
            "INSERT INTO channel_heartbeats"
            " (channel, node_id, status, detail, last_at, last_ok_at,"
            "  consecutive_failures)"
            " VALUES (%s, %s, %s, %s, %s, CASE WHEN %s THEN %s END, CASE WHEN %s THEN 0 ELSE 1 END)"
            " ON CONFLICT (channel, node_id) DO UPDATE SET"
            " status = EXCLUDED.status, detail = EXCLUDED.detail, last_at = EXCLUDED.last_at,"
            " last_ok_at = CASE WHEN %s THEN EXCLUDED.last_at"
            "                   ELSE channel_heartbeats.last_ok_at END,"
            " consecutive_failures = CASE WHEN %s THEN 0"
            "                             ELSE channel_heartbeats.consecutive_failures + 1 END",
            (
                channel,
                node_id,
                status,
                detail,
                at,
                status == "ok",
                at,
                status == "ok",
                status == "ok",
                status == "ok",
            ),
        )

    def heartbeats(self) -> list[Row]:
        return self._all("SELECT * FROM channel_heartbeats ORDER BY channel, node_id")

    # --- request nonces -------------------------------------------------------
    def claim_request_nonce(self, key_id: str, nonce: str, expires_at: int) -> bool:
        """True when this nonce is fresh for this key. False means a replay.

        Same shape as every other claim in this file: the primary key does the work
        and the loser of a race learns it lost, which is what makes it correct with
        more than one worker.
        """
        return (
            self._execute(
                "INSERT INTO http_nonces (key_id, nonce, expires_at) VALUES (%s, %s, %s)"
                " ON CONFLICT (key_id, nonce) DO NOTHING",
                (key_id, nonce, expires_at),
            )
            > 0
        )

    def prune_request_nonces(self, now: int) -> int:
        """Drop nonces whose signatures could no longer be fresh anyway."""
        return self._execute("DELETE FROM http_nonces WHERE expires_at <= %s", (now,))

    def order_counts(self) -> list[Row]:
        """Order counts by severity and drill flag, for metrics.

        Aggregated in the database rather than by loading rows: a scrape must stay
        cheap, and nothing here needs a single order's detail.
        """
        return self._all(
            "SELECT severity, drill, COUNT(*) AS n FROM orders"
            " GROUP BY severity, drill ORDER BY severity, drill"
        )

    # --- canary ---------------------------------------------------------------
    def record_canary_run(
        self,
        *,
        node_id: str,
        started_at: int,
        finished_at: int,
        ok: bool,
        delivered: int,
        detail: str = "",
        order_id: str | None = None,
    ) -> None:
        self._execute(
            "INSERT INTO canary_runs"
            " (order_id, node_id, started_at, finished_at, ok, delivered, detail)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (order_id, node_id, started_at, finished_at, ok, delivered, detail),
        )

    def latest_canary_run(self) -> Row | None:
        return self._one("SELECT * FROM canary_runs ORDER BY started_at DESC, id DESC LIMIT 1")

    def prune_canary_runs(self, keep: int = 2000) -> int:
        """Keep the recent history and drop the rest.

        The canary's own record is operational, not evidentiary -- what is evidence
        lives in the audit chain, which is never pruned. Keeping this table bounded
        is why the canary can run hourly without anyone having to think about it.
        """
        return self._execute(
            "DELETE FROM canary_runs WHERE id <= ("
            " SELECT MIN(id) FROM (SELECT id FROM canary_runs ORDER BY id DESC LIMIT %s) t"
            ") - 1",
            (keep,),
        )

    # --- WebSocket delivery across processes ----------------------------------
    def set_presence(self, process_id: str, person_id: str, devices: int, at: int) -> None:
        """Record how many devices of ``person_id`` this process holds; 0 removes it."""
        if devices <= 0:
            self._execute(
                "DELETE FROM ws_presence WHERE process_id = %s AND person_id = %s",
                (process_id, person_id),
            )
            return
        self._execute(
            "INSERT INTO ws_presence (process_id, person_id, devices, updated_at)"
            " VALUES (%s, %s, %s, %s)"
            " ON CONFLICT (process_id, person_id) DO UPDATE SET"
            " devices = EXCLUDED.devices, updated_at = EXCLUDED.updated_at",
            (process_id, person_id, devices, at),
        )

    def replace_presence(self, process_id: str, counts: Mapping[str, int], at: int) -> None:
        """Make this process's presence exactly ``counts``, in one transaction."""
        with self.tx():
            self._execute("DELETE FROM ws_presence WHERE process_id = %s", (process_id,))
            for person_id, devices in counts.items():
                if devices > 0:
                    self._execute(
                        "INSERT INTO ws_presence (process_id, person_id, devices, updated_at)"
                        " VALUES (%s, %s, %s, %s)",
                        (process_id, person_id, devices, at),
                    )

    def clear_presence(self, process_id: str) -> None:
        self._execute("DELETE FROM ws_presence WHERE process_id = %s", (process_id,))

    def present_elsewhere(self, person_id: str, process_id: str, fresh_after: int) -> list[str]:
        """Other processes that recently said they hold a socket for this person."""
        rows = self._all(
            "SELECT process_id FROM ws_presence"
            " WHERE person_id = %s AND process_id <> %s AND updated_at >= %s",
            (person_id, process_id, fresh_after),
        )
        return [row["process_id"] for row in rows]

    def presence_summary(self, fresh_after: int) -> Row | None:
        return self._one(
            "SELECT COUNT(DISTINCT person_id) AS people, COUNT(DISTINCT process_id) AS processes"
            " FROM ws_presence WHERE updated_at >= %s",
            (fresh_after,),
        )

    def create_relay(self, order_id: str, person_id: str, origin: str, at: int) -> int:
        row = self._one(
            "INSERT INTO ws_relay (order_id, person_id, origin, created_at)"
            " VALUES (%s, %s, %s, %s) RETURNING relay_id",
            (order_id, person_id, origin, at),
        )
        assert row is not None
        relay_id: int = row["relay_id"]
        return relay_id

    def notify(self, channel: str, payload: str) -> None:
        self._execute("SELECT pg_notify(%s, %s)", (channel, payload))

    def relay(self, relay_id: int) -> Row | None:
        return self._one(
            "SELECT r.relay_id, r.order_id, r.person_id, r.origin, o.envelope_json"
            " FROM ws_relay r JOIN orders o ON o.order_id = r.order_id"
            " WHERE r.relay_id = %s",
            (relay_id,),
        )

    def record_relay_result(self, relay_id: int, process_id: str, delivered: int, at: int) -> None:
        self._execute(
            "INSERT INTO ws_relay_result (relay_id, process_id, delivered, at)"
            " VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
            (relay_id, process_id, delivered, at),
        )

    def relay_results(self, relay_id: int) -> list[Row]:
        return self._all(
            "SELECT process_id, delivered FROM ws_relay_result WHERE relay_id = %s", (relay_id,)
        )

    def prune_relays(self, before: int) -> int:
        """Hand-offs are only interesting for the seconds they take."""
        return self._execute("DELETE FROM ws_relay WHERE created_at < %s", (before,))

    def prune_presence(self, before: int) -> int:
        """Rows a crashed process left behind."""
        return self._execute("DELETE FROM ws_presence WHERE updated_at < %s", (before,))
