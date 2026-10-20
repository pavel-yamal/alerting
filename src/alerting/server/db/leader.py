"""Single-climber election for the escalation ladder.

Every node runs an escalation worker, but only one may climb a ladder at a time.
The per-person latch in ``escalation_state`` stops the same person being called
twice, and the claims in ``escalation_extra`` stop a role or group being paged
twice -- but both are a last line. Two climbers still means two processes reading
the same orders, fanning out over the same channels and racing on every claim.
One climber makes the common case simple and the claims a backstop rather than a
load-bearing part.

**A session advisory lock, not a row with a lease.** A lease needs a heartbeat, a
clock both sides agree on, and a rule for what happens when the holder is merely
slow -- three things to get wrong in a component whose failure is silent. PostgreSQL
drops a session lock the moment the holder's connection goes, including when its
machine vanishes, and it does so without either side consulting a clock.

The lock therefore needs a connection of its own: one taken from the pool is handed
back after every statement, which would release it immediately.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any

import psycopg

from alerting.server.db import locks

log = logging.getLogger("alerting.db.leader")


class LeaderLock:
    """Try to hold the escalation lock. Safe to poll; safe to call when already held."""

    def __init__(self, dsn: str, key: int = locks.ESCALATION_LEADER) -> None:
        self._dsn = dsn
        self._key = key
        self._connection: psycopg.Connection[Any] | None = None
        self._held = False

    def held(self) -> bool:
        return self._held

    def acquire(self) -> bool:
        """Take the lock if it is free. Returns whether this process holds it.

        Called at the top of every tick rather than once at startup, which is what
        makes failover automatic: when the holder dies its connection goes with it,
        PostgreSQL drops the lock, and the next caller here picks it up. The cost is
        one cheap statement per tick.
        """
        try:
            if self._held and self._alive():
                return True
            self._held = False
            connection = self._connect()
            cursor = connection.execute("SELECT pg_try_advisory_lock(%s) AS got", (self._key,))
            row = cursor.fetchone()
            self._held = bool(row and row["got"])
            if self._held:
                log.info("this node is now the escalation leader")
            return self._held
        except Exception:
            # Losing the database is not a reason to climb a ladder blind: without it
            # nothing can be claimed, recorded or acknowledged anyway.
            log.warning("could not reach the database to take the escalation lock", exc_info=True)
            self._drop()
            return False

    def release(self) -> None:
        """Give the lock up now, rather than when the process finally exits.

        Shutdown is the case that matters: a restarting node that held the lock until
        its connection timed out would leave every other node idle in the meantime.
        """
        if self._connection is not None and self._held:
            try:
                self._connection.execute("SELECT pg_advisory_unlock(%s)", (self._key,))
                log.info("released the escalation leader lock")
            except Exception:
                log.warning("could not release the escalation lock cleanly", exc_info=True)
        self._drop()

    def _connect(self) -> psycopg.Connection[Any]:
        if self._connection is None or self._connection.closed:
            self._connection = psycopg.connect(
                self._dsn, row_factory=psycopg.rows.dict_row, autocommit=True
            )
        return self._connection

    def _alive(self) -> bool:
        connection = self._connection
        if connection is None or connection.closed:
            return False
        try:
            connection.execute("SELECT 1")
            return True
        except Exception:
            return False

    def _drop(self) -> None:
        self._held = False
        if self._connection is not None:
            with contextlib.suppress(Exception):
                self._connection.close()
            self._connection = None
