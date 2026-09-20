"""Connection pooling, and the one setting that keeps the port honest.

**The pool runs in autocommit mode.** That is deliberate, and it is the decision the
whole migration turns on.

Under SQLite this project ran with ``isolation_level=None``: every statement
committed on its own. ``AuditService.append`` relies on that. It catches any
exception, spools the entry to disk and *returns*, so that the alert still goes out --
"the logger never blocks the alert" is the first line of that module. Under psycopg's
default, a failed statement poisons the surrounding transaction and every later
statement raises ``InFailedSqlTransaction`` until someone rolls back. A survivable
audit failure would have become a failed dispatch: exactly the outcome the spool
exists to prevent.

So autocommit stays the default, matching the old semantics statement for statement,
and a transaction becomes what it should always have been -- explicit, narrow, and
present in only the three places that need one (see ``Repo.tx``).

The second reason for a pool rather than one shared connection: the escalation worker
and the request handlers interleave on the same event loop across ``await`` points.
With one connection they would share one transaction, and an acknowledgement arriving
mid-escalation would be committed or rolled back by whichever coroutine finished
first.
"""

from __future__ import annotations

import logging
from typing import Any

from psycopg import Connection
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

log = logging.getLogger("alerting.db")

#: How long a statement waits for a lock before giving up. The audit chain serializes
#: every appender on one advisory lock, so this is the bound on how long a dispatch
#: can be delayed by a slow one.
LOCK_TIMEOUT_MS = 5_000

#: A query that runs this long is not going to help anyone during an incident.
STATEMENT_TIMEOUT_MS = 15_000

#: A transaction left open by a bug would hold back vacuum and keep locks. Nothing
#: here legitimately holds one across I/O.
IDLE_IN_TRANSACTION_TIMEOUT_MS = 30_000


def _configure(connection: Connection[Any]) -> None:
    connection.execute(f"SET lock_timeout = {LOCK_TIMEOUT_MS}")
    connection.execute(f"SET statement_timeout = {STATEMENT_TIMEOUT_MS}")
    connection.execute(
        f"SET idle_in_transaction_session_timeout = {IDLE_IN_TRANSACTION_TIMEOUT_MS}"
    )


def open_pool(dsn: str, *, min_size: int = 2, max_size: int = 10) -> ConnectionPool[Any]:
    """Open a pool and wait for it, so a bad DSN fails at startup rather than later."""
    pool: ConnectionPool[Any] = ConnectionPool(
        dsn,
        min_size=min_size,
        max_size=max_size,
        kwargs={"row_factory": dict_row, "autocommit": True},
        configure=_configure,
        open=False,
        name="alerting",
    )
    pool.open(wait=True, timeout=10)
    return pool
