"""Versioned, checksummed migrations.

Three rules, each of which exists because of a specific way schema management fails
quietly:

* **Migrations are never applied by the application at startup.** They are a separate
  command (``alerting-server migrate``) run from a oneshot unit. An app that migrates
  on boot will, on the day two nodes restart together, run two migrations at once;
  and it gives every running node the privileges needed to rewrite the schema.
* **An applied migration's checksum is recorded and re-checked.** Editing a migration
  file after it has been deployed is the classic silent divergence: two nodes report
  the same schema version while having different schemas.
* **The application verifies the version and refuses to start on a mismatch**, rather
  than discovering it on the first request that needs the new column.
"""

from __future__ import annotations

import hashlib
import logging
import pathlib
import re
from typing import Any

from alerting.server.db import locks

log = logging.getLogger("alerting.db.migrate")

MIGRATIONS_DIR = pathlib.Path(__file__).with_name("migrations")

_NAME = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")


class SchemaMismatch(RuntimeError):
    """The database is not at the version this build expects."""


def discover() -> list[tuple[int, pathlib.Path]]:
    """Migration files shipped in this build, in order."""
    found: list[tuple[int, pathlib.Path]] = []
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        match = _NAME.match(path.name)
        if match is None:
            raise RuntimeError(
                f"migration {path.name!r} is not named NNNN_lower_snake.sql; refusing to "
                "guess its order"
            )
        found.append((int(match.group(1)), path))
    versions = [version for version, _ in found]
    if len(set(versions)) != len(versions):
        raise RuntimeError(f"duplicate migration versions: {versions}")
    return found


def expected_version() -> int:
    """The highest migration this build ships. 0 when there are none."""
    found = discover()
    return found[-1][0] if found else 0


def _checksum(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


_BOOTSTRAP = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    integer     PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now(),
    checksum   text        NOT NULL,
    name       text        NOT NULL
);
"""


def applied(connection: Any) -> dict[int, tuple[str, str]]:
    """``{version: (checksum, name)}`` already recorded in this database."""
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT 1 FROM information_schema.tables"
            " WHERE table_schema = current_schema() AND table_name = 'schema_migrations'"
        )
        if cursor.fetchone() is None:
            return {}
        cursor.execute("SELECT version, checksum, name FROM schema_migrations ORDER BY version")
        return {row["version"]: (row["checksum"], row["name"]) for row in cursor.fetchall()}


def schema_version(connection: Any) -> int:
    """Highest applied version, or 0 for an empty database."""
    seen = applied(connection)
    return max(seen) if seen else 0


def verify(connection: Any) -> None:
    """Refuse to continue unless the database matches this build exactly.

    Called at startup. A node that runs against a schema it was not built for either
    fails on the first request that needs a missing column -- in the middle of an
    incident, because that is when the unusual code paths run -- or, worse, writes
    rows the newer nodes cannot read.
    """
    want = expected_version()
    seen = applied(connection)
    have = max(seen) if seen else 0
    if have != want:
        raise SchemaMismatch(
            f"database is at schema version {have}, this build expects {want}. "
            "Run `alerting-server migrate` (as the owner role) before starting the node."
        )
    _verify_checksums(seen)


def _verify_checksums(seen: dict[int, tuple[str, str]]) -> None:
    for version, path in discover():
        recorded = seen.get(version)
        if recorded is None:
            continue
        digest = _checksum(path.read_text(encoding="utf-8"))
        if recorded[0] != digest:
            raise SchemaMismatch(
                f"migration {path.name} has changed since it was applied "
                f"(recorded {recorded[0][:12]}, on disk {digest[:12]}). Two nodes can now "
                "report the same schema version while having different schemas. Write a "
                "new migration instead of editing an applied one."
            )


def apply(connection: Any) -> list[int]:
    """Apply every pending migration. Returns the versions applied, in order.

    Safe to run concurrently: the whole run is serialized on an advisory lock, and a
    second caller that was waiting finds nothing left to do.
    """
    with connection.transaction():
        connection.execute(_BOOTSTRAP)
        connection.execute("GRANT SELECT ON schema_migrations TO alerting_app")

    with connection.transaction():
        connection.execute("SELECT pg_advisory_lock(%s)", (locks.MIGRATION,))
    try:
        seen = applied(connection)
        _verify_checksums(seen)
        done: list[int] = []
        for version, path in discover():
            if version in seen:
                continue
            body = path.read_text(encoding="utf-8")
            log.info("applying migration %s", path.name)
            # One transaction per migration: a failure leaves the database at the
            # last complete version rather than half-way through this one.
            with connection.transaction():
                connection.execute(body)
                connection.execute(
                    "INSERT INTO schema_migrations (version, checksum, name) VALUES (%s, %s, %s)",
                    (version, _checksum(body), path.name),
                )
            done.append(version)
        return done
    finally:
        with connection.transaction():
            connection.execute("SELECT pg_advisory_unlock(%s)", (locks.MIGRATION,))


def reset(connection: Any) -> list[int]:
    """Drop everything and migrate from scratch. **Demo and test use only.**

    This is the PostgreSQL replacement for what used to be ``db_path.unlink()`` --
    deleting the database file. That it is now four statements requiring the owner
    role, rather than removing a file, is the point: on SQLite an operator who
    mistyped a path could destroy a production audit chain with ``rm``.
    """
    with connection.transaction():
        connection.execute("DROP SCHEMA IF EXISTS public CASCADE")
        connection.execute("CREATE SCHEMA public")
        # A fresh schema carries none of the grants the old one had, and the
        # application role cannot see a schema it has no USAGE on.
        connection.execute("GRANT USAGE ON SCHEMA public TO alerting_app")
    return apply(connection)
