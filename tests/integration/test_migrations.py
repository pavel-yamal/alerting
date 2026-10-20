"""Migrations: the contract, not the mechanism.

Three properties, each of which exists because of a way schema management fails
without anybody noticing until an incident.
"""

from __future__ import annotations

import psycopg
import pytest

from alerting.server.app import AppServices
from alerting.server.db import migrate

pytestmark = pytest.mark.asyncio


async def test_applying_twice_changes_nothing(owner_conn):
    assert migrate.apply(owner_conn) == []
    assert migrate.schema_version(owner_conn) == migrate.expected_version()


async def test_a_migration_edited_after_it_was_applied_is_refused(owner_conn):
    """The classic silent divergence: somebody fixes a typo in an applied migration,
    and from then on two nodes report the same schema version while having different
    schemas. Nothing else in a deployment would ever say so.
    """
    version = migrate.expected_version()
    original = owner_conn.execute(
        "SELECT checksum FROM schema_migrations WHERE version = %s", (version,)
    ).fetchone()["checksum"]
    try:
        owner_conn.execute(
            "UPDATE schema_migrations SET checksum = %s WHERE version = %s",
            ("0" * 64, version),
        )
        with pytest.raises(migrate.SchemaMismatch, match="has changed since it was applied"):
            migrate.verify(owner_conn)
        with pytest.raises(migrate.SchemaMismatch):
            migrate.apply(owner_conn)
    finally:
        owner_conn.execute(
            "UPDATE schema_migrations SET checksum = %s WHERE version = %s", (original, version)
        )


async def test_a_node_refuses_to_start_against_the_wrong_schema_version(
    owner_conn, settings, clock
):
    """Not "fails on the first request that needs the new column" -- which, because
    unusual code paths run during incidents, means failing during an incident."""
    owner_conn.execute(
        "INSERT INTO schema_migrations (version, checksum, name) VALUES (%s, 'x', 'future.sql')",
        (migrate.expected_version() + 1,),
    )
    try:
        with pytest.raises(migrate.SchemaMismatch, match="expects"):
            AppServices(settings, clock)
    finally:
        owner_conn.execute(
            "DELETE FROM schema_migrations WHERE version = %s", (migrate.expected_version() + 1,)
        )


async def test_the_readiness_probe_reports_a_schema_mismatch(client, owner_conn):
    """A node can outlive a migration run against a shared database, so the check at
    startup is not enough on its own: the balancer needs to hear about it too."""
    assert client.get("/v1/readyz").json()["checks"]["schema"] is True

    owner_conn.execute(
        "INSERT INTO schema_migrations (version, checksum, name) VALUES (%s, 'x', 'future.sql')",
        (migrate.expected_version() + 1,),
    )
    try:
        response = client.get("/v1/readyz")
        assert response.status_code == 503
        assert response.json()["checks"]["schema"] is False
    finally:
        owner_conn.execute(
            "DELETE FROM schema_migrations WHERE version = %s", (migrate.expected_version() + 1,)
        )


async def test_migration_files_are_named_so_their_order_is_not_a_guess(owner_conn):
    versions = [version for version, _ in migrate.discover()]
    assert versions == sorted(versions)
    assert len(set(versions)) == len(versions)


async def test_the_application_role_cannot_run_migrations(app_dsn):
    """Migrations are a separate command run as the owner. If the running server
    could change the schema, every path into the process would be a path to the
    schema."""
    with (
        psycopg.connect(app_dsn, autocommit=True) as connection,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        connection.execute("CREATE TABLE should_not_exist (x integer)")
