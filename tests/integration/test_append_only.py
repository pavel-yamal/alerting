"""The audit log is append-only, and it is append-only twice.

Layer one is privileges: the role the server connects as holds ``SELECT`` and
``INSERT`` on ``audit_log`` and nothing else. Layer two is triggers, which catch the
owner -- the role that runs migrations and the one a tired administrator is logged in
as at 3am.

The layers are not redundant. Triggers alone miss ``TRUNCATE`` on old PostgreSQL
patterns and can be disabled by whoever owns the table; privileges alone would be
undone by the next ``GRANT ALL``. Neither stops somebody with the owner role and
intent -- that is what the hash chain and the externally published heads are for, and
``test_auditor_cli.py`` exercises exactly that path.
"""

from __future__ import annotations

import psycopg
import pytest

pytestmark = pytest.mark.asyncio

STATEMENTS = [
    ("UPDATE", "UPDATE audit_log SET ts = 0"),
    ("DELETE", "DELETE FROM audit_log"),
    ("TRUNCATE", "TRUNCATE audit_log"),
]


@pytest.mark.parametrize(("label", "statement"), STATEMENTS, ids=[s[0] for s in STATEMENTS])
async def test_the_application_role_cannot_rewrite_history(app_dsn, label, statement):
    """Not "is refused by a trigger" -- *has no privilege to try*.

    This is the guarantee that survives a fully compromised application process.
    """
    with (
        psycopg.connect(app_dsn, autocommit=True) as connection,
        pytest.raises(psycopg.errors.InsufficientPrivilege),
    ):
        connection.execute(statement)


@pytest.mark.parametrize(("label", "statement"), STATEMENTS, ids=[s[0] for s in STATEMENTS])
async def test_even_the_owner_is_stopped_by_the_triggers(owner_conn, label, statement):
    # A row has to exist: UPDATE and DELETE are *row* triggers, so on the empty table
    # the test would pass without the guard being there at all.
    owner_conn.execute(
        "INSERT INTO audit_log (idx, ts, prev, event, data_json, entry_hash)"
        " VALUES (0, 1, 'genesis', 'test.event', '{}', 'h')"
    )
    with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
        owner_conn.execute(statement)


async def test_the_application_role_can_still_append(services, org, clock):
    """The guard must not have been bought by breaking the thing it protects."""
    before = services.repo.audit_count()
    services.audit.append("test.event", {"order_id": "o-1"})
    assert services.repo.audit_count() == before + 1


async def test_the_application_role_cannot_grant_itself_more(app_dsn):
    """A compromised process that could re-grant itself UPDATE would make layer one
    decorative. It does not own the table, so the GRANT is a no-op.

    PostgreSQL answers a grant you are not entitled to make with a *warning*, not an
    error -- so asserting that the statement raises would be asserting the wrong
    thing. What matters is that nothing changed afterwards.
    """
    with psycopg.connect(app_dsn, autocommit=True) as connection:
        connection.execute("GRANT UPDATE ON audit_log TO alerting_app")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute("UPDATE audit_log SET ts = 0")
