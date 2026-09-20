"""A fully wired server on a real PostgreSQL database, driven by a fixed clock.

**How isolation works, and why it is not a database per test.** Under SQLite each
test got its own file for free. PostgreSQL has no equivalent, and creating a database
per test costs more than the tests do. So: one database, migrated once for the
session, and every test starts by emptying every table.

The emptying is done as ``alerting_owner`` and has to disable the append-only
trigger on ``audit_log`` to do it -- which is the shape of the real guarantee. The
application connects as ``alerting_app``, which holds no privilege that could empty
that table however many triggers were disabled. ``test_append_only.py`` asserts
exactly that.
"""

from __future__ import annotations

import os
import pathlib
from collections.abc import Iterator

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.rows import dict_row

from alerting.core.clock import FixedClock
from alerting.core.signing import public_key_to_b64u
from alerting.orgkit import Org, build_org
from alerting.server.app import AppServices, create_app
from alerting.server.config import Settings
from alerting.server.db import migrate
from alerting.server.services.bootstrap import publish_org

ISSUED_AT = 1_700_000_000

#: Owner DSN: creates and empties objects. Tests that check what the *application*
#: may do use ``app_dsn`` instead.
OWNER_DSN = os.environ.get(
    "ALERTING_TEST_DSN",
    os.environ.get("ALERTING_DSN", "postgres://alerting_owner:devpass@127.0.0.1:5432/alerting"),
)

APP_DSN = os.environ.get(
    "ALERTING_TEST_APP_DSN", "postgres://alerting_app:devpass@127.0.0.1:5432/alerting"
)

#: Tables emptied between tests, children before parents so one statement suffices.
_TABLES = (
    "escalation_state",
    "escalation_extra",
    "siren_activations",
    "stream_seq",
    "streams",
    "acks",
    "dispatches",
    "signatures",
    "orders",
    "proposals",
    "contacts",
    "bundles",
    "audit_heads",
    "audit_log",
)


@pytest.fixture(scope="session")
def owner_dsn() -> str:
    """Migrate once per session, and fail with something readable if there is no
    database at all -- ``make db-up`` is the answer, and a connection refused here
    would otherwise show up as 349 identical tracebacks."""
    try:
        with psycopg.connect(OWNER_DSN, row_factory=dict_row, autocommit=True) as connection:
            migrate.apply(connection)
    except psycopg.OperationalError as exc:  # pragma: no cover - environment problem
        pytest.exit(
            f"cannot reach the test database at {OWNER_DSN.split('@')[-1]}: {exc}\n"
            "Run `make db-up` first, or point ALERTING_TEST_DSN at a PostgreSQL "
            "database whose owner role can create and drop objects.",
            returncode=3,
        )
    return OWNER_DSN


@pytest.fixture
def app_dsn() -> str:
    """The DSN the server itself uses: the least-privileged role."""
    return APP_DSN


@pytest.fixture(autouse=True)
def clean_database(owner_dsn: str) -> Iterator[None]:
    """Empty every table before each test.

    ``audit_log`` has a statement trigger that refuses TRUNCATE, because that is how
    an append-only table usually gets emptied by accident. Turning it off here is
    deliberate and narrow; the ``finally`` puts it back even when a test fails, so a
    later test cannot silently run without the guard.
    """
    with psycopg.connect(owner_dsn, row_factory=dict_row, autocommit=True) as connection:
        _restore_triggers(connection)
        connection.execute("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_truncate")
        try:
            connection.execute(f"TRUNCATE {', '.join(_TABLES)} RESTART IDENTITY CASCADE")
        finally:
            connection.execute("ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_truncate")
    yield


#: ``{trigger name: the event it guards}``. The tampering tests in
#: ``test_auditor_cli.py`` drop these on purpose -- defeating them is the scenario --
#: so they have to be put back, or every later test would run against an unguarded
#: table and quietly stop proving anything.
_TRIGGERS = {
    "audit_log_no_update": "UPDATE",
    "audit_log_no_delete": "DELETE",
    "audit_log_no_truncate": "TRUNCATE",
}


def _restore_triggers(connection: psycopg.Connection) -> None:
    cursor = connection.execute(
        "SELECT tgname FROM pg_trigger WHERE tgrelid = 'audit_log'::regclass AND NOT tgisinternal"
    )
    present = {row["tgname"] for row in cursor.fetchall()}
    for name, event in _TRIGGERS.items():
        if name in present:
            continue
        scope = "FOR EACH STATEMENT" if event == "TRUNCATE" else "FOR EACH ROW"
        connection.execute(
            f"CREATE TRIGGER {name} BEFORE {event} ON audit_log"
            f" {scope} EXECUTE FUNCTION audit_log_append_only()"
        )


@pytest.fixture
def org() -> Org:
    return build_org(issued_at=ISSUED_AT)


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(ISSUED_AT + 5)


#: The shared key the test server runs with. Tests go through the same gate a
#: deployed node does, rather than round the side of it.
API_KEY = "test-api-key-not-a-secret"


@pytest.fixture
def api_key_file(tmp_path: pathlib.Path) -> pathlib.Path:
    path = tmp_path / "api-key"
    path.write_text(API_KEY, encoding="utf-8")
    path.chmod(0o600)  # read_secret_file refuses anything looser
    return path


@pytest.fixture
def settings(
    tmp_path: pathlib.Path,
    org: Org,
    api_key_file: pathlib.Path,
    app_dsn: str,
    owner_dsn: str,
) -> Settings:
    return Settings(
        org_id=org.org_id,
        dsn=app_dsn,
        root_public_key=public_key_to_b64u(org.root_public_key),
        heads_dir=tmp_path / "heads",
        spool_dir=tmp_path / "spool",
        wordlist_path="config/wordlist.ru.txt",
        drill_enabled_sites=frozenset(),
        api_key_file=str(api_key_file),
        # The tests exercise the stub adapters on purpose, so they opt in explicitly --
        # the same way a demo node has to. A production node must not set this.
        allow_stub_channels=True,
    )


@pytest.fixture
def services(settings: Settings, clock: FixedClock, org: Org) -> Iterator[AppServices]:
    """Server services without the HTTP layer, for tests that drive them directly."""
    app_services = AppServices(settings, clock)
    publish_org(app_services.repo, org, audit=app_services.audit)
    yield app_services
    app_services.close()


@pytest.fixture
def owner_conn(owner_dsn: str) -> Iterator[psycopg.Connection]:
    """A connection as the owner, for the few tests that must write around ``Repo``
    -- tampering with the chain, dropping a trigger, emptying a table."""
    with psycopg.connect(owner_dsn, row_factory=dict_row, autocommit=True) as connection:
        yield connection


@pytest.fixture
def client(settings: Settings, clock: FixedClock, org: Org) -> Iterator[TestClient]:
    """HTTP client. Escalation is off so tests drive ``tick()`` deterministically."""
    app = create_app(settings, clock, start_escalation=False)
    publish_org(app.state.alerting.repo, org, audit=app.state.alerting.audit)
    with TestClient(app, headers={"Alerting-Api-Key": API_KEY}) as test_client:
        yield test_client


@pytest.fixture
def anon_client(settings: Settings, clock: FixedClock, org: Org) -> Iterator[TestClient]:
    """The same server, without the key -- for asserting that the gate holds."""
    app = create_app(settings, clock, start_escalation=False)
    publish_org(app.state.alerting.repo, org, audit=app.state.alerting.audit)
    with TestClient(app) as test_client:
        yield test_client
