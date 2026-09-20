"""A fully wired server on a temporary database, driven by a fixed clock."""

from __future__ import annotations

import pathlib

import pytest
from fastapi.testclient import TestClient

from alerting.core.clock import FixedClock
from alerting.core.signing import public_key_to_b64u
from alerting.orgkit import Org, build_org
from alerting.server.app import AppServices, create_app
from alerting.server.config import Settings
from alerting.server.services.bootstrap import publish_org

ISSUED_AT = 1_700_000_000


@pytest.fixture
def org() -> Org:
    return build_org(issued_at=ISSUED_AT)


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(ISSUED_AT + 5)


@pytest.fixture
def settings(tmp_path: pathlib.Path, org: Org) -> Settings:
    return Settings(
        org_id=org.org_id,
        db_path=str(tmp_path / "alerting.db"),
        root_public_key=public_key_to_b64u(org.root_public_key),
        heads_dir=tmp_path / "heads",
        spool_dir=tmp_path / "spool",
        wordlist_path="config/wordlist.ru.txt",
        drill_enabled_sites=frozenset(),
        # The tests exercise the stub adapters on purpose, so they opt in explicitly —
        # the same way a demo node has to. A production node must not set this.
        allow_stub_channels=True,
    )


@pytest.fixture
def services(settings: Settings, clock: FixedClock, org: Org) -> AppServices:
    """Server services without the HTTP layer, for tests that drive them directly."""
    app_services = AppServices(settings, clock)
    publish_org(app_services.repo, org, audit=app_services.audit)
    yield app_services
    app_services.close()


@pytest.fixture
def client(settings: Settings, clock: FixedClock, org: Org):
    """HTTP client. Escalation is off so tests drive ``tick()`` deterministically."""
    app = create_app(settings, clock, start_escalation=False)
    publish_org(app.state.alerting.repo, org, audit=app.state.alerting.audit)
    with TestClient(app) as test_client:
        yield test_client
