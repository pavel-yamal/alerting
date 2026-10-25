"""The server answers only under /v1 -- the other half of tests/unit/test_one_domain_routes.py.

Behind deploy/nginx/alerting-one-domain.conf everything outside /v1 goes to the panel,
so a server route there would be unreachable without anyone noticing.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from alerting.core.clock import FixedClock
from alerting.server.app import create_app
from alerting.server.config import Settings


def test_the_server_answers_only_under_v1(settings: Settings, clock: FixedClock) -> None:
    app = create_app(settings, clock, start_escalation=False)
    with TestClient(app):  # the lifespan opens and closes the database pool
        # The schema, not app.routes: included routers are resolved lazily there.
        # Its own /docs and /openapi.json sit outside /v1 and are not in the schema;
        # behind the one-domain proxy they reach the panel, which answers 404.
        paths = set(app.openapi()["paths"])
    assert paths and all(p.startswith("/v1/") for p in paths), sorted(paths)
