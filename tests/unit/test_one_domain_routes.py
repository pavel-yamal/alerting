"""Panel and API under one domain (deploy/nginx/alerting-one-domain.conf, docs/12 §8).

One name works only while the paths do not overlap: the server answers only under
/v1, the panel never does. A panel route added under /v1 -- or a server route outside
it -- would silently land on the other service behind the proxy. The server half needs
its database and lives in tests/integration/test_server_routes_under_v1.py.
"""

from __future__ import annotations

import pathlib
import re

from fastapi.routing import APIRoute

from alerting.clients.panel.app import create_panel

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONF = (ROOT / "deploy" / "nginx" / "alerting-one-domain.conf").read_text(encoding="utf-8")


def paths(app) -> set[str]:
    return {r.path for r in app.routes if isinstance(r, APIRoute)}


def test_the_panel_never_answers_under_v1(tmp_path):
    panel = paths(
        create_panel(homes=None, server_url="http://unused", state_dir=tmp_path, server_keys=False)
    )
    assert "/api/config" in panel and "/privacy" in panel
    assert not [p for p in panel if p.startswith("/v1")], sorted(panel)


def location(prefix: str) -> str:
    match = re.search(r"location " + re.escape(prefix) + r" \{(.*?)\n    \}", CONF, re.S)
    assert match, prefix
    return match.group(1)


def test_the_proxy_sends_v1_to_the_api_and_the_rest_to_the_panel():
    assert "proxy_pass http://alerting_api;" in location("/v1/")
    assert "proxy_pass http://alerting_panel;" in location("/")
    assert "upstream alerting_api   { server 127.0.0.1:7070;" in CONF
    assert "upstream alerting_panel { server 127.0.0.1:7071;" in CONF


def test_login_is_rate_limited_and_health_is_not_public():
    login = location("~ ^/api/(device/begin|device/renew/begin|login)$")
    assert "limit_req zone=alerting_login" in login
    for internal in ("= /healthz", "~ ^/v1/(healthz|readyz|metricsz)$"):
        assert "deny all;" in location(internal)
