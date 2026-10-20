"""The metrics endpoint.

Two properties carry it, and neither is about the numbers. It must leak nothing --
that is the whole reason it can sit behind an IP allowlist instead of a signature --
and it must answer the same way from any worker, because the unit runs
``--workers 2`` and a per-process counter would answer differently depending on who
was scraped.
"""

from __future__ import annotations

import contextlib

import pytest

from alerting.server.app import AppServices
from alerting.server.metrics import Metric, Sample, collect, render

pytestmark = pytest.mark.asyncio


def values(text: str, name: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith(name)]


# --- what must not be there --------------------------------------------------


async def test_the_scrape_carries_no_personal_data(client, org, services):
    """An IP allowlist is only an acceptable gate for aggregates. The moment a
    person_id, a name or a phone number appears here, the endpoint needs the
    signature gate -- and a scraper cannot sign Ed25519 requests."""
    body = client.get("/v1/metricsz").text

    for person in org.people.values():
        assert person.person_id not in body, f"{person.person_id} leaked into metrics"
        assert person.name not in body
        assert person.phone not in body
        assert person.key_id not in body


async def test_statusz_stays_behind_the_signature_gate(anon_client):
    """It names who is connected and calls that a roster leak itself, so it is the
    thing metrics must not become."""
    assert anon_client.get("/v1/statusz").status_code == 401
    assert anon_client.get("/v1/metricsz").status_code == 200


# --- what must be there ------------------------------------------------------


async def test_the_scrape_is_prometheus_text(client):
    body = client.get("/v1/metricsz").text

    assert "# HELP alerting_audit_entries" in body
    assert "# TYPE alerting_audit_entries counter" in body
    assert values(body, "alerting_audit_entries ")
    assert client.get("/v1/metricsz").headers["content-type"].startswith("text/plain")


async def test_the_main_metric_is_exposed(client, services, org, clock):
    """The same number the auditor's report prints, from the same code."""
    from alerting.core.envelope import Audience
    from alerting.orgkit import make_order, sign_order

    order = make_order(org, issued_at=clock.now(), audience=Audience(groups=("fire-wardens",)))
    await services.dispatcher.dispatch(
        sign_order(order, [org.person("p-001"), org.person("p-002")]), channels=("ws",)
    )
    clock.advance(30)
    for person in ("x-101", "x-102"):
        services.audit.append(
            "ack.received",
            {
                "order_id": order.order_id,
                "person_id": person,
                "status": "acknowledged",
                "valid": True,
            },
        )

    body = client.get("/v1/metricsz").text
    assert values(body, "alerting_ack_share_seconds{"), "the main metric is missing"
    assert "30" in "".join(values(body, "alerting_ack_share_seconds{"))


async def test_replication_and_recovery_are_reported(client):
    """The RPO indicator. Replication is asynchronous by design, so how far behind a
    standby is IS how much a failover could lose."""
    body = client.get("/v1/metricsz").text

    assert values(body, "alerting_database_in_recovery 0"), "this database is a primary"
    assert values(body, "alerting_replication_standbys ")


# --- correct from any worker -------------------------------------------------


async def test_two_processes_report_the_same_numbers(settings, clock, org, client):
    """Everything is derived from shared state at scrape time. A counter living in
    one process would make this fail, which is exactly why there is no metrics
    library here."""
    second = AppServices(settings, clock)
    try:
        first_body = client.get("/v1/metricsz").text
        second_body = render(collect(second))
    finally:
        second.close()

    for name in (
        "alerting_audit_entries",
        "alerting_schema_version",
        "alerting_canary_ok",
        "alerting_audit_spool_files",
    ):
        assert values(first_body, name + " ") == values(second_body, name + " "), name


# --- a broken collector must not take the endpoint down ----------------------


async def test_one_failing_collector_does_not_silence_the_rest(client, monkeypatch):
    """The one signal saying a node is unwell must not go quiet because part of it
    raised."""
    import alerting.server.metrics as metrics_module

    def explode(app):
        raise RuntimeError("collector is broken")

    monkeypatch.setattr(metrics_module, "_audit", explode)
    body = client.get("/v1/metricsz").text

    assert 'alerting_collector_failed{collector="audit"} 1' in body
    assert values(body, "alerting_schema_version "), "other collectors still ran"


# --- the exposition format itself --------------------------------------------


def test_labels_are_escaped():
    metric = Metric("t", 'help with "quotes"', "gauge", (Sample("t", 1, (("peer", 'a"b\\c'),)),))
    assert 't{peer="a\\"b\\\\c"} 1' in render([metric])


# --- replication -------------------------------------------------------------


async def test_an_unreadable_replication_lag_is_not_reported_as_zero(services):
    """ "Cannot see it" and "there is none" are different answers, and the gauge said
    the second one.

    PostgreSQL blanks the LSN columns of ``pg_stat_replication`` for a role that is
    neither a superuser nor a member of ``pg_read_all_stats``. The row is still
    there, one per streaming standby, with every number NULL. The collector wrapped
    that in ``COALESCE(..., 0)``, so a node with no permission to see replication
    published a steady ``alerting_replication_lag_bytes 0`` -- a dashboard reading
    perfectly healthy from a node that had measured nothing at all. On a system whose
    RPO is exactly this number, that is the worst kind of wrong.
    """
    from typing import Any

    class BlankedStats:
        """The pool, with `pg_stat_replication` redacted the way PostgreSQL redacts
        it for an unprivileged role."""

        def __init__(self, real: Any) -> None:
            self._real = real

        @contextlib.contextmanager
        def connection(self) -> Any:
            with self._real.connection() as connection:
                yield _Redacting(connection)

        def __getattr__(self, name: str) -> Any:
            return getattr(self._real, name)

    class _Redacting:
        def __init__(self, real: Any) -> None:
            self._real = real

        def execute(self, sql: str, *args: Any, **kwargs: Any) -> Any:
            if "pg_stat_replication" in sql:
                return _Rows([{"peer": "16/standby", "lag": None}])
            return self._real.execute(sql, *args, **kwargs)

        def __getattr__(self, name: str) -> Any:
            return getattr(self._real, name)

    class _Rows:
        def __init__(self, rows: list[dict[str, Any]]) -> None:
            self._rows = rows

        def fetchall(self) -> list[dict[str, Any]]:
            return self._rows

        def fetchone(self) -> dict[str, Any]:
            return self._rows[0]

    real = services.pool
    services.pool = BlankedStats(real)
    try:
        body = render(collect(services))
    finally:
        services.pool = real

    assert not values(body, "alerting_replication_lag_bytes{"), (
        "a lag nobody is permitted to read must not be published as a number"
    )
    assert "alerting_replication_lag_unknown 1" in body
    # The standby is still counted: it exists, and saying otherwise would hide it.
    assert "alerting_replication_standbys 1" in body
