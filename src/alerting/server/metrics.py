"""Metrics exposition, computed at scrape time.

Two decisions shape this file, and both are about being correct rather than
conventional.

**Every value is derived from shared state when asked, not accumulated in the
process.** The unit runs ``--workers 2``. In-process counters would give two
different answers depending on which worker the scrape reached, which is the same
class of mistake phase 3 moved out of memory and into tables. That is also why there
is no metrics library here: a library's registries and histograms are exactly the
thing that would be per-process and therefore wrong. The cost is a handful of
queries per scrape; the benefit is that the number means something.

**Aggregates only. No series per person.** No ``person_id``, no names, no phone
numbers, no roster. That constraint is what lets this endpoint sit on the public
router behind an nginx IP allowlist, like liveness and readiness. ``/v1/statusz``,
which does name the people currently connected and calls that a roster leak in its
own docstring, stays behind the signature gate.

The exposition is written by hand -- it is a few dozen lines of a simple text format,
and hand-writing it is cheaper than a dependency that would have to be audited and
kept current for a system whose whole point is that its dependencies are few.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from alerting.core.metrics import MAIN_METRIC_SHARE, ack_timing, order_ids

log = logging.getLogger("alerting.metrics")

#: How many recent orders the main metric is reported for. A scrape has to be cheap
#: and bounded; the trend lives in whatever scrapes this, not here.
RECENT_ORDERS = 20


@dataclass(frozen=True)
class Sample:
    name: str
    value: float | int
    labels: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Metric:
    name: str
    help_text: str
    kind: str  # gauge | counter
    samples: tuple[Sample, ...]


def render(metrics: Iterable[Metric]) -> str:
    """Prometheus text exposition, format 0.0.4."""
    lines: list[str] = []
    for metric in metrics:
        lines.append(f"# HELP {metric.name} {metric.help_text}")
        lines.append(f"# TYPE {metric.name} {metric.kind}")
        for sample in metric.samples:
            labels = ""
            if sample.labels:
                inner = ",".join(f'{key}="{_escape(value)}"' for key, value in sample.labels)
                labels = "{" + inner + "}"
            lines.append(f"{metric.name}{labels} {_number(sample.value)}")
    return "\n".join(lines) + "\n"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _number(value: float | int) -> str:
    return str(int(value)) if isinstance(value, int) else repr(value)


def collect(app: Any) -> list[Metric]:
    """Everything worth scraping, read fresh. Never raises: a broken collector must
    not take the endpoint down, or the one signal saying the node is unwell goes
    quiet at exactly the wrong moment."""
    metrics: list[Metric] = []
    for name, build in (
        ("schema", _schema),
        ("audit", _audit),
        ("orders", _orders),
        ("main_metric", _main_metric),
        ("channels", _channels),
        ("escalation", _escalation),
        ("canary", _canary),
        ("spool", _spool),
        ("replication", _replication),
    ):
        try:
            metrics.extend(build(app))
        except Exception:
            log.warning("metrics collector %s failed", name, exc_info=True)
            metrics.append(
                Metric(
                    "alerting_collector_failed",
                    "1 when a metrics collector raised; the scrape is incomplete.",
                    "gauge",
                    (Sample("alerting_collector_failed", 1, (("collector", name),)),),
                )
            )
    return metrics


def _schema(app: Any) -> list[Metric]:
    from alerting.server.db import migrate

    with app.pool.connection() as connection:
        version = migrate.schema_version(connection)
    return [
        Metric(
            "alerting_schema_version",
            "Applied database schema version.",
            "gauge",
            (Sample("alerting_schema_version", version),),
        ),
        Metric(
            "alerting_schema_expected_version",
            "Schema version this build was written against.",
            "gauge",
            (Sample("alerting_schema_expected_version", migrate.expected_version()),),
        ),
    ]


def _audit(app: Any) -> list[Metric]:
    now = app.clock.now()
    count = app.repo.audit_count()
    head = app.repo.latest_head()
    head_age = now - int(head["ts"]) if head else -1
    return [
        Metric(
            "alerting_audit_entries",
            "Entries in the hash-chained audit log.",
            "counter",
            (Sample("alerting_audit_entries", count),),
        ),
        Metric(
            "alerting_audit_head_age_seconds",
            "Seconds since the last published audit head; -1 when none was ever "
            "published. A head that stops being produced is tamper-evidence that "
            "stopped being produced.",
            "gauge",
            (Sample("alerting_audit_head_age_seconds", head_age),),
        ),
    ]


def _orders(app: Any) -> list[Metric]:
    rows = app.repo.order_counts()
    samples = tuple(
        Sample(
            "alerting_orders",
            int(row["n"]),
            (("severity", row["severity"]), ("drill", "true" if row["drill"] else "false")),
        )
        for row in rows
    )
    return [
        Metric(
            "alerting_orders",
            "Orders recorded, by severity and drill flag.",
            "counter",
            samples,
        )
    ]


def _main_metric(app: Any) -> list[Metric]:
    """Median and 90%-acknowledged for recent orders.

    Per order, not averaged: a drill with eight people and one with eight hundred are
    not the same measurement, and one number over both hides the trend this exists to
    show. Orders the chain cannot answer for are simply absent rather than zero.
    """
    entries = list(app.repo.audit_entries(0, 100_000))
    median: list[Sample] = []
    share: list[Sample] = []
    unknown = 0

    for order_id in order_ids(entries)[-RECENT_ORDERS:]:
        timing = ack_timing(entries, order_id)
        drill = ("drill", "true" if timing.drill else "false")
        if timing.median_s is not None:
            median.append(Sample("alerting_ack_median_seconds", timing.median_s, (drill,)))
        if timing.share_s is not None:
            share.append(Sample("alerting_ack_share_seconds", timing.share_s, (drill,)))
        else:
            unknown += 1

    return [
        Metric(
            "alerting_ack_median_seconds",
            "Median seconds from quorum to an acknowledgement, per recent order.",
            "gauge",
            tuple(median),
        ),
        Metric(
            "alerting_ack_share_seconds",
            f"Seconds from quorum until {int(MAIN_METRIC_SHARE * 100)}% of recipients "
            "acknowledged -- the metric docs/06 §9 and docs/07 §2 call the main one.",
            "gauge",
            tuple(share),
        ),
        Metric(
            "alerting_ack_share_unknown",
            "Recent orders for which the share was not reached or cannot be computed.",
            "gauge",
            (Sample("alerting_ack_share_unknown", unknown),),
        ),
    ]


def _channels(app: Any) -> list[Metric]:
    health = app.heartbeat.health()
    healthy = tuple(
        Sample("alerting_channel_healthy", int(entry["healthy"]), (("channel", name),))
        for name, entry in sorted(health.items())
    )
    stale = tuple(
        Sample("alerting_channel_stale", int(entry["stale"]), (("channel", name),))
        for name, entry in sorted(health.items())
    )
    return [
        Metric(
            "alerting_channel_healthy",
            "1 when some node reached this channel recently. A channel with no "
            "provider behind it reports 0, because a stub is not health.",
            "gauge",
            healthy,
        ),
        Metric(
            "alerting_channel_stale",
            "1 when nothing has been RECORDED for this channel recently -- the "
            "heartbeat itself stopped, which is worse than a dead channel.",
            "gauge",
            stale,
        ),
    ]


def _escalation(app: Any) -> list[Metric]:
    leader = app.escalation.leader
    return [
        Metric(
            "alerting_escalation_leader",
            "1 on the node currently holding the escalation lock. Exactly one node "
            "in a healthy cluster; zero for longer than a tick means nobody is "
            "climbing ladders.",
            "gauge",
            (Sample("alerting_escalation_leader", int(bool(leader and leader.held()))),),
        ),
        Metric(
            "alerting_escalation_worker_healthy",
            "1 when this node's escalation worker is alive or deliberately not "
            "running; 0 when it started and died.",
            "gauge",
            (
                Sample(
                    "alerting_escalation_worker_healthy",
                    int(app.escalation.is_healthy()),
                ),
            ),
        ),
    ]


def _canary(app: Any) -> list[Metric]:
    """Whether a drill order could actually be sent, and how long ago it was tried.

    The age matters as much as the outcome: a canary that stopped running says
    nothing about delivery, and "last run succeeded" from six hours ago is not the
    same claim as "succeeded ten minutes ago".
    """
    now = app.clock.now()
    run = app.repo.latest_canary_run()
    ok = int(bool(run and run["ok"]))
    age = now - int(run["started_at"]) if run else -1
    return [
        Metric(
            "alerting_canary_ok",
            "1 when the last delivery canary reached the canary recipient.",
            "gauge",
            (Sample("alerting_canary_ok", ok),),
        ),
        Metric(
            "alerting_canary_age_seconds",
            "Seconds since the last canary ran; -1 when it has never run. Stale is a "
            "different problem from failing: it means nothing is being measured.",
            "gauge",
            (Sample("alerting_canary_age_seconds", age),),
        ),
    ]


def _spool(app: Any) -> list[Metric]:
    spool = app.settings.spool_dir
    files = 0
    if spool is not None and spool.exists():
        files = sum(1 for path in spool.iterdir() if path.is_file())
    return [
        Metric(
            "alerting_audit_spool_files",
            "Files in the audit spool. Non-zero means audit writes were failing and "
            "those entries are not in the chain.",
            "gauge",
            (Sample("alerting_audit_spool_files", files),),
        )
    ]


def _replication(app: Any) -> list[Metric]:
    """Replication lag in bytes, which is the RPO indicator.

    Replication is asynchronous on purpose (ADR 0009): a node that stopped
    dispatching because a replica was down would be the worst failure this system
    has. The price is that a failover can lose the tail, and this number is how much
    could be lost right now.
    """
    with app.pool.connection() as connection:
        recovery = connection.execute("SELECT pg_is_in_recovery() AS r").fetchone()["r"]
        rows: Sequence[Any] = []
        if not recovery:
            rows = connection.execute(
                "SELECT COALESCE(application_name, client_addr::text, 'standby') AS peer,"
                " COALESCE(pg_wal_lsn_diff(sent_lsn, replay_lsn), 0) AS lag"
                " FROM pg_stat_replication"
            ).fetchall()

    return [
        Metric(
            "alerting_database_in_recovery",
            "1 when this node's database is a standby. A node pointed at one cannot "
            "dispatch and must report itself not ready.",
            "gauge",
            (Sample("alerting_database_in_recovery", int(bool(recovery))),),
        ),
        Metric(
            "alerting_replication_lag_bytes",
            "WAL bytes a standby has received but not replayed -- how much a "
            "failover could lose right now. Replication is asynchronous by design.",
            "gauge",
            tuple(
                Sample(
                    "alerting_replication_lag_bytes",
                    int(row["lag"]),
                    (("peer", str(row["peer"])),),
                )
                for row in rows
            ),
        ),
        Metric(
            "alerting_replication_standbys",
            "Standbys currently streaming from this node.",
            "gauge",
            (Sample("alerting_replication_standbys", len(rows)),),
        ),
    ]
