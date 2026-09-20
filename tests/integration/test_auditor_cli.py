"""The auditor's independent check, including against a tampered database."""

from __future__ import annotations

import json

import pytest

from alerting.clients.auditor_cli import main
from alerting.core.audit_chain import head_of
from alerting.core.envelope import Audience
from alerting.orgkit import make_order, sign_order

pytestmark = pytest.mark.asyncio


async def incident(services, org, clock):
    order = make_order(org, issued_at=clock.now(), audience=Audience(groups=("fire-wardens",)))
    await services.dispatcher.dispatch(
        sign_order(order, [org.person("p-001"), org.person("p-002")]),
        channels=("ws", "sms"),
    )
    return order


async def test_verify_passes_on_an_intact_chain(services, org, clock, owner_dsn, capsys):
    await incident(services, org, clock)
    assert main(["verify", "--dsn", owner_dsn]) == 0
    assert "chain intact" in capsys.readouterr().out


async def test_verify_fails_at_the_right_index_after_a_direct_edit(
    services, org, clock, owner_dsn, owner_conn, capsys
):
    """Someone with database access edits a row. The triggers stop UPDATE, so they
    have to drop them first — which is exactly the scenario the chain is for."""
    await incident(services, org, clock)
    # Two layers have to be defeated, and the test defeats both on purpose. The
    # server's own role cannot UPDATE this table at all (see test_append_only.py);
    # only the owner can, and only after dropping the trigger.
    owner_conn.execute("DROP TRIGGER audit_log_no_update ON audit_log")
    owner_conn.execute(
        "UPDATE audit_log SET data_json = %s WHERE idx = 3",
        ('{"order_id": "substituted"}',),
    )

    assert main(["verify", "--dsn", owner_dsn]) == 1
    captured = capsys.readouterr()
    assert "FAILED at entry 3" in captured.err


async def test_verify_detects_a_truncated_tail_against_a_published_head(
    services, org, clock, owner_dsn, owner_conn, capsys
):
    await incident(services, org, clock)
    entries = list(services.repo.audit_entries(0, 10_000))
    services.audit.publish_head(len(entries) - 1, head_of(entries), clock.now())
    owner_conn.execute("DROP TRIGGER audit_log_no_delete ON audit_log")
    owner_conn.execute("DELETE FROM audit_log WHERE idx >= %s", (len(entries) - 2,))

    assert main(["verify", "--dsn", owner_dsn]) == 1
    assert "published head" in capsys.readouterr().err


async def test_verify_says_so_when_there_are_no_heads_to_check_against(
    services, org, clock, owner_dsn, capsys
):
    """Honesty about the gap: without a published head, a rewritten tail is
    undetectable, and the tool says that rather than printing a bare OK."""
    await incident(services, org, clock)
    main(["verify", "--dsn", owner_dsn, "--ignore-heads"])
    assert "rewritten tail is undetectable" in capsys.readouterr().out


async def test_report_reconstructs_the_timeline(services, org, clock, owner_dsn, capsys):
    order = await incident(services, org, clock)

    assert main(["report", "--dsn", owner_dsn, "--order-id", order.order_id]) == 0
    out = capsys.readouterr().out
    assert "order.dispatched" in out
    assert "quorum.met" in out
    assert order.order_id in out


async def test_pull_writes_a_self_contained_chain(services, org, clock, owner_dsn, tmp_path):
    await incident(services, org, clock)
    target = tmp_path / "chain.json"

    assert main(["pull", "--dsn", owner_dsn, "--out", str(target)]) == 0
    blob = json.loads(target.read_text(encoding="utf-8"))
    assert blob["entries"]
    assert main(["verify", "--file", str(target)]) == 0


async def test_report_flags_a_rapid_relaunch_after_a_stand_down(
    services, org, clock, owner_dsn, capsys
):
    """A launch -> cancel -> launch cycle inside ten minutes is what a coerced or
    mistaken stand-down looks like, so it is surfaced for a human to look at."""
    order = await incident(services, org, clock)
    cancel = make_order(
        org,
        issued_at=clock.now(),
        seq=order.seq + 1,
        order_type="cancel",
        cancels=order.order_id,
        action="STOP",
        audience=Audience(groups=("fire-wardens",)),
    )
    await services.dispatcher.dispatch(sign_order(cancel, [org.person("p-003")]))

    clock.advance(60)
    await incident(services, org, clock)

    main(["report", "--dsn", owner_dsn])
    assert "rapid launch/cancel/launch" in capsys.readouterr().out
