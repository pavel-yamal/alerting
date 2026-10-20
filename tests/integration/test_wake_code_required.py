"""SMS and voice must refuse to send without a wake code.

The training line is "a genuine message always carries your code". Sending one without
makes that line false and teaches people to accept codeless SMS — which is exactly the
phishing hole the code exists to close. The adapters used to substitute "—" and send
anyway, silently.
"""

from __future__ import annotations

import logging

import pytest

from alerting.core.envelope import Audience
from alerting.orgkit import make_order, sign_order
from alerting.server.channels.base import NoWakeCode

pytestmark = pytest.mark.asyncio


async def dispatch(services, org, clock, channels):
    order = make_order(org, issued_at=clock.now(), audience=Audience(groups=("fire-wardens",)))
    result = await services.dispatcher.dispatch(
        sign_order(order, [org.person("p-001"), org.person("p-002")]), channels=channels
    )
    assert result.accepted, result.decision.reasons
    return result


async def test_no_wordlist_means_no_sms_at_all(services, org, clock, caplog):
    caplog.set_level(logging.ERROR, logger="alerting.channel.sms")
    services.state.wordlist = []

    result = await dispatch(services, org, clock, ("sms",))

    assert services.channels["sms"].sent == [], "nothing may go out without a code"
    assert all(r.status == "failed" for r in result.receipts)
    assert all("no wake code" in r.detail for r in result.receipts)
    assert "would falsify the training" in caplog.text


async def test_a_person_without_a_wake_key_gets_no_sms(services, org, clock):
    services.repo.upsert_contact(
        "x-101",
        name=org.person("x-101").name,
        phone=org.person("x-101").phone,
        site="hq",
        groups=("fire-wardens",),
        wake_key="",  # never enrolled for wake codes
    )

    result = await dispatch(services, org, clock, ("sms",))
    by_person = {r.person_id: r for r in result.receipts}

    assert by_person["x-101"].status == "failed"
    assert by_person["x-102"].status == "stub", "the enrolled person still gets one"
    assert len(services.channels["sms"].sent) == 1


async def test_voice_refuses_the_same_way(services, org, clock):
    services.state.wordlist = []
    result = await dispatch(services, org, clock, ("voice",))

    assert services.channels["voice"].calls == []
    assert all(r.status == "failed" for r in result.receipts)


async def test_render_raises_rather_than_returning_a_codeless_message(services, org, clock):
    from alerting.server.channels.base import DispatchContext, Recipient

    order = make_order(org, issued_at=clock.now())
    context = DispatchContext(envelope={}, order=order, wordlist=[])
    recipient = Recipient(person_id="x-101", phone="+70000000000", wake_key=b"")

    with pytest.raises(NoWakeCode):
        services.channels["sms"].render(recipient, context)


async def test_the_sms_body_and_code_never_reach_the_log(services, org, clock, caplog):
    """Logs are less protected than the database, and the code is the secret that
    authenticates the message."""
    caplog.set_level(logging.INFO, logger="alerting.channel.sms")
    await dispatch(services, org, clock, ("sms",))

    sent_bodies = [text for _, text in services.channels["sms"].sent]
    assert sent_bodies
    for body in sent_bodies:
        code_line = next(line for line in body.splitlines() if line.startswith("Код:"))
        code = code_line.removeprefix("Код:").strip()
        assert code not in caplog.text, "the wake code must not be logged"
    assert "chars)" in caplog.text, "length is logged instead of the body"
