#!/usr/bin/env python3
"""The whole story end to end, in one process, on a deterministic clock.

Run it after ``make org-init``. It walks through: a proposal that one approver cannot
launch, a second signature that does, fan-out across channels, the executor's own
verification against the pinned root key, an acknowledgement, escalation for the person
who stayed silent, a stand-down, and a verified audit chain.

Then it shows the three attacks the design is actually built against, and the one it
cannot stop.
"""

from __future__ import annotations

import asyncio
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from alerting.core.clock import FixedClock
from alerting.core.directory import Directory, DirectoryPayload, KeyEntry
from alerting.core.envelope import AckStatus, Audience, Severity
from alerting.core.policy import Policy
from alerting.core.receipts import build_ack
from alerting.core.replay import ReplayWindow
from alerting.core.signing import (
    DOMAIN_DIRECTORY,
    generate_keypair,
    key_id,
    private_key_to_b64u,
    public_key_to_b64u,
)
from alerting.core.signing import (
    public_key_to_b64u as _pk,
)
from alerting.core.verify import verify_envelope
from alerting.core.wordcode import bucket_for, wake_code
from alerting.orgkit import build_org, make_order, sign_bundle, sign_order
from alerting.server.app import AppServices
from alerting.server.config import Settings
from alerting.server.services.bootstrap import publish_org

AT = 1_700_000_000
RULE = "─" * 74


def step(number: str, title: str) -> None:
    print(f"\n{RULE}\n {number}  {title}\n{RULE}")


async def main() -> int:
    tmp = pathlib.Path("var/demo")
    tmp.mkdir(parents=True, exist_ok=True)
    db = tmp / "demo.db"
    if db.exists():
        db.unlink()

    clock = FixedClock(AT)
    org = build_org(issued_at=AT)
    settings = Settings(
        org_id=org.org_id,
        db_path=str(db),
        root_public_key=public_key_to_b64u(org.root_public_key),
        heads_dir=tmp / "heads",
        spool_dir=tmp / "spool",
    )
    server_private, _ = generate_keypair()
    settings.server_private_key = private_key_to_b64u(server_private)
    services = AppServices(settings, clock)
    publish_org(services.repo, org, audit=services.audit)

    def client_view():
        """Exactly what an executor's device holds: the pinned root key, nothing else."""
        return (
            Directory.load(
                services.state.directory_bundle,
                root_public_key=org.root_public_key,
                org_id=org.org_id,
            ),
            Policy.load(
                services.state.policy_bundle,
                root_public_key=org.root_public_key,
                org_id=org.org_id,
            ),
        )

    step("1", "Кто может отдать приказ")
    policy = services.state.policy()
    for severity in ("warning", "critical", "catastrophic"):
        rule = policy.rule_for(Severity(severity), is_cancel=False)
        cancel = policy.rule_for(Severity(severity), is_cancel=True)
        print(f"  {severity:<14} запуск: {rule.m} подпис(и)   отбой: {cancel.m}")
    print("\n  Отбой требует меньше подписей, чем запуск: безопасное направление —")
    print("  остановка. Эвакуация не должна идти лишние 20 минут потому, что")
    print("  второй директор в самолёте.")

    step("2", "Один руководитель не может запустить критический приказ")
    order = make_order(
        org,
        issued_at=clock.now(),
        severity=Severity.CRITICAL,
        scenario="EVAC.BUILDING",
        drill=False,
        audience=Audience(groups=("fire-wardens",)),
        text="Задымление, 3 этаж, восточное крыло",
    )
    one = await services.dispatcher.dispatch(sign_order(order, [org.person("p-001")]))
    print(f"  подписал только {org.person('p-001').name}")
    print(f"  результат: ОТКАЗ — {[str(r) for r in one.decision.reasons]}")

    step("3", "Двое — могут")
    envelope = sign_order(order, [org.person("p-001"), org.person("p-002")])
    # No siren on the first pass: it is the last rung of the ladder, not the first.
    result = await services.dispatcher.dispatch(envelope, channels=("ws", "push", "sms"))
    print(f"  подписали: {', '.join(result.decision.signer_persons)}")
    print(f"  разослано: {', '.join(result.recipients)}")
    for receipt in result.receipts:
        print(
            f"    {receipt.channel:<6} {receipt.person_id:<7} {receipt.status:<8} {receipt.detail}"
        )

    step("4", "Что видит исполнитель — и что он проверяет сам")
    directory, policy = client_view()
    decision = verify_envelope(
        envelope,
        directory=directory,
        policy=policy,
        clock=clock,
        replay=ReplayWindow(),
        org_id=org.org_id,
    )
    print(f"  подлинность : {'ПОДТВЕРЖДЕНА' if decision.accepted else 'ОТКАЗ'}")
    print(f"  учебный?    : {'УЧЕНИЕ' if decision.is_drill else 'БОЕВОЕ'}")
    print(f"  подписали   : {', '.join(decision.signer_persons)}")
    print("\n  Проверка сделана только по корневому ключу, закреплённому при")
    print("  регистрации. Мнение сервера не спрашивали.")

    step("5", "SMS — это звонок в дверь, а не приказ")
    sms = services.channels["sms"]
    phone, text = sms.sent[0]
    print(f"  на {phone}:")
    for line in text.splitlines():
        print(f"    │ {line}")
    ivanov, petrova = org.person("x-101"), org.person("x-102")
    args = dict(
        org_id=org.org_id,
        order_id=order.order_id,
        bucket=bucket_for(order.issued_at),
        wordlist=services.state.wordlist,
    )
    print(f"\n  код Иванова : {'-'.join(wake_code(ivanov.wake_key, **args))}")
    print(f"  код Петровой: {'-'.join(wake_code(petrova.wake_key, **args))}")
    print("\n  Коды разные. Перехватив SMS Иванова, фишер не вычислит код Петровой,")
    print("  а по самому SMS всё равно нельзя действовать — только открыть приложение.")

    step("6", "Подтверждение — подписанная расписка")
    ack = build_ack(
        order=order,
        order_payload_raw=envelope.payload,
        person_id=ivanov.person_id,
        device_key_id=ivanov.key_id,
        status=AckStatus.EN_ROUTE,
        at=clock.now() + 20,
        nonce="demo-ack",
        private_key=ivanov.private_key,
    )
    services.repo.record_ack(
        order.order_id,
        ivanov.person_id,
        ivanov.key_id,
        "en_route",
        clock.now() + 20,
        ack.model_dump(mode="json"),
        True,
    )
    status = services.dispatcher.status(order.order_id)
    print(f"  подтвердили: {status['acknowledged']} из {len(status['people'])}")
    print(f"  молчат     : {', '.join(status['outstanding'])}")
    print("  order_digest в расписке фиксирует, какой именно текст видел исполнитель.")

    step("7", "Эскалация для того, кто молчит")
    for advance, label in ((70, "через 70 с"), (130, "через 200 с"), (450, "через 650 с")):
        clock.advance(advance)
        await services.escalation.tick()
        print(
            f"  {label:<14} SMS: {len(sms.sent)}  "
            f"звонков: {len(services.channels['voice'].calls)}  "
            f"сирена: {len(services.channels['siren'].activations)}"
        )
    print("\n  Обычный отказ — не подделка, а телефон на беззвучном. Лестница")
    print("  эскалации в будни ценнее подписей.")

    step("8", "Отбой одной подписью")
    cancel = make_order(
        org,
        issued_at=clock.now(),
        seq=order.seq + 1,
        order_type="cancel",
        cancels=order.order_id,
        action="STOP",
        audience=Audience(groups=("fire-wardens",)),
        text="Отбой, очаг ликвидирован",
    )
    cancel_result = await services.dispatcher.dispatch(
        sign_order(cancel, [org.person("p-003")]), channels=("ws", "sms")
    )
    print(f"  отбой дал: {', '.join(cancel_result.decision.signer_persons)} — видно на экране")
    print(f"  принят   : {cancel_result.accepted}")
    print("  Исходный приказ не стёрт. Исполнителя учат: отбой не отменяет то,")
    print("  что он видит своими глазами.")

    step("9", "Три атаки, от которых это защищает")
    directory, policy = client_view()

    forged_sk, forged_pk = generate_keypair()
    from alerting.orgkit import Person

    attacker = Person("evil", "Атакующий", "director", forged_sk, key_id(forged_pk))
    forged = sign_order(make_order(org, issued_at=clock.now(), seq=900), [attacker])
    verdict = verify_envelope(
        forged,
        directory=directory,
        policy=policy,
        clock=clock,
        replay=ReplayWindow(),
        org_id=org.org_id,
    )
    print(f"  подделка подписи        → {[str(r) for r in verdict.reasons]}")

    window = ReplayWindow()
    window.commit(order.stream_id, order.seq)
    verdict = verify_envelope(
        envelope,
        directory=directory,
        policy=policy,
        clock=clock,
        replay=window,
        org_id=org.org_id,
    )
    print(f"  повтор старого приказа  → {[str(r) for r in verdict.reasons]}")

    evil_root, _ = generate_keypair()
    payload = DirectoryPayload.model_validate(services.state.directory_bundle["payload"])
    injected = payload.model_copy(
        update={
            "version": 99,
            "keys": (
                *payload.keys,
                KeyEntry(
                    key_id=attacker.key_id,
                    public_key=_pk(forged_pk),
                    person_id="evil",
                    name="Атакующий",
                    role="director",
                    valid_from=AT - 3600,
                ),
            ),
        }
    )
    try:
        Directory.load(
            sign_bundle(injected, DOMAIN_DIRECTORY, evil_root),
            root_public_key=org.root_public_key,
            org_id=org.org_id,
        )
        print("  взломанный сервер       → ПРИНЯТО (это была бы дыра!)")
    except Exception as exc:
        print(f"  взломанный сервер       → {exc}")
        print("    (сервер подсунул свой ключ в справочник — клиент отверг его,")
        print("     потому что бандл не подписан закреплённым корнем организации)")

    step("10", "Чего это НЕ останавливает")
    print("  Взломанный сервер всё ещё может ЗАДЕРЖАТЬ или ПОДАВИТЬ оповещение")
    print("  и соврать на дашборде. Криптография этого не ловит.")
    print("  Ловят: heartbeat по каналам, эскалация, подписанные расписки и")
    print("  напечатанный резервный порядок (телефонное дерево + пара «вызов-отзыв»).")

    step("11", "Аудит")
    entries = list(services.repo.audit_entries(0, 10_000))
    from alerting.core.audit_chain import head_of

    services.audit.publish_head(len(entries) - 1, head_of(entries), clock.now())
    verdict = services.audit.verify()
    print(f"  записей в цепочке: {len(entries)}")
    state = "ЦЕЛА" if verdict.ok else f"НАРУШЕНА на {verdict.failed_index}"
    print(f"  проверка         : {state}")

    blob = str(entries)
    leaked = [p.name for p in org.people.values() if p.name in blob]
    print(f"  персональных данных в цепочке: {leaked or 'нет'}")
    print("  Цепочка принципиально неудаляема, поэтому в ней только псевдонимы,")
    print("  а сопоставление с личностью — в отдельной удаляемой таблице.")

    print(f"\n{RULE}")
    print(f" Готово. База: {db}")
    print(" Проверить аудит независимо:")
    print(f"   .venv/bin/python -m alerting.clients.auditor_cli report --db {db}")
    print(RULE)
    services.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
