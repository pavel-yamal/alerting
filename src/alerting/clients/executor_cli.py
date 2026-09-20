"""Executor client: enroll, listen, verify, acknowledge.

Everything that decides whether to raise the alarm happens here, against the pinned org
root key. The server's opinion is not consulted. That is the whole point: an executor
acts on an order because the people authorised to give it signed it, not because a
server said so.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import pathlib
import secrets
import sys
from typing import Any

import websockets

from alerting.clients.bundles import BundleCache, PinnedOrg
from alerting.clients.keystore import DEFAULT_DIR, load_key, save_key
from alerting.clients.transport import Api
from alerting.core.clock import SystemClock
from alerting.core.envelope import AckStatus, OrderPayload, SignedEnvelope
from alerting.core.errors import Reason
from alerting.core.receipts import build_ack
from alerting.core.signing import (
    DOMAIN_DEVICE_AUTH,
    generate_keypair,
    key_id,
    sign_payload,
)
from alerting.core.verify import Decision, verify_envelope
from alerting.core.wordcode import bucket_for, wake_code

CLOCK = SystemClock()

#: Plain-language rendering. An executor under stress reads words, not enum names.
REASON_TEXT: dict[Reason, str] = {
    Reason.BAD_SIGNATURE: "подпись не сходится",
    Reason.UNKNOWN_SIGNER: "подписал кто-то не из списка",
    Reason.REVOKED_SIGNER: "ключ подписавшего отозван",
    Reason.QUORUM_NOT_MET: "подписей меньше, чем требует политика",
    Reason.REPLAYED: "это повтор ранее полученного приказа",
    Reason.DRILL_MISMATCH: "учебный признак не совпадает с отменяемым приказом",
    Reason.UNKNOWN_SCENARIO: "сценарий отсутствует в кодовой книге",
    Reason.W_EXPIRED: "СРОК ИСТЁК — подтвердите голосом по номеру с карточки",
    Reason.W_OUT_OF_REPLAY_WINDOW: "номер вне окна — проверьте порядок приказов",
    Reason.W_STALE_DIRECTORY: "справочник ключей устарел",
    Reason.W_CLOCK_SKEW: "часы расходятся с сервером",
    Reason.CANCEL_TARGET_MISSING: "отменяемый приказ на этом устройстве не найден",
}


def describe(reason: Reason) -> str:
    return REASON_TEXT.get(reason, str(reason))


def cmd_enroll(args: argparse.Namespace, api: Api) -> int:
    """Generate a device key and pin the org root key.

    In a real enrollment the root key is read off a printed card or a QR code in
    person, against photo ID — never fetched from the server it is meant to check.
    """
    private, public = generate_keypair()
    passphrase = args.passphrase or getpass.getpass("New passphrase: ")
    save_key(args.person, private, passphrase, role="executor", directory=args.home)

    root = args.root_key
    if not root:
        root = input("Org root public key (from your enrollment card): ").strip()
    PinnedOrg(args.org, root, args.home).save()

    print(f"enrolled {args.person}")
    print(f"  key id : {key_id(public)}")
    print(f"  pinned : org={args.org} root={root[:16]}…")
    print("\nRead your key id back to the enrolling officer before you leave.")
    return 0


def cmd_sync(args: argparse.Namespace, api: Api) -> int:
    """Fetch the directory and policy and verify them against the pinned root key."""
    cache = BundleCache(PinnedOrg.load(args.home))
    directory = cache.accept("directory", api.get("/v1/directory"))
    policy = cache.accept("policy", api.get("/v1/policy"))
    print(f"directory v{directory.version}  policy {policy.policy_id} v{policy.version}")
    return 0


def render(decision: Decision, payload: dict[str, Any]) -> None:
    order = decision.payload
    banner = "УЧЕНИЕ" if decision.is_drill else "БОЕВОЕ"
    rule = "=" * 60
    print(f"\n{rule}\n  {banner}", end="")
    if order is not None:
        print(f"   {order.scenario}   [{order.severity}]   {order.action}")
        if order.text:
            print(f"\n  {order.text}")
        print(f"\n  подписали: {', '.join(decision.signer_persons) or '—'}")
        print(f"  приказ   : {order.order_id}")
    print(rule)

    if decision.rejected:
        print("  ОТКЛОНЕНО — не выполнять:")
        for reason in decision.reasons:
            print(f"    · {describe(reason)}")
    else:
        print("  ПОДЛИННЫЙ приказ")
    for warning in decision.warnings:
        print(f"  ! {describe(warning)}")
    print()


def verify_one(cache: BundleCache, envelope: dict[str, Any], cancel_target=None) -> Decision:
    window = cache.replay_window()
    decision = verify_envelope(
        SignedEnvelope.model_validate(envelope),
        directory=cache.directory(),
        policy=cache.policy(),
        clock=CLOCK,
        replay=window,
        org_id=cache.pin.org_id,
        seen_order_ids=cache.seen_order_ids(),
        cancel_target=cancel_target,
    )
    if decision.accepted and decision.payload is not None:
        window.commit(decision.payload.stream_id, decision.payload.seq)
        cache.save_replay(window)
        cache.remember_order(decision.payload.order_id)
    return decision


def cmd_verify(args: argparse.Namespace, api: Api) -> int:
    cache = BundleCache(PinnedOrg.load(args.home))
    envelope = (
        json.loads(pathlib.Path(args.file).read_text(encoding="utf-8"))
        if args.file
        else api.get(f"/v1/orders/{args.order_id}")
    )
    decision = verify_one(cache, envelope)
    render(decision, envelope["payload"])
    return 0 if decision.accepted else 1


def cmd_check_code(args: argparse.Namespace, api: Api) -> int:
    """Check the words from an SMS against the order in the app.

    This is the anti-phishing step, and it is the only thing an SMS is for.
    """
    cache = BundleCache(PinnedOrg.load(args.home))
    envelope = api.get(f"/v1/orders/{args.order_id}")
    order = OrderPayload.model_validate(envelope["payload"])

    # Unlocking the key proves it is this device's holder asking, and verifying the
    # order first means the words are only ever shown for a genuine order.
    load_key(
        args.person,
        args.passphrase or getpass.getpass("Passphrase: "),
        directory=args.home,
    )
    decision = verify_one(cache, envelope)
    if decision.rejected:
        render(decision, envelope["payload"])
        return 1

    wordlist = [
        line.strip()
        for line in pathlib.Path(args.wordlist).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    wake_key = bytes.fromhex(args.wake_key) if args.wake_key else b""
    expected = wake_code(
        wake_key,
        org_id=order.org_id,
        order_id=order.order_id,
        bucket=bucket_for(order.issued_at),
        wordlist=wordlist,
    )
    print(f"код для этого приказа: {'-'.join(expected)}")
    print("Если в SMS другие слова — это фишинг.")
    print("Приказ не выполнять, сообщить дежурному по номеру с карточки.")
    return 0


async def _listen(args: argparse.Namespace, api: Api) -> int:
    pin = PinnedOrg.load(args.home)
    cache = BundleCache(pin)
    stored = load_key(
        args.person,
        args.passphrase or getpass.getpass("Passphrase: "),
        directory=args.home,
    )

    async with websockets.connect(f"{api.ws_url}/v1/stream") as socket:
        challenge = json.loads(await socket.recv())
        payload = {
            "v": 1,
            "type": "device-auth",
            "org_id": pin.org_id,
            "person_id": stored.person_id,
            "key_id": stored.key_id,
            "nonce": challenge["nonce"],
            "at": CLOCK.now(),
        }
        await socket.send(
            json.dumps(
                {
                    "kind": "auth",
                    "payload": payload,
                    "sig": sign_payload(DOMAIN_DEVICE_AUTH, payload, stored.private_key),
                }
            )
        )
        ready = json.loads(await socket.recv())
        if ready.get("kind") != "ready":
            print(f"authentication refused: {ready}", file=sys.stderr)
            return 2
        print(f"listening as {stored.person_id}  (Ctrl-C to stop)")

        async for raw in socket:
            frame = json.loads(raw)
            if frame.get("kind") != "order":
                continue
            envelope = frame["envelope"]
            decision = verify_one(cache, envelope)
            render(decision, envelope["payload"])

            if not decision.accepted or decision.payload is None:
                continue
            ack = build_ack(
                order=decision.payload,
                order_payload_raw=envelope["payload"],
                person_id=stored.person_id,
                device_key_id=stored.key_id,
                status=AckStatus.RECEIVED,  # automatic; a human tap sends the rest
                at=CLOCK.now(),
                nonce=secrets.token_urlsafe(12),
                private_key=stored.private_key,
            )
            await socket.send(
                json.dumps(
                    {
                        "kind": "ack",
                        "payload": ack.payload,
                        "signature": ack.signature.model_dump(mode="json"),
                    }
                )
            )
    return 0


def cmd_listen(args: argparse.Namespace, api: Api) -> int:
    try:
        return asyncio.run(_listen(args, api))
    except KeyboardInterrupt:
        return 0


def cmd_ack(args: argparse.Namespace, api: Api) -> int:
    envelope = api.get(f"/v1/orders/{args.order_id}")
    order = OrderPayload.model_validate(envelope["payload"])
    stored = load_key(
        args.person,
        args.passphrase or getpass.getpass("Passphrase: "),
        directory=args.home,
    )
    ack = build_ack(
        order=order,
        order_payload_raw=envelope["payload"],
        person_id=stored.person_id,
        device_key_id=stored.key_id,
        status=AckStatus(args.status),
        at=CLOCK.now(),
        nonce=secrets.token_urlsafe(12),
        private_key=stored.private_key,
        reason=args.reason,
    )
    result = api.post(
        "/v1/acks",
        {"payload": ack.payload, "signature": ack.signature.model_dump(mode="json")},
    )
    print("accepted" if result["accepted"] else f"rejected: {result['reasons']}")
    return 0 if result["accepted"] else 1


def common_parser() -> argparse.ArgumentParser:
    """Shared options, attached to each subcommand so they can follow it on the
    command line — which is how people actually type them."""
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--server", default="http://127.0.0.1:8080")
    shared.add_argument("--home", type=pathlib.Path, default=DEFAULT_DIR)
    shared.add_argument("--person", default="", help="your person id")
    shared.add_argument("--passphrase", help="key passphrase (prompted if omitted)")
    return shared


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="alerting-executor")
    shared = common_parser()
    sub = parser.add_subparsers(dest="command", required=True)

    enroll = sub.add_parser(
        "enroll", parents=[shared], help="generate a device key and pin the org root"
    )
    enroll.add_argument("--org", default="acme")
    enroll.add_argument("--root-key", default="")
    enroll.set_defaults(func=cmd_enroll)

    sync = sub.add_parser(
        "sync", parents=[shared], help="fetch and verify the directory and policy"
    )
    sync.set_defaults(func=cmd_sync)

    listen = sub.add_parser("listen", parents=[shared], help="receive and verify orders")
    listen.set_defaults(func=cmd_listen)

    verify = sub.add_parser("verify", parents=[shared], help="verify one order")
    verify.add_argument("order_id", nargs="?", default="")
    verify.add_argument("--file", help="verify an envelope from a file instead")
    verify.set_defaults(func=cmd_verify)

    code = sub.add_parser(
        "check-code", parents=[shared], help="check SMS wake words against the order"
    )
    code.add_argument("order_id")
    code.add_argument("--wake-key", default="", help="hex, provisioned at enrollment")
    code.add_argument("--wordlist", default="config/wordlist.ru.txt")
    code.set_defaults(func=cmd_check_code)

    ack = sub.add_parser("ack", parents=[shared], help="acknowledge an order")
    ack.add_argument("order_id")
    ack.add_argument(
        "--status",
        default="acknowledged",
        choices=["acknowledged", "en_route", "completed", "cannot_comply"],
    )
    ack.add_argument("--reason", default=None, help="required for cannot_comply")
    ack.set_defaults(func=cmd_ack)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    with Api(args.server) as api:
        try:
            result: int = args.func(args, api)
            return result
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
