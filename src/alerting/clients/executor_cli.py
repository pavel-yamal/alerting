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
import os
import pathlib
import secrets
import sys
from typing import Any

import websockets

from alerting.clients.bundles import BundleCache, PinnedOrg
from alerting.clients.keystore import DEFAULT_DIR, StoredKey, save_key
from alerting.clients.session import open_api, unlock
from alerting.clients.transport import Api
from alerting.core.clock import Clock, SystemClock
from alerting.core.envelope import AckStatus, OrderPayload, SignedEnvelope
from alerting.core.errors import Reason
from alerting.core.receipts import build_ack
from alerting.core.replay import ReplayWindow
from alerting.core.signing import (
    DOMAIN_DEVICE_AUTH,
    generate_keypair,
    key_id,
    public_key_to_b64u,
    sign_payload,
)
from alerting.core.verify import Decision, verify_envelope
from alerting.core.wordcode import bucket_for, wake_code
from alerting.wordlist import load_wordlist

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


def cmd_enroll(args: argparse.Namespace) -> int:
    """Generate a device key and pin the org root key.

    In a real enrollment the root key is read off a printed card or a QR code in
    person, against photo ID — never fetched from the server it is meant to check.
    """
    private, public = generate_keypair()
    passphrase = args.passphrase or getpass.getpass("New passphrase: ")
    save_key(args.person, private, passphrase, role=args.role, directory=args.home)

    root = args.root_key
    if not root:
        root = input("Org root public key (from your enrollment card): ").strip()
    PinnedOrg(args.org, root, args.home).save()
    if args.wake_key:
        # The registrar's `alerting-org contact set` generated it; the server holds
        # the same key to derive this person's SMS words.
        bytes.fromhex(args.wake_key)
        path = args.home / "wake_key.hex"
        path.write_text(args.wake_key, encoding="utf-8")
        path.chmod(0o600)

    print(f"enrolled {args.person}")
    print(f"  public key : {public_key_to_b64u(public)}")
    print(f"  key id     : {key_id(public)}")
    print(f"  pinned     : org={args.org} root={root[:16]}…")
    print("\nGive the public key to the enrolling officer (QR or read aloud), then check")
    print("that the key id above appears in the published directory before you leave.")
    return 0


def cmd_sync(args: argparse.Namespace, api: Api, stored: StoredKey) -> int:
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


def verify_one(
    cache: BundleCache,
    envelope: dict[str, Any],
    cancel_target=None,
    *,
    reinspect: bool = False,
    clock: Clock | None = None,
) -> Decision:
    """Verify an envelope; record it as seen unless this is a re-inspection.

    ``reinspect`` exists for looking at an order the device already holds — checking
    the SMS wake words against it, or re-reading it. That is a local action, not a new
    delivery, so it must not be judged as a replay: the anti-phishing comparison is
    needed most in the ordinary flow where the listener already received the order,
    and treating it as a duplicate would make the check unavailable exactly then.
    Replay state is left untouched in that mode.
    """
    window = cache.replay_window()
    decision = verify_envelope(
        SignedEnvelope.model_validate(envelope),
        directory=cache.directory(),
        policy=cache.policy(),
        # Resolved here, not as the parameter default: a default would freeze the
        # module clock at import time and stop anything that swaps it.
        clock=clock or CLOCK,
        replay=ReplayWindow() if reinspect else window,
        org_id=cache.pin.org_id,
        seen_order_ids=() if reinspect else cache.seen_order_ids(),
        cancel_target=cancel_target,
    )
    if reinspect:
        return decision
    if decision.accepted and decision.payload is not None:
        window.commit(decision.payload.stream_id, decision.payload.seq)
        cache.save_replay(window)
        cache.remember_order(decision.payload.order_id)
    return decision


def cmd_verify(args: argparse.Namespace, api: Api, stored: StoredKey) -> int:
    cache = BundleCache(PinnedOrg.load(args.home))
    envelope = (
        json.loads(pathlib.Path(args.file).read_text(encoding="utf-8"))
        if args.file
        else api.get(f"/v1/orders/{args.order_id}")
    )
    decision = verify_one(cache, envelope)
    render(decision, envelope["payload"])
    return 0 if decision.accepted else 1


def cmd_check_code(args: argparse.Namespace, api: Api, stored: StoredKey) -> int:
    """Check the words from an SMS against the order in the app.

    This is the anti-phishing step, and it is the only thing an SMS is for.
    """
    cache = BundleCache(PinnedOrg.load(args.home))
    envelope = api.get(f"/v1/orders/{args.order_id}")
    order = OrderPayload.model_validate(envelope["payload"])

    # The key was unlocked to sign the request that fetched this order, and that is
    # the same proof of presence this step used to take for itself -- the words are
    # still only ever shown to whoever holds the device and its passphrase.
    # Re-inspection: this order may already have arrived over the listener.
    decision = verify_one(cache, envelope, reinspect=True)
    if decision.rejected:
        render(decision, envelope["payload"])
        return 1

    if not args.wordlist:
        print(
            "error: no wordlist. Pass --wordlist or set ALERTING_WORDLIST.",
            file=sys.stderr,
        )
        return 2
    wordlist = load_wordlist(pathlib.Path(args.wordlist))
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


async def _listen(args: argparse.Namespace, api: Api, stored: StoredKey) -> int:
    pin = PinnedOrg.load(args.home)
    cache = BundleCache(pin)
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
            kind = frame.get("kind")
            if kind not in ("order", "active"):
                continue
            envelope = frame["envelope"]
            # "active": an event still in force when this device connected (ADR
            # 0010). Verified in full, but as a re-inspection rather than a new
            # delivery, so seeing it again after a reconnect is not a replay.
            if kind == "active":
                print("\n  (действующее событие — объявлено до вашего подключения)")
            decision = verify_one(cache, envelope, reinspect=kind == "active")
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


def cmd_listen(args: argparse.Namespace, api: Api, stored: StoredKey) -> int:
    try:
        return asyncio.run(_listen(args, api, stored))
    except KeyboardInterrupt:
        return 0


def cmd_ack(args: argparse.Namespace, api: Api, stored: StoredKey) -> int:
    envelope = api.get(f"/v1/orders/{args.order_id}")
    order = OrderPayload.model_validate(envelope["payload"])
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
    shared.add_argument(
        "--person", default="", help="your person id; required — every request is signed"
    )
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
    enroll.add_argument(
        "--role", default="executor", help="recorded with the key; the directory decides"
    )
    enroll.add_argument("--wake-key", default="", help="hex, from the enrolling officer")
    enroll.set_defaults(func=cmd_enroll, needs_key=False)

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
    code.add_argument(
        "--wordlist",
        default=os.environ.get("ALERTING_WORDLIST", ""),
        help="path to the wake-code wordlist (or ALERTING_WORDLIST). Required: the "
        "old relative default only worked inside a source checkout.",
    )
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
    # `enroll` is the one command that runs before a key exists -- it is the command
    # that creates one -- so it neither unlocks a key nor opens a signed session.
    if not getattr(args, "needs_key", True):
        try:
            return int(args.func(args))
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    try:
        stored = unlock(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    with open_api(args, stored) as api:
        try:
            result: int = args.func(args, api, stored)
            return result
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
