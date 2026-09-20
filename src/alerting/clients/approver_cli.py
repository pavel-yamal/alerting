"""Decision-maker CLI: propose, inspect, sign, stand down.

The signing step deliberately re-derives the canonical bytes from the payload rather
than trusting the ``signing_input_b64u`` the server offers. A signer who signs whatever
bytes the server hands them has delegated their authority to the server, which is the
exact thing this design refuses to do.
"""

from __future__ import annotations

import argparse
import getpass
import json
import pathlib
import sys
from typing import Any

from alerting.clients.keystore import DEFAULT_DIR, load_key
from alerting.clients.transport import Api
from alerting.core.canonical import canonicalize
from alerting.core.signing import DOMAIN_ORDER, b64u_encode, sign_payload

#: Every field cmd_sign renders. Anything outside this set is surfaced as unshown.
KNOWN_PAYLOAD_FIELDS = {
    "v",
    "type",
    "order_id",
    "org_id",
    "stream_id",
    "seq",
    "nonce",
    "issued_at",
    "not_valid_after",
    "severity",
    "drill",
    "scenario",
    "action",
    "audience",
    "text",
    "requires_ack",
    "ack_deadline_s",
    "policy_id",
    "cancels",
}


def _passphrase(args: argparse.Namespace) -> str:
    return args.passphrase or getpass.getpass(f"Passphrase for {args.person}: ")


def cmd_propose(args: argparse.Namespace, api: Api) -> int:
    audience: dict[str, list[str]] = {}
    if args.sites:
        audience["sites"] = args.sites
    if args.groups:
        audience["groups"] = args.groups
    if args.persons:
        audience["persons"] = args.persons

    result = api.post(
        "/v1/proposals",
        {
            "scenario": args.scenario,
            "severity": args.severity,
            "drill": args.drill,  # explicit on the command line; there is no default
            "action": args.action,
            "audience": audience,
            "text": args.text,
            "ttl_s": args.ttl,
            "created_by": args.person or "dispatcher",
        },
    )
    kind = "УЧЕНИЕ" if args.drill else "БОЕВОЕ"
    print(f"{kind}  proposal {result['order_id']}")
    print(f"  scenario  : {args.scenario} ({args.severity})")
    print(f"  signatures: 0 of {result['required_signatures']} required")
    print(f"\nsign it with:\n  alerting-approver sign {result['order_id']} --person <id>")
    return 0


def cmd_show(args: argparse.Namespace, api: Api) -> int:
    proposal = api.get(f"/v1/proposals/{args.order_id}")
    payload = proposal["payload"]
    print(f"proposal {args.order_id}  [{proposal['status']}]")
    print(
        f"  {'УЧЕНИЕ' if payload['drill'] else 'БОЕВОЕ'}  {payload['scenario']}"
        f"  severity={payload['severity']}  action={payload['action']}"
    )
    if payload.get("text"):
        print(f"  text      : {payload['text']}")
    print(f"  audience  : {json.dumps(payload['audience'], ensure_ascii=False)}")
    print(f"  valid until {payload['not_valid_after']}")
    print(f"  signatures: {len(proposal['signatures'])}")
    for signature in proposal["signatures"]:
        print(f"    - {signature['key_id']}  at {signature['observed_at']}")
    return 0


def show_payload(payload: dict[str, Any], derived: str) -> None:
    """Print every field the signature will cover.

    Recomputing the canonical bytes proves we signed *these* bytes; it says nothing
    about whether the approver saw what is in them. A compromised server that widened
    the audience or flipped START to STOP would still get a correct signature over its
    own content unless the human is shown all of it. So everything actionable is
    printed here, not just the headline.
    """
    kind = "УЧЕНИЕ" if payload["drill"] else "БОЕВОЕ"
    audience = payload.get("audience", {})
    targets = ", ".join(
        f"{label}: {', '.join(values)}"
        for label, values in (
            ("площадки", audience.get("sites") or []),
            ("группы", audience.get("groups") or []),
            ("лично", audience.get("persons") or []),
        )
        if values
    )
    window = payload["not_valid_after"] - payload["issued_at"]

    print("\nВЫ ПОДПИСЫВАЕТЕ:")
    print(f"  режим      : {kind}")
    print(f"  сценарий   : {payload['scenario']}")
    print(f"  важность   : {payload['severity']}")
    print(f"  действие   : {payload['action']}")
    print(f"  аудитория  : {targets or '(ПУСТО — приказ не дойдёт ни до кого)'}")
    print(f"  действует  : {window} с (до {payload['not_valid_after']})")
    print(f"  поток/номер: {payload['stream_id']}#{payload['seq']}")
    print(
        f"  подтвержд. : {'требуется' if payload.get('requires_ack') else 'не требуется'}"
        f", срок {payload.get('ack_deadline_s')} с"
    )
    if payload.get("cancels"):
        print(f"  ОТМЕНЯЕТ   : {payload['cancels']}")
    if payload.get("text"):
        print(f"  текст      : {payload['text']}")
    print(f"  организация: {payload['org_id']}   политика: {payload['policy_id']}")
    print(f"  подписываемые байты: {derived[:32]}…")

    unexpected = set(payload) - KNOWN_PAYLOAD_FIELDS
    if unexpected:
        # Belt and braces: if the protocol ever grows a field, the approver is told
        # rather than silently signing something this prompt does not render.
        print(f"  !! НЕПОКАЗАННЫЕ ПОЛЯ: {sorted(unexpected)} — не подписывайте")


def cmd_sign(args: argparse.Namespace, api: Api) -> int:
    proposal = api.get(f"/v1/proposals/{args.order_id}")
    payload = proposal["payload"]

    # Re-derive the bytes ourselves. Never sign what the server tells us to sign.
    derived = b64u_encode(DOMAIN_ORDER + canonicalize(payload))

    show_payload(payload, derived)
    if not args.yes:
        confirm = input("Sign? [y/N] ").strip().lower()
        if confirm != "y":
            print("not signed")
            return 1

    stored = load_key(args.person, _passphrase(args), directory=args.home)
    result = api.post(
        f"/v1/proposals/{args.order_id}/signatures",
        {
            "key_id": stored.key_id,
            "sig": sign_payload(DOMAIN_ORDER, payload, stored.private_key),
        },
    )
    if result["dispatched"]:
        print(f"quorum met — dispatched to {len(result['recipients'])} people")
        for warning in result.get("warnings", []):
            print(f"  warning: {warning}")
    else:
        print(f"signature {result['signatures']} recorded; still blocking:")
        for reason in result["blocking"]:
            print(f"  - {reason}")
    return 0


def cmd_cancel(args: argparse.Namespace, api: Api) -> int:
    """Build a stand-down for an existing order and sign it in one step."""
    order = api.get(f"/v1/orders/{args.order_id}")
    payload = order["payload"]
    proposal = api.post(
        "/v1/proposals",
        {
            "scenario": payload["scenario"],
            "severity": payload["severity"],
            # Must match the target, or the cancel is refused. A drill envelope can
            # never stand down a real order.
            "drill": payload["drill"],
            "action": "STOP",
            "audience": payload["audience"],
            "text": args.text or "Отбой",
            "cancels": args.order_id,
            "created_by": args.person or "dispatcher",
        },
    )
    print(f"cancel proposal {proposal['order_id']} for {args.order_id}")
    args.order_id = proposal["order_id"]
    return cmd_sign(args, api)


def cmd_status(args: argparse.Namespace, api: Api) -> int:
    status = api.get(f"/v1/orders/{args.order_id}/status")
    print(
        f"order {status['order_id']}  "
        f"{'УЧЕНИЕ' if status['drill'] else 'БОЕВОЕ'}  {status['scenario']}"
    )
    print(f"  acknowledged: {status['acknowledged']} of {len(status['people'])}")
    for person in status["people"]:
        mark = {True: "ok", False: "INVALID", None: "--"}[person["ack_valid"]]
        print(
            f"    {person['person_id']:<8} {mark:<8} {person['ack_status'] or 'no ack'}"
            f"   via {','.join(person['channels_attempted'])}"
        )
    if status["outstanding"]:
        print(f"  outstanding : {', '.join(status['outstanding'])}")
    return 0


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
    parser = argparse.ArgumentParser(prog="alerting-approver")
    shared = common_parser()
    sub = parser.add_subparsers(dest="command", required=True)

    propose = sub.add_parser("propose", parents=[shared], help="create a proposal (not an order)")
    propose.add_argument("scenario")
    propose.add_argument(
        "--severity", default="critical", choices=["info", "warning", "critical", "catastrophic"]
    )
    drill = propose.add_mutually_exclusive_group(required=True)
    drill.add_argument("--drill", action="store_true", help="УЧЕНИЕ")
    drill.add_argument("--real", dest="drill", action="store_false", help="БОЕВОЕ")
    propose.add_argument("--action", default="START", choices=["START", "STOP", "HOLD"])
    propose.add_argument("--sites", nargs="*", default=[])
    propose.add_argument("--groups", nargs="*", default=[])
    propose.add_argument("--persons", nargs="*", default=[])
    propose.add_argument("--text", default="")
    propose.add_argument("--ttl", type=int, default=900)
    propose.set_defaults(func=cmd_propose)

    show = sub.add_parser("show", parents=[shared], help="inspect a proposal")
    show.add_argument("order_id")
    show.set_defaults(func=cmd_show)

    sign_cmd = sub.add_parser("sign", parents=[shared], help="sign a proposal")
    sign_cmd.add_argument("order_id")
    sign_cmd.add_argument("--yes", action="store_true", help="skip confirmation")
    sign_cmd.set_defaults(func=cmd_sign)

    cancel = sub.add_parser("cancel", parents=[shared], help="stand down («отбой»)")
    cancel.add_argument("order_id")
    cancel.add_argument("--text", default="")
    cancel.add_argument("--yes", action="store_true")
    cancel.set_defaults(func=cmd_cancel)

    status = sub.add_parser("status", parents=[shared], help="who has acknowledged")
    status.add_argument("order_id")
    status.set_defaults(func=cmd_status)
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
