"""``alerting-org``: sign a policy offline, publish a signed bundle.

The codebook (which events exist, what each tells an executor to do, which ones stay
in force until a stand-down) and the quorum rules live in the root-signed policy,
not in the server's configuration. That is the point: a phone checks the policy
against the org root key it pinned at enrollment, so whoever controls the server --
or its ``.env`` -- cannot add an event, soften a quorum, or rewrite an instruction.

So changing the list is two steps, and they happen in different places:

1. ``sign-policy`` -- on the custodians' offline machine, with the root key. It reads
   a YAML file, builds the policy, and writes the signed bundle.
2. ``publish`` -- from anywhere, as an operator. It carries the signed bundle to the
   server, which verifies it the same way every client will and refuses anything not
   newer than what it has.

Nothing in step 2 needs the root key, and nothing in step 1 needs the network.
"""

from __future__ import annotations

import argparse
import getpass
import json
import pathlib
import sys
import time
from typing import Any

import yaml

from alerting.core.policy import PolicyPayload
from alerting.core.signing import DOMAIN_POLICY, private_key_from_b64u, public_key_to_b64u
from alerting.orgkit import sign_bundle

#: A policy past its validity is refused by every client. A year is long enough not
#: to be an operational hazard and short enough that a lost root key's last policy
#: does not outlive the people who would notice.
DEFAULT_TTL_DAYS = 365


def build_policy(
    document: dict[str, Any],
    *,
    scenarios: dict[str, Any] | None,
    version: int | None,
    issued_at: int,
    ttl_days: int,
) -> PolicyPayload:
    """Turn the YAML into a validated policy payload. Raises on anything wrong."""
    body = dict(document)
    if scenarios is not None:
        body["scenarios"] = scenarios
    if "scenarios" not in body or not body["scenarios"]:
        raise ValueError("the policy has no scenarios: pass --scenarios or add a scenarios: key")
    if version is not None:
        body["version"] = version
    body.update(
        v=1,
        type="policy",
        issued_at=issued_at,
        not_valid_after=issued_at + ttl_days * 86400,
    )
    # YAML hands back plain ints and strings, which is what the strict model wants;
    # anything else (a float quorum, a quoted bool) is refused here, offline, rather
    # than by every client after publication.
    return PolicyPayload.model_validate(body)


def cmd_sign_policy(args: argparse.Namespace) -> int:
    document = yaml.safe_load(args.policy.read_text(encoding="utf-8")) or {}
    scenarios = (
        yaml.safe_load(args.scenarios.read_text(encoding="utf-8")) if args.scenarios else None
    )
    try:
        payload = build_policy(
            document,
            scenarios=scenarios,
            version=args.version,
            issued_at=int(time.time()),
            ttl_days=args.ttl_days,
        )
    except Exception as exc:
        print(f"error: the policy is not valid: {exc}", file=sys.stderr)
        return 2

    root_key = private_key_from_b64u(args.root_key.read_text(encoding="utf-8").strip())
    bundle = sign_bundle(payload, DOMAIN_POLICY, root_key)
    args.out.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"signed policy {payload.policy_id} version {payload.version} -> {args.out}")
    print(f"  org      : {payload.org_id}")
    print(f"  root key : {public_key_to_b64u(root_key.public_key())}")
    print(f"  valid to : {time.strftime('%Y-%m-%d', time.gmtime(payload.not_valid_after))}")
    print("  scenarios:")
    for code, rule in sorted(payload.scenarios.items()):
        flags = " [до отбоя]" if rule.until_cancelled else ""
        print(f"    {code:<20} {rule.description}{flags}")
    print("\nCheck the root key above against the one on the custodians' card, then publish.")
    return 0


def cmd_publish(args: argparse.Namespace) -> int:
    from alerting.clients.bundles import PinnedOrg
    from alerting.clients.keystore import load_key
    from alerting.clients.transport import Api, ServerError, SignedRequests

    bundle = json.loads(args.file.read_text(encoding="utf-8"))
    pin = PinnedOrg.load(args.home)
    passphrase = args.passphrase or getpass.getpass(f"Passphrase for {args.person}: ")
    stored = load_key(args.person, passphrase, directory=args.home)
    api = Api(
        args.server,
        auth=SignedRequests(
            org_id=pin.org_id,
            key_id=stored.key_id,
            person_id=stored.person_id,
            private_key=stored.private_key,
        ),
    )
    try:
        result = api.post("/v1/bundles", {"bundle": bundle})
    except ServerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        api.close()
    print(f"published {result['kind']} version {result['version']}")
    print("Clients pick it up on their next sync; the panel and the phone page on next login.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="alerting-org", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    sign = sub.add_parser("sign-policy", help="build and sign a policy from YAML (offline)")
    sign.add_argument("--policy", type=pathlib.Path, required=True, help="policy YAML")
    sign.add_argument(
        "--scenarios", type=pathlib.Path, help="codebook YAML (overrides scenarios: in --policy)"
    )
    sign.add_argument("--root-key", type=pathlib.Path, required=True, help="root private key file")
    sign.add_argument(
        "--version", type=int, help="policy version (default: the one in --policy); must grow"
    )
    sign.add_argument("--ttl-days", type=int, default=DEFAULT_TTL_DAYS)
    sign.add_argument("--out", type=pathlib.Path, required=True)
    sign.set_defaults(func=cmd_sign_policy)

    publish = sub.add_parser("publish", help="upload a signed directory or policy")
    publish.add_argument("--file", type=pathlib.Path, required=True)
    publish.add_argument("--server", default="http://127.0.0.1:8080")
    publish.add_argument("--person", required=True, help="your person id (an operator)")
    publish.add_argument("--home", type=pathlib.Path, required=True, help="your key home")
    publish.add_argument("--passphrase")
    publish.set_defaults(func=cmd_publish)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
