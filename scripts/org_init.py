#!/usr/bin/env python3
"""Create a demo organisation: root key, people, signed bundles, server database.

Real enrollment is an in-person procedure and looks nothing like this — see
docs/02-trust-and-approval.md. This exists so a reviewer can get a working system in
one command.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import secrets
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from alerting.clients.bundles import PinnedOrg
from alerting.clients.keystore import save_key
from alerting.core.clock import SystemClock
from alerting.core.signing import (
    generate_keypair,
    private_key_to_b64u,
    public_key_to_b64u,
)
from alerting.orgkit import build_org
from alerting.server.db.connection import connect, migrate
from alerting.server.db.repo import Repo
from alerting.server.services.audit_service import AuditService
from alerting.server.services.bootstrap import publish_org

DEMO_PASSPHRASE = "demo"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="var/alerting.db")
    parser.add_argument("--home", type=pathlib.Path, default=pathlib.Path("var/clients"))
    parser.add_argument("--org", default="acme")
    parser.add_argument("--passphrase", default=DEMO_PASSPHRASE)
    parser.add_argument(
        "--i-understand-this-is-a-demo",
        action="store_true",
        help="required when ALERTING_ENV is set: this script writes the org ROOT "
        "PRIVATE KEY to local disk, which must never happen on a real host",
    )
    args = parser.parse_args()

    # The root key is the trust anchor for the whole system. docs/02 says it lives on
    # two encrypted USB keys held by two custodians; this script writes it to the
    # working directory. That is fine for a demo and a total compromise anywhere else.
    environment = os.environ.get("ALERTING_ENV", "")
    if environment.lower() in {"production", "prod", "staging"}:
        parser.error(
            f"refusing to run with ALERTING_ENV={environment}: this script writes the "
            "org root private key to disk. Generate org bundles on an offline machine "
            "and import them instead."
        )
    if environment and not args.i_understand_this_is_a_demo:
        parser.error(
            "ALERTING_ENV is set; pass --i-understand-this-is-a-demo to confirm this "
            "host may hold the org root private key"
        )

    clock = SystemClock()
    org = build_org(org_id=args.org, issued_at=clock.now())

    db_path = pathlib.Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()
    connection = connect(str(db_path))
    migrate(connection)
    repo = Repo(connection)

    # A separate server key signs published audit heads. Without it every head carries
    # an empty signature and gives no tamper-evidence against whoever can rewrite the
    # database — which is the whole point of publishing heads.
    server_private, server_public = generate_keypair()
    audit = AuditService(repo, clock, server_key=server_private)
    publish_org(repo, org, audit=audit)

    root_pub = public_key_to_b64u(org.root_public_key)
    for person in org.people.values():
        home = args.home / person.person_id
        save_key(
            person.person_id,
            person.private_key,
            args.passphrase,
            role=person.role,
            directory=home,
        )
        PinnedOrg(args.org, root_pub, home).save()
        (home / "wake_key.hex").write_text(person.wake_key.hex(), encoding="utf-8")

    api_key_path = pathlib.Path("var/api-key.SECRET")
    api_key_path.write_text(secrets.token_urlsafe(32), encoding="utf-8")
    api_key_path.chmod(0o600)

    server_key_path = pathlib.Path("var/server-key.SECRET")
    server_key_path.write_text(private_key_to_b64u(server_private), encoding="utf-8")
    server_key_path.chmod(0o600)

    root_path = pathlib.Path("var/root-key.SECRET")
    root_path.write_text(private_key_to_b64u(org.root_private_key), encoding="utf-8")
    root_path.chmod(0o600)

    print(f"organisation '{args.org}' created")
    print(f"  database    : {db_path}")
    print(f"  client homes: {args.home}/<person_id>")
    print(f"  passphrase  : {args.passphrase}  (demo only)")
    print(f"\n  ORG ROOT PUBLIC KEY (pin this in every client):\n    {root_pub}")
    print(f"\n  root private key written to {root_path}")
    print("  DEMO ONLY. In production this lives on two encrypted USB keys held by")
    print("  two custodians, is used a handful of times a year, and MUST NEVER be")
    print("  written to a server that serves traffic. It is the one place a hardware")
    print("  token is justified today.\n")
    print("  people:")
    for person in org.people.values():
        print(f"    {person.person_id:<8} {person.role:<13} {person.name}")
    print("\n  wake keys: one per person, written to <home>/wake_key.hex.")
    print("  Each executor's SMS code is derived from their own key, so intercepting")
    print("  one person's message says nothing about anyone else's code.")
    print(
        f"\n  AUDIT HEAD SIGNING KEY (public, for the auditor):"
        f"\n    {public_key_to_b64u(server_public)}"
    )
    print(f"  private half in {server_key_path}")

    print(f"\n  SHARED API KEY written to {api_key_path} (mode 0600).")
    print("  Every CLI needs it: export ALERTING_API_KEY=$(cat var/api-key.SECRET)")
    print("  This is the interim gate; signed per-person requests replace it.")

    print("\nstart the server with:")
    print(f"  ALERTING_ROOT_PUBKEY={root_pub} \\")
    print(f"  ALERTING_SERVER_KEY_FILE={server_key_path} \\")
    print(f"  ALERTING_API_KEY_FILE={api_key_path} \\")
    print("  ALERTING_ALLOW_STUB_CHANNELS=1 \\")
    print(f"  ALERTING_DB={db_path} ALERTING_ORG={args.org} make serve")
    print("\n  (ALLOW_STUB_CHANNELS because this demo org has no real providers;")
    print("   a production node must never set it.)")
    connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
