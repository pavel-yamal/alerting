"""Opening an authenticated session: unlock the key once, sign every request.

Shared by all three CLIs so that "how a client proves who it is" has one
implementation. It also puts the passphrase prompt in one place, which matters more
than it looks: the key now has to be unlocked **before the first request**, not in
the middle of a command, so a command that makes four calls asks once.
"""

from __future__ import annotations

import argparse
import getpass
import sys

from alerting.clients.bundles import PinnedOrg
from alerting.clients.keystore import StoredKey, load_key
from alerting.clients.transport import Api, SignedRequests


def passphrase_for(args: argparse.Namespace) -> str:
    return args.passphrase or getpass.getpass(f"Passphrase for {args.person}: ")


def unlock(args: argparse.Namespace) -> StoredKey:
    """Load this person's key, or exit with something they can act on."""
    if not args.person:
        print(
            "--person is required: every request is signed with your personal key.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return load_key(args.person, passphrase_for(args), directory=args.home)


def open_api(args: argparse.Namespace, stored: StoredKey) -> Api:
    """An ``Api`` that signs every request with ``stored``.

    The organisation id comes from the device's own pinned record, not from the
    server: it is part of what is signed, so taking it from the party being
    authenticated to would defeat the point.
    """
    pin = PinnedOrg.load(args.home)
    return Api(
        args.server,
        auth=SignedRequests(
            org_id=pin.org_id,
            key_id=stored.key_id,
            person_id=stored.person_id,
            private_key=stored.private_key,
        ),
    )
