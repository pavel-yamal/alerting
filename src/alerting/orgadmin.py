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

from alerting.core.directory import (
    Directory,
    DirectoryPayload,
    KeyEntry,
    Revocation,
    RevocationListPayload,
    Revoker,
)
from alerting.core.policy import PolicyPayload
from alerting.core.signing import (
    DOMAIN_DIRECTORY,
    DOMAIN_POLICY,
    DOMAIN_REVOCATIONS,
    b64u_encode,
    key_id,
    private_key_from_b64u,
    public_key_from_b64u,
    public_key_to_b64u,
    sign_payload,
    verify_signature,
)
from alerting.orgkit import sign_bundle

#: The revocation key's file name in its keystore home.
REVOKER_NAME = "revoker"

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


# --- the key directory ---------------------------------------------------------------
#
# Who may sign what. Every change produces the next version, signed by the root key on
# the custodians' machine; the server and every device refuse a version lower than the
# highest they have seen, so a revocation cannot be rolled back.


def verified_current(bundle: dict[str, Any], root_public_b64u: str) -> DirectoryPayload:
    """The directory being changed, checked against the root key doing the change.

    Refusing here catches the mistake of editing another organisation's directory, or
    a file somebody altered on the way to the offline machine.
    """
    payload = bundle.get("payload") or {}
    directory = Directory.load(
        bundle,
        root_public_key=public_key_from_b64u(root_public_b64u),
        org_id=str(payload.get("org_id", "")),
    )
    return directory.payload


_KEEP: Any = object()


def _next(
    current: DirectoryPayload,
    *,
    keys: Any,
    revoked: Any,
    issued_at: int,
    revokers: Any = _KEEP,
) -> DirectoryPayload:
    return DirectoryPayload(
        v=1,
        type="directory",
        org_id=current.org_id,
        version=current.version + 1,
        issued_at=issued_at,
        keys=tuple(keys),
        revoked=tuple(revoked),
        revokers=current.revokers if revokers is _KEEP else revokers,
    )


def add_key(
    current: DirectoryPayload,
    *,
    person_id: str,
    name: str,
    role: str,
    public_key: str,
    issued_at: int,
    valid_days: int | None = None,
) -> tuple[DirectoryPayload, KeyEntry]:
    """Enroll one device key for one person."""
    kid = key_id(public_key_from_b64u(public_key))
    if any(entry.key_id == kid for entry in current.keys):
        raise ValueError(f"key {kid} is already in the directory")
    roles = {entry.role for entry in current.keys if entry.person_id == person_id}
    if roles and roles != {role}:
        raise ValueError(
            f"{person_id} already holds role {', '.join(sorted(roles))}; one person, one role"
        )
    entry = KeyEntry(
        key_id=kid,
        public_key=public_key,
        person_id=person_id,
        name=name,
        role=role,
        valid_from=issued_at,
        valid_until=issued_at + valid_days * 86400 if valid_days else None,
    )
    return (
        _next(current, keys=(*current.keys, entry), revoked=current.revoked, issued_at=issued_at),
        entry,
    )


def _select(
    current: DirectoryPayload,
    person_id: str | None,
    kid: str | None,
    at: int,
    also_revoked: frozenset[str] = frozenset(),
) -> list[KeyEntry]:
    """The keys a command acts on.

    By person, only keys still valid at ``at``: a key retired at an earlier device
    change is not revoked along with the current one, or the orders it signed
    before retirement would stop verifying. A key named by id is taken as named.
    """
    if bool(person_id) == bool(kid):
        raise ValueError("name exactly one of --person or --key-id")
    revoked = {r.key_id for r in current.revoked} | also_revoked
    chosen = [
        e
        for e in current.keys
        if e.key_id not in revoked
        and (
            e.key_id == kid
            or (e.person_id == person_id and (e.valid_until is None or e.valid_until > at))
        )
    ]
    if not chosen:
        raise ValueError(f"no live key for {person_id or kid}")
    return chosen


def retire_keys(
    current: DirectoryPayload, *, person_id: str | None, kid: str | None, at: int
) -> tuple[DirectoryPayload, list[KeyEntry]]:
    """End a key's validity now: someone leaves, or replaces their device.

    Orders signed before ``at`` keep verifying -- an evacuation the departing director
    signed this morning is still a genuine order -- but nothing signed after counts,
    and the key no longer authenticates to the server.
    """
    chosen = {e.key_id for e in _select(current, person_id, kid, at)}
    keys = [
        e.model_copy(update={"valid_until": at})
        if e.key_id in chosen and (e.valid_until is None or e.valid_until > at)
        else e
        for e in current.keys
    ]
    retired = [e for e in keys if e.key_id in chosen]
    return _next(current, keys=keys, revoked=current.revoked, issued_at=at), retired


def revoke_keys(
    current: DirectoryPayload, *, person_id: str | None, kid: str | None, at: int, reason: str
) -> tuple[DirectoryPayload, list[KeyEntry]]:
    """Revoke a key outright: it was lost or compromised.

    Unlike retiring, every signature it ever made stops counting -- whoever holds it
    could have backdated an order. Events it co-signed that are still in force will
    no longer verify on devices; the publish step lists them.
    """
    chosen = _select(current, person_id, kid, at)
    revoked = (
        *current.revoked,
        *(Revocation(key_id=e.key_id, revoked_at=at, reason=reason) for e in chosen),
    )
    return _next(current, keys=current.keys, revoked=revoked, issued_at=at), chosen


# --- revocation keys: the fast path ---------------------------------------------------
#
# The root key is offline with two custodians; a stolen phone cannot wait for them. A
# revocation key, named in the directory by the root, signs revocation lists and
# nothing else. It is held by the duty shift. See docs/02-trust-and-approval.md §4.


def add_revoker(
    current: DirectoryPayload, *, public_key: str, label: str, issued_at: int
) -> tuple[DirectoryPayload, Revoker]:
    revoker = Revoker(
        key_id=key_id(public_key_from_b64u(public_key)), public_key=public_key, label=label
    )
    existing = current.revokers or ()
    if any(r.key_id == revoker.key_id for r in existing):
        raise ValueError(f"revocation key {revoker.key_id} is already named")
    if any(e.key_id == revoker.key_id for e in current.keys):
        raise ValueError("a person's signing key cannot double as a revocation key")
    payload = _next(
        current,
        keys=current.keys,
        revoked=current.revoked,
        issued_at=issued_at,
        revokers=(*existing, revoker),
    )
    return payload, revoker


def remove_revoker(
    current: DirectoryPayload,
    *,
    kid: str,
    absorb: dict[str, Any] | None,
    issued_at: int,
) -> tuple[DirectoryPayload, list[Revocation]]:
    """Stop naming a revocation key, folding its list into ``revoked`` or not.

    Once the key is gone its list stops counting everywhere. Absorbing keeps those
    revocations; discarding (``absorb=None``) is for a revocation key that was itself
    stolen, whose list cannot be trusted -- re-revoke what was genuine by hand.
    """
    existing = current.revokers or ()
    if not any(r.key_id == kid for r in existing):
        raise ValueError(f"{kid} is not a revocation key in this directory")
    folded: list[Revocation] = []
    if absorb:
        listed = RevocationListPayload.model_validate(absorb["payload"])
        signers = {r.key_id for r in existing}
        if listed.signer not in signers:
            raise ValueError("the list to absorb was not signed by a key this directory names")
        # Verified here against the key that signed it: a file carried to the offline
        # machine is not trusted for being on a USB stick.
        signer = next(r for r in existing if r.key_id == listed.signer)
        if not verify_signature(
            DOMAIN_REVOCATIONS, absorb["payload"], absorb["signature"], signer.public()
        ):
            raise ValueError("the list to absorb does not verify")
        already = {r.key_id for r in current.revoked}
        folded = [r for r in listed.entries if r.key_id not in already]
    remaining = tuple(r for r in existing if r.key_id != kid)
    payload = _next(
        current,
        keys=current.keys,
        revoked=(*current.revoked, *folded),
        issued_at=issued_at,
        revokers=remaining,
    )
    return payload, folded


def next_revocations(
    directory: Directory,
    latest: dict[str, Any] | None,
    *,
    signer: str,
    person_id: str | None,
    kid: str | None,
    at: int,
    reason: str,
) -> tuple[RevocationListPayload, list[KeyEntry]]:
    """The next revocation list: everything still in force, plus these keys.

    ``directory`` is the verified directory with the current list applied; ``latest``
    is the newest list the server holds, applied or not, whose version must be
    exceeded.
    """
    if signer not in directory.revokers:
        raise ValueError(f"{signer} is not a revocation key in the current directory")
    carried = directory.revocations.entries if directory.revocations else ()
    chosen = _select(
        directory.payload, person_id, kid, at, also_revoked=frozenset(r.key_id for r in carried)
    )
    version = int(latest["payload"]["version"]) if latest else 0
    payload = RevocationListPayload(
        v=1,
        type="revocations",
        org_id=directory.org_id,
        version=version + 1,
        issued_at=at,
        signer=signer,
        entries=(
            *carried,
            *(Revocation(key_id=e.key_id, revoked_at=at, reason=reason) for e in chosen),
        ),
    )
    return payload, chosen


def _sign_directory(args: argparse.Namespace, payload: DirectoryPayload) -> None:
    root_key = private_key_from_b64u(args.root_key.read_text(encoding="utf-8").strip())
    bundle = sign_bundle(payload, DOMAIN_DIRECTORY, root_key)
    args.out.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"signed directory version {payload.version} -> {args.out}")
    print(f"  root key : {public_key_to_b64u(root_key.public_key())}")


def _current(args: argparse.Namespace) -> DirectoryPayload:
    root_key = private_key_from_b64u(args.root_key.read_text(encoding="utf-8").strip())
    bundle = json.loads(args.source.read_text(encoding="utf-8"))
    return verified_current(bundle, public_key_to_b64u(root_key.public_key()))


def cmd_directory_add(args: argparse.Namespace) -> int:
    try:
        payload, entry = add_key(
            _current(args),
            person_id=args.person,
            name=args.name,
            role=args.role,
            public_key=args.public_key,
            issued_at=int(time.time()),
            valid_days=args.valid_days,
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _sign_directory(args, payload)
    print(f"  added    : {entry.person_id} ({entry.role}) {entry.name}")
    print(f"  key id   : {entry.key_id}")
    print("\nThe person checks this key id against the one their device showed. Then publish.")
    return 0


def cmd_directory_retire(args: argparse.Namespace) -> int:
    try:
        payload, keys = retire_keys(
            _current(args), person_id=args.person, kid=args.key_id, at=int(time.time())
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _sign_directory(args, payload)
    for entry in keys:
        print(f"  retired  : {entry.person_id} {entry.key_id} (earlier signatures still count)")
    return 0


def cmd_directory_revoke(args: argparse.Namespace) -> int:
    try:
        payload, keys = revoke_keys(
            _current(args),
            person_id=args.person,
            kid=args.key_id,
            at=int(time.time()),
            reason=args.reason,
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _sign_directory(args, payload)
    for entry in keys:
        print(f"  REVOKED  : {entry.person_id} {entry.key_id} (every signature it made)")
    return 0


def cmd_directory_revoker(args: argparse.Namespace) -> int:
    try:
        if args.add:
            payload, revoker = add_revoker(
                _current(args), public_key=args.add, label=args.label, issued_at=int(time.time())
            )
            note = f"  revocation key added: {revoker.key_id} ({revoker.label})"
        else:
            if not args.absorb and not args.discard_revocations:
                raise ValueError(
                    "say what happens to the revocations it signed: --absorb FILE"
                    " (alerting-org fetch --kind revocations) or --discard-revocations"
                )
            absorb = json.loads(args.absorb.read_text(encoding="utf-8")) if args.absorb else None
            payload, folded = remove_revoker(
                _current(args), kid=args.remove, absorb=absorb or None, issued_at=int(time.time())
            )
            note = f"  revocation key removed: {args.remove}; folded {len(folded)} revocation(s)"
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _sign_directory(args, payload)
    print(note)
    return 0


def cmd_directory_show(args: argparse.Namespace) -> int:
    bundle = json.loads(args.file.read_text(encoding="utf-8"))
    payload = DirectoryPayload.model_validate(bundle["payload"])
    revoked = {r.key_id: r for r in payload.revoked}
    print(f"directory {payload.org_id} version {payload.version}")
    for entry in sorted(payload.keys, key=lambda e: (e.person_id, e.valid_from)):
        state = (
            "REVOKED"
            if entry.key_id in revoked
            else (
                f"until {time.strftime('%Y-%m-%d', time.gmtime(entry.valid_until))}"
                if entry.valid_until
                else "live"
            )
        )
        print(f"  {entry.person_id:<8} {entry.role:<13} {entry.key_id}  {state:<18} {entry.name}")
    for revoker in payload.revokers or ():
        print(f"  revocation key {revoker.key_id}  {revoker.label}")
    return 0


# --- talking to the server -------------------------------------------------------------


def _api(args: argparse.Namespace) -> Any:
    from alerting.clients.bundles import PinnedOrg
    from alerting.clients.keystore import load_key
    from alerting.clients.transport import Api, SignedRequests

    pin = PinnedOrg.load(args.home)
    passphrase = args.passphrase or getpass.getpass(f"Passphrase for {args.person}: ")
    stored = load_key(args.person, passphrase, directory=args.home)
    return Api(
        args.server,
        auth=SignedRequests(
            org_id=pin.org_id,
            key_id=stored.key_id,
            person_id=stored.person_id,
            private_key=stored.private_key,
        ),
    )


def cmd_fetch(args: argparse.Namespace) -> int:
    """Bring the current signed bundle to a file, to carry to the offline machine."""
    from alerting.clients.transport import ServerError

    api = _api(args)
    try:
        bundle = api.get(f"/v1/{args.kind}")
    except ServerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        api.close()
    args.out.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")
    version = bundle["payload"]["version"] if bundle else "none yet"
    print(f"{args.kind} version {version} -> {args.out}")
    return 0


def cmd_contact_set(args: argparse.Namespace) -> int:
    """Where to reach a person: phone, site, groups. Personal data, held by the server.

    Not signed by the root: it decides who an order is *sent* to, never whether an
    order is genuine. A new wake key is generated each time and written to
    ``--wake-key-out`` for the person's device (``alerting-executor enroll
    --wake-key``); the server keeps the same key to derive their SMS words.
    Without ``--wake-key-out`` the server keeps the key it has: a new one with no
    device-side copy would make every SMS word disagree with the device.
    """
    import secrets

    from alerting.clients.transport import ServerError

    wake_key = secrets.token_bytes(32) if args.wake_key_out else b""
    body = {
        "person_id": args.target,
        "name": args.name,
        "phone": args.phone,
        "site": args.site,
        "groups": args.groups,
        "role": args.role,
        "wake_key": b64u_encode(wake_key) if wake_key else "",
    }
    api = _api(args)
    try:
        api.post("/v1/contacts", body)
    except ServerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        api.close()
    if args.wake_key_out:
        args.wake_key_out.write_text(wake_key.hex(), encoding="utf-8")
        args.wake_key_out.chmod(0o600)
        print(f"wake key for the device -> {args.wake_key_out} (hand over in person)")
    print(f"contact {args.target}: site={args.site or '-'} groups={','.join(args.groups) or '-'}")
    return 0


def cmd_contact_remove(args: argparse.Namespace) -> int:
    from alerting.clients.transport import ServerError

    api = _api(args)
    try:
        api.post(f"/v1/contacts/{args.target}/deactivate")
    except ServerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        api.close()
    print(f"contact {args.target} deactivated: no further orders are sent to them")
    return 0


def cmd_revoker_keygen(args: argparse.Namespace) -> int:
    """Make a revocation key. Its public half goes to the custodians for the directory."""
    from alerting.clients.keystore import save_key
    from alerting.core.signing import generate_keypair

    private, public = generate_keypair()
    passphrase = args.passphrase or getpass.getpass("New passphrase for the revocation key: ")
    path = save_key(REVOKER_NAME, private, passphrase, role="revoker", directory=args.home)
    print(f"revocation key -> {path}")
    print(f"  public key : {public_key_to_b64u(public)}")
    print(f"  key id     : {key_id(public)}")
    print("\nCustodians add it with: alerting-org directory revoker --add <public key> --label ...")
    return 0


def cmd_revoke_now(args: argparse.Namespace) -> int:
    """Revoke a key in seconds, with the revocation key instead of the root.

    Fetches the directory and the current list, verifies both against the root key
    pinned in the operator's home, signs the next list and publishes it.
    """
    from alerting.clients.bundles import PinnedOrg
    from alerting.clients.keystore import load_key
    from alerting.clients.transport import ServerError

    pin = PinnedOrg.load(args.home)
    revoker_pass = args.revoker_passphrase or getpass.getpass("Revocation key passphrase: ")
    try:
        revoker = load_key(REVOKER_NAME, revoker_pass, directory=args.revoker_home)
    except Exception as exc:
        print(f"error: cannot open the revocation key: {exc}", file=sys.stderr)
        return 2
    api = _api(args)
    try:
        latest = api.get("/v1/revocations") or None
        directory = Directory.load(
            api.get("/v1/directory"), root_public_key=pin.root_public_key, org_id=pin.org_id
        ).with_revocations(latest)
        payload, chosen = next_revocations(
            directory,
            latest,
            signer=revoker.key_id,
            person_id=args.target,
            kid=args.key_id,
            at=int(time.time()),
            reason=args.reason,
        )
        raw = payload.to_payload()
        signature = sign_payload(DOMAIN_REVOCATIONS, raw, revoker.private_key)
        bundle = {"payload": raw, "signature": signature}
        result = api.post("/v1/bundles", {"bundle": bundle})
    except (ServerError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        api.close()
    for entry in chosen:
        print(f"REVOKED {entry.person_id} {entry.key_id} (revocation list v{result['version']})")
    for line in result.get("invalidated", []):
        print(f"  !! no longer verifies: {line}")
    if result.get("invalidated"):
        print("  Those events were co-signed by a revoked key. Re-issue them if they stand.")
    print("The server refuses the key from now on; open sockets close within 15 s.")
    return 0


def cmd_publish(args: argparse.Namespace) -> int:
    from alerting.clients.transport import ServerError

    bundle = json.loads(args.file.read_text(encoding="utf-8"))
    api = _api(args)
    try:
        result = api.post("/v1/bundles", {"bundle": bundle})
    except ServerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        api.close()
    print(f"published {result['kind']} version {result['version']}")
    for line in result.get("invalidated", []):
        print(f"  !! no longer verifies: {line}")
    if result.get("invalidated"):
        print("  Those events were co-signed by a revoked key. Re-issue them if they stand.")
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

    def server_args(command: argparse.ArgumentParser) -> None:
        command.add_argument("--server", default="http://127.0.0.1:8080")
        command.add_argument("--person", required=True, help="your person id (an operator)")
        command.add_argument("--home", type=pathlib.Path, required=True, help="your key home")
        command.add_argument("--passphrase")

    publish = sub.add_parser("publish", help="upload a signed directory or policy")
    publish.add_argument("--file", type=pathlib.Path, required=True)
    server_args(publish)
    publish.set_defaults(func=cmd_publish)

    fetch = sub.add_parser("fetch", help="download the current signed directory or policy")
    fetch.add_argument("--kind", choices=["directory", "policy", "revocations"], required=True)
    fetch.add_argument("--out", type=pathlib.Path, required=True)
    server_args(fetch)
    fetch.set_defaults(func=cmd_fetch)

    directory = sub.add_parser("directory", help="change the key directory (offline, root key)")
    dsub = directory.add_subparsers(dest="directory_command", required=True)

    def signing_args(command: argparse.ArgumentParser) -> None:
        command.add_argument(
            "--from", dest="source", type=pathlib.Path, required=True,
            help="the current signed directory (alerting-org fetch)",
        )  # fmt: skip
        command.add_argument("--root-key", type=pathlib.Path, required=True)
        command.add_argument("--out", type=pathlib.Path, required=True)

    add = dsub.add_parser("add", help="enroll a device key")
    signing_args(add)
    add.add_argument("--person", required=True)
    add.add_argument("--name", required=True)
    add.add_argument(
        "--role", required=True, help="executor, duty_officer, deputy, director, auditor"
    )
    add.add_argument("--public-key", required=True, help="as the device printed it at enrollment")
    add.add_argument("--valid-days", type=int, help="expire the key after this many days")
    add.set_defaults(func=cmd_directory_add)

    for name, func, text in (
        ("retire", cmd_directory_retire, "end validity now; earlier signatures still count"),
        ("revoke", cmd_directory_revoke, "lost or compromised; every signature stops counting"),
    ):
        command = dsub.add_parser(name, help=text)
        signing_args(command)
        command.add_argument("--person", help="all of this person's live keys")
        command.add_argument("--key-id", help="just this key")
        if name == "revoke":
            command.add_argument("--reason", required=True)
        command.set_defaults(func=func)

    revoker = dsub.add_parser("revoker", help="name or drop a revocation key (fast path)")
    signing_args(revoker)
    which = revoker.add_mutually_exclusive_group(required=True)
    which.add_argument("--add", metavar="PUBLIC_KEY", help="from alerting-org revoker-keygen")
    which.add_argument("--remove", metavar="KEY_ID")
    revoker.add_argument("--label", default="дежурная смена")
    fate = revoker.add_mutually_exclusive_group()
    fate.add_argument("--absorb", type=pathlib.Path, help="its list, to keep as revoked[]")
    fate.add_argument("--discard-revocations", action="store_true", help="it was stolen")
    revoker.set_defaults(func=cmd_directory_revoker)

    show = dsub.add_parser("show", help="list the keys in a signed directory")
    show.add_argument("--file", type=pathlib.Path, required=True)
    show.set_defaults(func=cmd_directory_show)

    keygen = sub.add_parser("revoker-keygen", help="make a revocation key for the duty shift")
    keygen.add_argument("--home", type=pathlib.Path, required=True)
    keygen.add_argument("--passphrase")
    keygen.set_defaults(func=cmd_revoker_keygen)

    now = sub.add_parser("revoke-now", help="revoke with the revocation key, in seconds")
    server_args(now)
    now.add_argument("--for", dest="target", help="all of this person's live keys")
    now.add_argument("--key-id", help="just this key")
    now.add_argument("--reason", required=True)
    now.add_argument("--revoker-home", type=pathlib.Path, required=True)
    now.add_argument("--revoker-passphrase")
    now.set_defaults(func=cmd_revoke_now)

    contact = sub.add_parser("contact", help="where to reach a person (server-held)")
    csub = contact.add_subparsers(dest="contact_command", required=True)
    cset = csub.add_parser("set", help="add or update a person's contact")
    server_args(cset)
    cset.add_argument("--for", dest="target", required=True, help="the person being enrolled")
    cset.add_argument("--name", required=True)
    cset.add_argument("--phone", default="")
    cset.add_argument("--site", default="")
    cset.add_argument("--groups", nargs="*", default=[])
    cset.add_argument("--role", default="executor")
    cset.add_argument(
        "--wake-key-out", type=pathlib.Path,
        help="issue a new wake key and write it here for the device; omit to keep the old one",
    )  # fmt: skip
    cset.set_defaults(func=cmd_contact_set)
    cremove = csub.add_parser("remove", help="stop sending orders to a person")
    server_args(cremove)
    cremove.add_argument("--for", dest="target", required=True)
    cremove.set_defaults(func=cmd_contact_remove)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
