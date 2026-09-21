"""Auditor CLI: pull the chain, verify it, and report on an incident.

Verification here is deliberately independent of the server: it recomputes every hash
from the entries themselves and checks them against heads that were published out of
band. A server that rewrote its own history still has to match a head somebody else
already holds.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections import Counter
from typing import Any

from alerting.clients.keystore import DEFAULT_DIR
from alerting.core.audit_chain import verify_chain
from alerting.core.metrics import MAIN_METRIC_SHARE, ack_timing, order_ids
from alerting.core.signing import (
    DOMAIN_AUDIT_HEAD,
    public_key_from_b64u,
    verify_signature,
)


def _load(args: argparse.Namespace) -> tuple[list[dict[str, Any]], dict[int, str]]:
    """Entries and published heads, from a file, a database, or the server."""
    if args.file:
        blob = json.loads(pathlib.Path(args.file).read_text(encoding="utf-8"))
        return blob["entries"], {int(k): v for k, v in blob.get("heads", {}).items()}

    if args.dsn:
        # Reading the live database is the operator's path, not the auditor's: an
        # auditor with a connection to production is trusting the same machine whose
        # history they are checking. `--file` and `--server` are the independent
        # ones. The import is lazy so the auditor tool does not require a database
        # driver unless this path is used.
        from alerting.server.db.pool import open_pool
        from alerting.server.db.repo import Repo

        pool = open_pool(args.dsn, min_size=1, max_size=2)
        try:
            repo = Repo(pool)
            return list(repo.audit_entries(0, 1_000_000)), repo.heads()
        finally:
            pool.close()

    # The only path that needs a key, and the only one that is not independent.
    # `--file` and `--server` differ in exactly that: a pulled export can be checked
    # on a machine the organisation does not run, which is the point of an auditor.
    from alerting.clients.session import open_api, unlock

    stored = unlock(args)
    with open_api(args, stored) as api:
        entries: list[dict[str, Any]] = []
        while True:
            page = api.get("/v1/audit", from_idx=len(entries), limit=500)
            batch = page["entries"]
            if not batch:
                return entries, {int(k): v for k, v in page.get("heads", {}).items()}
            entries.extend(batch)


def cmd_pull(args: argparse.Namespace) -> int:
    entries, heads = _load(args)
    payload = {"entries": entries, "heads": {str(k): v for k, v in heads.items()}}
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.out:
        pathlib.Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {len(entries)} entries to {args.out}")
    else:
        print(text)
    return 0


def _heads_from_dir(directory: pathlib.Path) -> dict[int, str]:
    """Heads read from files published out of band, not from the database.

    This is the only kind of head worth anything after a failover. A head the server
    wrote is a row in the same database whose tail was lost, so it disappears with
    it and the shortened chain verifies perfectly against what is left of itself.
    The file an auditor already holds does not disappear, and
    :func:`verify_chain` answers "chain is shorter than a published head".
    """
    heads: dict[int, str] = {}
    for path in sorted(directory.glob("head-*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))["payload"]
        heads[int(payload["idx"])] = str(payload["head"])
    return heads


def cmd_verify(args: argparse.Namespace) -> int:
    entries, heads = _load(args)
    if args.heads_dir:
        # Replacing, not merging: the point of the flag is to check the chain against
        # heads the database did not get to choose.
        heads = _heads_from_dir(pathlib.Path(args.heads_dir))
        print(f"     using {len(heads)} head(s) published out of band")
    if args.ignore_heads:
        heads = {}
    verdict = verify_chain(entries, expected_heads=heads)

    if verdict.ok:
        print(f"OK — {verdict.checked} entries, chain intact")
        print(f"     checked against {len(heads)} published head(s)")
        if not heads:
            print("     NOTE: no published heads, so a rewritten tail is undetectable")
        return 0

    print(f"FAILED at entry {verdict.failed_index}: {verdict.problem}", file=sys.stderr)
    print(f"  {verdict.checked} entries verified before the break", file=sys.stderr)
    if verdict.failed_index is not None and verdict.failed_index < len(entries):
        entry = entries[verdict.failed_index]
        print(
            f"  entry {verdict.failed_index}: {entry.get('event')} at {entry.get('ts')}",
            file=sys.stderr,
        )
    return 1


def cmd_heads(args: argparse.Namespace) -> int:
    _, heads = _load(args)
    if not heads:
        print("no heads published")
        return 1
    for idx in sorted(heads):
        print(f"  idx {idx:>6}  {heads[idx]}")

    if args.server_key:
        from alerting.clients.session import open_api, unlock

        public = public_key_from_b64u(args.server_key)
        stored = unlock(args)
        with open_api(args, stored) as api:
            head = api.get("/v1/audit/head")
        payload = {"idx": head["idx"], "head": head["head"], "ts": head["ts"]}
        ok = verify_signature(DOMAIN_AUDIT_HEAD, payload, head["signature"], public)
        print(f"\nlatest head signature: {'valid' if ok else 'INVALID'}")
        return 0 if ok else 1
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """What happened, reconstructed from the chain alone."""
    entries, heads = _load(args)
    verdict = verify_chain(entries, expected_heads=heads)
    print(
        f"chain: {'intact' if verdict.ok else 'BROKEN at ' + str(verdict.failed_index)}"
        f"  ({verdict.checked} entries)\n"
    )

    counts = Counter(entry["event"] for entry in entries)
    print("events:")
    for event, count in sorted(counts.items()):
        print(f"  {event:<28} {count}")

    if args.order_id:
        print(f"\ntimeline for {args.order_id}:")
        for entry in entries:
            if entry["data"].get("order_id") != args.order_id:
                continue
            detail = {
                k: v
                for k, v in entry["data"].items()
                if k not in {"order_id"} and v not in (None, [], "")
            }
            print(f"  [{entry['idx']:>4}] {entry['ts']}  {entry['event']:<24} {detail}")

    # `order.dispatched` is also written when an order is REFUSED, with
    # accepted=False -- so counting the event counted forged and replayed attempts as
    # dispatches, and overstated what the system had actually sent.
    launches = [
        e
        for e in entries
        if e["event"] == "order.dispatched" and e["data"].get("accepted") is not False
    ]
    refused = [
        e
        for e in entries
        if e["event"] == "order.dispatched" and e["data"].get("accepted") is False
    ]
    cancels = [e for e in entries if e["event"] == "cancel.issued"]
    drills = [e for e in launches if e["data"].get("drill")]
    print(f"\norders: {len(launches)} dispatched ({len(drills)} drills), {len(cancels)} stood down")
    if refused:
        print(f"        {len(refused)} refused before dispatch")

    _print_main_metric(entries, args.order_id)

    # A launch -> cancel -> launch cycle inside ten minutes is worth a human look:
    # it is what a coerced or mistaken stand-down would look like.
    suspicious = _relaunch_cycles(entries)
    if suspicious:
        print("\nreview: rapid launch/cancel/launch cycles")
        for order_id, seconds in suspicious:
            print(f"  {order_id} re-issued {seconds}s after a stand-down")
    return 0 if verdict.ok else 1


def _print_main_metric(entries: list[dict[str, Any]], order_id: str) -> None:
    """The metric docs/06 §9 and docs/07 §2 both call the main one.

    They told the reader to get it from this command, and this command did not print
    it -- so a duty officer was asked to watch a number no tool produced, and to
    judge by it whether the system was rotting.

    Reported per order rather than averaged across them: a drill with eight people
    and one with eight hundred are not the same measurement, and one number over both
    would hide the trend the metric exists to show.
    """
    # Drills are what docs/07 measures, but docs/06 §9 lists this as a continuous
    # duty check -- so the default is the most recent dispatches, drill or not.
    wanted = [order_id] if order_id else order_ids(entries)[-5:]
    if not wanted:
        return

    share = int(MAIN_METRIC_SHARE * 100)
    print(f"\nquorum -> {share}% acknowledged (the main metric):")
    for candidate in wanted:
        timing = ack_timing(entries, candidate)
        if timing.quorum_at is None:
            print(f"  {candidate}  never reached quorum")
            continue

        answered = f"{timing.acknowledged}"
        if timing.recipients is not None:
            answered += f"/{timing.recipients}"
        median = f"{timing.median_s}s" if timing.median_s is not None else "--"

        if timing.known:
            headline = f"{timing.share_s}s"
        elif timing.recipients is None:
            # An order dispatched before the recipient count was recorded. Saying 0
            # would make the worst case look like the best one.
            headline = "unknown (chain has no recipient count)"
        else:
            headline = f"not reached ({timing.acknowledged} of {timing.recipients})"
        print(f"  {candidate}  {headline:<44} median {median}  answered {answered}")


def _relaunch_cycles(entries: list[dict[str, Any]], window_s: int = 600) -> list[tuple[str, int]]:
    cancels = {
        entry["data"].get("cancels"): entry["ts"]
        for entry in entries
        if entry["event"] == "cancel.issued"
    }
    out: list[tuple[str, int]] = []
    for entry in entries:
        if entry["event"] != "order.dispatched":
            continue
        for cancelled_id, cancelled_at in cancels.items():
            gap = entry["ts"] - cancelled_at
            if 0 < gap <= window_s:
                out.append((str(cancelled_id), gap))
    return out


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="alerting-auditor")
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--server", default="http://127.0.0.1:8080")
    shared.add_argument(
        "--dsn",
        help="read a PostgreSQL database directly (operator path; prefer --file)",
    )
    shared.add_argument("--file", help="read a previously pulled chain")
    # Needed only for `--server`: reading the chain over HTTP is a signed request like
    # any other, made with the auditor's own key. `--file` and `--dsn` need neither.
    shared.add_argument("--home", type=pathlib.Path, default=DEFAULT_DIR)
    shared.add_argument("--person", default="", help="your person id, for --server")
    shared.add_argument("--passphrase", help="key passphrase (prompted if omitted)")
    sub = parser.add_subparsers(dest="command", required=True)

    pull = sub.add_parser("pull", parents=[shared], help="download the chain")
    pull.add_argument("--out")
    pull.set_defaults(func=cmd_pull)

    verify = sub.add_parser("verify", parents=[shared], help="recompute and check")
    verify.add_argument(
        "--ignore-heads",
        action="store_true",
        help="check internal linkage only (a rewritten tail then goes undetected)",
    )
    verify.add_argument(
        "--heads-dir",
        help="check against head files published out of band instead of the database's own",
    )
    verify.set_defaults(func=cmd_verify)

    heads = sub.add_parser("heads", parents=[shared], help="list published heads")
    heads.add_argument("--server-key", default="", help="verify the latest head signature")
    heads.set_defaults(func=cmd_heads)

    report = sub.add_parser("report", parents=[shared], help="summarize an incident")
    report.add_argument("--order-id", default="")
    report.set_defaults(func=cmd_report)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result: int = args.func(args)
        return result
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
