"""Server entry point: ``alerting-server``.

There was none. The only documented way to start the server was
``uvicorn alerting.server.app:create_app --factory`` from the repository root, with
no proxy headers, no graceful-shutdown timeout, and every path resolved relative to
whatever directory the command happened to run in.

This exists so that a systemd unit has one command to call, so the uvicorn flags a
deployment needs are set in one place rather than remembered per host, and so a
misconfiguration is reported as a clear line of text instead of a traceback.
"""

from __future__ import annotations

import argparse
import logging
import pathlib
import re
import sys
from typing import Any

from alerting.server.config import Settings
from alerting.server.logging_config import configure as configure_logging

log = logging.getLogger("alerting.server.cli")

#: Long enough for an in-flight dispatch and the shutdown sequence in
#: ``AppServices.aclose`` (close sockets, drain the escalation tick, publish a final
#: audit head). The unit's ``TimeoutStopSec`` must exceed this.
GRACEFUL_SHUTDOWN_S = 30

#: Keeps an idle executor socket alive through middleboxes. nginx's read timeout
#: alone is not enough — an alert stream is idle for hours by design.
WS_PING_INTERVAL_S = 20.0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="alerting-server",
        description="Run the alerting server. Configuration comes from the "
        "environment; see docs/09-deployment.md.",
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="serve",
        choices=["serve", "migrate", "import-root"],
        help="serve (default), or apply pending database migrations and exit. "
        "`migrate` connects as the owner role and is meant to run from a oneshot "
        "unit before the service, not from the service itself. `import-root` moves "
        "the organisation to a new root key from the custodians' answer file.",
    )
    parser.add_argument(
        "answer",
        nargs="?",
        type=pathlib.Path,
        help="import-root: the custodians' answer file (a migration)",
    )
    parser.add_argument(
        "--fingerprint",
        default="",
        help="import-root: the new root's fingerprint, typed from the custodians' card",
    )
    parser.add_argument("--host", default="127.0.0.1", help="bind address")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--forwarded-allow-ips",
        default="",
        help="comma-separated proxy addresses trusted for X-Forwarded-*. Required "
        "when running behind nginx; without it client addresses in logs are the "
        "proxy's.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="number of worker processes (default 1). Safe since the sequence "
        "counter, the replay window, the siren's dedupe and the escalation ladder "
        "moved into the database; before that, two workers meant two replay windows "
        "and two climbers.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate configuration and exit without serving",
    )
    return parser


def services_of(app: Any) -> Any:
    """The ``AppServices`` hanging off a built app."""
    return app.state.alerting


def redact_dsn(dsn: str) -> str:
    """Strip the password before a connection string reaches the journal.

    The startup banner is the first thing anyone reads during an incident, and it is
    also the first thing that gets pasted into a ticket.
    """
    return re.sub(r"(?<=:)[^:@/]*(?=@)", "***", dsn)


def _describe_settings(settings: Settings) -> str:
    """What this node will actually do, for the first line in the journal.

    Every value here has bitten somebody: a relative database path silently creating
    an empty database, a wordlist that was not found, stub channels reporting delivery.
    """
    return "\n".join(
        [
            f"  org            : {settings.org_id}",
            f"  database       : {redact_dsn(settings.dsn_file or settings.dsn)}",
            f"  wordlist       : {settings.wordlist_path}",
            f"  escalation     : {settings.escalation_config}",
            f"  heads / spool  : {settings.heads_dir} / {settings.spool_dir}",
            f"  drill sites    : {sorted(settings.drill_enabled_sites) or 'none'}",
            f"  stub channels  : {'ALLOWED' if settings.allow_stub_channels else 'refused'}",
            "  http auth      : signed requests, verified against the directory",
            f"  audit heads    : {'signed' if settings.server_key_file else 'UNSIGNED'}",
        ]
    )


def _migrate(settings: Settings) -> int:
    """Apply pending migrations and exit.

    Deliberately not part of starting the server: see the note in
    ``AppServices.__init__``. The DSN this reads must belong to the *owner* role,
    which is the only one allowed to change the schema.
    """
    import psycopg
    from psycopg.rows import dict_row

    from alerting.server.db import migrate

    try:
        dsn = settings.load_dsn()
    except (RuntimeError, FileNotFoundError, PermissionError) as exc:
        log.error("%s", exc)
        return 2
    log.info("migrating %s", redact_dsn(dsn))
    try:
        with psycopg.connect(dsn, row_factory=dict_row, autocommit=True) as connection:
            done = migrate.apply(connection)
            version = migrate.schema_version(connection)
    except Exception as exc:
        log.error("migration failed: %s", exc)
        return 1
    if done:
        log.info("applied %s; schema is now at version %d", done, version)
    else:
        log.info("nothing to apply; schema is at version %d", version)
    return 0


class _ImportRaced(Exception):
    """Another publication landed between the version check and the write."""


def _import_root(settings: Settings, answer_path: pathlib.Path | None, typed: str) -> int:
    """Move this server to the custodians' new root key.

    The one step that cannot go through the panel or the API, on purpose: it changes
    what the server trusts, so it must not be reachable by anyone who only holds a
    login. It runs on the server, by its administrator, with the server stopped.

    Checks, in order: the fingerprint the administrator typed from the custodians'
    printed card matches the answer's root key (a file swapped on its way here is
    caught by a person, not by the file); the bundles verify under that key; their
    versions exceed everything stored. Then both are stored and the change recorded
    in the audit chain. ``ALERTING_ROOT_PUBKEY`` is changed by the caller
    (``docker/rotate-root.sh``) afterwards.
    """
    import json

    from alerting import custody
    from alerting.core.audit_chain import Event
    from alerting.core.clock import SystemClock
    from alerting.core.directory import Directory
    from alerting.core.policy import Policy
    from alerting.core.signing import public_key_from_b64u
    from alerting.server.db import migrate
    from alerting.server.db.pool import open_pool
    from alerting.server.db.repo import Repo
    from alerting.server.services.audit_service import AuditService

    if answer_path is None or not answer_path.exists():
        log.error("import-root needs the answer file")
        return 2
    answer = json.loads(answer_path.read_text(encoding="utf-8"))
    try:
        bundles = custody.read_answer(answer, org_id=settings.org_id)
    except custody.CustodyError as exc:
        log.error("%s", exc)
        return 2
    new_root = str(answer.get("root_public_key", ""))
    expected = custody.fingerprint(new_root)
    if "".join(typed.split()).lower() != "".join(expected.split()).lower():
        log.error(
            "the fingerprint typed does not match the answer's root key (%s). Compare it "
            "with the custodians' printed card; do not proceed if they differ",
            expected,
        )
        return 2
    if new_root == settings.root_public_key:
        log.error("this server already trusts that root key; publish the answer in the panel")
        return 2
    if set(bundles) != {"directory", "policy"}:
        log.error("a migration answer carries both the directory and the policy")
        return 2
    root = public_key_from_b64u(new_root)
    try:
        org = settings.org_id
        directory = Directory.load(bundles["directory"], root_public_key=root, org_id=org)
        policy = Policy.load(bundles["policy"], root_public_key=root, org_id=org)
    except Exception as exc:
        log.error("the answer does not verify under its own root key: %s", exc)
        return 2

    pool = open_pool(settings.load_dsn())
    try:
        with pool.connection() as connection:
            migrate.verify(connection)
        repo = Repo(pool)
        clock = SystemClock()
        now = clock.now()
        pairs = (
            ("directory", directory, bundles["directory"]),
            ("policy", policy, bundles["policy"]),
        )
        # Both versions checked before anything is written, then both written in one
        # transaction: half a migration -- a directory under the new root, a policy
        # still under the old -- would leave a server that verifies neither, and a
        # retry refused because the directory is no longer newer.
        seen: dict[str, int] = {}
        for kind, loaded, _ in pairs:
            current = repo.latest_bundle(kind)
            seen[kind] = int(current["payload"]["version"]) if current else 0
            if loaded.version <= seen[kind]:
                log.error(
                    "%s version %d is not above the stored %d", kind, loaded.version, seen[kind]
                )
                return 2
        try:
            with repo.tx():
                for kind, loaded, bundle in pairs:
                    if not repo.put_bundle_if_latest(
                        kind, loaded.version, bundle, now, expected_latest=seen[kind]
                    ):
                        raise _ImportRaced(kind)
        except _ImportRaced as exc:
            log.error("%s changed while importing; nothing was stored. Run again", exc)
            return 1
        raw_key = settings.load_server_key()
        from alerting.core.signing import private_key_from_b64u

        audit = AuditService(
            repo,
            clock,
            server_key=private_key_from_b64u(raw_key) if raw_key else None,
            spool_dir=settings.spool_dir,
            heads_dir=settings.heads_dir,
        )
        audit.append(
            Event.ROOT_ROTATED,
            {
                "previous_fingerprint": (
                    custody.fingerprint(settings.root_public_key)
                    if settings.root_public_key
                    else None
                ),
                "fingerprint": expected,
                "directory_version": directory.version,
                "policy_version": policy.version,
            },
        )
    finally:
        pool.close()
    print(f"ALERTING_ROOT_PUBKEY={new_root}")
    log.info(
        "imported directory v%d and policy v%d under root %s; set ALERTING_ROOT_PUBKEY and restart",
        directory.version,
        policy.version,
        expected,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        settings = Settings.from_env()
    except ValueError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    configure_logging(settings.log_level, json_output=settings.log_json)

    if args.command == "migrate":
        return _migrate(settings)
    if args.command == "import-root":
        return _import_root(settings, args.answer, args.fingerprint)

    log.info("alerting server starting\n%s", _describe_settings(settings))

    # Build the app before handing control to uvicorn, so a configuration problem is
    # one readable line rather than a traceback from inside the server's startup.
    from alerting.server.app import create_app

    try:
        app = create_app(settings)
    except (RuntimeError, FileNotFoundError, PermissionError, ValueError) as exc:
        log.error("refusing to start: %s", exc)
        return 1

    if args.check:
        log.info("configuration is valid; not serving (--check)")
        services_of(app).close()
        return 0

    import uvicorn

    target: Any = app
    factory = False
    if args.workers > 1:
        # uvicorn forks workers from an import string, not from an object, so each
        # one builds its own services. The instance built above was only ever a
        # configuration check -- hand back its pool and its leader lock rather than
        # leaving them held by a parent process that will not serve a request.
        services_of(app).close()
        target, factory = "alerting.server.app:create_app", True
        log.info("serving with %d workers", args.workers)

    uvicorn.run(
        target,
        factory=factory,
        workers=args.workers,
        host=args.host,
        port=args.port,
        # Set here and not per host: behind a proxy these are not optional, and
        # forgetting them is invisible until somebody reads the logs during an
        # incident and sees the proxy's address for every client.
        proxy_headers=bool(args.forwarded_allow_ips),
        forwarded_allow_ips=args.forwarded_allow_ips or None,
        ws_ping_interval=WS_PING_INTERVAL_S,
        ws_ping_timeout=WS_PING_INTERVAL_S,
        timeout_graceful_shutdown=GRACEFUL_SHUTDOWN_S,
        # Logging is already configured; uvicorn must not replace it.
        log_config=None,
        access_log=False,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
