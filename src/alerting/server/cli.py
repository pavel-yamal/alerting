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
import sys

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
        "--check",
        action="store_true",
        help="validate configuration and exit without serving",
    )
    return parser


def _describe_settings(settings: Settings) -> str:
    """What this node will actually do, for the first line in the journal.

    Every value here has bitten somebody: a relative database path silently creating
    an empty database, a wordlist that was not found, stub channels reporting delivery.
    """
    return "\n".join(
        [
            f"  org            : {settings.org_id}",
            f"  database       : {settings.db_path}",
            f"  wordlist       : {settings.wordlist_path}",
            f"  escalation     : {settings.escalation_config}",
            f"  heads / spool  : {settings.heads_dir} / {settings.spool_dir}",
            f"  drill sites    : {sorted(settings.drill_enabled_sites) or 'none'}",
            f"  stub channels  : {'ALLOWED' if settings.allow_stub_channels else 'refused'}",
            f"  http auth      : {'OPEN' if settings.allow_unauthenticated else 'shared key'}",
            f"  audit heads    : {'signed' if settings.server_key_file else 'UNSIGNED'}",
        ]
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        settings = Settings.from_env()
    except ValueError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    configure_logging(settings.log_level, json_output=settings.log_json)
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
        return 0

    import uvicorn

    uvicorn.run(
        app,
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
