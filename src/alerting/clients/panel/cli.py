"""Entry point: ``alerting-panel``.

Runs the duty officer's web panel, a client of the alerting server.

With ``--org`` and ``--root-key`` people sign in with a key kept in their own browser
(docs/adr/0012). ``--server-keys`` additionally allows the demo login with keys under
``--homes`` -- unlocked in this process, which is what the Docker stand uses and what
a real installation should not.
"""

from __future__ import annotations

import argparse
import os
import pathlib

from alerting.server.logging_config import configure as configure_logging


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="alerting-panel", description=__doc__)
    parser.add_argument(
        "--server",
        default=os.environ.get("ALERTING_PANEL_SERVER", "http://127.0.0.1:8080"),
        help="alerting server URL (or ALERTING_PANEL_SERVER)",
    )
    parser.add_argument(
        "--homes",
        type=pathlib.Path,
        default=pathlib.Path(os.environ.get("ALERTING_PANEL_HOMES", "var/clients")),
        help="directory holding one key home per person (or ALERTING_PANEL_HOMES)",
    )
    parser.add_argument(
        "--org",
        default=os.environ.get("ALERTING_PANEL_ORG") or None,
        help="organisation id, for device-key login (or ALERTING_PANEL_ORG)",
    )
    parser.add_argument(
        "--root-key",
        default=os.environ.get("ALERTING_PANEL_ROOT_PUBKEY") or None,
        help="the org root PUBLIC key, from the custodians' card (or ALERTING_PANEL_ROOT_PUBKEY)",
    )
    parser.add_argument(
        "--state",
        type=pathlib.Path,
        default=pathlib.Path(os.environ.get("ALERTING_PANEL_STATE", "var/panel")),
        help="where verified bundles are cached for device-key sessions",
    )
    parser.add_argument(
        "--server-keys",
        action="store_true",
        default=os.environ.get("ALERTING_PANEL_SERVER_KEYS", "") in ("1", "true", "yes"),
        help="also allow the demo login with keys held under --homes (stand only)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="bind address. With --server-keys it holds unlocked keys: keep it on localhost",
    )
    parser.add_argument("--port", type=int, default=8090)
    args = parser.parse_args(argv)

    configure_logging(os.environ.get("ALERTING_LOG_LEVEL", "INFO"), json_output=False)

    import uvicorn

    from alerting.clients.panel.app import create_panel

    if not args.org and not args.server_keys:
        parser.error("nobody could sign in: give --org and --root-key, or --server-keys")
    app = create_panel(
        homes=args.homes,
        server_url=args.server,
        org_id=args.org,
        root_public_key=args.root_key,
        state_dir=args.state,
        server_keys=args.server_keys,
    )
    uvicorn.run(app, host=args.host, port=args.port, log_config=None, access_log=False)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
