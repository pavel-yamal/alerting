"""Entry point: ``alerting-panel``.

Runs the duty officer's web panel. It is a client of the alerting server, with the
same standing as ``alerting-approver``: it signs with the keys found under
``--homes``, one directory per person, laid out as ``scripts/org_init.py`` writes
them.
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
        "--host",
        default="127.0.0.1",
        help="bind address. The panel holds unlocked keys: keep it on localhost",
    )
    parser.add_argument("--port", type=int, default=8090)
    args = parser.parse_args(argv)

    configure_logging(os.environ.get("ALERTING_LOG_LEVEL", "INFO"), json_output=False)

    import uvicorn

    from alerting.clients.panel.app import create_panel

    app = create_panel(homes=args.homes, server_url=args.server)
    uvicorn.run(app, host=args.host, port=args.port, log_config=None, access_log=False)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
