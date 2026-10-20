"""Entry point: ``alerting-mobile``.

The executor's client with a phone-sized web page. It signs with the keys found
under ``--homes``, one directory per person, as ``scripts/org_init.py`` writes them.
"""

from __future__ import annotations

import argparse
import os
import pathlib

from alerting.server.logging_config import configure as configure_logging


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="alerting-mobile", description=__doc__)
    parser.add_argument(
        "--server",
        default=os.environ.get("ALERTING_MOBILE_SERVER", "http://127.0.0.1:8080"),
        help="alerting server URL (or ALERTING_MOBILE_SERVER)",
    )
    parser.add_argument(
        "--homes",
        type=pathlib.Path,
        default=pathlib.Path(os.environ.get("ALERTING_MOBILE_HOMES", "var/clients")),
        help="directory holding one key home per person (or ALERTING_MOBILE_HOMES)",
    )
    parser.add_argument(
        "--wordlist",
        type=pathlib.Path,
        default=os.environ.get("ALERTING_WORDLIST") or None,
        help="wake-code wordlist, to show the words an SMS must carry (or ALERTING_WORDLIST)",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8091)
    args = parser.parse_args(argv)

    configure_logging(os.environ.get("ALERTING_LOG_LEVEL", "INFO"), json_output=False)

    import uvicorn

    from alerting.clients.mobile.app import create_mobile

    app = create_mobile(homes=args.homes, server_url=args.server, wordlist=args.wordlist)
    uvicorn.run(app, host=args.host, port=args.port, log_config=None, access_log=False)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
