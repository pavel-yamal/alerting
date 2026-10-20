"""Entry point: ``alerting-custodian``, on the offline laptop.

    alerting-custodian --vault /media/custodians/root-vault.json

then open http://127.0.0.1:7090 in the laptop's browser.
"""

from __future__ import annotations

import argparse
import os
import pathlib

from alerting.server.logging_config import configure as configure_logging


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="alerting-custodian", description=__doc__)
    parser.add_argument(
        "--vault",
        type=pathlib.Path,
        default=pathlib.Path(
            os.environ.get("ALERTING_CUSTODIAN_VAULT", "~/alerting-root/root-vault.json")
        ).expanduser(),
        help="the sealed root key file (created on first use)",
    )
    parser.add_argument("--port", type=int, default=7090)
    args = parser.parse_args(argv)

    configure_logging(os.environ.get("ALERTING_LOG_LEVEL", "INFO"), json_output=False)

    import uvicorn

    from alerting.clients.custodian.app import create_custodian

    print(f"Окно хранителей: http://127.0.0.1:{args.port}   (ключ: {args.vault})")
    # Localhost only, always: this process is the root key's only door.
    uvicorn.run(
        create_custodian(args.vault),
        host="127.0.0.1",
        port=args.port,
        log_config=None,
        access_log=False,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
