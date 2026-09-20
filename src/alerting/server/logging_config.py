"""Logging configuration.

There was none: no ``basicConfig``, no ``dictConfig``, no handler anywhere, so what
an operator saw depended on whatever uvicorn happened to install.

Everything goes to stdout. Rotation and retention are journald's job on a systemd
box (``SystemMaxUse=`` in ``journald.conf``); an app-level ``RotatingFileHandler``
there is redundant machinery that only adds a second place for logs to go missing.

What must never appear in a log line, because these logs are less protected than the
database and are shipped off the host:

* **wake codes** — the code is the secret that authenticates an SMS to its recipient;
* **phone numbers and names** — personal data, see ``docs/08-personal-data.md``;
* **private keys** of any kind.

Pseudonymous ``person_id`` and ``key_id`` values are fine and are what the audit
chain uses too.
"""

from __future__ import annotations

import logging
import logging.config
from typing import Any

PLAIN_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"


class JsonFormatter(logging.Formatter):
    """Minimal structured output for hosts that ship logs somewhere.

    Deliberately hand-rolled: one formatter is not worth a dependency, and a
    dependency here would be one more thing to audit in the alerting path.
    """

    def format(self, record: logging.LogRecord) -> str:
        import json

        payload: dict[str, Any] = {
            "ts": int(record.created),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure(level: str = "INFO", *, json_output: bool = False) -> None:
    """Install the logging configuration. Idempotent."""
    formatter: dict[str, Any] = (
        {"()": f"{__name__}.JsonFormatter"}
        if json_output
        else {"format": PLAIN_FORMAT, "datefmt": "%Y-%m-%dT%H:%M:%S"}
    )
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {"default": formatter},
            "handlers": {
                "stdout": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                    "formatter": "default",
                }
            },
            "root": {"handlers": ["stdout"], "level": level.upper()},
            "loggers": {
                # Delivery attempts are the operational record an incident review
                # reads, so they stay at INFO even when the rest is turned down.
                "alerting.channel": {"level": "INFO", "propagate": True},
                # Rejected requests are a security signal, not noise.
                "alerting.auth": {"level": "INFO", "propagate": True},
                "uvicorn.access": {"level": "WARNING", "propagate": True},
            },
        }
    )
