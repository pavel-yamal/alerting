"""SQLite connection handling."""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = Path(__file__).with_name("schema.sql")

#: How long a writer waits for a busy database before giving up.
BUSY_TIMEOUT_MS = 5000


def connect(path: str) -> sqlite3.Connection:
    """Open a connection with row access by name and foreign keys on."""
    connection = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    # Without this a second writer gets an immediate "database is locked" rather than
    # waiting. One process today, but a stray `--workers 2` in a unit file would turn
    # a brief contention into a failed dispatch.
    connection.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    return connection


def migrate(connection: sqlite3.Connection) -> None:
    """Apply the schema. Idempotent — every statement is CREATE ... IF NOT EXISTS."""
    connection.executescript(SCHEMA.read_text())
