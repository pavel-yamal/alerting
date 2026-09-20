-- Reference schema. Explicit SQL rather than an ORM: a system whose whole point is
-- provable history should not hide its writes behind a mapper.
--
-- Note the split that matters for both privacy and security:
--   * audit_log  -- hash-chained, insert-only, PSEUDONYMS ONLY
--   * contacts   -- names, phone numbers, wake keys; ordinary deletable rows
-- The chain is deliberately undeletable, so personal data must never enter it.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- Root-signed bundles as published to clients. Kind is 'directory' or 'policy'.
CREATE TABLE IF NOT EXISTS bundles (
    kind         TEXT    NOT NULL,
    version      INTEGER NOT NULL,
    bundle_json  TEXT    NOT NULL,
    published_at INTEGER NOT NULL,
    PRIMARY KEY (kind, version)
);

-- Personal data. Kept out of the audit chain on purpose; erasable on request.
CREATE TABLE IF NOT EXISTS contacts (
    person_id   TEXT PRIMARY KEY,
    name        TEXT    NOT NULL,
    phone       TEXT    NOT NULL DEFAULT '',
    site        TEXT    NOT NULL DEFAULT '',
    groups_csv  TEXT    NOT NULL DEFAULT '',
    wake_key    TEXT    NOT NULL DEFAULT '',
    role        TEXT    NOT NULL DEFAULT 'executor',
    active      INTEGER NOT NULL DEFAULT 1
);

-- A proposal is an unsigned-or-partially-signed order. It is never actionable.
CREATE TABLE IF NOT EXISTS proposals (
    order_id     TEXT PRIMARY KEY,
    stream_id    TEXT    NOT NULL,
    seq          INTEGER NOT NULL,
    payload_json TEXT    NOT NULL,
    created_at   INTEGER NOT NULL,
    created_by   TEXT    NOT NULL,
    status       TEXT    NOT NULL DEFAULT 'open',  -- open | dispatched | abandoned
    UNIQUE (stream_id, seq)
);

-- Server-observed arrival time is the only non-forgeable timing evidence we have,
-- because signature entries deliberately carry no self-asserted timestamp.
CREATE TABLE IF NOT EXISTS signatures (
    order_id    TEXT    NOT NULL REFERENCES proposals(order_id),
    key_id      TEXT    NOT NULL,
    sig         TEXT    NOT NULL,
    observed_at INTEGER NOT NULL,
    PRIMARY KEY (order_id, key_id)
);

CREATE TABLE IF NOT EXISTS orders (
    order_id      TEXT PRIMARY KEY,
    envelope_json TEXT    NOT NULL,
    dispatched_at INTEGER NOT NULL,
    drill         INTEGER NOT NULL,
    severity      TEXT    NOT NULL,
    scenario      TEXT    NOT NULL,
    cancels       TEXT,
    order_digest  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS dispatches (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id     TEXT    NOT NULL REFERENCES orders(order_id),
    person_id    TEXT    NOT NULL,
    channel      TEXT    NOT NULL,
    attempted_at INTEGER NOT NULL,
    status       TEXT    NOT NULL,  -- sent | failed | queued
    detail       TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_dispatches_order ON dispatches(order_id);

CREATE TABLE IF NOT EXISTS acks (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id      TEXT    NOT NULL REFERENCES orders(order_id),
    person_id     TEXT    NOT NULL,
    device_key_id TEXT    NOT NULL,
    status        TEXT    NOT NULL,
    at            INTEGER NOT NULL,
    ack_json      TEXT    NOT NULL,
    valid         INTEGER NOT NULL,
    reasons       TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_acks_order ON acks(order_id);

CREATE TABLE IF NOT EXISTS escalation_state (
    order_id  TEXT    NOT NULL REFERENCES orders(order_id),
    person_id TEXT    NOT NULL,
    rung      INTEGER NOT NULL,
    fired_at  INTEGER NOT NULL,
    PRIMARY KEY (order_id, person_id, rung)
);

-- Insert-only. The triggers below stop a careless admin; the hash chain and the
-- published heads are what stop someone with real database access.
CREATE TABLE IF NOT EXISTS audit_log (
    idx        INTEGER PRIMARY KEY,
    ts         INTEGER NOT NULL,
    prev       TEXT    NOT NULL,
    event      TEXT    NOT NULL,
    data_json  TEXT    NOT NULL,
    entry_hash TEXT    NOT NULL
);

CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TABLE IF NOT EXISTS audit_heads (
    idx       INTEGER PRIMARY KEY,
    head      TEXT    NOT NULL,
    ts        INTEGER NOT NULL,
    signature TEXT    NOT NULL DEFAULT ''
);
