-- Initial schema. Explicit SQL rather than an ORM: a system whose whole point is
-- provable history should not hide its writes behind a mapper (ADR 0002, ADR 0006).
--
-- The split that matters for both privacy and security:
--   * audit_log  -- hash-chained, insert-only, PSEUDONYMS ONLY
--   * contacts   -- names, phone numbers, wake keys; ordinary deletable rows
-- The chain is deliberately undeletable, so personal data must never enter it.
--
-- Two conventions this file follows deliberately:
--
--   * every Unix-second column is `bigint`, never `integer`. PostgreSQL's integer is
--     four bytes and would stop accepting timestamps in 2038 -- SQLite's was 64-bit,
--     so a literal port of the old schema would have narrowed silently.
--   * every *_json column is `text`, never `json`/`jsonb`. psycopg parses json
--     columns into Python objects, so `json.loads` would receive a dict; and jsonb
--     rewrites what it stores (key order, whitespace, numeric literals). These
--     columns feed the hash-chain verifier, where "probably still hashes the same"
--     is the wrong standard.

-- Root-signed bundles as published to clients. Kind is 'directory' or 'policy'.
CREATE TABLE bundles (
    kind         text   NOT NULL,
    version      bigint NOT NULL,
    bundle_json  text   NOT NULL,
    published_at bigint NOT NULL,
    PRIMARY KEY (kind, version)
);

-- Personal data. Kept out of the audit chain on purpose; erasable on request.
CREATE TABLE contacts (
    person_id   text    PRIMARY KEY,
    name        text    NOT NULL,
    phone       text    NOT NULL DEFAULT '',
    site        text    NOT NULL DEFAULT '',
    groups_csv  text    NOT NULL DEFAULT '',
    wake_key    text    NOT NULL DEFAULT '',
    role        text    NOT NULL DEFAULT 'executor',
    active      boolean NOT NULL DEFAULT true
);

-- A proposal is an unsigned-or-partially-signed order. It is never actionable.
CREATE TABLE proposals (
    order_id     text   PRIMARY KEY,
    stream_id    text   NOT NULL,
    seq          bigint NOT NULL,
    payload_json text   NOT NULL,
    created_at   bigint NOT NULL,
    created_by   text   NOT NULL,
    status       text   NOT NULL DEFAULT 'open',  -- open | dispatched | abandoned
    UNIQUE (stream_id, seq)
);

-- Server-observed arrival time is the only non-forgeable timing evidence we have,
-- because signature entries deliberately carry no self-asserted timestamp.
CREATE TABLE signatures (
    order_id    text   NOT NULL REFERENCES proposals(order_id),
    key_id      text   NOT NULL,
    sig         text   NOT NULL,
    observed_at bigint NOT NULL,
    PRIMARY KEY (order_id, key_id)
);

CREATE TABLE orders (
    order_id      text    PRIMARY KEY,
    envelope_json text    NOT NULL,
    dispatched_at bigint  NOT NULL,
    drill         boolean NOT NULL,
    severity      text    NOT NULL,
    scenario      text    NOT NULL,
    cancels       text,
    order_digest  text    NOT NULL
);

CREATE TABLE dispatches (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    order_id     text   NOT NULL REFERENCES orders(order_id),
    person_id    text   NOT NULL,
    channel      text   NOT NULL,
    attempted_at bigint NOT NULL,
    status       text   NOT NULL,  -- sent | failed | queued | refused | stub
    detail       text   NOT NULL DEFAULT ''
);
CREATE INDEX idx_dispatches_order ON dispatches(order_id);

CREATE TABLE acks (
    id            bigint  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    order_id      text    NOT NULL REFERENCES orders(order_id),
    person_id     text    NOT NULL,
    device_key_id text    NOT NULL,
    status        text    NOT NULL,
    at            bigint  NOT NULL,
    ack_json      text    NOT NULL,
    valid         boolean NOT NULL,
    reasons       text    NOT NULL DEFAULT ''
);
CREATE INDEX idx_acks_order ON acks(order_id);

CREATE TABLE escalation_state (
    order_id  text    NOT NULL REFERENCES orders(order_id),
    person_id text    NOT NULL,
    rung      integer NOT NULL,
    fired_at  bigint  NOT NULL,
    PRIMARY KEY (order_id, person_id, rung)
);

-- Insert-only. The triggers below stop a careless admin; the REVOKE at the bottom
-- stops the application itself; and the hash chain with its externally published
-- heads is what stops someone who holds the owner role.
CREATE TABLE audit_log (
    idx        bigint PRIMARY KEY,
    ts         bigint NOT NULL,
    prev       text   NOT NULL,
    event      text   NOT NULL,
    data_json  text   NOT NULL,
    entry_hash text   NOT NULL
);

CREATE FUNCTION audit_log_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$;

CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();
-- TRUNCATE bypasses row triggers entirely, which is exactly how an append-only
-- table is usually emptied by accident.
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_append_only();

CREATE TABLE audit_heads (
    idx       bigint PRIMARY KEY,
    head      text   NOT NULL,
    ts        bigint NOT NULL,
    signature text   NOT NULL DEFAULT ''
);

-- --- privileges ----------------------------------------------------------------
--
-- Grants live in the migration, not in a one-off script: a table added by a later
-- migration without its grants is a node that starts and then fails on first use.

GRANT SELECT, INSERT, UPDATE, DELETE ON
    bundles, contacts, proposals, signatures, orders,
    dispatches, acks, escalation_state, audit_heads
    TO alerting_app;

-- The whole point. INSERT and SELECT only, and no TRUNCATE.
GRANT SELECT, INSERT ON audit_log TO alerting_app;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM alerting_app;
