-- State that used to live in one Python process, moved into the database.
--
-- Four things were held in memory, and each of them breaks the moment a second
-- process exists -- which today means a stray `--workers 2` in a unit file, and
-- tomorrow means a second node:
--
--   * the anti-replay window   -> stream_seq
--   * the proposal seq counter -> streams
--   * the siren's dedupe and rate limit -> siren_activations
--   * the escalation ladder's role/group notifications -> escalation_extra
--
-- The first is the security-critical one: with a per-process window, a replayed
-- order is rejected by the process that has seen it and accepted by the one that
-- has not. Whoever can pick which worker answers gets replay for free.

-- Sequence allocation for proposals. One row per stream, bumped with
-- ON CONFLICT DO UPDATE ... RETURNING, so allocating a number is a single atomic
-- statement rather than SELECT MAX(seq) followed by an insert.
--
-- Separate from stream_seq below on purpose: a number handed out here may belong to
-- a proposal that is never signed and never dispatched.
CREATE TABLE streams (
    stream_id text   PRIMARY KEY,
    next_seq  bigint NOT NULL
);

-- Every (stream, seq) that has actually been dispatched. The primary key IS the
-- anti-replay mechanism: claiming a pair is one atomic insert, and the loser of a
-- race learns it lost.
--
-- order_id is stored so a retry of the *same* order can be told apart from a replay
-- of a different one carrying the same number.
CREATE TABLE stream_seq (
    stream_id text   NOT NULL,
    seq       bigint NOT NULL,
    order_id  text   NOT NULL,
    seen_at   bigint NOT NULL,
    PRIMARY KEY (stream_id, seq)
);
CREATE INDEX idx_stream_seq_order ON stream_seq(order_id);

-- One siren activation per site per order, and the timestamp the rate limit reads.
-- A siren that sounds twice for one order is not a cosmetic bug: people outside have
-- no way to tell a repeat from a second emergency.
CREATE TABLE siren_activations (
    site     text   NOT NULL,
    order_id text   NOT NULL,
    pattern  text   NOT NULL,
    fired_at bigint NOT NULL,
    PRIMARY KEY (site, order_id)
);
CREATE INDEX idx_siren_site_time ON siren_activations(site, fired_at DESC);

-- Claims for the escalation rungs that notify a ROLE or a GROUP rather than the
-- individuals who have not acknowledged.
--
-- escalation_state already latches per person, but two processes climbing the same
-- ladder claim different subsets of the outstanding people and then BOTH run the
-- role and group notifications attached to that rung -- so the duty officer is
-- called twice and the alternates are paged twice. A separate table because the
-- target is a role or group name, not a person_id, and overloading a person_id
-- column with a reserved prefix is the kind of shortcut that is wrong exactly once.
CREATE TABLE escalation_extra (
    order_id text    NOT NULL REFERENCES orders(order_id),
    rung     integer NOT NULL,
    target   text    NOT NULL,  -- 'role:duty_officer' | 'group:alternates'
    fired_at bigint  NOT NULL,
    PRIMARY KEY (order_id, rung, target)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON
    streams, stream_seq, siren_activations, escalation_extra
    TO alerting_app;
