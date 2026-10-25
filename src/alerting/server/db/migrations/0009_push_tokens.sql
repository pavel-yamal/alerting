-- Devices of decision-makers that receive push notifications from the app.
--
-- The token is a secret of the same order as a Web Push endpoint: whoever holds it
-- can write into that person's notification shade. It is never returned by the API;
-- lists show only its tail.
--
-- Keyed by the token itself: on a shared phone the row moves to the new owner,
-- otherwise the previous one would keep receiving someone else's notifications.
CREATE TABLE push_tokens (
    token            text    PRIMARY KEY,
    person_id        text    NOT NULL,
    platform         text    NOT NULL CHECK (platform IN ('ios', 'android')),
    -- iOS only: where this token was last accepted. A build from Xcode gets a
    -- sandbox token, TestFlight and the App Store a production one.
    apns_env         text    CHECK (apns_env IN ('production', 'sandbox')),
    device_label     text    NOT NULL DEFAULT '',
    app_version      text    NOT NULL DEFAULT '',
    created_at       bigint  NOT NULL,
    last_seen_at     bigint  NOT NULL,
    last_success_at  bigint,
    last_error       text,
    failure_count    integer NOT NULL DEFAULT 0
);
CREATE INDEX push_tokens_person ON push_tokens (person_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON push_tokens TO alerting_app;
