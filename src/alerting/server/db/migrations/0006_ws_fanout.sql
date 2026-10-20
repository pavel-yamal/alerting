-- Delivery over WebSocket across processes and nodes.
--
-- A socket lives in the memory of the process that accepted it. The order is
-- dispatched by whichever process received the last signature, or by the
-- escalation leader -- with `--workers 2`, and with two nodes behind nginx, usually
-- a different one. Before this the dispatching process looked only at its own
-- sockets and recorded `ws:failed` for a phone that was connected next door.
--
-- Three tables, all operational and none evidentiary (the evidence of what was sent
-- is `dispatches` and the audit chain, unchanged):
--
--   ws_presence      who is connected to which process, kept fresh by that process;
--   ws_relay         "deliver this order to this person", one row per hand-off,
--                    announced with NOTIFY;
--   ws_relay_result  each receiving process says how many devices it reached, and
--                    only that turns a hand-off into `sent`.

CREATE TABLE ws_presence (
    process_id  text    NOT NULL,
    person_id   text    NOT NULL,
    devices     integer NOT NULL CHECK (devices > 0),
    updated_at  bigint  NOT NULL,
    PRIMARY KEY (process_id, person_id)
);
CREATE INDEX idx_ws_presence_person ON ws_presence(person_id, updated_at);

CREATE TABLE ws_relay (
    relay_id    bigint  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    order_id    text    NOT NULL REFERENCES orders(order_id),
    person_id   text    NOT NULL,
    origin      text    NOT NULL,
    created_at  bigint  NOT NULL
);
CREATE INDEX idx_ws_relay_created ON ws_relay(created_at);

CREATE TABLE ws_relay_result (
    relay_id    bigint  NOT NULL REFERENCES ws_relay(relay_id) ON DELETE CASCADE,
    process_id  text    NOT NULL,
    delivered   integer NOT NULL,
    at          bigint  NOT NULL,
    PRIMARY KEY (relay_id, process_id)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON ws_presence, ws_relay, ws_relay_result TO alerting_app;
