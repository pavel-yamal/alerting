-- Channel heartbeats.
--
-- Four documents described this as working and it did not exist. It is named in the
-- threat model as the measure against attacks 4 and 5 -- a suppressed order and a
-- fully compromised server -- and the residual risk of suppression is accepted there
-- *on the grounds that heartbeats would reveal it*. That made the acceptance
-- unfounded, which is a worse defect than the missing feature.
--
-- One row per (channel, node), not per channel. A probe is a statement about what
-- ONE node could reach at one moment: the WebSocket channel's answer depends on
-- which node the executors' sockets landed on, and a provider may be reachable from
-- one node and firewalled from another. Collapsing that into a single row per
-- channel would hide exactly the partial failure worth seeing.
--
-- Note what is NOT here: heartbeat results do not go into the audit chain. It is
-- append-only and undeletable, and a probe every minute per channel per node would
-- bury an incident under millions of rows saying nothing happened. Only transitions
-- are audited -- see `channel.silent` and `channel.recovered`.
CREATE TABLE channel_heartbeats (
    channel              text    NOT NULL,
    node_id              text    NOT NULL,
    status               text    NOT NULL,  -- ok | failed | stub
    detail               text    NOT NULL DEFAULT '',
    last_at              bigint  NOT NULL,
    last_ok_at           bigint,
    consecutive_failures integer NOT NULL DEFAULT 0,
    PRIMARY KEY (channel, node_id)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON channel_heartbeats TO alerting_app;
