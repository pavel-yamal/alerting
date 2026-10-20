-- The delivery canary.
--
-- A canary order is a real order row, and that is deliberate: an order that
-- dispatched but left nothing behind is exactly the state this system must never be
-- able to reach. So it is recorded like any other, and its presence in the audit
-- chain is what makes "the system was working at 14:00" provable.
--
-- But it must not crowd out the real ones. `EscalationWorker.tick` sweeps the 200
-- most recent orders; an hourly canary fills that window in eight days, after which
-- a genuine unacknowledged order would drop out of it and never be escalated. Hence
-- the flag, and hence `Repo.orders()` excluding it -- the escalation sweep and the
-- operator's list both mean "real orders".
ALTER TABLE orders ADD COLUMN canary boolean NOT NULL DEFAULT false;

-- Recent orders, excluding canaries: the shape the escalation sweep asks for.
CREATE INDEX idx_orders_real_recent ON orders(dispatched_at DESC, order_id DESC)
    WHERE NOT canary;

-- One row per canary run. Separate from `orders` because what is interesting here is
-- the outcome over time -- did it deliver, how long did it take -- and that question
-- should not require reading the dispatch table.
CREATE TABLE canary_runs (
    id          bigint  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    order_id    text,
    node_id     text    NOT NULL,
    started_at  bigint  NOT NULL,
    finished_at bigint  NOT NULL,
    ok          boolean NOT NULL,
    delivered   integer NOT NULL DEFAULT 0,
    detail      text    NOT NULL DEFAULT ''
);
CREATE INDEX idx_canary_runs_recent ON canary_runs(started_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON canary_runs TO alerting_app;
