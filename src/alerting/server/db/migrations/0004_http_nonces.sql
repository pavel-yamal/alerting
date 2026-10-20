-- Per-request replay protection for signed HTTP requests.
--
-- The WebSocket handshake does not need this: the server mints the nonce and holds
-- it in the handler's stack frame, so a captured handshake cannot be replayed onto a
-- new socket and nothing has to be stored. An HTTP request has no prior round trip,
-- so the nonce has to come from the client and the server has to remember it.
--
-- A dict in the process would be wrong on day one, not later: the unit already runs
-- `--workers 2`, and this is exactly the argument phase 3 wrote down in
-- core/replay.py -- a window held in one process's memory is not a window, because
-- the worker that has not seen the request accepts it.
--
-- Bounded by `expires_at` rather than by count: a row is only useful for as long as
-- the signature it guards could still be inside the freshness window, so anything
-- older is deleted. Without the pruning this table grows forever, which is why the
-- index below exists.
CREATE TABLE http_nonces (
    key_id     text   NOT NULL,
    nonce      text   NOT NULL,
    expires_at bigint NOT NULL,
    PRIMARY KEY (key_id, nonce)
);
CREATE INDEX idx_http_nonces_expiry ON http_nonces(expires_at);

-- DELETE is granted here and nowhere near audit_log: pruning spent nonces is
-- housekeeping, and a nonce row carries no evidence.
GRANT SELECT, INSERT, DELETE ON http_nonces TO alerting_app;
