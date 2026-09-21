-- Cluster-level setup, run ONCE by a superuser before the first migration.
--
-- Two roles, and the split is the whole point:
--
--   alerting_owner  owns every object and runs migrations. It is the only role
--                   that can change the shape of the database.
--   alerting_app    is what the running server connects as. On audit_log it has
--                   SELECT and INSERT and nothing else.
--
-- The triggers in the migration stop a careless UPDATE. They do NOT stop TRUNCATE,
-- which bypasses row triggers entirely -- and a statement trigger can be disabled by
-- whoever owns the table. That is why the runtime role is a different role from the
-- owner: the process that handles requests must not be able to rewrite history even
-- if it is fully compromised.
--
--     sudo -u postgres psql -v ON_ERROR_STOP=1 \
--         -v owner_password="'...'" -v app_password="'...'" \
--         -f deploy/postgres/roles.sql

\set ON_ERROR_STOP on

-- NOLOGIN by design: migrations are run by a human or a oneshot unit that switches
-- to this role explicitly, not by anything that holds a password.
CREATE ROLE alerting_owner LOGIN PASSWORD :owner_password;
CREATE ROLE alerting_app   LOGIN PASSWORD :app_password;

CREATE DATABASE alerting OWNER alerting_owner;
-- CREATEDB, and only that. The quarterly restore drill restores into a scratch
-- database and drops it again; without this the drill needs a superuser, and a drill
-- that needs a superuser is a drill that does not get run. Not having run a restore
-- is the failure this whole procedure exists to prevent, so the privilege is the
-- cheaper risk. It does not let this role touch any database it does not own.
ALTER ROLE alerting_owner CREATEDB;


\connect alerting

-- Nobody else gets to create objects in this database.
REVOKE ALL ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO alerting_owner;
GRANT USAGE ON SCHEMA public TO alerting_app;
GRANT CONNECT ON DATABASE alerting TO alerting_app;

-- Read-only access to the statistics views, and it is needed for one number:
-- replication lag, which on this system IS the recovery point objective
-- (docs/10-failover.md). PostgreSQL blanks every LSN column in
-- `pg_stat_replication` for a role that is neither superuser nor a member of this
-- one -- the row per standby is still there, with all its numbers NULL. Without the
-- grant the metrics endpoint answers `alerting_replication_lag_unknown 1` and can
-- say nothing about how much a failover would lose.
--
-- pg_read_all_stats, not pg_monitor: pg_monitor also carries pg_read_all_settings
-- and pg_stat_scan_tables, and neither is needed here.
--
-- Granting it to the runtime role does not weaken the split this file exists for.
-- That split is about who can rewrite history; this privilege reads statistics and
-- grants nothing on any table. A fully compromised `alerting_app` still cannot
-- UPDATE, DELETE or TRUNCATE a single audit row.
GRANT pg_read_all_stats TO alerting_owner;
GRANT pg_read_all_stats TO alerting_app;
