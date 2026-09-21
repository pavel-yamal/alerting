-- Development only. The production equivalent is deploy/postgres/roles.sql, which
-- takes passwords as psql variables instead of hardcoding one.
--
-- Idempotent so `make db-up` can be run repeatedly.

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'alerting_owner') THEN
        CREATE ROLE alerting_owner LOGIN PASSWORD 'devpass';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'alerting_app') THEN
        CREATE ROLE alerting_app LOGIN PASSWORD 'devpass';
    END IF;
END
$$;

ALTER ROLE alerting_owner CREATEDB;  -- see roles.sql: the restore drill needs it

SELECT 'CREATE DATABASE alerting OWNER alerting_owner'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'alerting')\gexec

\connect alerting

REVOKE ALL ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO alerting_owner;
GRANT USAGE ON SCHEMA public TO alerting_app;
GRANT CONNECT ON DATABASE alerting TO alerting_app;

-- Replication role for the standby. Development only: production creates it in
-- roles.sql with a real password and a pg_hba rule scoped to the standby's address.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'alerting_repl') THEN
        CREATE ROLE alerting_repl LOGIN REPLICATION PASSWORD 'devpass';
    END IF;
END
$$;

-- Without this, `pg_stat_replication` returns a row per standby with every LSN
-- column NULL: PostgreSQL redacts other sessions' statistics from a role that is
-- neither a superuser nor a member of pg_read_all_stats. The metrics endpoint would
-- then be unable to say how far behind a replica is -- and the honest answer,
-- "unknown", is not a number an operator can act on.
-- pg_read_all_stats, not pg_monitor: pg_monitor also carries pg_read_all_settings
-- and pg_stat_scan_tables, neither of which anything here needs.
GRANT pg_read_all_stats TO alerting_owner;
GRANT pg_read_all_stats TO alerting_app;
