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
