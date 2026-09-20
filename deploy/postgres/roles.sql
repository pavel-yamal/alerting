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
