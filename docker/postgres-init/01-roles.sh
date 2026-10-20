#!/bin/bash
# Роли и база для alerting — эквивалент deploy/postgres/roles.sql для контейнера.
# Выполняется образом postgres один раз, при инициализации пустого тома.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
    -v owner_pw="$(cat /secrets/owner-password)" \
    -v app_pw="$(cat /secrets/app-password)" <<'SQL'
CREATE ROLE alerting_owner LOGIN CREATEDB PASSWORD :'owner_pw';
CREATE ROLE alerting_app LOGIN PASSWORD :'app_pw';
CREATE DATABASE alerting OWNER alerting_owner;
\connect alerting
REVOKE ALL ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO alerting_owner;
GRANT USAGE ON SCHEMA public TO alerting_app;
GRANT CONNECT ON DATABASE alerting TO alerting_app;
GRANT pg_read_all_stats TO alerting_owner;
GRANT pg_read_all_stats TO alerting_app;
SQL
