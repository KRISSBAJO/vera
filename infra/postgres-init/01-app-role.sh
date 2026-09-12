#!/bin/sh
# Runs once when the Postgres volume is first created (docker-entrypoint-initdb.d).
#
# The application connects as vera_app: no superuser, no BYPASSRLS, so row-level security applies
# (SR-14). Migrations run as the owning superuser `vera` via MIGRATION_DATABASE_URL.
#
# A shell script rather than plain .sql so the password can come from the environment: development
# keeps the well-known one, a pilot sets VERA_APP_PASSWORD to something real. `:'app_password'` is
# psql's own quoting, so a password containing a quote cannot end the string early.
set -e

psql -v ON_ERROR_STOP=1 \
  -v app_password="${VERA_APP_PASSWORD:-vera_app}" \
  --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'EOSQL'
CREATE ROLE vera_app LOGIN PASSWORD :'app_password' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
GRANT USAGE ON SCHEMA public TO vera_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO vera_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO vera_app;
ALTER DEFAULT PRIVILEGES FOR ROLE vera IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO vera_app;
ALTER DEFAULT PRIVILEGES FOR ROLE vera IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO vera_app;
EOSQL
