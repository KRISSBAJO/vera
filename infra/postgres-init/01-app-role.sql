-- Runs once when the Postgres volume is first created (docker-entrypoint-initdb.d).
-- The application connects as vera_app: no superuser, no BYPASSRLS, so row-level security applies
-- (SR-14). Migrations run as the owning superuser `vera` via MIGRATION_DATABASE_URL.
CREATE ROLE vera_app LOGIN PASSWORD 'vera_app' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
GRANT USAGE ON SCHEMA public TO vera_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO vera_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO vera_app;
ALTER DEFAULT PRIVILEGES FOR ROLE vera IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO vera_app;
ALTER DEFAULT PRIVILEGES FOR ROLE vera IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO vera_app;
