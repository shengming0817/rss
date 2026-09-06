-- psql-only demo provisioning, run once as an administrator against an empty demo database.
-- These roles, business tables and grants are application examples, not component migrations.
\set ON_ERROR_STOP on
CREATE ROLE projection_owner NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE projection_runtime LOGIN NOSUPERUSER NOBYPASSRLS;
-- Assign runtime credentials separately (for example psql \password projection_runtime).
SELECT format('GRANT CREATE ON DATABASE %I TO projection_owner', current_database()) \gexec
SET ROLE projection_owner;
\ir ../migrations/0001_create_projection.sql
\ir ../migrations/0002_require_baseline_receipts.sql
RESET ROLE;
GRANT USAGE ON SCHEMA rss_projection TO projection_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA rss_projection TO projection_runtime;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_projection TO projection_runtime;
\ir counter/read-model.sql
