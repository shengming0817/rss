\set ON_ERROR_STOP on
-- Example role provisioning only. Run as administrator against an empty database.
-- Set both login passwords separately; install schemas using the published Rust constants.
CREATE ROLE handoff_owner LOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE handoff_runtime LOGIN NOSUPERUSER NOBYPASSRLS;
SELECT format('GRANT CREATE ON DATABASE %I TO handoff_owner',current_database()) \gexec
GRANT CREATE ON SCHEMA public TO handoff_owner;
