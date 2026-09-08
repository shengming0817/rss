-- Shared definer identity for Runtime, Recovery, DR and Archive admission.
-- ref: PostgreSQL src/backend/utils/adt/acl.c@REL_16_STABLE
WITH relay AS (
 SELECT * FROM pg_roles WHERE rolname = 'rss_tmsg_relay'
)
SELECT EXISTS (SELECT 1 FROM relay WHERE NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls
 AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication)
 -- Every inherited/SET/ADMIN path starts with a direct membership. The definer has none.
 AND NOT EXISTS (SELECT 1 FROM pg_auth_members m JOIN relay r ON m.member = r.oid)
