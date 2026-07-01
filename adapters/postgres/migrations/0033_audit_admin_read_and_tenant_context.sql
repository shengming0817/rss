-- #1583: audited RowScope::All runtime wiring + target-tenant audit read.
--
-- `auth_audit_events.tenant_context` records the tenant context of the audited operation. It is not an
-- ownership/RLS column and deliberately avoids the `tenant_id` name so schema-rls does not classify the platform
-- audit table as tenant-owned.
--
-- `rss_audit_admin` is the dedicated read-only LOGIN role for SuperAdmin target-tenant audit reads. It remains
-- NOBYPASSRLS and uses SET LOCAL rss.tenant_id with the existing audit_entries tenant_isolation policy; no
-- allow-all RLS policy is introduced. Deployments inject its password out-of-band.

ALTER TABLE auth_audit_events
    RENAME COLUMN principal_tenant TO tenant_context;

ALTER INDEX auth_audit_events_principal_tenant_idx
    RENAME TO auth_audit_events_tenant_context_idx;

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_audit_admin') THEN
        CREATE ROLE rss_audit_admin LOGIN NOBYPASSRLS;
    ELSE
        ALTER ROLE rss_audit_admin LOGIN NOBYPASSRLS;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO rss_audit_admin;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM rss_audit_admin;
GRANT SELECT ON audit_entries TO rss_audit_admin;
REVOKE INSERT, UPDATE, DELETE ON audit_entries FROM rss_audit_admin;
