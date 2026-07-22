-- 0072_create_certificate_revocations.sql
--
-- Persistent, tenant/device-scoped certificate revocation ledger. The serving writer may append
-- immutable records and query them, but cannot choose revoked_at or mutate/delete prior evidence.
-- Physical retention and its global aggregate backlog observation are available only through two
-- fixed SECURITY DEFINER functions owned by the same non-login maintenance role.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

CREATE TABLE public.certificate_revocations (
    tenant_id  uuid        NOT NULL,
    device_id  uuid        NOT NULL,
    serial     bytea       NOT NULL,
    revoked_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    not_after  timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, device_id, serial),
    CONSTRAINT certificate_revocations_serial_length
        CHECK (
            pg_catalog.octet_length(serial) >= 1
            AND pg_catalog.octet_length(serial) <= 20
        ),
    CONSTRAINT certificate_revocations_time_order
        CHECK (revoked_at < not_after)
);

CREATE INDEX certificate_revocations_retention_idx
    ON public.certificate_revocations (not_after, tenant_id, device_id, serial);

ALTER TABLE public.certificate_revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.certificate_revocations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.certificate_revocations
    USING (
        tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid
    );

REVOKE ALL ON TABLE public.certificate_revocations
    FROM PUBLIC, rss_app, rss_app_read;
GRANT SELECT ON TABLE public.certificate_revocations TO rss_app;
-- revoked_at is deliberately absent: PostgreSQL owns the immutable first-revocation timestamp.
GRANT INSERT (tenant_id, device_id, serial, not_after)
    ON TABLE public.certificate_revocations TO rss_app;
GRANT SELECT ON TABLE public.certificate_revocations TO rss_app_read;
REVOKE UPDATE, DELETE ON TABLE public.certificate_revocations FROM rss_app, rss_app_read;

DO $$
DECLARE
    maintenance_oid oid;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rss_revocation_maintenance'
    ) THEN
        CREATE ROLE rss_revocation_maintenance
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION BYPASSRLS;
    ELSE
        ALTER ROLE rss_revocation_maintenance
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION BYPASSRLS;
    END IF;

    SELECT oid INTO STRICT maintenance_oid
    FROM pg_catalog.pg_roles
    WHERE rolname = 'rss_revocation_maintenance';
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members AS membership
        WHERE membership.roleid = maintenance_oid OR membership.member = maintenance_oid
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'rss_revocation_maintenance must have no role memberships';
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO rss_revocation_maintenance;
REVOKE ALL ON TABLE public.certificate_revocations FROM rss_revocation_maintenance;
-- UPDATE is required by SELECT ... FOR UPDATE. The NOLOGIN role is reachable only through the
-- fixed function below.
GRANT SELECT, UPDATE, DELETE ON TABLE public.certificate_revocations
    TO rss_revocation_maintenance;

CREATE FUNCTION public.rss_sweep_expired_certificate_revocations()
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    deleted_rows bigint;
BEGIN
    WITH expired AS (
        SELECT tenant_id, device_id, serial
        FROM public.certificate_revocations
        WHERE not_after <= pg_catalog.clock_timestamp() - interval '5 minutes'
        ORDER BY not_after, tenant_id, device_id, serial
        LIMIT 1000
        FOR UPDATE SKIP LOCKED
    )
    DELETE FROM public.certificate_revocations AS revocation
    USING expired
    WHERE revocation.tenant_id = expired.tenant_id
      AND revocation.device_id = expired.device_id
      AND revocation.serial = expired.serial;

    GET DIAGNOSTICS deleted_rows = ROW_COUNT;
    RETURN deleted_rows;
END;
$$;

ALTER FUNCTION public.rss_sweep_expired_certificate_revocations()
    OWNER TO rss_revocation_maintenance;
REVOKE ALL ON FUNCTION public.rss_sweep_expired_certificate_revocations()
    FROM PUBLIC, rss_app, rss_app_read;
GRANT EXECUTE ON FUNCTION public.rss_sweep_expired_certificate_revocations() TO rss_app;

-- Global retention backlog is intentionally exposed only as aggregate values. FORCE RLS prevents
-- the serving role from sampling all tenants directly; the fixed definer function preserves that
-- isolation while giving the maintenance worker one low-cardinality operational observation.
CREATE FUNCTION public.rss_certificate_revocation_retention_backlog()
RETURNS TABLE (depth bigint, oldest_age_seconds bigint)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT pg_catalog.count(*)::bigint AS depth,
           COALESCE(
               pg_catalog.floor(
                   EXTRACT(
                       EPOCH FROM pg_catalog.clock_timestamp()
                           - (pg_catalog.min(not_after) + interval '5 minutes')
                   )
               )::bigint,
               0::bigint
           ) AS oldest_age_seconds
    FROM public.certificate_revocations
    WHERE not_after <= pg_catalog.clock_timestamp() - interval '5 minutes'
$$;

ALTER FUNCTION public.rss_certificate_revocation_retention_backlog()
    OWNER TO rss_revocation_maintenance;
REVOKE ALL ON FUNCTION public.rss_certificate_revocation_retention_backlog()
    FROM PUBLIC, rss_app, rss_app_read;
GRANT EXECUTE ON FUNCTION public.rss_certificate_revocation_retention_backlog() TO rss_app;
