-- 0079_align_auth_grant_sweeper_lock_order.sql
--
-- Replace the AuthGrant retention capability so it follows the authentication writer lock order:
-- refresh family before AuthGrant root. The previous root-first DELETE delegated child deletion to
-- the FK cascade and could deadlock with refresh rotation's refresh-before-root path.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

-- The NOLOGIN maintenance owner is reachable only through the fixed SECURITY DEFINER function.
-- Explicit family locking requires SELECT + UPDATE in addition to the existing DELETE capability.
GRANT SELECT, UPDATE, DELETE ON TABLE public.refresh_tokens TO rss_auth_grant_maintenance;

CREATE OR REPLACE FUNCTION public.rss_sweep_expired_auth_grants()
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    candidate record;
    deleted_rows bigint := 0;
    deleted_root bigint;
BEGIN
    FOR candidate IN
        SELECT root.tenant_id, root.grant_id
        FROM public.auth_grants AS root
        WHERE root.expires_at <= pg_catalog.clock_timestamp()
        ORDER BY root.expires_at, root.tenant_id, root.grant_id
        LIMIT 1000
    LOOP
        -- Establish a deterministic family lock before touching the root. The explicit lock pass
        -- prevents DELETE's physical scan order from becoming part of the concurrency protocol.
        PERFORM refresh.id
        FROM public.refresh_tokens AS refresh
        WHERE refresh.tenant_id = candidate.tenant_id
          AND refresh.auth_grant_id = candidate.grant_id
        ORDER BY refresh.id
        FOR UPDATE;

        DELETE FROM public.refresh_tokens AS refresh
        WHERE refresh.tenant_id = candidate.tenant_id
          AND refresh.auth_grant_id = candidate.grant_id;

        -- Revalidate expiry only after the family is locked and removed. A concurrent sweeper or
        -- writer may already have terminalized/deleted the root; that is an idempotent zero-row
        -- outcome, never permission to delete a different family.
        DELETE FROM public.auth_grants AS root
        WHERE root.tenant_id = candidate.tenant_id
          AND root.grant_id = candidate.grant_id
          AND root.expires_at <= pg_catalog.clock_timestamp();

        GET DIAGNOSTICS deleted_root = ROW_COUNT;
        deleted_rows := deleted_rows + deleted_root;
    END LOOP;

    RETURN deleted_rows;
END;
$$;

ALTER FUNCTION public.rss_sweep_expired_auth_grants()
    OWNER TO rss_auth_grant_maintenance;
REVOKE ALL ON FUNCTION public.rss_sweep_expired_auth_grants() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rss_sweep_expired_auth_grants() TO rss_app;
