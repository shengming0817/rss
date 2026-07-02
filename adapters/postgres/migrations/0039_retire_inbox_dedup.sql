-- 0039_retire_inbox_dedup.sql
-- Runtime cutover to tenant-scoped inbox_receipts (#1650).
--
-- Pre-GA clean cutover: no dual-write, shim, fallback, or backfill. The old
-- global inbox_dedup table is retired in the same forward migration after the
-- fixed-shape maintenance function is installed for inbox_receipts retention.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rss_inbox_receipt_maintenance') THEN
        CREATE ROLE rss_inbox_receipt_maintenance NOLOGIN BYPASSRLS;
    ELSE
        ALTER ROLE rss_inbox_receipt_maintenance NOLOGIN BYPASSRLS;
    END IF;
END $$;

GRANT SELECT, DELETE ON inbox_receipts TO rss_inbox_receipt_maintenance;

CREATE OR REPLACE FUNCTION rss_sweep_inbox_receipts(p_retain_seconds bigint)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_deleted bigint;
BEGIN
    -- DB-side fail-closed backstop for rss_app direct calls. Rust uses the same
    -- strict floor via max_redelivery_window_secs() = 1023s.
    IF p_retain_seconds <= 1023 THEN
        RAISE EXCEPTION 'rss_sweep_inbox_receipts retain seconds must be > 1023';
    END IF;

    WITH deleted AS (
        DELETE FROM inbox_receipts
        WHERE ctid IN (
            SELECT ctid
            FROM inbox_receipts
            WHERE status = 'done'
              AND committed_at <= now() - (p_retain_seconds * interval '1 second')
            ORDER BY committed_at, tenant_id, event_id, consumer_group
            LIMIT 1000
        )
        RETURNING 1
    )
    SELECT count(*)::bigint INTO v_deleted FROM deleted;

    RETURN v_deleted;
END;
$$;

ALTER FUNCTION rss_sweep_inbox_receipts(bigint) OWNER TO rss_inbox_receipt_maintenance;
REVOKE ALL ON FUNCTION rss_sweep_inbox_receipts(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION rss_sweep_inbox_receipts(bigint) TO rss_app;

REVOKE ALL ON inbox_dedup FROM rss_app;
DROP TABLE inbox_dedup;
