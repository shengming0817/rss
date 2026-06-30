-- 0030_grant_runtime_serving.sql
-- Split migrator and serving roles: the long-lived app login inherits rss_app
-- runtime DML only, while migrations/DDL stay on the short-lived migrator role.
-- No schema CREATE, ownership, CREATEROLE, or BYPASSRLS grant is allowed to
-- rss_app here. The dead-letter retention worker uses a separate NOLOGIN
-- SECURITY DEFINER owner below so the serving pool still cannot DELETE rows
-- directly.
-- outbox DML stays with rss_app until runtime has a dedicated writer/relay/
-- maintenance pool. Current serving runtime writes outbox rows in business
-- transactions and runs relay/sampler/sweeper from the same PgStore pool.

GRANT SELECT, INSERT, UPDATE, DELETE ON outbox TO rss_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON inbox_dedup TO rss_app;
GRANT SELECT, INSERT, UPDATE ON checkpoint TO rss_app;
GRANT SELECT, INSERT ON saga_journal TO rss_app;
GRANT SELECT, INSERT ON dead_letter TO rss_app;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rss_dead_letter_maintenance') THEN
        CREATE ROLE rss_dead_letter_maintenance NOLOGIN BYPASSRLS;
    ELSE
        ALTER ROLE rss_dead_letter_maintenance NOLOGIN BYPASSRLS;
    END IF;
END
$$;

GRANT SELECT, DELETE ON dead_letter TO rss_dead_letter_maintenance;

-- Narrow maintenance capability for the runtime dead-letter retention worker.
-- The long-lived connection remains rss_app; the owner/migrator role only installs
-- this fixed-shape function during migrations. The function owner is a NOLOGIN
-- role because dead_letter has FORCE RLS and the function must sweep all tenants.
CREATE OR REPLACE FUNCTION rss_sweep_dead_letter(p_retain_seconds bigint)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    deleted_rows bigint;
BEGIN
    IF p_retain_seconds < 2592000 THEN
        RAISE EXCEPTION 'dead_letter retain seconds must be >= 2592000';
    END IF;

    DELETE FROM dead_letter
    WHERE last_attempt_at <= now() - make_interval(secs => p_retain_seconds::double precision);
    GET DIAGNOSTICS deleted_rows = ROW_COUNT;
    RETURN deleted_rows;
END;
$$;

ALTER FUNCTION rss_sweep_dead_letter(bigint) OWNER TO rss_dead_letter_maintenance;
REVOKE ALL ON FUNCTION rss_sweep_dead_letter(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION rss_sweep_dead_letter(bigint) TO rss_app;
