-- 0032_create_session_sweeper.sql
-- Fixed-shape sessions expiry maintenance (#1233).
--
-- Runtime serving connections stay on rss_app. Because sessions has FORCE RLS,
-- full-tenant expiry cleanup is installed as a narrow SECURITY DEFINER function
-- owned by a NOLOGIN BYPASSRLS role. rss_app must not keep direct table DELETE;
-- it only receives EXECUTE on the fixed bounded function.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rss_session_maintenance') THEN
        CREATE ROLE rss_session_maintenance NOLOGIN BYPASSRLS;
    ELSE
        ALTER ROLE rss_session_maintenance NOLOGIN BYPASSRLS;
    END IF;
END
$$;

GRANT SELECT, DELETE ON sessions TO rss_session_maintenance;
REVOKE DELETE ON sessions FROM rss_app;

CREATE OR REPLACE FUNCTION rss_sweep_expired_sessions()
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    deleted_rows bigint;
BEGIN
    WITH expired AS (
        SELECT session_id
        FROM sessions
        WHERE expires_at <= now()
        ORDER BY expires_at, session_id
        LIMIT 1000
    )
    DELETE FROM sessions AS s
    USING expired
    WHERE s.session_id = expired.session_id;

    GET DIAGNOSTICS deleted_rows = ROW_COUNT;
    RETURN deleted_rows;
END;
$$;

ALTER FUNCTION rss_sweep_expired_sessions() OWNER TO rss_session_maintenance;
REVOKE ALL ON FUNCTION rss_sweep_expired_sessions() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION rss_sweep_expired_sessions() TO rss_app;
