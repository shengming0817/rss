-- 0056_add_outbox_terminal_timestamps.sql
--
-- Persist the actual outbox terminal transition time. Retention must start when a fact is
-- published, not when a possibly long-pending row was created. DLX timestamps are retained for
-- operator inspection and cleared only by an explicit redrive.
--
-- ref: Spring Modulith spring-modulith-events/spring-modulith-events-jdbc/src/main/java/org/springframework/modulith/events/jdbc/JdbcEventPublicationRepositoryV2.java@c75f173e5201208d8129b4cd8c112defb1158c67

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

DO $$
BEGIN
    IF pg_total_relation_size('outbox'::regclass) > 10737418240 THEN
        RAISE EXCEPTION 'outbox exceeds 10 GiB terminal timestamp migration capacity limit';
    END IF;
END
$$;

ALTER TABLE outbox ADD COLUMN published_at timestamptz;
ALTER TABLE outbox ADD COLUMN dlx_at timestamptz;

-- updated_at is the only pre-0056 evidence of when the current terminal state was entered.
-- Backfill in one deterministic statement; migration time and created_at would both invent history.
UPDATE outbox
SET published_at = CASE WHEN status = 'published' THEN updated_at ELSE NULL END,
    dlx_at = CASE WHEN status = 'dlx' THEN updated_at ELSE NULL END
WHERE status IN ('published', 'dlx');

ALTER TABLE outbox ADD CONSTRAINT outbox_published_at_matches_status
    CHECK ((status = 'published') = (published_at IS NOT NULL));
ALTER TABLE outbox ADD CONSTRAINT outbox_dlx_at_matches_status
    CHECK ((status = 'dlx') = (dlx_at IS NOT NULL));

DROP INDEX idx_outbox_sweep;
CREATE INDEX idx_outbox_sweep
    ON outbox (published_at)
    WHERE status = 'published';

CREATE OR REPLACE FUNCTION rss_outbox_settle_published(p_event_id text, p_lease_token uuid)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    changed bigint;
BEGIN
    UPDATE outbox
    SET status = 'published',
        published_at = now(),
        dlx_at = NULL,
        updated_at = now()
    WHERE event_id = p_event_id
      AND status = 'publishing'
      AND lease_token = p_lease_token;
    GET DIAGNOSTICS changed = ROW_COUNT;
    RETURN changed;
END;
$$;

CREATE OR REPLACE FUNCTION rss_outbox_mark_dlx(
    p_event_id text,
    p_retry_count int,
    p_lease_token uuid
)
RETURNS TABLE(
    tenant_id text,
    domain text,
    contract_id text,
    topic text,
    payload bytea,
    metadata text,
    contract_version text,
    schema_hash text
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    WITH outbox_status(name) AS (VALUES ('publishing'))
    UPDATE outbox
    SET status = 'dlx',
        retry_count = p_retry_count,
        published_at = NULL,
        dlx_at = now(),
        updated_at = now()
    FROM outbox_status
    WHERE event_id = p_event_id
      AND status = outbox_status.name
      AND lease_token = p_lease_token
    RETURNING tenant_id::text, domain, contract_id, topic, payload, metadata::text,
              contract_version, schema_hash
$$;

CREATE OR REPLACE FUNCTION rss_outbox_redrive(p_event_id text, p_tenant_id uuid)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    changed bigint;
BEGIN
    UPDATE outbox
    SET status = 'pending',
        retry_count = 0,
        retry_after = NULL,
        lease_token = NULL,
        published_at = NULL,
        dlx_at = NULL,
        updated_at = now()
    WHERE event_id = p_event_id
      AND tenant_id = p_tenant_id
      AND status = 'dlx';
    GET DIAGNOSTICS changed = ROW_COUNT;
    RETURN changed;
END;
$$;

CREATE OR REPLACE FUNCTION rss_sweep_outbox_published(p_retain_seconds bigint)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    deleted_rows bigint;
BEGIN
    IF p_retain_seconds IS NULL OR p_retain_seconds <= 0 THEN
        RAISE EXCEPTION 'rss_sweep_outbox_published retain seconds must be positive';
    END IF;

    DELETE FROM outbox
    WHERE status = 'published'
      AND published_at <= now() - make_interval(secs => p_retain_seconds::double precision);
    GET DIAGNOSTICS deleted_rows = ROW_COUNT;
    RETURN deleted_rows;
END;
$$;

ALTER FUNCTION rss_outbox_settle_published(text, uuid) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_outbox_mark_dlx(text, int, uuid) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_outbox_redrive(text, uuid) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_sweep_outbox_published(bigint) OWNER TO rss_outbox_maintenance;

REVOKE ALL ON FUNCTION rss_outbox_settle_published(text, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_mark_dlx(text, int, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_redrive(text, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_sweep_outbox_published(bigint) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION rss_outbox_settle_published(text, uuid) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_mark_dlx(text, int, uuid) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_redrive(text, uuid) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_sweep_outbox_published(bigint) TO rss_app;
