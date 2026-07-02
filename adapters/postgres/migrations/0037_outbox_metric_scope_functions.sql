-- Add tenant/contract metric scope to outbox poll/backlog SECURITY DEFINER functions.
-- Forward-only: 0031 created the original functions; 0036 extended acquire/dlx schema headers.

DROP FUNCTION IF EXISTS rss_outbox_poll_pending(text, bigint);
CREATE FUNCTION rss_outbox_poll_pending(p_domain text, p_limit bigint)
RETURNS TABLE(tenant_id text, contract_id text, topic text, event_id text, payload bytea)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF p_limit IS NULL THEN
        RAISE EXCEPTION 'rss_outbox_poll_pending poll limit must be non-null';
    END IF;
    IF p_limit < 1 OR p_limit > 10000 THEN
        RAISE EXCEPTION 'rss_outbox_poll_pending poll limit must be in range [1, 10000]';
    END IF;

    RETURN QUERY
    SELECT o.tenant_id::text, o.contract_id, o.topic, o.event_id, o.payload
    FROM outbox o
    WHERE o.domain = p_domain
      AND (
            (o.status = 'pending' AND (o.retry_after IS NULL OR o.retry_after <= now()))
         OR (o.status = 'publishing' AND o.updated_at <= now() - make_interval(secs => 60))
      )
      AND (o.partition_key IS NULL
        OR NOT EXISTS (
            SELECT 1 FROM outbox b
            WHERE b.tenant_id = o.tenant_id
              AND b.domain = o.domain
              AND b.partition_key = o.partition_key
              AND b.seq < o.seq
              AND b.status <> 'published'
        ))
    ORDER BY o.seq
    LIMIT p_limit
    FOR UPDATE OF o SKIP LOCKED;
END;
$$;

DROP FUNCTION IF EXISTS rss_outbox_sample_backlog(text);
CREATE FUNCTION rss_outbox_sample_backlog(p_domain text)
RETURNS TABLE(tenant_id text, contract_id text, depth bigint, oldest_age_seconds bigint)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    WITH scoped AS (
        SELECT tenant_id,
               contract_id,
               created_at,
               (
                    (status = 'pending' AND (retry_after IS NULL OR retry_after <= now()))
                 OR (status = 'publishing' AND updated_at <= now() - make_interval(secs => 60))
               ) AS is_backlog
        FROM outbox
        WHERE domain = p_domain
    )
    SELECT tenant_id::text,
           contract_id,
           count(*) FILTER (WHERE is_backlog)::bigint AS depth,
           COALESCE(
               EXTRACT(EPOCH FROM (now() - min(created_at) FILTER (WHERE is_backlog)))::bigint,
               0
           ) AS oldest_age_seconds
    FROM scoped
    GROUP BY tenant_id, contract_id
    ORDER BY tenant_id, contract_id
$$;

ALTER FUNCTION rss_outbox_poll_pending(text, bigint) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_outbox_sample_backlog(text) OWNER TO rss_outbox_maintenance;

REVOKE ALL ON FUNCTION rss_outbox_poll_pending(text, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_sample_backlog(text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION rss_outbox_poll_pending(text, bigint) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_sample_backlog(text) TO rss_app;
