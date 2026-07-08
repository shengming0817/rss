-- Add partition head-blocked depth to outbox backlog sampling.
--
-- The metric intentionally does not return partition_key: partition keys can carry credential-grade
-- bearer identifiers. Operators locate the concrete key through controlled DB inspection by event_id.

DROP FUNCTION IF EXISTS rss_outbox_sample_backlog(text);
CREATE FUNCTION rss_outbox_sample_backlog(p_domain text)
RETURNS TABLE(
    tenant_id text,
    contract_id text,
    depth bigint,
    oldest_age_seconds bigint,
    partition_blocked_depth bigint
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    WITH scoped AS (
        SELECT o.tenant_id,
               o.contract_id,
               o.created_at,
               (
                    (o.status = 'pending' AND (o.retry_after IS NULL OR o.retry_after <= now()))
                 OR (o.status = 'publishing' AND o.updated_at <= now() - make_interval(secs => 60))
               ) AS is_backlog,
               (
                    o.partition_key IS NOT NULL
                AND EXISTS (
                    SELECT 1
                    FROM outbox b
                    WHERE b.tenant_id = o.tenant_id
                      AND b.domain = o.domain
                      AND b.partition_key = o.partition_key
                      AND b.seq < o.seq
                      AND b.status <> 'published'
                )
               ) AS is_partition_blocked
        FROM outbox o
        WHERE o.domain = p_domain
    )
    SELECT tenant_id::text,
           contract_id,
           count(*) FILTER (WHERE is_backlog)::bigint AS depth,
           COALESCE(
               EXTRACT(EPOCH FROM (now() - min(created_at) FILTER (WHERE is_backlog)))::bigint,
               0
           ) AS oldest_age_seconds,
           count(*) FILTER (WHERE is_partition_blocked)::bigint AS partition_blocked_depth
    FROM scoped
    GROUP BY tenant_id, contract_id
    ORDER BY tenant_id, contract_id
$$;

ALTER FUNCTION rss_outbox_sample_backlog(text) OWNER TO rss_outbox_maintenance;

REVOKE ALL ON FUNCTION rss_outbox_sample_backlog(text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION rss_outbox_sample_backlog(text) TO rss_app;
