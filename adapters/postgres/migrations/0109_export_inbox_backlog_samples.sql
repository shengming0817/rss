-- #1683 Export a bounded, generated-group inbox stale-claim backlog catalog.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

CREATE INDEX idx_inbox_receipts_group_stale_claims
    ON public.inbox_receipts (consumer_group, claimed_at, tenant_id)
    WHERE status = 'claimed';

-- `rss_app_read` observes backlog only through the bounded aggregate function below. Receipt
-- details include event/trace/lease coordinates and must not remain a serving-reader capability.
REVOKE ALL ON TABLE public.inbox_receipts FROM rss_app_read;

CREATE FUNCTION public.rss_inbox_sample_backlog(p_consumer_groups text[])
RETURNS TABLE (
    tenant_id uuid,
    consumer_group text,
    depth bigint,
    oldest_age_seconds bigint
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    v_allowed constant text[] := ARRAY[
        'audit.policy-updated',
        'audit.role-assigned',
        'audit.role-revoked',
        'audit.security-event',
        'audit.session-created',
        'settings.config-version-changed'
    ]::text[];
BEGIN
    IF p_consumer_groups IS NULL
       OR pg_catalog.cardinality(p_consumer_groups) = 0
       OR pg_catalog.array_position(p_consumer_groups, NULL) IS NOT NULL
       OR pg_catalog.cardinality(p_consumer_groups) <>
          (SELECT pg_catalog.count(DISTINCT requested)::integer
           FROM pg_catalog.unnest(p_consumer_groups) AS requested)
       OR EXISTS (
           SELECT 1
           FROM pg_catalog.unnest(p_consumer_groups) AS requested
           WHERE NOT requested = ANY (v_allowed)
       ) THEN
        RAISE EXCEPTION 'invalid inbox backlog consumer group selection'
            USING ERRCODE = '22023';
    END IF;

    RETURN QUERY
    SELECT receipt.tenant_id,
           receipt.consumer_group,
           pg_catalog.count(*)::bigint,
           pg_catalog.date_part(
               'epoch', pg_catalog.now() - pg_catalog.min(receipt.claimed_at)
           )::bigint
    FROM public.inbox_receipts AS receipt
    WHERE receipt.consumer_group = ANY (p_consumer_groups)
      AND receipt.status = 'claimed'
      AND receipt.claimed_at <= pg_catalog.now() - pg_catalog.make_interval(secs => 60)
    GROUP BY receipt.tenant_id, receipt.consumer_group
    ORDER BY receipt.tenant_id, receipt.consumer_group;
END;
$function$;

ALTER FUNCTION public.rss_inbox_sample_backlog(text[])
    OWNER TO rss_inbox_receipt_maintenance;

REVOKE ALL ON FUNCTION public.rss_inbox_sample_backlog(text[])
    FROM PUBLIC, rss_app, rss_app_read;
GRANT EXECUTE ON FUNCTION public.rss_inbox_sample_backlog(text[])
    TO rss_app_read;
