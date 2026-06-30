-- 0031_harden_outbox_tenant_scope.sql
-- Tenant-harden ordered outbox delivery. Ordered gating is now scoped by
-- (tenant_id, domain, partition_key), so one tenant's DLX head cannot block
-- another tenant with the same business key.
--
-- Runtime connections remain rss_app. Cross-tenant relay/maintenance work is
-- exposed only through fixed SECURITY DEFINER functions owned by a NOLOGIN
-- BYPASSRLS role; rss_app no longer receives broad UPDATE/DELETE on outbox.

ALTER TABLE outbox ADD COLUMN tenant_id uuid;

DO $$
DECLARE
    bad_rows bigint;
BEGIN
    SELECT count(*) INTO bad_rows
    FROM outbox
    WHERE NOT (
        metadata ? 'tenantId'
        AND CASE
            WHEN metadata->>'tenantId' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            THEN metadata->>'tenantId' = ((metadata->>'tenantId')::uuid)::text
                 AND (metadata->>'tenantId')::uuid <> '00000000-0000-0000-0000-000000000000'::uuid
            ELSE false
        END
    );

    IF bad_rows > 0 THEN
        RAISE EXCEPTION 'outbox tenant_id backfill requires metadata.tenantId';
    END IF;
END
$$;

UPDATE outbox
SET tenant_id = (metadata->>'tenantId')::uuid
WHERE tenant_id IS NULL;

ALTER TABLE outbox ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE outbox ADD CONSTRAINT outbox_metadata_tenant_matches
    CHECK (metadata ? 'tenantId' AND (metadata->>'tenantId')::uuid = tenant_id);

DROP INDEX IF EXISTS idx_outbox_partition_head;
CREATE INDEX idx_outbox_partition_head
    ON outbox (tenant_id, domain, partition_key, seq)
    WHERE partition_key IS NOT NULL AND status <> 'published';

ALTER TABLE outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON outbox
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);

REVOKE UPDATE, DELETE ON outbox FROM rss_app;
GRANT SELECT, INSERT ON outbox TO rss_app;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rss_outbox_maintenance') THEN
        CREATE ROLE rss_outbox_maintenance NOLOGIN BYPASSRLS;
    ELSE
        ALTER ROLE rss_outbox_maintenance NOLOGIN BYPASSRLS;
    END IF;
END
$$;

GRANT SELECT, UPDATE, DELETE ON outbox TO rss_outbox_maintenance;

CREATE OR REPLACE FUNCTION rss_outbox_poll_pending(p_domain text, p_limit bigint)
RETURNS TABLE(topic text, event_id text, payload bytea)
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
    SELECT o.topic, o.event_id, o.payload
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

CREATE OR REPLACE FUNCTION rss_outbox_acquire_lease(p_event_id text)
RETURNS TABLE(
    retry_count int,
    lease_token text,
    tenant_id text,
    metadata text,
    domain text,
    contract_id text,
    topic text,
    now_epoch bigint
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    UPDATE outbox
    SET status = 'publishing',
        lease_token = gen_random_uuid(),
        updated_at = now()
    WHERE event_id = p_event_id
      AND (
            status = 'pending'
         OR (status = 'publishing' AND updated_at <= now() - make_interval(secs => 60))
      )
    RETURNING retry_count, lease_token::text, tenant_id::text, metadata::text, domain, contract_id, topic,
              EXTRACT(EPOCH FROM now())::bigint
$$;

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
        updated_at = now()
    WHERE event_id = p_event_id
      AND status = 'publishing'
      AND lease_token = p_lease_token;
    GET DIAGNOSTICS changed = ROW_COUNT;
    RETURN changed;
END;
$$;

CREATE OR REPLACE FUNCTION rss_outbox_settle_retry(
    p_event_id text,
    p_retry_count int,
    p_backoff_secs bigint,
    p_lease_token uuid
)
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
        retry_count = p_retry_count,
        retry_after = now() + make_interval(secs => p_backoff_secs::double precision),
        lease_token = NULL,
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
RETURNS TABLE(tenant_id text, domain text, contract_id text, topic text, payload bytea, metadata text)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    UPDATE outbox
    SET status = 'dlx',
        retry_count = p_retry_count,
        updated_at = now()
    WHERE event_id = p_event_id
      AND status = 'publishing'
      AND lease_token = p_lease_token
    RETURNING tenant_id::text, domain, contract_id, topic, payload, metadata::text
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
    IF p_retain_seconds < 0 THEN
        RAISE EXCEPTION 'rss_sweep_outbox_published retain seconds must be non-negative';
    END IF;

    DELETE FROM outbox
    WHERE status = 'published'
      AND created_at <= now() - make_interval(secs => p_retain_seconds::double precision);
    GET DIAGNOSTICS deleted_rows = ROW_COUNT;
    RETURN deleted_rows;
END;
$$;

CREATE OR REPLACE FUNCTION rss_outbox_sample_backlog(p_domain text)
RETURNS TABLE(depth bigint, oldest_age_seconds bigint)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT count(*)::bigint AS depth,
           COALESCE(EXTRACT(EPOCH FROM (now() - min(created_at)))::bigint, 0) AS oldest_age_seconds
    FROM outbox
    WHERE domain = p_domain
      AND (
            (status = 'pending' AND (retry_after IS NULL OR retry_after <= now()))
         OR (status = 'publishing' AND updated_at <= now() - make_interval(secs => 60))
      )
$$;

ALTER FUNCTION rss_outbox_poll_pending(text, bigint) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_outbox_acquire_lease(text) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_outbox_settle_published(text, uuid) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_outbox_settle_retry(text, int, bigint, uuid) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_outbox_mark_dlx(text, int, uuid) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_outbox_redrive(text, uuid) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_sweep_outbox_published(bigint) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_outbox_sample_backlog(text) OWNER TO rss_outbox_maintenance;

REVOKE ALL ON FUNCTION rss_outbox_poll_pending(text, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_acquire_lease(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_settle_published(text, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_settle_retry(text, int, bigint, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_mark_dlx(text, int, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_redrive(text, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_sweep_outbox_published(bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_sample_backlog(text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION rss_outbox_poll_pending(text, bigint) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_acquire_lease(text) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_settle_published(text, uuid) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_settle_retry(text, int, bigint, uuid) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_mark_dlx(text, int, uuid) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_redrive(text, uuid) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_sweep_outbox_published(bigint) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_sample_backlog(text) TO rss_app;
