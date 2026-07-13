-- 0057_atomic_outbox_claim.sql
--
-- Replace the split poll/acquire protocol with one atomic, deadline-fenced batch claim.  The
-- relay capability returned to Rust is backed by the exact token/deadline pair persisted here.
--
-- ref: apalis packages/apalis-sql/migrations/postgres/20250307001101_add_job_priority.sql@49f90e1304f8f218eb08ce6ca0f1b4934f3ed011
-- ref: Diggsey/sqlxmq migrations/20220208120856_fix_concurrent_poll.up.sql@79cbd3091ab39178d5de65d14416dad6067ac067

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

DO $$
BEGIN
    IF pg_total_relation_size('outbox'::regclass) > 10737418240 THEN
        RAISE EXCEPTION 'outbox exceeds 10 GiB atomic claim migration capacity limit';
    END IF;
END
$$;

ALTER TABLE outbox ADD COLUMN lease_until timestamptz;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM outbox
        WHERE status = 'publishing' AND lease_token IS NULL
        LIMIT 1
    ) THEN
        RAISE EXCEPTION 'publishing outbox rows must have lease_token before atomic claim migration';
    END IF;
END
$$;

UPDATE outbox
SET lease_until = updated_at + make_interval(secs => 60)
WHERE status = 'publishing';

UPDATE outbox
SET lease_token = NULL,
    lease_until = NULL
WHERE status <> 'publishing'
  AND (lease_token IS NOT NULL OR lease_until IS NOT NULL);

ALTER TABLE outbox ADD CONSTRAINT outbox_lease_token_matches_status
    CHECK ((status = 'publishing') = (lease_token IS NOT NULL));
ALTER TABLE outbox ADD CONSTRAINT outbox_lease_deadline_matches_status
    CHECK ((status = 'publishing') = (lease_until IS NOT NULL));
ALTER TABLE outbox ADD CONSTRAINT outbox_lease_deadline_after_claim
    CHECK (status <> 'publishing' OR lease_until > updated_at);
ALTER TABLE outbox ADD CONSTRAINT outbox_retry_count_nonnegative
    CHECK (retry_count >= 0);

DROP INDEX IF EXISTS idx_outbox_stale_publishing;
CREATE INDEX idx_outbox_stale_publishing
    ON outbox (domain, lease_until)
    WHERE status = 'publishing';

DROP FUNCTION IF EXISTS rss_outbox_poll_pending(text, bigint);
DROP FUNCTION IF EXISTS rss_outbox_acquire_lease(text);
DROP FUNCTION IF EXISTS rss_outbox_claim_batch(text, bigint);
CREATE FUNCTION rss_outbox_claim_batch(p_domain text, p_limit bigint)
RETURNS TABLE(
    tenant_id text,
    contract_id text,
    topic text,
    event_id text,
    payload bytea,
    retry_count int,
    metadata text,
    domain text,
    contract_version text,
    schema_hash text,
    claimed_at_epoch_seconds bigint,
    lease_token text,
    deadline_epoch_micros bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF p_limit IS NULL THEN
        RAISE EXCEPTION 'rss_outbox_claim_batch limit must be non-null';
    END IF;
    IF p_limit < 1 OR p_limit > 10000 THEN
        RAISE EXCEPTION 'rss_outbox_claim_batch limit must be in range [1, 10000]';
    END IF;

    RETURN QUERY
    WITH claim_clock AS MATERIALIZED (
        SELECT clock_timestamp() AS claimed_at
    ),
    eligible AS MATERIALIZED (
        SELECT o.id, o.seq, claim_clock.claimed_at
        FROM outbox AS o
        CROSS JOIN claim_clock
        WHERE o.domain = p_domain
          AND (
                (o.status = 'pending'
                 AND (o.retry_after IS NULL OR o.retry_after <= claim_clock.claimed_at))
             OR (o.status = 'publishing' AND o.lease_until <= claim_clock.claimed_at)
          )
          AND (
                o.partition_key IS NULL
             OR NOT EXISTS (
                    SELECT 1
                    FROM outbox AS blocker
                    WHERE blocker.tenant_id = o.tenant_id
                      AND blocker.domain = o.domain
                      AND blocker.partition_key = o.partition_key
                      AND blocker.seq < o.seq
                      AND blocker.status <> 'published'
                )
          )
        ORDER BY o.seq
        LIMIT p_limit
        FOR UPDATE OF o SKIP LOCKED
    ),
    claimed AS (
        UPDATE outbox AS o
        SET status = 'publishing',
            lease_token = gen_random_uuid(),
            lease_until = eligible.claimed_at + make_interval(secs => 60),
            published_at = NULL,
            dlx_at = NULL,
            updated_at = eligible.claimed_at
        FROM eligible
        WHERE o.id = eligible.id
        RETURNING o.seq,
                  o.tenant_id::text AS tenant_id,
                  o.contract_id,
                  o.topic,
                  o.event_id,
                  o.payload,
                  o.retry_count,
                  o.metadata::text AS metadata,
                  o.domain,
                  o.contract_version,
                  o.schema_hash,
                  eligible.claimed_at,
                  o.lease_token::text AS lease_token,
                  o.lease_until
    )
    SELECT claimed.tenant_id,
           claimed.contract_id,
           claimed.topic,
           claimed.event_id,
           claimed.payload,
           claimed.retry_count,
           claimed.metadata,
           claimed.domain,
           claimed.contract_version,
           claimed.schema_hash,
           EXTRACT(EPOCH FROM claimed.claimed_at)::bigint,
           claimed.lease_token,
           (EXTRACT(EPOCH FROM claimed.lease_until) * 1000000)::bigint
    FROM claimed
    ORDER BY claimed.seq;
END;
$$;

DROP FUNCTION IF EXISTS rss_outbox_lease_can_publish(text, uuid, bigint);
CREATE FUNCTION rss_outbox_lease_can_publish(
    p_event_id text,
    p_lease_token uuid,
    p_lease_deadline_epoch_micros bigint
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM outbox AS o
        WHERE o.event_id = p_event_id
          AND o.status = 'publishing'
          AND o.lease_token = p_lease_token
          AND o.lease_until = timestamptz 'epoch'
                              + p_lease_deadline_epoch_micros * interval '1 microsecond'
          AND o.lease_until > clock_timestamp() + interval '50 seconds'
    )
$$;

DROP FUNCTION IF EXISTS rss_outbox_settle_published(text, uuid);
DROP FUNCTION IF EXISTS rss_outbox_settle_published(text, uuid, bigint);
CREATE FUNCTION rss_outbox_settle_published(
    p_event_id text,
    p_lease_token uuid,
    p_lease_deadline_epoch_micros bigint
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
SET lock_timeout = '5s'
AS $$
DECLARE
    locked_id uuid;
    changed bigint;
    settled_at timestamptz;
BEGIN
    SELECT o.id
    INTO locked_id
    FROM outbox AS o
    WHERE o.event_id = p_event_id
      AND o.status = 'publishing'
      AND o.lease_token = p_lease_token
      AND o.lease_until = timestamptz 'epoch'
                          + p_lease_deadline_epoch_micros * interval '1 microsecond'
    FOR UPDATE OF o;
    IF NOT FOUND THEN
        RETURN 0;
    END IF;

    settled_at := clock_timestamp();
    UPDATE outbox AS o
    SET status = 'published',
        lease_token = NULL,
        lease_until = NULL,
        published_at = settled_at,
        dlx_at = NULL,
        updated_at = settled_at
    WHERE o.id = locked_id
      AND o.lease_until > settled_at;
    GET DIAGNOSTICS changed = ROW_COUNT;
    RETURN changed;
END;
$$;

DROP FUNCTION IF EXISTS rss_outbox_settle_retry(text, int, bigint, uuid);
DROP FUNCTION IF EXISTS rss_outbox_settle_retry(text, int, bigint, uuid, bigint);
DROP FUNCTION IF EXISTS rss_outbox_settle_retry(text, bigint, uuid, bigint);
DROP FUNCTION IF EXISTS rss_outbox_settle_retry(text, uuid, bigint);
CREATE FUNCTION rss_outbox_settle_retry(
    p_event_id text,
    p_lease_token uuid,
    p_lease_deadline_epoch_micros bigint
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
SET lock_timeout = '5s'
AS $$
DECLARE
    locked_id uuid;
    changed bigint;
    settled_at timestamptz;
BEGIN
    SELECT o.id
    INTO locked_id
    FROM outbox AS o
    WHERE o.event_id = p_event_id
      AND o.status = 'publishing'
      AND o.lease_token = p_lease_token
      AND o.lease_until = timestamptz 'epoch'
                          + p_lease_deadline_epoch_micros * interval '1 microsecond'
    FOR UPDATE OF o;
    IF NOT FOUND THEN
        RETURN 0;
    END IF;

    settled_at := clock_timestamp();
    UPDATE outbox AS o
    SET status = 'pending',
        retry_count = o.retry_count + 1,
        retry_after = settled_at + make_interval(secs => CASE
            WHEN o.retry_count >= 12 THEN 3600::double precision
            ELSE (1::bigint << o.retry_count)::double precision
        END),
        lease_token = NULL,
        lease_until = NULL,
        published_at = NULL,
        dlx_at = NULL,
        updated_at = settled_at
    WHERE o.id = locked_id
      AND o.lease_until > settled_at;
    GET DIAGNOSTICS changed = ROW_COUNT;
    RETURN changed;
END;
$$;

DROP FUNCTION IF EXISTS rss_outbox_mark_dlx(text, int, uuid);
DROP FUNCTION IF EXISTS rss_outbox_mark_dlx(text, int, uuid, bigint);
DROP FUNCTION IF EXISTS rss_outbox_mark_dlx(text, uuid, bigint);
CREATE FUNCTION rss_outbox_mark_dlx(
    p_event_id text,
    p_lease_token uuid,
    p_lease_deadline_epoch_micros bigint
)
RETURNS TABLE(
    tenant_id text,
    domain text,
    contract_id text,
    topic text,
    payload bytea,
    metadata text,
    contract_version text,
    schema_hash text,
    retry_count int
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
SET lock_timeout = '5s'
AS $$
DECLARE
    locked_id uuid;
    settled_at timestamptz;
BEGIN
    SELECT o.id
    INTO locked_id
    FROM outbox AS o
    WHERE o.event_id = p_event_id
      AND o.status = 'publishing'
      AND o.lease_token = p_lease_token
      AND o.lease_until = timestamptz 'epoch'
                          + p_lease_deadline_epoch_micros * interval '1 microsecond'
    FOR UPDATE OF o;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    settled_at := clock_timestamp();
    RETURN QUERY
    UPDATE outbox AS o
    SET status = 'dlx',
        retry_count = o.retry_count + 1,
        lease_token = NULL,
        lease_until = NULL,
        published_at = NULL,
        dlx_at = settled_at,
        updated_at = settled_at
    WHERE o.id = locked_id
      AND o.lease_until > settled_at
    RETURNING o.tenant_id::text, o.domain, o.contract_id, o.topic,
              o.payload, o.metadata::text, o.contract_version,
              o.schema_hash, o.retry_count;
END;
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
        lease_until = NULL,
        published_at = NULL,
        dlx_at = NULL,
        updated_at = clock_timestamp()
    WHERE event_id = p_event_id
      AND tenant_id = p_tenant_id
      AND status = 'dlx';
    GET DIAGNOSTICS changed = ROW_COUNT;
    RETURN changed;
END;
$$;

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
    WITH sample_clock AS MATERIALIZED (
        SELECT clock_timestamp() AS sampled_at
    ),
    scoped AS (
        SELECT o.tenant_id,
               o.contract_id,
               o.created_at,
               (
                    (o.status = 'pending'
                     AND (o.retry_after IS NULL OR o.retry_after <= sample_clock.sampled_at))
                 OR (o.status = 'publishing' AND o.lease_until <= sample_clock.sampled_at)
               ) AS is_backlog,
               (
                    o.partition_key IS NOT NULL
                AND EXISTS (
                    SELECT 1
                    FROM outbox AS blocker
                    WHERE blocker.tenant_id = o.tenant_id
                      AND blocker.domain = o.domain
                      AND blocker.partition_key = o.partition_key
                      AND blocker.seq < o.seq
                      AND blocker.status <> 'published'
                )
               ) AS is_partition_blocked,
               sample_clock.sampled_at
        FROM outbox AS o
        CROSS JOIN sample_clock
        WHERE o.domain = p_domain
    )
    SELECT tenant_id::text,
           contract_id,
           count(*) FILTER (WHERE is_backlog)::bigint,
           COALESCE(
               EXTRACT(EPOCH FROM (min(sampled_at) - min(created_at) FILTER (WHERE is_backlog)))::bigint,
               0
           ),
           count(*) FILTER (WHERE is_partition_blocked)::bigint
    FROM scoped
    GROUP BY tenant_id, contract_id
    ORDER BY tenant_id, contract_id
$$;

ALTER FUNCTION rss_outbox_claim_batch(text, bigint) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_outbox_lease_can_publish(text, uuid, bigint) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_outbox_settle_published(text, uuid, bigint) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_outbox_settle_retry(text, uuid, bigint) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_outbox_mark_dlx(text, uuid, bigint) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_outbox_redrive(text, uuid) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_outbox_sample_backlog(text) OWNER TO rss_outbox_maintenance;

REVOKE ALL ON FUNCTION rss_outbox_claim_batch(text, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_lease_can_publish(text, uuid, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_settle_published(text, uuid, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_settle_retry(text, uuid, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_mark_dlx(text, uuid, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_redrive(text, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_sample_backlog(text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION rss_outbox_claim_batch(text, bigint) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_lease_can_publish(text, uuid, bigint) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_settle_published(text, uuid, bigint) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_settle_retry(text, uuid, bigint) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_mark_dlx(text, uuid, bigint) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_redrive(text, uuid) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_sample_backlog(text) TO rss_app;
