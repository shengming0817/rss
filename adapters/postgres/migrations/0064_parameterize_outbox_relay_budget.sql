-- 0064_parameterize_outbox_relay_budget.sql
--
-- Make the typed relay budget an explicit database capability. This is a breaking replacement:
-- old relay binaries cannot call these functions after this migration and must be stopped first.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

DROP FUNCTION rss_outbox_claim_batch(text, bigint);
CREATE FUNCTION rss_outbox_claim_batch(
    p_domain text,
    p_limit bigint,
    p_lease_ttl_ms bigint,
    p_required_budget_ms bigint
)
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
DECLARE
    v_automatic_window_seconds bigint;
BEGIN
    IF p_limit IS NULL THEN
        RAISE EXCEPTION 'rss_outbox_claim_batch limit must be non-null';
    END IF;
    IF p_limit < 1 OR p_limit > 10000 THEN
        RAISE EXCEPTION 'rss_outbox_claim_batch limit must be in range [1, 10000]';
    END IF;
    IF p_lease_ttl_ms IS NULL OR p_required_budget_ms IS NULL THEN
        RAISE EXCEPTION 'rss_outbox_claim_batch relay budget must be non-null';
    END IF;
    IF p_lease_ttl_ms <= 0 OR p_required_budget_ms <= 0 THEN
        RAISE EXCEPTION 'rss_outbox_claim_batch relay budget must be positive';
    END IF;
    -- 24h operational ceiling also keeps interval/timestamp arithmetic far inside PostgreSQL range.
    IF p_lease_ttl_ms > 86400000 OR p_required_budget_ms > 86400000 THEN
        RAISE EXCEPTION 'rss_outbox_claim_batch relay budget exceeds operational maximum 86400000ms';
    END IF;
    IF p_required_budget_ms >= p_lease_ttl_ms THEN
        RAISE EXCEPTION 'rss_outbox_claim_batch required budget must be below lease ttl';
    END IF;

    SELECT policy.automatic_retry_window_seconds
    INTO STRICT v_automatic_window_seconds
    FROM event_delivery_policy AS policy
    WHERE policy.singleton;

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
                      AND blocker.status NOT IN ('published', 'abandoned')
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
            lease_until = eligible.claimed_at + p_lease_ttl_ms * interval '1 millisecond',
            automatic_retry_deadline = COALESCE(
                o.automatic_retry_deadline,
                eligible.claimed_at
                    + make_interval(secs => v_automatic_window_seconds::double precision)
            ),
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

DROP FUNCTION rss_outbox_publish_preflight(text, uuid, bigint);
CREATE FUNCTION rss_outbox_publish_preflight(
    p_event_id text,
    p_lease_token uuid,
    p_lease_deadline_epoch_micros bigint,
    p_lease_ttl_ms bigint,
    p_required_budget_ms bigint
)
RETURNS smallint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_phase text;
    v_lease_until timestamptz;
    v_automatic_deadline timestamptz;
    v_redrive_deadline timestamptz;
    v_checked_at timestamptz;
BEGIN
    IF p_lease_ttl_ms IS NULL OR p_required_budget_ms IS NULL THEN
        RAISE EXCEPTION 'rss_outbox_publish_preflight relay budget must be non-null';
    END IF;
    IF p_lease_ttl_ms <= 0 OR p_required_budget_ms <= 0 THEN
        RAISE EXCEPTION 'rss_outbox_publish_preflight relay budget must be positive';
    END IF;
    IF p_lease_ttl_ms > 86400000 OR p_required_budget_ms > 86400000 THEN
        RAISE EXCEPTION 'rss_outbox_publish_preflight relay budget exceeds operational maximum 86400000ms';
    END IF;
    IF p_required_budget_ms >= p_lease_ttl_ms THEN
        RAISE EXCEPTION 'rss_outbox_publish_preflight required budget must be below lease ttl';
    END IF;

    SELECT o.same_id_delivery_phase,
           o.lease_until,
           o.automatic_retry_deadline,
           o.same_id_redrive_deadline
    INTO v_phase, v_lease_until, v_automatic_deadline, v_redrive_deadline
    FROM outbox AS o
    WHERE o.event_id = p_event_id
      AND o.status = 'publishing'
      AND o.lease_token = p_lease_token
      AND o.lease_until = timestamptz 'epoch'
                          + p_lease_deadline_epoch_micros * interval '1 microsecond';
    IF NOT FOUND THEN
        RETURN 1;
    END IF;

    IF v_automatic_deadline IS NULL
       OR (v_phase = 'redrive' AND v_redrive_deadline IS NULL) THEN
        RAISE EXCEPTION 'outbox same-ID deadline invariant violated';
    END IF;

    v_checked_at := clock_timestamp();
    IF v_phase = 'automatic' AND v_automatic_deadline <= v_checked_at THEN
        RETURN 2;
    ELSIF v_phase = 'redrive' AND v_redrive_deadline <= v_checked_at THEN
        RETURN 3;
    ELSIF v_phase NOT IN ('automatic', 'redrive') THEN
        RAISE EXCEPTION 'outbox same-ID phase invariant violated';
    END IF;

    IF v_lease_until <= v_checked_at + p_required_budget_ms * interval '1 millisecond' THEN
        RETURN 1;
    END IF;
    RETURN 0;
END;
$$;

ALTER FUNCTION rss_outbox_claim_batch(text, bigint, bigint, bigint) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_outbox_publish_preflight(text, uuid, bigint, bigint, bigint) OWNER TO rss_outbox_maintenance;

REVOKE ALL ON FUNCTION rss_outbox_claim_batch(text, bigint, bigint, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_publish_preflight(text, uuid, bigint, bigint, bigint) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION rss_outbox_claim_batch(text, bigint, bigint, bigint) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_publish_preflight(text, uuid, bigint, bigint, bigint) TO rss_app;
