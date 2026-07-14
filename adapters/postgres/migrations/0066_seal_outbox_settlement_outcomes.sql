-- 0066_seal_outbox_settlement_outcomes.sql
--
-- Break the old row-count/optional-row ambiguity. Every settlement now returns one closed outcome;
-- the database clock is sampled only after the matching lease row has been locked.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

CREATE TYPE rss_outbox_settlement_outcome AS ENUM ('settled', 'expired', 'lost_lease');
ALTER TYPE rss_outbox_settlement_outcome OWNER TO rss_outbox_maintenance;
REVOKE ALL ON TYPE rss_outbox_settlement_outcome FROM PUBLIC;
GRANT USAGE ON TYPE rss_outbox_settlement_outcome TO rss_app;

DROP FUNCTION rss_outbox_settle_published(text, uuid, bigint);
CREATE FUNCTION rss_outbox_settle_published(
    p_event_id text,
    p_lease_token uuid,
    p_lease_deadline_epoch_micros bigint
)
RETURNS rss_outbox_settlement_outcome
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_locked_id uuid;
    v_lease_until timestamptz;
    v_settled_at timestamptz;
    v_changed bigint;
BEGIN
    SELECT o.id, o.lease_until
    INTO v_locked_id, v_lease_until
    FROM outbox AS o
    WHERE o.event_id = p_event_id
      AND o.status = 'publishing'
      AND o.lease_token = p_lease_token
      AND o.lease_until = timestamptz 'epoch'
                          + p_lease_deadline_epoch_micros * interval '1 microsecond'
    FOR UPDATE OF o;
    IF NOT FOUND THEN
        RETURN 'lost_lease';
    END IF;

    v_settled_at := clock_timestamp();
    IF v_lease_until <= v_settled_at THEN
        RETURN 'expired';
    END IF;

    UPDATE outbox AS o
    SET status = 'published',
        lease_token = NULL,
        lease_until = NULL,
        published_at = v_settled_at,
        dlx_at = NULL,
        updated_at = v_settled_at
    WHERE o.id = v_locked_id
      AND o.status = 'publishing'
      AND o.lease_token = p_lease_token
      AND o.lease_until = timestamptz 'epoch'
                          + p_lease_deadline_epoch_micros * interval '1 microsecond'
      AND o.lease_until > v_settled_at;
    GET DIAGNOSTICS v_changed = ROW_COUNT;
    IF v_changed = 1 THEN
        RETURN 'settled';
    END IF;
    RETURN 'lost_lease';
END;
$$;

DROP FUNCTION rss_outbox_settle_retry(text, uuid, bigint);
CREATE FUNCTION rss_outbox_settle_retry(
    p_event_id text,
    p_lease_token uuid,
    p_lease_deadline_epoch_micros bigint
)
RETURNS rss_outbox_settlement_outcome
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_locked_id uuid;
    v_lease_until timestamptz;
    v_settled_at timestamptz;
    v_changed bigint;
BEGIN
    SELECT o.id, o.lease_until
    INTO v_locked_id, v_lease_until
    FROM outbox AS o
    WHERE o.event_id = p_event_id
      AND o.status = 'publishing'
      AND o.lease_token = p_lease_token
      AND o.lease_until = timestamptz 'epoch'
                          + p_lease_deadline_epoch_micros * interval '1 microsecond'
    FOR UPDATE OF o;
    IF NOT FOUND THEN
        RETURN 'lost_lease';
    END IF;

    v_settled_at := clock_timestamp();
    IF v_lease_until <= v_settled_at THEN
        RETURN 'expired';
    END IF;

    UPDATE outbox AS o
    SET status = 'pending',
        retry_count = o.retry_count + 1,
        retry_after = v_settled_at + make_interval(secs => CASE
            WHEN o.retry_count >= 12 THEN 3600::double precision
            ELSE (1::bigint << o.retry_count)::double precision
        END),
        lease_token = NULL,
        lease_until = NULL,
        published_at = NULL,
        dlx_at = NULL,
        updated_at = v_settled_at
    WHERE o.id = v_locked_id
      AND o.status = 'publishing'
      AND o.lease_token = p_lease_token
      AND o.lease_until = timestamptz 'epoch'
                          + p_lease_deadline_epoch_micros * interval '1 microsecond'
      AND o.lease_until > v_settled_at;
    GET DIAGNOSTICS v_changed = ROW_COUNT;
    IF v_changed = 1 THEN
        RETURN 'settled';
    END IF;
    RETURN 'lost_lease';
END;
$$;

DROP FUNCTION rss_outbox_mark_dlx(text, uuid, bigint);
CREATE FUNCTION rss_outbox_mark_dlx(
    p_event_id text,
    p_lease_token uuid,
    p_lease_deadline_epoch_micros bigint
)
RETURNS TABLE(
    settlement_outcome rss_outbox_settlement_outcome,
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
AS $$
DECLARE
    v_locked_id uuid;
    v_lease_until timestamptz;
    v_settled_at timestamptz;
    v_redrive_horizon_seconds bigint;
BEGIN
    SELECT policy.same_id_redrive_horizon_seconds
    INTO STRICT v_redrive_horizon_seconds
    FROM event_delivery_policy AS policy
    WHERE policy.singleton;

    SELECT o.id, o.lease_until
    INTO v_locked_id, v_lease_until
    FROM outbox AS o
    WHERE o.event_id = p_event_id
      AND o.status = 'publishing'
      AND o.lease_token = p_lease_token
      AND o.lease_until = timestamptz 'epoch'
                          + p_lease_deadline_epoch_micros * interval '1 microsecond'
    FOR UPDATE OF o;
    IF NOT FOUND THEN
        RETURN QUERY SELECT
            'lost_lease'::rss_outbox_settlement_outcome,
            NULL::text, NULL::text, NULL::text, NULL::text, NULL::bytea,
            NULL::text, NULL::text, NULL::text, NULL::int;
        RETURN;
    END IF;

    v_settled_at := clock_timestamp();
    IF v_lease_until <= v_settled_at THEN
        RETURN QUERY SELECT
            'expired'::rss_outbox_settlement_outcome,
            NULL::text, NULL::text, NULL::text, NULL::text, NULL::bytea,
            NULL::text, NULL::text, NULL::text, NULL::int;
        RETURN;
    END IF;

    RETURN QUERY
    WITH changed AS (
        UPDATE outbox AS o
        SET status = 'dlx',
            retry_count = o.retry_count + 1,
            lease_token = NULL,
            lease_until = NULL,
            published_at = NULL,
            dlx_at = v_settled_at,
            same_id_redrive_deadline = COALESCE(
                o.same_id_redrive_deadline,
                LEAST(
                    o.automatic_retry_deadline
                        + make_interval(secs => v_redrive_horizon_seconds::double precision),
                    v_settled_at
                        + make_interval(secs => v_redrive_horizon_seconds::double precision)
                )
            ),
            updated_at = v_settled_at
        WHERE o.id = v_locked_id
          AND o.status = 'publishing'
          AND o.lease_token = p_lease_token
          AND o.lease_until = timestamptz 'epoch'
                              + p_lease_deadline_epoch_micros * interval '1 microsecond'
          AND o.lease_until > v_settled_at
        RETURNING o.tenant_id::text AS tenant_id, o.domain, o.contract_id, o.topic,
                  o.payload, o.metadata::text AS metadata, o.contract_version,
                  o.schema_hash, o.retry_count
    )
    SELECT 'settled'::rss_outbox_settlement_outcome, changed.*
    FROM changed;
    IF NOT FOUND THEN
        RETURN QUERY SELECT
            'lost_lease'::rss_outbox_settlement_outcome,
            NULL::text, NULL::text, NULL::text, NULL::text, NULL::bytea,
            NULL::text, NULL::text, NULL::text, NULL::int;
    END IF;
END;
$$;

ALTER FUNCTION rss_outbox_settle_published(text, uuid, bigint) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_outbox_settle_retry(text, uuid, bigint) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_outbox_mark_dlx(text, uuid, bigint) OWNER TO rss_outbox_maintenance;

REVOKE ALL ON FUNCTION rss_outbox_settle_published(text, uuid, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_settle_retry(text, uuid, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_mark_dlx(text, uuid, bigint) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION rss_outbox_settle_published(text, uuid, bigint) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_settle_retry(text, uuid, bigint) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_mark_dlx(text, uuid, bigint) TO rss_app;
