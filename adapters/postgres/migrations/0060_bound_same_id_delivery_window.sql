-- 0060_bound_same_id_delivery_window.sql
--
-- Freeze the release policy that bounds every same-ID outbox delivery path. Automatic relay
-- retries and operator redrive use persisted absolute deadlines; inbox receipt retention is read
-- from the same database singleton. Historical rows fail closed at the migration cutover.
--
-- ref: Spring Modulith spring-modulith-events/spring-modulith-events-jdbc/src/main/java/org/springframework/modulith/events/jdbc/JdbcEventPublicationRepositoryV2.java@c75f173e5201208d8129b4cd8c112defb1158c67

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

DO $$
BEGIN
    IF pg_total_relation_size('outbox'::regclass) > 10737418240 THEN
        RAISE EXCEPTION 'outbox exceeds 10 GiB same-ID delivery migration capacity limit';
    END IF;
END
$$;

CREATE TABLE event_delivery_policy (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    policy_revision text NOT NULL CHECK (policy_revision = 'same-id-delivery-v1'),
    automatic_retry_window_seconds bigint NOT NULL CHECK (automatic_retry_window_seconds > 0),
    same_id_redrive_horizon_seconds bigint NOT NULL CHECK (same_id_redrive_horizon_seconds > 0),
    safety_margin_seconds bigint NOT NULL CHECK (safety_margin_seconds > 0),
    inbox_receipt_retention_seconds bigint NOT NULL CHECK (inbox_receipt_retention_seconds > 0),
    CONSTRAINT event_delivery_policy_retention_covers_delivery
        CHECK (
            inbox_receipt_retention_seconds::numeric
                > automatic_retry_window_seconds::numeric
                + same_id_redrive_horizon_seconds::numeric
                + safety_margin_seconds::numeric
        ),
    CONSTRAINT event_delivery_policy_intervals_bounded
        CHECK (
            automatic_retry_window_seconds <= 315360000
            AND same_id_redrive_horizon_seconds <= 315360000
            AND safety_margin_seconds <= 315360000
            AND inbox_receipt_retention_seconds <= 315360000
        )
);

INSERT INTO event_delivery_policy (
    singleton,
    policy_revision,
    automatic_retry_window_seconds,
    same_id_redrive_horizon_seconds,
    safety_margin_seconds,
    inbox_receipt_retention_seconds
) VALUES (true, 'same-id-delivery-v1', 86400, 86400, 86400, 604800);

REVOKE ALL ON event_delivery_policy FROM PUBLIC;
REVOKE ALL ON event_delivery_policy FROM rss_app;
GRANT SELECT ON event_delivery_policy TO rss_outbox_maintenance;
GRANT SELECT ON event_delivery_policy TO rss_inbox_receipt_maintenance;

ALTER TABLE outbox
    ADD COLUMN same_id_delivery_phase text NOT NULL DEFAULT 'automatic',
    ADD COLUMN automatic_retry_deadline timestamptz,
    ADD COLUMN same_id_redrive_deadline timestamptz,
    ADD COLUMN abandoned_at timestamptz;

ALTER TABLE outbox DROP CONSTRAINT outbox_status_check;

-- Existing receipts may already have been swept. Giving historical outbox rows a fresh window
-- would therefore recreate durable effects. One materialized cutover makes every historical
-- pending/publishing/DLX path immediately expire and is deterministic for the whole migration.
WITH cutover AS MATERIALIZED (
    SELECT clock_timestamp() AS cutover_at
)
UPDATE outbox
SET same_id_delivery_phase = 'automatic',
    automatic_retry_deadline = cutover.cutover_at,
    same_id_redrive_deadline = cutover.cutover_at
FROM cutover;

-- One composite state-machine constraint gives 0061 one physical validation scan. Splitting these
-- predicates into independent NOT VALID constraints would rescan the same large table repeatedly.
ALTER TABLE outbox ADD CONSTRAINT outbox_same_id_state_valid CHECK (
    status IN ('pending', 'publishing', 'published', 'dlx', 'abandoned')
    AND same_id_delivery_phase IN ('automatic', 'redrive')
    AND (
        status NOT IN ('publishing', 'published', 'dlx', 'abandoned')
        OR automatic_retry_deadline IS NOT NULL
    )
    AND (status NOT IN ('dlx', 'abandoned') OR same_id_redrive_deadline IS NOT NULL)
    AND (same_id_delivery_phase <> 'redrive' OR same_id_redrive_deadline IS NOT NULL)
    AND (same_id_redrive_deadline IS NULL OR automatic_retry_deadline IS NOT NULL)
    AND ((status = 'abandoned') = (abandoned_at IS NOT NULL))
) NOT VALID;

CREATE TABLE outbox_expired_resolutions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    blocked_event_id text NOT NULL UNIQUE,
    resolution_kind text NOT NULL CHECK (resolution_kind IN ('accepted_gap', 'compensated')),
    change_ticket text NOT NULL CHECK (
        char_length(change_ticket) BETWEEN 1 AND 128
        AND change_ticket = btrim(change_ticket)
        AND change_ticket !~ '[[:cntrl:]]'
    ),
    operator_subject text NOT NULL CHECK (
        char_length(operator_subject) BETWEEN 1 AND 256
        AND operator_subject = btrim(operator_subject)
        AND operator_subject !~ '[[:cntrl:]]'
    ),
    evidence_event_id text,
    verified_at timestamptz NOT NULL,
    CONSTRAINT outbox_expired_resolution_evidence_shape
        CHECK (
            (resolution_kind = 'accepted_gap' AND evidence_event_id IS NULL)
            OR (resolution_kind = 'compensated' AND evidence_event_id IS NOT NULL)
        )
);

ALTER TABLE outbox_expired_resolutions ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox_expired_resolutions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON outbox_expired_resolutions
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);

REVOKE ALL ON outbox_expired_resolutions FROM PUBLIC;
REVOKE ALL ON outbox_expired_resolutions FROM rss_app;
GRANT SELECT, INSERT ON outbox_expired_resolutions TO rss_outbox_maintenance;

-- Producers may supply immutable event facts only. State, phase, deadlines, lease/retry fields,
-- terminal timestamps, generated identity/fingerprint, and database clocks remain DB-owned.
REVOKE INSERT ON outbox FROM rss_app;
GRANT INSERT (
    event_id,
    tenant_id,
    domain,
    topic,
    contract_id,
    contract_version,
    schema_hash,
    payload,
    metadata,
    partition_key,
    causation_id
) ON outbox TO rss_app;

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
DECLARE
    v_automatic_window_seconds bigint;
BEGIN
    IF p_limit IS NULL THEN
        RAISE EXCEPTION 'rss_outbox_claim_batch limit must be non-null';
    END IF;
    IF p_limit < 1 OR p_limit > 10000 THEN
        RAISE EXCEPTION 'rss_outbox_claim_batch limit must be in range [1, 10000]';
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
            lease_until = eligible.claimed_at + make_interval(secs => 60),
            automatic_retry_deadline = COALESCE(
                o.automatic_retry_deadline,
                eligible.claimed_at + make_interval(secs => v_automatic_window_seconds::double precision)
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

DROP FUNCTION rss_outbox_lease_can_publish(text, uuid, bigint);
DROP FUNCTION IF EXISTS rss_outbox_publish_preflight(text, uuid, bigint);
CREATE FUNCTION rss_outbox_publish_preflight(
    p_event_id text,
    p_lease_token uuid,
    p_lease_deadline_epoch_micros bigint
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

    IF v_lease_until <= v_checked_at + interval '50 seconds' THEN
        RETURN 1;
    END IF;
    RETURN 0;
END;
$$;

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
    v_redrive_horizon_seconds bigint;
BEGIN
    SELECT policy.same_id_redrive_horizon_seconds
    INTO STRICT v_redrive_horizon_seconds
    FROM event_delivery_policy AS policy
    WHERE policy.singleton;

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
        same_id_redrive_deadline = COALESCE(
            o.same_id_redrive_deadline,
            LEAST(
                o.automatic_retry_deadline
                    + make_interval(secs => v_redrive_horizon_seconds::double precision),
                settled_at + make_interval(secs => v_redrive_horizon_seconds::double precision)
            )
        ),
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
SET lock_timeout = '5s'
AS $$
DECLARE
    locked_id uuid;
    v_redrive_deadline timestamptz;
    checked_at timestamptz;
    changed bigint;
BEGIN
    IF NULLIF(current_setting('rss.tenant_id', true), '')::uuid IS DISTINCT FROM p_tenant_id THEN
        RAISE EXCEPTION 'rss_outbox_redrive tenant scope mismatch';
    END IF;

    SELECT o.id, o.same_id_redrive_deadline
    INTO locked_id, v_redrive_deadline
    FROM outbox AS o
    WHERE o.event_id = p_event_id
      AND o.tenant_id = p_tenant_id
      AND o.status = 'dlx'
    FOR UPDATE OF o;
    IF NOT FOUND THEN
        RETURN 0;
    END IF;
    IF v_redrive_deadline IS NULL THEN
        RAISE EXCEPTION 'outbox redrive deadline invariant violated';
    END IF;

    checked_at := clock_timestamp();
    IF v_redrive_deadline <= checked_at THEN
        RETURN -1;
    END IF;

    UPDATE outbox AS o
    SET status = 'pending',
        same_id_delivery_phase = 'redrive',
        retry_count = 0,
        retry_after = NULL,
        lease_token = NULL,
        lease_until = NULL,
        published_at = NULL,
        dlx_at = NULL,
        updated_at = checked_at
    WHERE o.id = locked_id;
    GET DIAGNOSTICS changed = ROW_COUNT;
    RETURN changed;
END;
$$;

DROP FUNCTION IF EXISTS rss_outbox_resolve_expired(text, uuid, text, text, text, text);
CREATE FUNCTION rss_outbox_resolve_expired(
    p_event_id text,
    p_tenant_id uuid,
    p_resolution_kind text,
    p_change_ticket text,
    p_operator_subject text,
    p_evidence_event_id text
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
SET lock_timeout = '5s'
AS $$
DECLARE
    locked_id uuid;
    v_redrive_deadline timestamptz;
    checked_at timestamptz;
BEGIN
    IF NULLIF(current_setting('rss.tenant_id', true), '')::uuid IS DISTINCT FROM p_tenant_id THEN
        RAISE EXCEPTION 'rss_outbox_resolve_expired tenant scope mismatch';
    END IF;
    IF p_resolution_kind NOT IN ('accepted_gap', 'compensated')
       OR p_change_ticket IS NULL
       OR btrim(p_change_ticket) = ''
       OR p_change_ticket <> btrim(p_change_ticket)
       OR char_length(p_change_ticket) > 128
       OR p_change_ticket ~ '[[:cntrl:]]'
       OR p_operator_subject IS NULL
       OR btrim(p_operator_subject) = ''
       OR p_operator_subject <> btrim(p_operator_subject)
       OR char_length(p_operator_subject) > 256
       OR p_operator_subject ~ '[[:cntrl:]]'
       OR (p_resolution_kind = 'accepted_gap' AND p_evidence_event_id IS NOT NULL)
       OR (p_resolution_kind = 'compensated' AND p_evidence_event_id IS NULL) THEN
        RETURN -2;
    END IF;

    SELECT o.id, o.same_id_redrive_deadline
    INTO locked_id, v_redrive_deadline
    FROM outbox AS o
    WHERE o.event_id = p_event_id
      AND o.tenant_id = p_tenant_id
      AND o.status = 'dlx'
    FOR UPDATE OF o;
    IF NOT FOUND THEN
        RETURN 0;
    END IF;
    IF v_redrive_deadline IS NULL THEN
        RAISE EXCEPTION 'outbox expired resolution deadline invariant violated';
    END IF;

    checked_at := clock_timestamp();
    IF v_redrive_deadline > checked_at THEN
        RETURN -1;
    END IF;

    IF p_resolution_kind = 'compensated' AND NOT EXISTS (
        SELECT 1
        FROM outbox AS evidence
        WHERE evidence.tenant_id = p_tenant_id
          AND evidence.event_id = p_evidence_event_id
          AND evidence.status = 'published'
          AND evidence.causation_id = p_event_id
    ) THEN
        RETURN -2;
    END IF;

    INSERT INTO outbox_expired_resolutions (
        tenant_id,
        blocked_event_id,
        resolution_kind,
        change_ticket,
        operator_subject,
        evidence_event_id,
        verified_at
    ) VALUES (
        p_tenant_id,
        p_event_id,
        p_resolution_kind,
        p_change_ticket,
        p_operator_subject,
        p_evidence_event_id,
        checked_at
    );

    UPDATE outbox AS o
    SET status = 'abandoned',
        retry_after = NULL,
        lease_token = NULL,
        lease_until = NULL,
        published_at = NULL,
        dlx_at = NULL,
        abandoned_at = checked_at,
        updated_at = checked_at
    WHERE o.id = locked_id;
    RETURN 1;
END;
$$;

DROP FUNCTION rss_sweep_inbox_receipts(bigint);
DROP FUNCTION IF EXISTS rss_sweep_inbox_receipts();
CREATE FUNCTION rss_sweep_inbox_receipts()
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_retain_seconds bigint;
    v_deleted bigint;
BEGIN
    SELECT policy.inbox_receipt_retention_seconds
    INTO STRICT v_retain_seconds
    FROM event_delivery_policy AS policy
    WHERE policy.singleton;

    WITH deleted AS (
        DELETE FROM inbox_receipts
        WHERE ctid IN (
            SELECT ctid
            FROM inbox_receipts
            WHERE status = 'done'
              AND committed_at <= clock_timestamp()
                  - make_interval(secs => v_retain_seconds::double precision)
            ORDER BY committed_at, tenant_id, event_id, consumer_group
            LIMIT 1000
        )
        RETURNING 1
    )
    SELECT count(*)::bigint INTO v_deleted FROM deleted;
    RETURN v_deleted;
END;
$$;

ALTER FUNCTION rss_outbox_claim_batch(text, bigint) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_outbox_publish_preflight(text, uuid, bigint) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_outbox_mark_dlx(text, uuid, bigint) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_outbox_redrive(text, uuid) OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_outbox_resolve_expired(text, uuid, text, text, text, text)
    OWNER TO rss_outbox_maintenance;
ALTER FUNCTION rss_sweep_inbox_receipts() OWNER TO rss_inbox_receipt_maintenance;

REVOKE ALL ON FUNCTION rss_outbox_claim_batch(text, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_publish_preflight(text, uuid, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_mark_dlx(text, uuid, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_redrive(text, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_redrive(text, uuid) FROM rss_app;
REVOKE ALL ON FUNCTION rss_outbox_resolve_expired(text, uuid, text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_outbox_resolve_expired(text, uuid, text, text, text, text) FROM rss_app;
REVOKE ALL ON FUNCTION rss_sweep_inbox_receipts() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION rss_outbox_claim_batch(text, bigint) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_publish_preflight(text, uuid, bigint) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_mark_dlx(text, uuid, bigint) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_outbox_resolve_expired(text, uuid, text, text, text, text)
    TO rss_outbox_maintenance;
GRANT EXECUTE ON FUNCTION rss_sweep_inbox_receipts() TO rss_app;
