-- 0100_install_l2_dr_recovery.sql
--
-- Application-level recovery for a PostgreSQL/RabbitMQ divergent restore point. The operator
-- freezes one exact tenant/event set and the database either arms every still-durable published
-- fact for bounded same-ID relay or records that the normal Inbox path must consume the retained
-- broker delivery. No caller-controlled payload, fingerprint, topic, policy or deadline enters
-- this function.
--
-- ref: Apalis packages/apalis-sql/src/postgres/migrations/20230110112156_tasks.sql@49f90e

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rss_l2_dr_recovery_owner'
    ) THEN
        CREATE ROLE rss_l2_dr_recovery_owner
            NOLOGIN NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rss_l2_dr_recovery_auditor'
    ) THEN
        CREATE ROLE rss_l2_dr_recovery_auditor
            NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rss_l2_dr_recovery_executor'
    ) THEN
        CREATE ROLE rss_l2_dr_recovery_executor
            NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
    END IF;
END
$$;

ALTER ROLE rss_l2_dr_recovery_owner
    NOLOGIN NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
ALTER ROLE rss_l2_dr_recovery_auditor
    NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
ALTER ROLE rss_l2_dr_recovery_auditor SET search_path = pg_catalog, public;
ALTER ROLE rss_l2_dr_recovery_executor
    NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
ALTER ROLE rss_l2_dr_recovery_executor SET search_path = pg_catalog, public;

DO $$
DECLARE
    checked_role oid;
BEGIN
    FOREACH checked_role IN ARRAY ARRAY[
        'rss_l2_dr_recovery_owner'::regrole::oid,
        'rss_l2_dr_recovery_auditor'::regrole::oid,
        'rss_l2_dr_recovery_executor'::regrole::oid
    ] LOOP
        IF EXISTS (
            SELECT 1
            FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = checked_role OR membership.roleid = checked_role
        ) THEN
            RAISE EXCEPTION 'L2 DR recovery roles must have no memberships';
        END IF;
    END LOOP;
END
$$;

CREATE TABLE public.event_l2_dr_recovery_receipt (
    epoch_id uuid PRIMARY KEY CHECK (
        epoch_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    tenant_id uuid NOT NULL CHECK (
        tenant_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    direction text NOT NULL CHECK (
        direction IN ('database_ahead_broker_earlier', 'broker_ahead_database_earlier')
    ),
    pg_restore_point_epoch_micros bigint NOT NULL CHECK (pg_restore_point_epoch_micros > 0),
    rabbitmq_restore_point_epoch_micros bigint NOT NULL CHECK (
        rabbitmq_restore_point_epoch_micros > 0
    ),
    change_ticket text NOT NULL CHECK (
        pg_catalog.octet_length(change_ticket) BETWEEN 1 AND 128
        AND change_ticket = pg_catalog.btrim(change_ticket)
        AND change_ticket !~ '[[:cntrl:]]'
    ),
    event_ids text[] NOT NULL CHECK (pg_catalog.cardinality(event_ids) BETWEEN 1 AND 500),
    plan_digest bytea NOT NULL CHECK (pg_catalog.octet_length(plan_digest) = 32),
    policy_revision text NOT NULL CHECK (policy_revision = 'same-id-delivery-v1'),
    operator_subject text NOT NULL CHECK (
        pg_catalog.octet_length(operator_subject) BETWEEN 1 AND 128
        AND operator_subject = pg_catalog.btrim(operator_subject)
        AND operator_subject !~ '[[:cntrl:]]'
    ),
    start_audit_id uuid NOT NULL CHECK (
        start_audit_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ) UNIQUE,
    outcome text NOT NULL CHECK (
        outcome IN ('same_id_redrive_armed', 'normal_consume_resume')
    ),
    applied_at timestamptz NOT NULL,
    CONSTRAINT event_l2_dr_recovery_restore_order CHECK (
        (direction = 'database_ahead_broker_earlier'
            AND pg_restore_point_epoch_micros > rabbitmq_restore_point_epoch_micros)
        OR (direction = 'broker_ahead_database_earlier'
            AND rabbitmq_restore_point_epoch_micros > pg_restore_point_epoch_micros)
    )
);

ALTER TABLE public.event_l2_dr_recovery_receipt ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.event_l2_dr_recovery_receipt FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.event_l2_dr_recovery_receipt
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);

CREATE FUNCTION public.rss_l2_dr_recovery_receipt_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'event_l2_dr_recovery_receipt is append-only' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER event_l2_dr_recovery_receipt_immutable
BEFORE UPDATE OR DELETE ON public.event_l2_dr_recovery_receipt
FOR EACH ROW EXECUTE FUNCTION public.rss_l2_dr_recovery_receipt_immutable();

ALTER TABLE public.event_l2_dr_recovery_receipt OWNER TO rss_l2_dr_recovery_owner;
ALTER FUNCTION public.rss_l2_dr_recovery_receipt_immutable()
    OWNER TO rss_l2_dr_recovery_owner;
REVOKE ALL ON TABLE public.event_l2_dr_recovery_receipt FROM PUBLIC, rss_app;
REVOKE ALL ON FUNCTION public.rss_l2_dr_recovery_receipt_immutable() FROM PUBLIC, rss_app;
GRANT SELECT ON TABLE public.event_l2_dr_recovery_receipt TO rss_app_read;
GRANT SELECT, INSERT ON TABLE public.event_l2_dr_recovery_receipt
    TO rss_l2_dr_recovery_owner;

-- Durable start proof is a private carrier owned solely by the SECURITY DEFINER owner.
-- Append-only auth_audit_events remains the human-readable audit trail, but apply must never
-- treat that rss_app-writable table as proof: serving can mint matching rows and bypass auditor SoD.
CREATE TABLE public.event_l2_dr_recovery_start_proof (
    start_audit_id uuid PRIMARY KEY CHECK (
        start_audit_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    operator_subject text NOT NULL CHECK (
        pg_catalog.octet_length(operator_subject) BETWEEN 1 AND 128
        AND operator_subject = pg_catalog.btrim(operator_subject)
        AND operator_subject !~ '[[:cntrl:]]'
    ),
    target_tenant_id uuid NOT NULL CHECK (
        target_tenant_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    epoch_id uuid NOT NULL CHECK (
        epoch_id <> '00000000-0000-0000-0000-000000000000'::uuid
    ),
    plan_digest bytea NOT NULL CHECK (pg_catalog.octet_length(plan_digest) = 32),
    recorded_at timestamptz NOT NULL
);

ALTER TABLE public.event_l2_dr_recovery_start_proof ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.event_l2_dr_recovery_start_proof FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.event_l2_dr_recovery_start_proof
    USING (target_tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (target_tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);

CREATE FUNCTION public.rss_l2_dr_recovery_start_proof_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'event_l2_dr_recovery_start_proof is append-only' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER event_l2_dr_recovery_start_proof_immutable
BEFORE UPDATE OR DELETE ON public.event_l2_dr_recovery_start_proof
FOR EACH ROW EXECUTE FUNCTION public.rss_l2_dr_recovery_start_proof_immutable();

ALTER TABLE public.event_l2_dr_recovery_start_proof OWNER TO rss_l2_dr_recovery_owner;
ALTER FUNCTION public.rss_l2_dr_recovery_start_proof_immutable()
    OWNER TO rss_l2_dr_recovery_owner;
REVOKE ALL ON TABLE public.event_l2_dr_recovery_start_proof FROM PUBLIC, rss_app;
REVOKE ALL ON FUNCTION public.rss_l2_dr_recovery_start_proof_immutable() FROM PUBLIC, rss_app;
GRANT SELECT, INSERT ON TABLE public.event_l2_dr_recovery_start_proof
    TO rss_l2_dr_recovery_owner;

CREATE FUNCTION public.rss_l2_dr_recovery_record_start_audit(
    p_occurred_at_secs bigint,
    p_occurred_at_nanos integer,
    p_operator_subject text,
    p_target_tenant uuid,
    p_epoch_id uuid,
    p_plan_digest bytea,
    p_start_audit_id uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF p_occurred_at_secs < 0
        OR p_occurred_at_nanos < 0 OR p_occurred_at_nanos >= 1000000000
        OR p_operator_subject IS NULL
        OR pg_catalog.octet_length(p_operator_subject) NOT BETWEEN 1 AND 128
        OR p_target_tenant IS NULL
        OR p_target_tenant = '00000000-0000-0000-0000-000000000000'::uuid
        OR p_epoch_id IS NULL
        OR p_epoch_id = '00000000-0000-0000-0000-000000000000'::uuid
        OR p_plan_digest IS NULL
        OR pg_catalog.octet_length(p_plan_digest) <> 32
        OR p_start_audit_id IS NULL
        OR p_start_audit_id = '00000000-0000-0000-0000-000000000000'::uuid
    THEN
        RAISE EXCEPTION 'invalid L2 DR recovery start audit record' USING ERRCODE = '22023';
    END IF;

    INSERT INTO public.event_l2_dr_recovery_start_proof (
        start_audit_id, operator_subject, target_tenant_id, epoch_id, plan_digest, recorded_at
    ) VALUES (
        p_start_audit_id, p_operator_subject, p_target_tenant, p_epoch_id, p_plan_digest,
        pg_catalog.clock_timestamp()
    );

    -- Append-only operator audit trail. Apply does not trust this table as durable start proof.
    INSERT INTO public.auth_audit_events (
        occurred_at_secs, occurred_at_nanos, principal_id, principal_kind, tenant_context,
        resource_kind, resource_id, action, outcome, failure_reason, request_id, correlation_id
    ) VALUES (
        p_occurred_at_secs, p_occurred_at_nanos, p_operator_subject, 'service', p_target_tenant,
        'eventing.l2-dr-recovery', p_epoch_id::text,
        'eventing.l2-dr-recovery.apply.start', 'success', NULL,
        p_start_audit_id::text, 'sha256:' || pg_catalog.encode(p_plan_digest, 'hex')
    );
END;
$$;

CREATE FUNCTION public.rss_l2_dr_recovery_record_finish_audit(
    p_occurred_at_secs bigint,
    p_occurred_at_nanos integer,
    p_operator_subject text,
    p_target_tenant uuid,
    p_epoch_id uuid,
    p_outcome text,
    p_failure_reason text,
    p_start_audit_id uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_plan_correlation text;
BEGIN
    IF p_occurred_at_secs < 0
        OR p_occurred_at_nanos < 0 OR p_occurred_at_nanos >= 1000000000
        OR p_operator_subject IS NULL
        OR pg_catalog.octet_length(p_operator_subject) NOT BETWEEN 1 AND 128
        OR p_target_tenant IS NULL
        OR p_target_tenant = '00000000-0000-0000-0000-000000000000'::uuid
        OR p_epoch_id IS NULL
        OR p_epoch_id = '00000000-0000-0000-0000-000000000000'::uuid
        OR p_outcome NOT IN ('success', 'failure')
        OR ((p_outcome = 'failure') IS DISTINCT FROM (p_failure_reason IS NOT NULL))
        OR (p_failure_reason IS NOT NULL AND p_failure_reason NOT IN (
            'operator_auth', 'operator_grants', 'operator_authorization',
            'operator_provider_config', 'plan_invalid', 'epoch_conflict',
            'tenant_scope', 'event_missing', 'event_state', 'deadline',
            'policy', 'execution', 'audit'
        ))
        OR p_start_audit_id IS NULL
        OR p_start_audit_id = '00000000-0000-0000-0000-000000000000'::uuid
    THEN
        RAISE EXCEPTION 'invalid L2 DR recovery finish audit record' USING ERRCODE = '22023';
    END IF;

    SELECT 'sha256:' || pg_catalog.encode(proof.plan_digest, 'hex')
    INTO v_plan_correlation
    FROM public.event_l2_dr_recovery_start_proof AS proof
    WHERE proof.start_audit_id = p_start_audit_id
      AND proof.operator_subject = p_operator_subject
      AND proof.target_tenant_id = p_target_tenant
      AND proof.epoch_id = p_epoch_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'L2 DR recovery finish audit lacks its durable start' USING ERRCODE = '22023';
    END IF;

    INSERT INTO public.auth_audit_events (
        occurred_at_secs, occurred_at_nanos, principal_id, principal_kind, tenant_context,
        resource_kind, resource_id, action, outcome, failure_reason, request_id, correlation_id
    ) VALUES (
        p_occurred_at_secs, p_occurred_at_nanos, p_operator_subject, 'service', p_target_tenant,
        'eventing.l2-dr-recovery', p_epoch_id::text,
        'eventing.l2-dr-recovery.apply.finish', p_outcome, p_failure_reason,
        p_start_audit_id::text, v_plan_correlation
    );
END;
$$;

CREATE FUNCTION public.rss_l2_dr_recovery_apply(
    p_epoch_id uuid,
    p_tenant_id uuid,
    p_direction text,
    p_pg_restore_point_epoch_micros bigint,
    p_rabbitmq_restore_point_epoch_micros bigint,
    p_change_ticket text,
    p_event_ids text[],
    p_plan_digest bytea,
    p_operator_subject text,
    p_start_audit_id uuid
)
RETURNS TABLE (
    result_epoch_id uuid,
    result_tenant_id uuid,
    result_direction text,
    result_pg_restore_point_epoch_micros bigint,
    result_rabbitmq_restore_point_epoch_micros bigint,
    result_event_ids text[],
    result_plan_digest bytea,
    result_policy_revision text,
    result_operator_subject text,
    result_start_audit_id uuid,
    result_applied_at timestamptz,
    result_store_outcome text,
    result_already_applied boolean,
    result_outcome text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET lock_timeout = '5s'
SET statement_timeout = '5min'
AS $$
DECLARE
    v_existing public.event_l2_dr_recovery_receipt%ROWTYPE;
    v_policy_revision text;
    v_redrive_horizon_seconds bigint;
    v_locked_event_ids text[];
    v_state_is_valid boolean;
    v_deadline_is_valid boolean;
    v_checked_at timestamptz;
    v_changed bigint;
    v_outcome text;
BEGIN
    IF NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
            IS DISTINCT FROM p_tenant_id
        OR p_tenant_id IS NULL
        OR p_tenant_id = '00000000-0000-0000-0000-000000000000'::uuid
    THEN
        RAISE EXCEPTION 'L2 DR recovery tenant scope mismatch' USING ERRCODE = 'P1831';
    END IF;

    IF p_epoch_id IS NULL
        OR p_epoch_id = '00000000-0000-0000-0000-000000000000'::uuid
        OR p_direction NOT IN ('database_ahead_broker_earlier', 'broker_ahead_database_earlier')
        OR p_pg_restore_point_epoch_micros <= 0
        OR p_rabbitmq_restore_point_epoch_micros <= 0
        OR NOT (
            (p_direction = 'database_ahead_broker_earlier'
                AND p_pg_restore_point_epoch_micros > p_rabbitmq_restore_point_epoch_micros)
            OR (p_direction = 'broker_ahead_database_earlier'
                AND p_rabbitmq_restore_point_epoch_micros > p_pg_restore_point_epoch_micros)
        )
        OR p_change_ticket IS NULL
        OR pg_catalog.octet_length(p_change_ticket) NOT BETWEEN 1 AND 128
        OR p_change_ticket <> pg_catalog.btrim(p_change_ticket)
        OR p_change_ticket ~ '[[:cntrl:]]'
        OR p_event_ids IS NULL
        OR pg_catalog.array_ndims(p_event_ids) <> 1
        OR pg_catalog.cardinality(p_event_ids) NOT BETWEEN 1 AND 500
        OR p_plan_digest IS NULL
        OR pg_catalog.octet_length(p_plan_digest) <> 32
        OR p_operator_subject IS NULL
        OR pg_catalog.octet_length(p_operator_subject) NOT BETWEEN 1 AND 128
        OR p_operator_subject <> pg_catalog.btrim(p_operator_subject)
        OR p_operator_subject ~ '[[:cntrl:]]'
        OR p_start_audit_id IS NULL
        OR p_start_audit_id = '00000000-0000-0000-0000-000000000000'::uuid
        OR EXISTS (
            SELECT 1 FROM pg_catalog.unnest(p_event_ids) AS selected(item)
            WHERE selected.item IS NULL OR selected.item = ''
        )
        OR p_event_ids IS DISTINCT FROM ARRAY(
            SELECT selected.item
            FROM pg_catalog.unnest(p_event_ids) AS selected(item)
            ORDER BY selected.item COLLATE "C"
        )
        OR (
            SELECT pg_catalog.count(DISTINCT selected.item)
            FROM pg_catalog.unnest(p_event_ids) AS selected(item)
        ) <> pg_catalog.cardinality(p_event_ids)
    THEN
        RAISE EXCEPTION 'invalid L2 DR recovery plan' USING ERRCODE = 'P1832';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM public.event_l2_dr_recovery_start_proof AS proof
        WHERE proof.start_audit_id = p_start_audit_id
          AND proof.operator_subject = p_operator_subject
          AND proof.target_tenant_id = p_tenant_id
          AND proof.epoch_id = p_epoch_id
          AND proof.plan_digest = p_plan_digest
    ) THEN
        RAISE EXCEPTION 'L2 DR recovery durable start audit mismatch' USING ERRCODE = 'P1839';
    END IF;

    -- Serialize one immutable epoch before checking its receipt. A concurrent identical retry then
    -- observes AlreadyApplied; a different digest observes EpochConflict instead of leaking a raw
    -- unique violation after doing speculative outbox work.
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(p_epoch_id::text, 1837)
    );

    SELECT receipt.*
    INTO v_existing
    FROM public.event_l2_dr_recovery_receipt AS receipt
    WHERE receipt.epoch_id = p_epoch_id;
    IF FOUND THEN
        IF v_existing.tenant_id IS DISTINCT FROM p_tenant_id
            OR v_existing.direction IS DISTINCT FROM p_direction
            OR v_existing.pg_restore_point_epoch_micros
                IS DISTINCT FROM p_pg_restore_point_epoch_micros
            OR v_existing.rabbitmq_restore_point_epoch_micros
                IS DISTINCT FROM p_rabbitmq_restore_point_epoch_micros
            OR v_existing.change_ticket IS DISTINCT FROM p_change_ticket
            OR v_existing.event_ids IS DISTINCT FROM p_event_ids
            OR v_existing.plan_digest IS DISTINCT FROM p_plan_digest
            OR v_existing.policy_revision IS DISTINCT FROM 'same-id-delivery-v1'
            OR v_existing.outcome IS DISTINCT FROM (CASE p_direction
                WHEN 'database_ahead_broker_earlier' THEN 'same_id_redrive_armed'
                WHEN 'broker_ahead_database_earlier' THEN 'normal_consume_resume'
            END)
        THEN
            RAISE EXCEPTION 'L2 DR recovery epoch conflict' USING ERRCODE = 'P1833';
        END IF;
        RETURN QUERY SELECT
            v_existing.epoch_id,
            v_existing.tenant_id,
            v_existing.direction,
            v_existing.pg_restore_point_epoch_micros,
            v_existing.rabbitmq_restore_point_epoch_micros,
            v_existing.event_ids,
            v_existing.plan_digest,
            v_existing.policy_revision,
            v_existing.operator_subject,
            v_existing.start_audit_id,
            v_existing.applied_at,
            v_existing.outcome,
            true,
            'already_applied'::text;
        RETURN;
    END IF;

    SELECT policy.policy_revision, policy.same_id_redrive_horizon_seconds
    INTO v_policy_revision, v_redrive_horizon_seconds
    FROM public.event_delivery_policy AS policy
    WHERE policy.singleton;
    IF NOT FOUND OR v_policy_revision <> 'same-id-delivery-v1' THEN
        RAISE EXCEPTION 'L2 DR recovery policy mismatch' USING ERRCODE = 'P1834';
    END IF;

    IF p_direction = 'database_ahead_broker_earlier' THEN
        PERFORM outbox.id
        FROM public.outbox AS outbox
        WHERE outbox.tenant_id = p_tenant_id
          AND outbox.event_id = ANY(p_event_ids)
        ORDER BY outbox.event_id COLLATE "C"
        FOR UPDATE OF outbox;

        v_checked_at := pg_catalog.clock_timestamp();
        SELECT
            pg_catalog.array_agg(outbox.event_id ORDER BY outbox.event_id COLLATE "C"),
            pg_catalog.bool_and(
                outbox.status = 'published'
                AND outbox.published_at IS NOT NULL
                AND outbox.automatic_retry_deadline IS NOT NULL
                AND (
                    outbox.same_id_redrive_deadline IS NULL
                    OR outbox.same_id_redrive_deadline <= LEAST(
                        outbox.automatic_retry_deadline
                            + pg_catalog.make_interval(
                                secs => v_redrive_horizon_seconds::double precision
                            ),
                        outbox.published_at
                            + pg_catalog.make_interval(
                                secs => v_redrive_horizon_seconds::double precision
                            )
                    )
                )
            ),
            pg_catalog.bool_and(
                COALESCE(
                    outbox.same_id_redrive_deadline,
                    LEAST(
                        outbox.automatic_retry_deadline
                            + pg_catalog.make_interval(
                                secs => v_redrive_horizon_seconds::double precision
                            ),
                        outbox.published_at
                            + pg_catalog.make_interval(
                                secs => v_redrive_horizon_seconds::double precision
                            )
                    )
                ) > v_checked_at
            )
        INTO v_locked_event_ids, v_state_is_valid, v_deadline_is_valid
        FROM public.outbox AS outbox
        WHERE outbox.tenant_id = p_tenant_id
          AND outbox.event_id = ANY(p_event_ids);

        IF v_locked_event_ids IS DISTINCT FROM p_event_ids THEN
            RAISE EXCEPTION 'L2 DR recovery event set is missing' USING ERRCODE = 'P1835';
        END IF;
        IF v_state_is_valid IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'L2 DR recovery event state is invalid' USING ERRCODE = 'P1836';
        END IF;
        IF v_deadline_is_valid IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'L2 DR recovery deadline expired' USING ERRCODE = 'P1837';
        END IF;

        UPDATE public.outbox AS outbox
        SET status = 'pending',
            same_id_delivery_phase = 'redrive',
            retry_count = 0,
            retry_after = NULL,
            lease_token = NULL,
            lease_until = NULL,
            published_at = NULL,
            dlx_at = NULL,
            abandoned_at = NULL,
            same_id_redrive_deadline = COALESCE(
                outbox.same_id_redrive_deadline,
                LEAST(
                    outbox.automatic_retry_deadline
                        + pg_catalog.make_interval(
                            secs => v_redrive_horizon_seconds::double precision
                        ),
                    outbox.published_at
                        + pg_catalog.make_interval(
                            secs => v_redrive_horizon_seconds::double precision
                        )
                )
            ),
            updated_at = v_checked_at
        WHERE outbox.tenant_id = p_tenant_id
          AND outbox.event_id = ANY(p_event_ids)
          AND outbox.status = 'published';
        GET DIAGNOSTICS v_changed = ROW_COUNT;
        IF v_changed <> pg_catalog.cardinality(p_event_ids) THEN
            RAISE EXCEPTION 'L2 DR recovery apply lost an event lock' USING ERRCODE = 'P1838';
        END IF;
        v_outcome := 'same_id_redrive_armed';
    ELSE
        -- Broker-ahead / database-earlier intentionally does not require the planned event IDs to exist
        -- in PostgreSQL outbox. The frozen event set is an operator attestation that the broker retained
        -- those deliveries; this path only records a no-op receipt (normal_consume_resume) and must not
        -- mutate outbox or inbox. Requiring outbox existence would reject a correct divergent restore.
        v_checked_at := pg_catalog.clock_timestamp();
        v_outcome := 'normal_consume_resume';
    END IF;

    INSERT INTO public.event_l2_dr_recovery_receipt (
        epoch_id, tenant_id, direction, pg_restore_point_epoch_micros,
        rabbitmq_restore_point_epoch_micros, change_ticket, event_ids, plan_digest,
        policy_revision, operator_subject, start_audit_id, outcome, applied_at
    ) VALUES (
        p_epoch_id, p_tenant_id, p_direction, p_pg_restore_point_epoch_micros,
        p_rabbitmq_restore_point_epoch_micros, p_change_ticket, p_event_ids, p_plan_digest,
        v_policy_revision, p_operator_subject, p_start_audit_id, v_outcome, v_checked_at
    );

    RETURN QUERY SELECT
        p_epoch_id,
        p_tenant_id,
        p_direction,
        p_pg_restore_point_epoch_micros,
        p_rabbitmq_restore_point_epoch_micros,
        p_event_ids,
        p_plan_digest,
        v_policy_revision,
        p_operator_subject,
        p_start_audit_id,
        v_checked_at,
        v_outcome,
        false,
        'applied'::text;
END;
$$;

ALTER FUNCTION public.rss_l2_dr_recovery_record_start_audit(
    bigint, integer, text, uuid, uuid, bytea, uuid
) OWNER TO rss_l2_dr_recovery_owner;
ALTER FUNCTION public.rss_l2_dr_recovery_record_finish_audit(
    bigint, integer, text, uuid, uuid, text, text, uuid
) OWNER TO rss_l2_dr_recovery_owner;
ALTER FUNCTION public.rss_l2_dr_recovery_apply(
    uuid, uuid, text, bigint, bigint, text, text[], bytea, text, uuid
) OWNER TO rss_l2_dr_recovery_owner;

REVOKE ALL ON FUNCTION public.rss_l2_dr_recovery_record_start_audit(
    bigint, integer, text, uuid, uuid, bytea, uuid
) FROM PUBLIC, rss_app;
REVOKE ALL ON FUNCTION public.rss_l2_dr_recovery_record_finish_audit(
    bigint, integer, text, uuid, uuid, text, text, uuid
) FROM PUBLIC, rss_app;
REVOKE ALL ON FUNCTION public.rss_l2_dr_recovery_apply(
    uuid, uuid, text, bigint, bigint, text, text[], bytea, text, uuid
) FROM PUBLIC, rss_app;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM
    rss_l2_dr_recovery_auditor, rss_l2_dr_recovery_executor;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM
    rss_l2_dr_recovery_auditor, rss_l2_dr_recovery_executor;
GRANT SELECT ON TABLE public._sqlx_migrations TO
    rss_l2_dr_recovery_auditor, rss_l2_dr_recovery_executor;
GRANT SELECT, INSERT ON TABLE public.auth_audit_events TO rss_l2_dr_recovery_owner;
GRANT USAGE, SELECT ON SEQUENCE public.auth_audit_events_id_seq
    TO rss_l2_dr_recovery_owner;
GRANT SELECT ON TABLE public.event_delivery_policy TO rss_l2_dr_recovery_owner;
GRANT SELECT, UPDATE ON TABLE public.outbox TO rss_l2_dr_recovery_owner;
GRANT USAGE ON SCHEMA public TO rss_l2_dr_recovery_owner;
-- Updating relay state re-evaluates the stored generated fact fingerprint. These immutable
-- canonical helpers are the same exact dependency set held by rss_outbox_maintenance; no payload
-- or identity column becomes writable through the public operator role.
GRANT EXECUTE ON FUNCTION public.rss_outbox_fact_frame(integer, integer, bytea)
    TO rss_l2_dr_recovery_owner;
GRANT EXECUTE ON FUNCTION public.rss_outbox_canonical_number(jsonb)
    TO rss_l2_dr_recovery_owner;
GRANT EXECUTE ON FUNCTION public.rss_outbox_canonical_json(jsonb, boolean)
    TO rss_l2_dr_recovery_owner;
GRANT EXECUTE ON FUNCTION public.rss_outbox_fact_fingerprint(
    text, text, text, text, text, text, text, bytea, text, text, jsonb
) TO rss_l2_dr_recovery_owner;
GRANT EXECUTE ON FUNCTION public.rss_service_token_replay_check_and_record(bytea, timestamptz)
    TO rss_l2_dr_recovery_auditor;
GRANT EXECUTE ON FUNCTION public.rss_l2_dr_recovery_record_start_audit(
    bigint, integer, text, uuid, uuid, bytea, uuid
) TO rss_l2_dr_recovery_auditor;
GRANT EXECUTE ON FUNCTION public.rss_l2_dr_recovery_record_finish_audit(
    bigint, integer, text, uuid, uuid, text, text, uuid
) TO rss_l2_dr_recovery_auditor;
GRANT EXECUTE ON FUNCTION public.rss_l2_dr_recovery_apply(
    uuid, uuid, text, bigint, bigint, text, text[], bytea, text, uuid
) TO rss_l2_dr_recovery_executor;
GRANT USAGE ON SCHEMA public TO
    rss_l2_dr_recovery_auditor, rss_l2_dr_recovery_executor;
