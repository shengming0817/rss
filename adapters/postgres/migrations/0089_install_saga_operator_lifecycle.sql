-- 0089_install_saga_operator_lifecycle.sql
--
-- Pre-activation hard cutover for the assembly-owned Saga start/operator surface. Durable Saga
-- rows have never been activated in production, so start authority and unresolved age are added
-- only after an exact empty-table gate. Retry and terminate are fenced, exact CAS operations whose
-- operator evidence is appended in the same statement as the lifecycle transition.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

LOCK TABLE public.saga_instances IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.saga_instances LIMIT 1) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'saga_instances must be empty before installing operator lifecycle v2';
    END IF;
END
$$;

DROP INDEX public.saga_instances_terminal_retention_idx;
DROP INDEX public.saga_instances_unresolved_observation_idx;

ALTER TABLE public.saga_instances
    DROP CONSTRAINT saga_instances_status_valid,
    DROP CONSTRAINT saga_instances_resolution_shape,
    DROP CONSTRAINT saga_instances_terminal_time_consistent,
    ADD COLUMN start_actor text NOT NULL,
    ADD COLUMN start_audit_id text NOT NULL,
    ADD COLUMN unresolved_at timestamptz,
    ADD CONSTRAINT saga_instances_start_actor_valid CHECK (
        pg_catalog.octet_length(start_actor) BETWEEN 1 AND 128
    ),
    ADD CONSTRAINT saga_instances_start_audit_id_valid CHECK (
        pg_catalog.octet_length(start_audit_id) BETWEEN 1 AND 128
    ),
    ADD CONSTRAINT saga_instances_status_valid CHECK (status IN (
        'ready', 'running', 'succeeded', 'compensating', 'compensated', 'expired',
        'compensation_failed', 'operator_required', 'degraded', 'terminated'
    )),
    ADD CONSTRAINT saga_instances_resolution_shape CHECK (
        (status = 'operator_required') = (operator_reason IS NOT NULL)
        AND (
            status IN ('compensating', 'compensated', 'expired', 'compensation_failed')
            OR (status = 'operator_required'
                AND operator_reason = 'compensation_outcome_unknown')
        )
            = (compensation_cause IS NOT NULL)
        AND (status <> 'expired' OR compensation_cause = 'expired')
    ),
    ADD CONSTRAINT saga_instances_terminal_time_consistent CHECK (
        (status IN ('succeeded', 'compensated', 'expired', 'terminated'))
            = (terminal_at IS NOT NULL)
    ),
    ADD CONSTRAINT saga_instances_unresolved_time_consistent CHECK (
        (status IN ('operator_required', 'degraded', 'compensation_failed'))
            = (unresolved_at IS NOT NULL)
    );

ALTER TABLE public.saga_operator_decisions
    ADD COLUMN operator_reason_text text NOT NULL,
    ADD CONSTRAINT saga_operator_decisions_reason_text_valid CHECK (
        pg_catalog.octet_length(operator_reason_text) BETWEEN 1 AND 512
    );

CREATE OR REPLACE FUNCTION public.rss_saga_terminal_at_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.status IN ('succeeded', 'compensated', 'expired', 'terminated') THEN
        IF TG_OP = 'INSERT'
            OR OLD.status NOT IN ('succeeded', 'compensated', 'expired', 'terminated')
        THEN
            NEW.terminal_at := pg_catalog.clock_timestamp();
        ELSE
            NEW.terminal_at := OLD.terminal_at;
        END IF;
    ELSE
        NEW.terminal_at := NULL;
    END IF;

    IF NEW.status IN ('operator_required', 'degraded', 'compensation_failed') THEN
        IF TG_OP = 'INSERT'
            OR OLD.status NOT IN ('operator_required', 'degraded', 'compensation_failed')
        THEN
            NEW.unresolved_at := pg_catalog.clock_timestamp();
        ELSE
            -- Lease claim/renew/release and same-unresolved-state updates must not reset backlog age.
            NEW.unresolved_at := OLD.unresolved_at;
        END IF;
    ELSE
        NEW.unresolved_at := NULL;
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.rss_saga_terminal_at_guard() FROM PUBLIC;

CREATE INDEX saga_instances_terminal_retention_idx
    ON public.saga_instances (terminal_at, tenant_id, saga_id)
    WHERE status IN ('succeeded', 'compensated', 'expired', 'terminated');

CREATE INDEX saga_instances_unresolved_observation_idx
    ON public.saga_instances (owner, contract_id, unresolved_at)
    INCLUDE (status)
    WHERE status IN ('operator_required', 'degraded', 'compensation_failed');

DROP FUNCTION public.rss_sweep_terminal_sagas();

CREATE FUNCTION public.rss_sweep_terminal_sagas()
RETURNS TABLE (
    deleted bigint,
    backlog_depth bigint,
    oldest_expired_age_seconds bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    deleted_rows bigint;
    observed_at timestamptz := pg_catalog.clock_timestamp();
BEGIN
    WITH expired AS (
        SELECT tenant_id, saga_id
        FROM public.saga_instances
        WHERE status IN ('succeeded', 'compensated', 'expired', 'terminated')
          AND terminal_at < observed_at - interval '30 days'
          AND (lease_token IS NULL OR expires_at <= observed_at)
        ORDER BY terminal_at, tenant_id, saga_id
        LIMIT 1000
        FOR UPDATE SKIP LOCKED
    ),
    deleted AS (
        DELETE FROM public.saga_instances AS instance
        USING expired
        WHERE instance.tenant_id = expired.tenant_id
          AND instance.saga_id = expired.saga_id
        RETURNING 1
    )
    SELECT pg_catalog.count(*) INTO deleted_rows FROM deleted;
    RETURN QUERY
    SELECT
        deleted_rows,
        pg_catalog.count(*),
        coalesce(
            extract(epoch FROM observed_at - pg_catalog.min(instance.terminal_at))::bigint,
            0::bigint
        )
    FROM public.saga_instances AS instance
    WHERE instance.status IN ('succeeded', 'compensated', 'expired', 'terminated')
      AND instance.terminal_at < observed_at - interval '30 days'
      AND (instance.lease_token IS NULL OR instance.expires_at <= observed_at);
END;
$$;

ALTER FUNCTION public.rss_sweep_terminal_sagas() OWNER TO rss_saga_receipt_maintenance;
REVOKE ALL ON FUNCTION public.rss_sweep_terminal_sagas() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rss_sweep_terminal_sagas() TO rss_app;

DROP FUNCTION public.rss_saga_observe_unresolved(text, text);

CREATE FUNCTION public.rss_saga_observe_unresolved(p_owner text, p_contract_id text)
RETURNS TABLE (
    operator_required_count bigint,
    degraded_count bigint,
    compensation_failed_count bigint,
    oldest_unresolved_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF p_owner IS NULL OR pg_catalog.length(p_owner) = 0 THEN
        RAISE EXCEPTION 'rss_saga_observe_unresolved owner must be non-empty';
    END IF;
    IF p_contract_id IS NULL OR pg_catalog.length(p_contract_id) = 0 THEN
        RAISE EXCEPTION 'rss_saga_observe_unresolved contract id must be non-empty';
    END IF;

    RETURN QUERY
    SELECT
        pg_catalog.count(*) FILTER (WHERE instance.status = 'operator_required'),
        pg_catalog.count(*) FILTER (WHERE instance.status = 'degraded'),
        pg_catalog.count(*) FILTER (WHERE instance.status = 'compensation_failed'),
        pg_catalog.min(instance.unresolved_at)
    FROM public.saga_instances AS instance
    WHERE instance.owner = p_owner
      AND instance.contract_id = p_contract_id
      AND instance.status IN ('operator_required', 'degraded', 'compensation_failed');
END;
$$;

ALTER FUNCTION public.rss_saga_observe_unresolved(text, text) OWNER TO rss_saga_maintenance;
REVOKE ALL ON FUNCTION public.rss_saga_observe_unresolved(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rss_saga_observe_unresolved(text, text) TO rss_app;

CREATE TABLE public.saga_operator_transitions (
    tenant_id uuid NOT NULL,
    saga_id uuid NOT NULL,
    transition_epoch bigint NOT NULL CHECK (transition_epoch > 0),
    transition text NOT NULL CHECK (transition IN ('retry_compensation', 'terminate')),
    from_status text NOT NULL CHECK (from_status IN ('ready', 'compensation_failed')),
    to_status text NOT NULL CHECK (to_status IN ('compensating', 'terminated')),
    from_operator_reason text CHECK (
        from_operator_reason IS NULL OR from_operator_reason IN (
            'forward_outcome_unknown', 'compensation_outcome_unknown', 'receipt_missing',
            'receipt_integrity', 'receipt_format_unsupported', 'completion_commit_unknown',
            'definition_unsupported'
        )
    ),
    from_compensation_cause text CHECK (
        from_compensation_cause IS NULL
        OR from_compensation_cause IN ('business_failure', 'expired')
    ),
    observed_unresolved_at timestamptz,
    basis_seq bigint CHECK (basis_seq IS NULL OR basis_seq >= 0),
    basis_step_name text CHECK (
        basis_step_name IS NULL
        OR (pg_catalog.octet_length(basis_step_name) BETWEEN 1 AND 128)
    ),
    basis_attempt integer CHECK (basis_attempt IS NULL OR basis_attempt > 0),
    basis_effect_key bytea CHECK (
        basis_effect_key IS NULL OR pg_catalog.octet_length(basis_effect_key) = 32
    ),
    operator_actor text NOT NULL CHECK (
        pg_catalog.octet_length(operator_actor) BETWEEN 1 AND 128
    ),
    operator_reason_text text NOT NULL CHECK (
        pg_catalog.octet_length(operator_reason_text) BETWEEN 1 AND 512
    ),
    change_ticket text NOT NULL CHECK (
        pg_catalog.octet_length(change_ticket) BETWEEN 1 AND 128
    ),
    start_audit_id text NOT NULL CHECK (
        pg_catalog.octet_length(start_audit_id) BETWEEN 1 AND 128
    ),
    transitioned_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (tenant_id, saga_id, transition_epoch),
    FOREIGN KEY (tenant_id, saga_id)
        REFERENCES public.saga_instances (tenant_id, saga_id) ON DELETE CASCADE,
    CONSTRAINT saga_operator_transitions_shape CHECK (
        (
            (
                transition = 'retry_compensation'
                AND from_status = 'compensation_failed'
                AND to_status = 'compensating'
                AND from_operator_reason IS NULL
                AND from_compensation_cause IS NOT NULL
                AND observed_unresolved_at IS NOT NULL
                AND basis_seq IS NOT NULL
                AND basis_step_name IS NOT NULL
                AND basis_attempt IS NOT NULL
                AND basis_effect_key IS NOT NULL
            )
            OR (
                transition = 'terminate'
                AND from_status = 'ready'
                AND to_status = 'terminated'
                AND from_operator_reason IS NULL
                AND from_compensation_cause IS NULL
                AND observed_unresolved_at IS NULL
                AND basis_seq IS NULL
                AND basis_step_name IS NULL
                AND basis_attempt IS NULL
                AND basis_effect_key IS NULL
            )
        )
    )
);

ALTER TABLE public.saga_operator_transitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.saga_operator_transitions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.saga_operator_transitions
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);

CREATE INDEX saga_operator_transitions_time_idx
    ON public.saga_operator_transitions (tenant_id, transitioned_at, saga_id);

-- Registration now consumes the durable authorization facts minted before start. The old function
-- is removed rather than retained as a compatibility path that could invent missing audit data.
DROP FUNCTION public.rss_saga_register(uuid, text, text, text, text, text);

CREATE FUNCTION public.rss_saga_register(
    saga_id uuid, owner text, contract_id text, definition_version text,
    definition_schema_digest text, action_registry_generation text,
    start_actor text, start_audit_id text
)
RETURNS boolean
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    WITH inserted AS (
        INSERT INTO public.saga_instances (
            tenant_id, saga_id, owner, contract_id, definition_version,
            definition_schema_digest, action_registry_generation, start_actor, start_audit_id
        )
        SELECT NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid,
               saga_id, owner, contract_id, definition_version,
               definition_schema_digest, action_registry_generation, start_actor, start_audit_id
        WHERE NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '') IS NOT NULL
        ON CONFLICT (tenant_id, saga_id) DO NOTHING
        RETURNING 1
    )
    SELECT pg_catalog.count(*) = 1 FROM inserted
$$;

-- Adding saga_instances.start_audit_id creates a new column with the same name as the existing
-- operator-decision function argument. Qualify the argument explicitly so PostgreSQL cannot bind
-- the durable Saga-start audit id in place of the operator action audit id.
DROP FUNCTION public.rss_saga_record_operator_decision(
    uuid, uuid, bigint, bigint, text, text, text, text, text, text
);

CREATE FUNCTION public.rss_saga_record_operator_decision(
    saga_id uuid, lease_token uuid, epoch bigint, decision_seq bigint,
    phase text, decision text, expected_reason text, reason_text text, operator_actor text,
    change_ticket text, start_audit_id text
)
RETURNS boolean
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    WITH inserted AS (
        INSERT INTO public.saga_operator_decisions (
            tenant_id, saga_id, intent_seq, decision_seq, phase, decision,
            operator_reason, operator_reason_text, operator_actor, change_ticket, start_audit_id,
            repair_epoch
        )
        SELECT instance.tenant_id, instance.saga_id, decision_seq - 1, decision_seq,
               phase, decision, expected_reason, reason_text, operator_actor, change_ticket,
               rss_saga_record_operator_decision.start_audit_id, instance.epoch
        FROM public.saga_instances AS instance
        JOIN public.saga_journal AS journal
          ON journal.tenant_id = instance.tenant_id
         AND journal.saga_id = instance.saga_id
         AND journal.seq = decision_seq
        WHERE instance.tenant_id =
                  NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
          AND instance.saga_id = rss_saga_record_operator_decision.saga_id
          AND instance.lease_token = rss_saga_record_operator_decision.lease_token
          AND instance.epoch = rss_saga_record_operator_decision.epoch
          AND instance.expires_at > pg_catalog.clock_timestamp()
          AND instance.status = 'operator_required'
          AND instance.operator_reason = expected_reason
          AND (
              (phase = 'forward'
               AND expected_reason IN ('forward_outcome_unknown', 'completion_commit_unknown')
               AND ((decision = 'confirmed_applied'
                     AND journal.status = 'forward_completed')
                    OR (decision = 'confirmed_not_applied'
                        AND journal.status = 'forward_not_applied')))
              OR (phase = 'compensation'
                  AND expected_reason = 'compensation_outcome_unknown'
                  AND ((decision = 'confirmed_applied'
                        AND journal.status = 'compensation_completed')
                       OR (decision = 'confirmed_not_applied'
                           AND journal.status = 'compensation_not_applied')))
          )
        ON CONFLICT DO NOTHING
        RETURNING 1
    )
    SELECT pg_catalog.count(*) = 1 FROM inserted
$$;

CREATE FUNCTION public.rss_saga_retry_compensation(
    p_saga_id uuid, p_expected_owner text, p_expected_contract_id text, p_failure_seq bigint,
    p_failure_step_name text, p_failure_attempt integer, p_failure_effect_key bytea,
    p_operator_actor text, p_reason_text text, p_change_ticket text, p_start_audit_id text
)
RETURNS boolean
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    WITH current_state AS (
        SELECT instance.tenant_id, instance.saga_id, instance.status,
               instance.operator_reason, instance.compensation_cause,
               instance.unresolved_at, instance.epoch
        FROM public.saga_instances AS instance
        WHERE instance.tenant_id =
                  NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
          AND instance.saga_id = p_saga_id
          AND instance.owner = p_expected_owner
          AND instance.contract_id = p_expected_contract_id
          AND instance.status = 'compensation_failed'
          AND instance.unresolved_at IS NOT NULL
          AND (instance.lease_token IS NULL
               OR instance.expires_at <= pg_catalog.clock_timestamp())
          AND EXISTS (
              SELECT 1
              FROM public.saga_journal AS failure
              WHERE failure.tenant_id = instance.tenant_id
                AND failure.saga_id = instance.saga_id
                AND failure.seq = p_failure_seq
                AND failure.step_name = p_failure_step_name
                AND failure.status = 'compensation_failed'
                AND failure.attempt = p_failure_attempt
                AND failure.effect_key = p_failure_effect_key
                AND EXISTS (
                    SELECT 1
                    FROM public.saga_journal AS intent
                    WHERE intent.tenant_id = failure.tenant_id
                      AND intent.saga_id = failure.saga_id
                      AND intent.seq + 1 = failure.seq
                      AND intent.step_name = failure.step_name
                      AND intent.status = 'compensation_intent'
                      AND intent.attempt = failure.attempt
                      AND intent.effect_key = failure.effect_key
                      AND intent.compensation_cause = instance.compensation_cause
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM public.saga_journal AS later
                    WHERE later.tenant_id = failure.tenant_id
                      AND later.saga_id = failure.saga_id
                      AND later.seq > failure.seq
                )
          )
        FOR UPDATE
    ), transitioned AS (
        UPDATE public.saga_instances AS instance
        SET status = 'compensating', operator_reason = NULL, epoch = instance.epoch + 1,
            lease_token = NULL, holder_id = NULL, acquired_at = NULL,
            expires_at = NULL, heartbeat_at = NULL,
            updated_at = pg_catalog.clock_timestamp()
        FROM current_state
        WHERE instance.tenant_id = current_state.tenant_id
          AND instance.saga_id = current_state.saga_id
        RETURNING current_state.tenant_id, current_state.saga_id, current_state.status,
                  current_state.operator_reason, current_state.compensation_cause,
                  current_state.unresolved_at, instance.epoch
    ), audited AS (
        INSERT INTO public.saga_operator_transitions (
            tenant_id, saga_id, transition_epoch, transition, from_status, to_status,
            from_operator_reason, from_compensation_cause, observed_unresolved_at,
            basis_seq, basis_step_name, basis_attempt, basis_effect_key,
            operator_actor, operator_reason_text, change_ticket, start_audit_id
        )
        SELECT transitioned.tenant_id, transitioned.saga_id, transitioned.epoch,
               'retry_compensation', transitioned.status, 'compensating',
               transitioned.operator_reason, transitioned.compensation_cause,
               transitioned.unresolved_at, p_failure_seq, p_failure_step_name,
               p_failure_attempt, p_failure_effect_key,
               p_operator_actor, p_reason_text, p_change_ticket, p_start_audit_id
        FROM transitioned
        RETURNING 1
    )
    SELECT pg_catalog.count(*) = 1 FROM audited
$$;

CREATE FUNCTION public.rss_saga_terminate(
    p_saga_id uuid, p_expected_owner text, p_expected_contract_id text,
    p_operator_actor text, p_reason_text text, p_change_ticket text, p_start_audit_id text
)
RETURNS boolean
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    WITH current_state AS (
        SELECT instance.tenant_id, instance.saga_id, instance.status,
               instance.operator_reason, instance.compensation_cause,
               instance.unresolved_at, instance.epoch
        FROM public.saga_instances AS instance
        WHERE instance.tenant_id =
                  NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
          AND instance.saga_id = p_saga_id
          AND instance.owner = p_expected_owner
          AND instance.contract_id = p_expected_contract_id
          AND instance.status = 'ready'
          AND instance.unresolved_at IS NULL
          AND (instance.lease_token IS NULL
               OR instance.expires_at <= pg_catalog.clock_timestamp())
          AND NOT EXISTS (
              SELECT 1
              FROM public.saga_journal AS intent
              WHERE intent.tenant_id = instance.tenant_id
                AND intent.saga_id = instance.saga_id
                AND intent.status IN ('forward_intent', 'compensation_intent')
          )
        FOR UPDATE
    ), transitioned AS (
        UPDATE public.saga_instances AS instance
        SET status = 'terminated', operator_reason = NULL, compensation_cause = NULL,
            epoch = instance.epoch + 1,
            lease_token = NULL, holder_id = NULL, acquired_at = NULL,
            expires_at = NULL, heartbeat_at = NULL,
            updated_at = pg_catalog.clock_timestamp()
        FROM current_state
        WHERE instance.tenant_id = current_state.tenant_id
          AND instance.saga_id = current_state.saga_id
        RETURNING current_state.tenant_id, current_state.saga_id, current_state.status,
                  current_state.operator_reason, current_state.compensation_cause,
                  current_state.unresolved_at, instance.epoch
    ), audited AS (
        INSERT INTO public.saga_operator_transitions (
            tenant_id, saga_id, transition_epoch, transition, from_status, to_status,
            from_operator_reason, from_compensation_cause, observed_unresolved_at,
            operator_actor, operator_reason_text, change_ticket, start_audit_id
        )
        SELECT transitioned.tenant_id, transitioned.saga_id, transitioned.epoch,
               'terminate', transitioned.status, 'terminated', transitioned.operator_reason,
               transitioned.compensation_cause, transitioned.unresolved_at,
               p_operator_actor, p_reason_text, p_change_ticket, p_start_audit_id
        FROM transitioned
        RETURNING 1
    )
    SELECT pg_catalog.count(*) = 1 FROM audited
$$;

ALTER FUNCTION public.rss_saga_register(uuid, text, text, text, text, text, text, text)
    OWNER TO rss_saga_writer;
ALTER FUNCTION public.rss_saga_record_operator_decision(
    uuid, uuid, bigint, bigint, text, text, text, text, text, text, text
) OWNER TO rss_saga_writer;
ALTER FUNCTION public.rss_saga_retry_compensation(
    uuid, text, text, bigint, text, integer, bytea, text, text, text, text
) OWNER TO rss_saga_writer;
ALTER FUNCTION public.rss_saga_terminate(
    uuid, text, text, text, text, text, text
) OWNER TO rss_saga_writer;

REVOKE ALL ON TABLE public.saga_operator_transitions FROM PUBLIC, rss_app, rss_app_read,
    rss_saga_writer;
GRANT SELECT, INSERT ON TABLE public.saga_operator_transitions TO rss_saga_writer;
GRANT SELECT ON TABLE public.saga_operator_transitions TO rss_app, rss_app_read;

REVOKE ALL ON FUNCTION public.rss_saga_register(
    uuid, text, text, text, text, text, text, text
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rss_saga_record_operator_decision(
    uuid, uuid, bigint, bigint, text, text, text, text, text, text, text
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rss_saga_retry_compensation(
    uuid, text, text, bigint, text, integer, bytea, text, text, text, text
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rss_saga_terminate(
    uuid, text, text, text, text, text, text
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.rss_saga_register(
    uuid, text, text, text, text, text, text, text
) TO rss_app;
GRANT EXECUTE ON FUNCTION public.rss_saga_record_operator_decision(
    uuid, uuid, bigint, bigint, text, text, text, text, text, text, text
) TO rss_app;
GRANT EXECUTE ON FUNCTION public.rss_saga_retry_compensation(
    uuid, text, text, bigint, text, integer, bytea, text, text, text, text
) TO rss_app;
GRANT EXECUTE ON FUNCTION public.rss_saga_terminate(
    uuid, text, text, text, text, text, text
) TO rss_app;
