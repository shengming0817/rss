-- 0086_close_saga_durable_recovery.sql
--
-- Pre-activation breaking cutover to the closed Saga durable writer/recovery model. No durable
-- Saga row has been activated in production, so refusing every non-empty table is safer than
-- assigning invented intent keys, attempts or operator resolution metadata.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

LOCK TABLE public.saga_instances, public.saga_journal, public.saga_step_receipts
    IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.saga_instances LIMIT 1)
        OR EXISTS (SELECT 1 FROM public.saga_journal LIMIT 1)
        OR EXISTS (SELECT 1 FROM public.saga_step_receipts LIMIT 1)
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'cannot close saga durable recovery while saga durable rows exist';
    END IF;
END
$$;

DROP TRIGGER saga_receipt_requires_completed ON public.saga_step_receipts;
DROP TRIGGER saga_completed_requires_receipt ON public.saga_journal;
DROP FUNCTION public.rss_assert_saga_receipt_has_completed();
DROP FUNCTION public.rss_assert_saga_completed_has_receipt();

DROP INDEX public.saga_instances_terminal_retention_idx;
DROP TRIGGER saga_instances_terminal_at_guard ON public.saga_instances;
DROP FUNCTION public.rss_saga_terminal_at_guard();

ALTER TABLE public.saga_instances
    DROP CONSTRAINT saga_instances_status_valid,
    DROP CONSTRAINT saga_instances_terminal_time_consistent,
    ADD COLUMN operator_reason text,
    ADD COLUMN compensation_cause text,
    ADD CONSTRAINT saga_instances_status_valid CHECK (status IN (
        'ready', 'running', 'succeeded', 'compensating', 'compensated', 'expired',
        'compensation_failed', 'operator_required', 'degraded'
    )),
    ADD CONSTRAINT saga_instances_operator_reason_valid CHECK (
        operator_reason IS NULL OR operator_reason IN (
            'forward_outcome_unknown', 'compensation_outcome_unknown', 'receipt_missing',
            'receipt_integrity', 'receipt_format_unsupported', 'completion_commit_unknown',
            'definition_unsupported'
        )
    ),
    ADD CONSTRAINT saga_instances_compensation_cause_valid CHECK (
        compensation_cause IS NULL OR compensation_cause IN ('business_failure', 'expired')
    ),
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
        (status IN ('succeeded', 'compensated', 'expired', 'compensation_failed'))
            = (terminal_at IS NOT NULL)
    );

CREATE FUNCTION public.rss_saga_terminal_at_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.status IN ('succeeded', 'compensated', 'expired', 'compensation_failed') THEN
        IF TG_OP = 'INSERT'
            OR OLD.status NOT IN ('succeeded', 'compensated', 'expired', 'compensation_failed')
        THEN
            NEW.terminal_at := pg_catalog.clock_timestamp();
        ELSE
            NEW.terminal_at := OLD.terminal_at;
        END IF;
    ELSE
        NEW.terminal_at := NULL;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER saga_instances_terminal_at_guard
BEFORE INSERT OR UPDATE ON public.saga_instances
FOR EACH ROW EXECUTE FUNCTION public.rss_saga_terminal_at_guard();

REVOKE ALL ON FUNCTION public.rss_saga_terminal_at_guard() FROM PUBLIC;

ALTER TABLE public.saga_journal
    DROP CONSTRAINT saga_journal_status_check,
    ADD COLUMN attempt integer NOT NULL,
    ADD COLUMN effect_key bytea NOT NULL,
    ADD COLUMN compensation_cause text,
    ADD CONSTRAINT saga_journal_status_check CHECK (status IN (
        'forward_intent', 'forward_completed', 'forward_not_applied',
        'compensation_intent', 'compensation_completed', 'compensation_not_applied',
        'compensation_failed'
    )),
    ADD CONSTRAINT saga_journal_attempt_positive CHECK (attempt > 0),
    ADD CONSTRAINT saga_journal_effect_key_width CHECK (pg_catalog.octet_length(effect_key) = 32),
    ADD CONSTRAINT saga_journal_compensation_cause_valid CHECK (
        compensation_cause IS NULL OR compensation_cause IN ('business_failure', 'expired')
    ),
    ADD CONSTRAINT saga_journal_compensation_cause_shape CHECK (
        (status IN ('compensation_intent', 'compensation_not_applied'))
            = (compensation_cause IS NOT NULL)
    ),
    ADD CONSTRAINT saga_journal_error_shape CHECK (
        (status = 'compensation_failed') = (error_summary IS NOT NULL)
    );

CREATE FUNCTION public.rss_assert_saga_receipt_has_completed()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM public.saga_journal AS journal
        WHERE journal.tenant_id = NEW.tenant_id
          AND journal.saga_id = NEW.saga_id
          AND journal.seq = NEW.completed_seq
          AND journal.step_name = NEW.step_name
          AND journal.status = 'forward_completed'
          AND journal.attempt = NEW.successful_attempt
          AND journal.effect_key = NEW.effect_key
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'saga receipt requires exact forward_completed journal row';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.rss_assert_saga_completed_has_receipt()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.status IN ('forward_intent', 'compensation_intent')
        AND (
            NEW.attempt <> 1 + (
                SELECT pg_catalog.count(*)
                FROM public.saga_journal AS prior
                WHERE prior.tenant_id = NEW.tenant_id
                  AND prior.saga_id = NEW.saga_id
                  AND prior.seq < NEW.seq
                  AND prior.step_name = NEW.step_name
                  AND prior.status = NEW.status
            )
            OR EXISTS (
                SELECT 1
                FROM public.saga_journal AS duplicate
                WHERE duplicate.tenant_id = NEW.tenant_id
                  AND duplicate.saga_id = NEW.saga_id
                  AND duplicate.seq <> NEW.seq
                  AND duplicate.step_name = NEW.step_name
                  AND duplicate.status = NEW.status
                  AND duplicate.attempt = NEW.attempt
            )
        )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'saga intent attempt must be contiguous within step and phase';
    END IF;
    IF NEW.status = 'compensation_intent' AND NOT EXISTS (
        SELECT 1
        FROM public.saga_instances AS instance
        WHERE instance.tenant_id = NEW.tenant_id
          AND instance.saga_id = NEW.saga_id
          AND NEW.compensation_cause = instance.compensation_cause
          AND instance.compensation_cause IS NOT NULL
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'saga compensation intent requires the pinned instance cause';
    END IF;
    IF NEW.status = 'forward_completed' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM public.saga_step_receipts AS receipt
            WHERE receipt.tenant_id = NEW.tenant_id
              AND receipt.saga_id = NEW.saga_id
              AND receipt.completed_seq = NEW.seq
              AND receipt.step_name = NEW.step_name
              AND receipt.successful_attempt = NEW.attempt
              AND receipt.effect_key = NEW.effect_key
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'saga forward_completed journal row requires exact receipt';
        END IF;
        IF NOT EXISTS (
            SELECT 1
            FROM public.saga_journal AS intent
            WHERE intent.tenant_id = NEW.tenant_id
              AND intent.saga_id = NEW.saga_id
              AND intent.seq + 1 = NEW.seq
              AND intent.step_name = NEW.step_name
              AND intent.status = 'forward_intent'
              AND intent.attempt = NEW.attempt
              AND intent.effect_key = NEW.effect_key
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'saga forward_completed journal row requires exact prior intent';
        END IF;
    ELSIF NEW.status IN (
        'forward_not_applied', 'compensation_completed',
        'compensation_not_applied', 'compensation_failed'
    )
        AND NOT EXISTS (
            SELECT 1
            FROM public.saga_journal AS intent
            JOIN public.saga_instances AS instance
              ON instance.tenant_id = intent.tenant_id
             AND instance.saga_id = intent.saga_id
            WHERE intent.tenant_id = NEW.tenant_id
              AND intent.saga_id = NEW.saga_id
              AND intent.seq + 1 = NEW.seq
              AND intent.step_name = NEW.step_name
              AND intent.status = CASE
                    WHEN NEW.status = 'forward_not_applied' THEN 'forward_intent'
                    ELSE 'compensation_intent'
                  END
              AND intent.attempt = NEW.attempt
              AND intent.effect_key = NEW.effect_key
              AND (
                    NEW.status = 'forward_not_applied'
                    OR (
                        intent.compensation_cause = instance.compensation_cause
                        AND instance.compensation_cause IS NOT NULL
                    )
                  )
        )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'saga operator/completion transition requires exact prior pinned intent';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER saga_receipt_requires_completed
AFTER INSERT OR UPDATE ON public.saga_step_receipts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.rss_assert_saga_receipt_has_completed();

CREATE CONSTRAINT TRIGGER saga_completed_requires_receipt
AFTER INSERT OR UPDATE ON public.saga_journal
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.rss_assert_saga_completed_has_receipt();

REVOKE ALL ON FUNCTION public.rss_assert_saga_receipt_has_completed() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rss_assert_saga_completed_has_receipt() FROM PUBLIC;

CREATE TABLE public.saga_operator_decisions (
    tenant_id uuid NOT NULL,
    saga_id uuid NOT NULL,
    intent_seq bigint NOT NULL CHECK (intent_seq >= 0),
    decision_seq bigint NOT NULL CHECK (decision_seq = intent_seq + 1),
    phase text NOT NULL CHECK (phase IN ('forward', 'compensation')),
    decision text NOT NULL CHECK (decision IN ('confirmed_applied', 'confirmed_not_applied')),
    operator_reason text NOT NULL CHECK (operator_reason IN (
        'forward_outcome_unknown', 'compensation_outcome_unknown', 'completion_commit_unknown'
    )),
    operator_actor text NOT NULL CHECK (
        pg_catalog.octet_length(operator_actor) BETWEEN 1 AND 128
    ),
    change_ticket text NOT NULL CHECK (
        pg_catalog.octet_length(change_ticket) BETWEEN 1 AND 128
    ),
    start_audit_id text NOT NULL CHECK (
        pg_catalog.octet_length(start_audit_id) BETWEEN 1 AND 128
    ),
    repair_epoch bigint NOT NULL CHECK (repair_epoch > 0),
    decided_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (tenant_id, saga_id, intent_seq),
    FOREIGN KEY (tenant_id, saga_id)
        REFERENCES public.saga_instances (tenant_id, saga_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, saga_id, decision_seq)
        REFERENCES public.saga_journal (tenant_id, saga_id, seq)
        DEFERRABLE INITIALLY DEFERRED
);

ALTER TABLE public.saga_operator_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.saga_operator_decisions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.saga_operator_decisions
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);

CREATE INDEX saga_instances_terminal_retention_idx
    ON public.saga_instances (terminal_at, tenant_id, saga_id)
    WHERE status IN ('succeeded', 'compensated', 'expired', 'compensation_failed');

CREATE INDEX saga_instances_worker_candidate_idx
    ON public.saga_instances (owner, contract_id, status, tenant_id, expires_at)
    WHERE status IN ('ready', 'running', 'compensating');

CREATE INDEX saga_instances_unresolved_observation_idx
    ON public.saga_instances (owner, contract_id, tenant_id)
    WHERE status IN ('operator_required', 'degraded');

CREATE OR REPLACE FUNCTION public.rss_saga_worker_tenant_index_refresh()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.status IN ('ready', 'running', 'compensating') THEN
        INSERT INTO public.saga_worker_tenant_index (tenant_id, owner, contract_id, updated_at)
        VALUES (NEW.tenant_id, NEW.owner, NEW.contract_id, pg_catalog.clock_timestamp())
        ON CONFLICT (tenant_id, owner, contract_id) DO UPDATE
        SET updated_at = EXCLUDED.updated_at;
        RETURN NEW;
    END IF;

    DELETE FROM public.saga_worker_tenant_index AS candidate
    WHERE candidate.tenant_id = NEW.tenant_id
      AND candidate.owner = NEW.owner
      AND candidate.contract_id = NEW.contract_id
      AND NOT EXISTS (
          SELECT 1
          FROM public.saga_instances AS instance
          WHERE instance.tenant_id = NEW.tenant_id
            AND instance.owner = NEW.owner
            AND instance.contract_id = NEW.contract_id
            AND instance.status IN ('ready', 'running', 'compensating')
      );
    RETURN NEW;
END;
$$;

DELETE FROM public.saga_worker_tenant_index AS candidate
WHERE NOT EXISTS (
    SELECT 1
    FROM public.saga_instances AS instance
    WHERE instance.tenant_id = candidate.tenant_id
      AND instance.owner = candidate.owner
      AND instance.contract_id = candidate.contract_id
      AND instance.status IN ('ready', 'running', 'compensating')
);

DROP FUNCTION public.rss_saga_candidate_tenants(text, text, bigint);

CREATE FUNCTION public.rss_saga_candidate_tenants(
    p_owner text, p_contract_id text, p_after_tenant uuid, p_limit bigint
)
RETURNS TABLE (tenant_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF p_owner IS NULL OR pg_catalog.length(p_owner) = 0 THEN
        RAISE EXCEPTION 'rss_saga_candidate_tenants owner must be non-empty';
    END IF;
    IF p_contract_id IS NULL OR pg_catalog.length(p_contract_id) = 0 THEN
        RAISE EXCEPTION 'rss_saga_candidate_tenants contract id must be non-empty';
    END IF;
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 10001 THEN
        RAISE EXCEPTION 'rss_saga_candidate_tenants fetch limit must be in range [1, 10001]';
    END IF;

    RETURN QUERY
    SELECT candidate.tenant_id
    FROM public.saga_worker_tenant_index AS candidate
    WHERE candidate.owner = p_owner
      AND candidate.contract_id = p_contract_id
      AND (p_after_tenant IS NULL OR candidate.tenant_id > p_after_tenant)
      AND EXISTS (
          SELECT 1
          FROM public.saga_instances AS instance
          WHERE instance.tenant_id = candidate.tenant_id
            AND instance.owner = candidate.owner
            AND instance.contract_id = candidate.contract_id
            AND instance.status IN ('ready', 'running', 'compensating')
            AND (instance.lease_token IS NULL
                 OR instance.expires_at <= pg_catalog.clock_timestamp())
      )
    ORDER BY candidate.tenant_id
    LIMIT p_limit;
END;
$$;

CREATE FUNCTION public.rss_saga_observe_unresolved(p_owner text, p_contract_id text)
RETURNS boolean
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
    RETURN EXISTS (
        SELECT 1
        FROM public.saga_instances AS instance
        WHERE instance.owner = p_owner
          AND instance.contract_id = p_contract_id
          AND instance.status IN ('operator_required', 'degraded')
    );
END;
$$;

ALTER FUNCTION public.rss_saga_worker_tenant_index_refresh() OWNER TO rss_saga_maintenance;
ALTER FUNCTION public.rss_saga_candidate_tenants(text, text, uuid, bigint)
    OWNER TO rss_saga_maintenance;
ALTER FUNCTION public.rss_saga_observe_unresolved(text, text) OWNER TO rss_saga_maintenance;
REVOKE ALL ON FUNCTION public.rss_saga_worker_tenant_index_refresh() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rss_saga_candidate_tenants(text, text, uuid, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rss_saga_observe_unresolved(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rss_saga_candidate_tenants(text, text, uuid, bigint) TO rss_app;
GRANT EXECUTE ON FUNCTION public.rss_saga_observe_unresolved(text, text) TO rss_app;

CREATE OR REPLACE FUNCTION public.rss_sweep_terminal_sagas()
RETURNS bigint
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
        WHERE status IN ('succeeded', 'compensated', 'expired', 'compensation_failed')
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
    RETURN deleted_rows;
END;
$$;

ALTER FUNCTION public.rss_sweep_terminal_sagas() OWNER TO rss_saga_receipt_maintenance;
REVOKE ALL ON FUNCTION public.rss_sweep_terminal_sagas() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rss_sweep_terminal_sagas() TO rss_app;

-- All serving writes cross a fixed SECURITY DEFINER surface. The owner is deliberately NOLOGIN;
-- BYPASSRLS is confined to these functions, which derive the tenant from the transaction GUC and
-- fence every mutation by exact aggregate state and, after claim, an unexpired token plus epoch.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rss_saga_writer'
    ) THEN
        CREATE ROLE rss_saga_writer
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION BYPASSRLS;
    ELSE
        ALTER ROLE rss_saga_writer
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION BYPASSRLS;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members AS membership
        JOIN pg_catalog.pg_roles AS role
          ON role.oid = membership.roleid OR role.oid = membership.member
        WHERE role.rolname = 'rss_saga_writer'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'rss_saga_writer must have no role memberships';
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO rss_saga_writer;
REVOKE ALL ON TABLE public.saga_instances, public.saga_journal,
    public.saga_step_receipts, public.saga_operator_decisions FROM rss_saga_writer;
GRANT SELECT, INSERT, UPDATE ON TABLE public.saga_instances TO rss_saga_writer;
GRANT SELECT, INSERT ON TABLE public.saga_journal, public.saga_step_receipts,
    public.saga_operator_decisions TO rss_saga_writer;

CREATE FUNCTION public.rss_saga_register(
    saga_id uuid, owner text, contract_id text, definition_version text,
    definition_schema_digest text, action_registry_generation text
)
RETURNS boolean
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    WITH inserted AS (
        INSERT INTO public.saga_instances (
            tenant_id, saga_id, owner, contract_id, definition_version,
            definition_schema_digest, action_registry_generation
        )
        SELECT NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid,
               saga_id, owner, contract_id, definition_version,
               definition_schema_digest, action_registry_generation
        WHERE NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '') IS NOT NULL
        ON CONFLICT (tenant_id, saga_id) DO NOTHING
        RETURNING 1
    )
    SELECT pg_catalog.count(*) = 1 FROM inserted
$$;

CREATE FUNCTION public.rss_saga_claim(
    saga_id uuid, owner text, contract_id text, definition_version text,
    definition_schema_digest text, action_registry_generation text,
    expected_status text, holder_id text, ttl_micros bigint
)
RETURNS TABLE (lease_token text, epoch bigint)
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    UPDATE public.saga_instances AS instance
    SET status = CASE WHEN instance.status = 'ready' THEN 'running' ELSE instance.status END,
        lease_token = pg_catalog.gen_random_uuid(), holder_id = rss_saga_claim.holder_id,
        epoch = instance.epoch + 1, acquired_at = pg_catalog.clock_timestamp(),
        expires_at = pg_catalog.clock_timestamp() + (ttl_micros * interval '1 microsecond'),
        heartbeat_at = pg_catalog.clock_timestamp(), updated_at = pg_catalog.clock_timestamp()
    WHERE instance.tenant_id =
              NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
      AND instance.saga_id = rss_saga_claim.saga_id
      AND instance.owner = rss_saga_claim.owner
      AND instance.contract_id = rss_saga_claim.contract_id
      AND instance.definition_version = rss_saga_claim.definition_version
      AND instance.definition_schema_digest = rss_saga_claim.definition_schema_digest
      AND instance.action_registry_generation = rss_saga_claim.action_registry_generation
      AND rss_saga_claim.expected_status IN ('ready', 'running', 'compensating')
      AND instance.status = rss_saga_claim.expected_status
      AND (instance.lease_token IS NULL
           OR instance.expires_at <= pg_catalog.clock_timestamp())
      AND ttl_micros > 0
    RETURNING instance.lease_token::text, instance.epoch
$$;

CREATE FUNCTION public.rss_saga_claim_operator(
    saga_id uuid, expected_owner text, expected_contract_id text,
    expected_reason text, holder_id text, ttl_micros bigint
)
RETURNS TABLE (lease_token text, epoch bigint)
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    UPDATE public.saga_instances AS instance
    SET lease_token = pg_catalog.gen_random_uuid(),
        holder_id = rss_saga_claim_operator.holder_id, epoch = instance.epoch + 1,
        acquired_at = pg_catalog.clock_timestamp(),
        expires_at = pg_catalog.clock_timestamp() + (ttl_micros * interval '1 microsecond'),
        heartbeat_at = pg_catalog.clock_timestamp(), updated_at = pg_catalog.clock_timestamp()
    WHERE instance.tenant_id =
              NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
      AND instance.saga_id = rss_saga_claim_operator.saga_id
      AND instance.owner = rss_saga_claim_operator.expected_owner
      AND instance.contract_id = rss_saga_claim_operator.expected_contract_id
      AND instance.status = 'operator_required'
      AND instance.operator_reason = rss_saga_claim_operator.expected_reason
      AND rss_saga_claim_operator.expected_reason IN (
          'forward_outcome_unknown', 'compensation_outcome_unknown',
          'receipt_missing', 'receipt_integrity', 'receipt_format_unsupported',
          'completion_commit_unknown', 'definition_unsupported'
      )
      AND (instance.lease_token IS NULL
           OR instance.expires_at <= pg_catalog.clock_timestamp())
      AND ttl_micros > 0
    RETURNING instance.lease_token::text, instance.epoch
$$;

CREATE FUNCTION public.rss_saga_renew_lease(
    saga_id uuid, lease_token uuid, epoch bigint, ttl_micros bigint
)
RETURNS boolean
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    WITH renewed AS (
        UPDATE public.saga_instances AS instance
        SET expires_at = pg_catalog.clock_timestamp() + (ttl_micros * interval '1 microsecond'),
            heartbeat_at = pg_catalog.clock_timestamp(), updated_at = pg_catalog.clock_timestamp()
        WHERE instance.tenant_id =
                  NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
          AND instance.saga_id = rss_saga_renew_lease.saga_id
          AND instance.lease_token = rss_saga_renew_lease.lease_token
          AND instance.epoch = rss_saga_renew_lease.epoch
          AND instance.expires_at > pg_catalog.clock_timestamp()
          AND instance.status IN ('running', 'compensating', 'operator_required')
          AND ttl_micros > 0
        RETURNING 1
    )
    SELECT pg_catalog.count(*) = 1 FROM renewed
$$;

CREATE FUNCTION public.rss_saga_release_lease(
    saga_id uuid, lease_token uuid, epoch bigint
)
RETURNS boolean
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    WITH released AS (
        UPDATE public.saga_instances AS instance
        SET lease_token = NULL, holder_id = NULL, acquired_at = NULL,
            expires_at = NULL, heartbeat_at = NULL, updated_at = pg_catalog.clock_timestamp()
        WHERE instance.tenant_id =
                  NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
          AND instance.saga_id = rss_saga_release_lease.saga_id
          AND instance.lease_token = rss_saga_release_lease.lease_token
          AND instance.epoch = rss_saga_release_lease.epoch
          AND instance.expires_at > pg_catalog.clock_timestamp()
          AND instance.status IN ('running', 'compensating', 'operator_required')
        RETURNING 1
    )
    SELECT pg_catalog.count(*) = 1 FROM released
$$;

CREATE FUNCTION public.rss_saga_apply_lifecycle(
    p_saga_id uuid, p_lease_token uuid, p_epoch bigint, p_next_status text,
    p_operator_reason text, p_compensation_cause text, p_clear_lease boolean,
    p_expected_statuses text[], p_preserve_compensation_cause boolean
)
RETURNS boolean
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    WITH transitioned AS (
        UPDATE public.saga_instances AS instance
        SET status = p_next_status,
            operator_reason = p_operator_reason,
            compensation_cause = CASE
                WHEN p_preserve_compensation_cause THEN instance.compensation_cause
                ELSE p_compensation_cause
            END,
            lease_token = CASE WHEN p_clear_lease
                THEN NULL ELSE instance.lease_token END,
            holder_id = CASE WHEN p_clear_lease
                THEN NULL ELSE instance.holder_id END,
            acquired_at = CASE WHEN p_clear_lease
                THEN NULL ELSE instance.acquired_at END,
            expires_at = CASE WHEN p_clear_lease
                THEN NULL ELSE instance.expires_at END,
            heartbeat_at = CASE WHEN p_clear_lease
                THEN NULL ELSE instance.heartbeat_at END,
            updated_at = pg_catalog.clock_timestamp()
        WHERE instance.tenant_id =
                  NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
          AND instance.saga_id = p_saga_id
          AND instance.lease_token = p_lease_token
          AND instance.epoch = p_epoch
          AND instance.expires_at > pg_catalog.clock_timestamp()
          AND instance.status = ANY(p_expected_statuses)
          AND (
              (p_next_status = 'succeeded' AND p_operator_reason IS NULL
               AND p_compensation_cause IS NULL AND p_clear_lease
               AND p_expected_statuses = ARRAY['running']::text[]
               AND NOT p_preserve_compensation_cause)
              OR (p_next_status = 'compensating' AND p_operator_reason IS NULL
                  AND p_compensation_cause IN ('business_failure', 'expired')
                  AND NOT p_clear_lease
                  AND p_expected_statuses = ARRAY['running', 'compensating']::text[]
                  AND NOT p_preserve_compensation_cause)
              OR (p_next_status = 'compensating' AND p_operator_reason IS NULL
                  AND p_compensation_cause IS NULL AND NOT p_clear_lease
                  AND p_expected_statuses = ARRAY['compensating']::text[]
                  AND p_preserve_compensation_cause)
              OR (p_next_status IN ('compensated', 'compensation_failed')
                  AND p_operator_reason IS NULL AND p_compensation_cause IS NULL
                  AND p_clear_lease AND p_expected_statuses = ARRAY['compensating']::text[]
                  AND p_preserve_compensation_cause)
              OR (p_next_status = 'expired' AND p_operator_reason IS NULL
                  AND p_compensation_cause = 'expired' AND p_clear_lease
                  AND p_expected_statuses = ARRAY['compensating']::text[]
                  AND NOT p_preserve_compensation_cause)
              OR (p_next_status = 'operator_required'
                  AND p_operator_reason IS NOT NULL
                  AND p_operator_reason <> 'compensation_outcome_unknown'
                  AND p_compensation_cause IS NULL AND p_clear_lease
                  AND p_expected_statuses = ARRAY['running']::text[]
                  AND NOT p_preserve_compensation_cause)
              OR (p_next_status = 'operator_required'
                  AND p_operator_reason = 'compensation_outcome_unknown'
                  AND p_compensation_cause IS NULL AND p_clear_lease
                  AND p_expected_statuses = ARRAY['compensating']::text[]
                  AND p_preserve_compensation_cause)
              OR (p_next_status = 'degraded' AND p_operator_reason IS NULL
                  AND p_compensation_cause IS NULL AND p_clear_lease
                  AND p_expected_statuses = ARRAY['running', 'compensating']::text[]
                  AND NOT p_preserve_compensation_cause)
              OR (p_expected_statuses = ARRAY['operator_required']::text[]
                  AND p_operator_reason IS NULL AND p_clear_lease
                  AND (
                      (p_next_status IN ('running', 'succeeded', 'degraded')
                       AND p_compensation_cause IS NULL
                       AND instance.operator_reason IN (
                           'forward_outcome_unknown', 'completion_commit_unknown'
                       )
                       AND NOT p_preserve_compensation_cause)
                      OR (p_next_status IN ('compensating', 'compensated')
                          AND p_compensation_cause IS NULL
                          AND instance.operator_reason = 'compensation_outcome_unknown'
                          AND p_preserve_compensation_cause)
                      OR (p_next_status = 'compensating'
                          AND p_compensation_cause IN ('business_failure', 'expired')
                          AND instance.operator_reason = 'compensation_outcome_unknown'
                          AND NOT p_preserve_compensation_cause)
                      OR (p_next_status = 'expired' AND p_compensation_cause = 'expired'
                          AND instance.operator_reason = 'compensation_outcome_unknown'
                          AND NOT p_preserve_compensation_cause)
                  ))
          )
          AND (p_preserve_compensation_cause
               OR p_compensation_cause IS NULL
               OR instance.compensation_cause IS NULL
               OR instance.compensation_cause = p_compensation_cause)
        RETURNING 1
    )
    SELECT pg_catalog.count(*) = 1 FROM transitioned
$$;

CREATE FUNCTION public.rss_saga_append_journal(
    p_saga_id uuid, p_lease_token uuid, p_epoch bigint, p_seq bigint, p_step_name text,
    p_journal_status text, p_error_summary text, p_attempt integer, p_effect_key bytea,
    p_compensation_cause text
)
RETURNS boolean
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    WITH inserted AS (
        INSERT INTO public.saga_journal (
            tenant_id, saga_id, seq, step_name, status, error_summary, attempt, effect_key,
            compensation_cause
        )
        SELECT instance.tenant_id, instance.saga_id, p_seq, p_step_name,
               p_journal_status, p_error_summary, p_attempt, p_effect_key,
               p_compensation_cause
        FROM public.saga_instances AS instance
        WHERE instance.tenant_id =
                  NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
          AND instance.saga_id = p_saga_id
          AND instance.lease_token = p_lease_token
          AND instance.epoch = p_epoch
          AND instance.expires_at > pg_catalog.clock_timestamp()
          AND (
              (p_journal_status = 'forward_intent' AND instance.status = 'running')
              OR (p_journal_status = 'forward_completed'
                  AND (instance.status = 'running'
                       OR (instance.status = 'operator_required'
                           AND instance.operator_reason IN (
                               'forward_outcome_unknown', 'completion_commit_unknown'
                           ))))
              OR (p_journal_status = 'forward_not_applied'
                  AND instance.status = 'operator_required'
                  AND instance.operator_reason = 'forward_outcome_unknown')
              OR (p_journal_status = 'compensation_intent'
                  AND instance.status IN ('running', 'compensating'))
              OR (p_journal_status IN ('compensation_completed', 'compensation_failed')
                  AND (instance.status = 'compensating'
                       OR (instance.status = 'operator_required'
                           AND instance.operator_reason = 'compensation_outcome_unknown')))
              OR (p_journal_status = 'compensation_not_applied'
                  AND instance.status = 'operator_required'
                  AND instance.operator_reason = 'compensation_outcome_unknown')
          )
        FOR UPDATE
        ON CONFLICT (tenant_id, saga_id, seq) DO NOTHING
        RETURNING 1
    )
    SELECT pg_catalog.count(*) = 1 FROM inserted
$$;

CREATE FUNCTION public.rss_saga_record_operator_decision(
    saga_id uuid, lease_token uuid, epoch bigint, decision_seq bigint,
    phase text, decision text, expected_reason text, operator_actor text, change_ticket text,
    start_audit_id text
)
RETURNS boolean
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    WITH inserted AS (
        INSERT INTO public.saga_operator_decisions (
            tenant_id, saga_id, intent_seq, decision_seq, phase, decision,
            operator_reason, operator_actor, change_ticket, start_audit_id, repair_epoch
        )
        SELECT instance.tenant_id, instance.saga_id, decision_seq - 1, decision_seq,
               phase, decision, expected_reason, operator_actor, change_ticket,
               start_audit_id, instance.epoch
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

CREATE FUNCTION public.rss_saga_insert_receipt(
    saga_id uuid, lease_token uuid, epoch bigint, owner text, contract_id text,
    definition_version text, definition_schema_digest text,
    action_registry_generation text, step_name text, effect_key bytea,
    receipt_schema text, format_version smallint, ciphertext bytea, key_ref text,
    content_hmac_key_id text, content_hmac bytea, successful_attempt integer,
    completed_seq bigint
)
RETURNS boolean
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    WITH inserted AS (
        INSERT INTO public.saga_step_receipts (
            tenant_id, saga_id, owner, contract_id, definition_version,
            definition_schema_digest, action_registry_generation, step_name, effect_key,
            receipt_schema, format_version, ciphertext, key_ref, content_hmac_key_id,
            content_hmac, successful_attempt, completed_seq
        )
        SELECT instance.tenant_id, instance.saga_id, rss_saga_insert_receipt.owner,
               rss_saga_insert_receipt.contract_id, rss_saga_insert_receipt.definition_version,
               rss_saga_insert_receipt.definition_schema_digest,
               rss_saga_insert_receipt.action_registry_generation,
               rss_saga_insert_receipt.step_name, rss_saga_insert_receipt.effect_key,
               rss_saga_insert_receipt.receipt_schema, rss_saga_insert_receipt.format_version,
               rss_saga_insert_receipt.ciphertext, rss_saga_insert_receipt.key_ref,
               rss_saga_insert_receipt.content_hmac_key_id, rss_saga_insert_receipt.content_hmac,
               rss_saga_insert_receipt.successful_attempt, rss_saga_insert_receipt.completed_seq
        FROM public.saga_instances AS instance
        WHERE instance.tenant_id =
                  NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
          AND instance.saga_id = rss_saga_insert_receipt.saga_id
          AND instance.lease_token = rss_saga_insert_receipt.lease_token
          AND instance.epoch = rss_saga_insert_receipt.epoch
          AND instance.expires_at > pg_catalog.clock_timestamp()
          AND instance.owner = rss_saga_insert_receipt.owner
          AND instance.contract_id = rss_saga_insert_receipt.contract_id
          AND instance.definition_version = rss_saga_insert_receipt.definition_version
          AND instance.definition_schema_digest = rss_saga_insert_receipt.definition_schema_digest
          AND instance.action_registry_generation =
              rss_saga_insert_receipt.action_registry_generation
          AND (instance.status = 'running'
               OR (instance.status = 'operator_required'
                   AND instance.operator_reason IN (
                       'forward_outcome_unknown', 'completion_commit_unknown'
                   )))
        FOR UPDATE
        ON CONFLICT DO NOTHING
        RETURNING 1
    )
    SELECT pg_catalog.count(*) = 1 FROM inserted
$$;

CREATE FUNCTION public.rss_saga_observe_claim(saga_id uuid)
RETURNS TABLE (
    owner text, contract_id text, definition_version text,
    definition_schema_digest text, action_registry_generation text,
    status text, operator_reason text, lease_busy boolean
)
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT instance.owner, instance.contract_id, instance.definition_version,
           instance.definition_schema_digest, instance.action_registry_generation,
           instance.status, instance.operator_reason,
           instance.lease_token IS NOT NULL
               AND instance.expires_at > pg_catalog.clock_timestamp()
    FROM public.saga_instances AS instance
    WHERE instance.tenant_id =
              NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
      AND instance.saga_id = rss_saga_observe_claim.saga_id
    FOR UPDATE
$$;

CREATE FUNCTION public.rss_saga_has_exact_prior_intent(
    saga_id uuid, lease_token uuid, epoch bigint, completed_seq bigint,
    step_name text, required_status text, attempt integer, effect_key bytea
)
RETURNS TABLE (matches boolean)
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.saga_journal AS intent
        WHERE intent.tenant_id = instance.tenant_id
          AND intent.saga_id = instance.saga_id
          AND intent.seq + 1 = completed_seq
          AND intent.step_name = rss_saga_has_exact_prior_intent.step_name
          AND intent.status = required_status
          AND intent.attempt = rss_saga_has_exact_prior_intent.attempt
          AND intent.effect_key = rss_saga_has_exact_prior_intent.effect_key
          AND (required_status <> 'compensation_intent'
               OR (intent.compensation_cause = instance.compensation_cause
                   AND instance.compensation_cause IS NOT NULL))
    )
    FROM public.saga_instances AS instance
    WHERE instance.tenant_id =
              NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
      AND instance.saga_id = rss_saga_has_exact_prior_intent.saga_id
      AND instance.lease_token = rss_saga_has_exact_prior_intent.lease_token
      AND instance.epoch = rss_saga_has_exact_prior_intent.epoch
      AND instance.expires_at > pg_catalog.clock_timestamp()
      AND instance.status IN ('running', 'compensating', 'operator_required')
    FOR UPDATE
$$;

CREATE FUNCTION public.rss_saga_intent_attempt_is_next(
    saga_id uuid, lease_token uuid, epoch bigint, seq bigint,
    step_name text, journal_status text, attempt integer
)
RETURNS TABLE (matches boolean)
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT attempt::bigint = 1 + (
               SELECT pg_catalog.count(*)
               FROM public.saga_journal AS prior
               WHERE prior.tenant_id = instance.tenant_id
                 AND prior.saga_id = instance.saga_id
                 AND prior.seq < rss_saga_intent_attempt_is_next.seq
                 AND prior.step_name = rss_saga_intent_attempt_is_next.step_name
                 AND prior.status = journal_status
           )
           AND NOT EXISTS (
               SELECT 1
               FROM public.saga_journal AS duplicate
               WHERE duplicate.tenant_id = instance.tenant_id
                 AND duplicate.saga_id = instance.saga_id
                 AND duplicate.seq <> rss_saga_intent_attempt_is_next.seq
                 AND duplicate.step_name = rss_saga_intent_attempt_is_next.step_name
                 AND duplicate.status = journal_status
                 AND duplicate.attempt = rss_saga_intent_attempt_is_next.attempt
           )
    FROM public.saga_instances AS instance
    WHERE instance.tenant_id =
              NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
      AND instance.saga_id = rss_saga_intent_attempt_is_next.saga_id
      AND instance.lease_token = rss_saga_intent_attempt_is_next.lease_token
      AND instance.epoch = rss_saga_intent_attempt_is_next.epoch
      AND instance.expires_at > pg_catalog.clock_timestamp()
      AND instance.status IN ('running', 'compensating')
    FOR UPDATE
$$;

CREATE FUNCTION public.rss_saga_lease_is_held(
    saga_id uuid, lease_token uuid, epoch bigint
)
RETURNS TABLE (held boolean)
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT true
    FROM public.saga_instances AS instance
    WHERE instance.tenant_id =
              NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
      AND instance.saga_id = rss_saga_lease_is_held.saga_id
      AND instance.lease_token = rss_saga_lease_is_held.lease_token
      AND instance.epoch = rss_saga_lease_is_held.epoch
      AND instance.expires_at > pg_catalog.clock_timestamp()
      AND instance.status IN ('running', 'compensating', 'operator_required')
    FOR UPDATE
$$;

ALTER FUNCTION public.rss_saga_register(uuid, text, text, text, text, text)
    OWNER TO rss_saga_writer;
ALTER FUNCTION public.rss_saga_claim(uuid, text, text, text, text, text, text, text, bigint)
    OWNER TO rss_saga_writer;
ALTER FUNCTION public.rss_saga_claim_operator(uuid, text, text, text, text, bigint)
    OWNER TO rss_saga_writer;
ALTER FUNCTION public.rss_saga_renew_lease(uuid, uuid, bigint, bigint)
    OWNER TO rss_saga_writer;
ALTER FUNCTION public.rss_saga_release_lease(uuid, uuid, bigint)
    OWNER TO rss_saga_writer;
ALTER FUNCTION public.rss_saga_apply_lifecycle(
    uuid, uuid, bigint, text, text, text, boolean, text[], boolean
) OWNER TO rss_saga_writer;
ALTER FUNCTION public.rss_saga_append_journal(
    uuid, uuid, bigint, bigint, text, text, text, integer, bytea, text
) OWNER TO rss_saga_writer;
ALTER FUNCTION public.rss_saga_record_operator_decision(
    uuid, uuid, bigint, bigint, text, text, text, text, text, text
) OWNER TO rss_saga_writer;
ALTER FUNCTION public.rss_saga_insert_receipt(
    uuid, uuid, bigint, text, text, text, text, text, text, bytea, text, smallint,
    bytea, text, text, bytea, integer, bigint
) OWNER TO rss_saga_writer;
ALTER FUNCTION public.rss_saga_observe_claim(uuid) OWNER TO rss_saga_writer;
ALTER FUNCTION public.rss_saga_has_exact_prior_intent(
    uuid, uuid, bigint, bigint, text, text, integer, bytea
) OWNER TO rss_saga_writer;
ALTER FUNCTION public.rss_saga_intent_attempt_is_next(
    uuid, uuid, bigint, bigint, text, text, integer
) OWNER TO rss_saga_writer;
ALTER FUNCTION public.rss_saga_lease_is_held(uuid, uuid, bigint) OWNER TO rss_saga_writer;

REVOKE ALL ON FUNCTION public.rss_saga_register(uuid, text, text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rss_saga_claim(
    uuid, text, text, text, text, text, text, text, bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rss_saga_claim_operator(
    uuid, text, text, text, text, bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rss_saga_renew_lease(uuid, uuid, bigint, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rss_saga_release_lease(uuid, uuid, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rss_saga_apply_lifecycle(
    uuid, uuid, bigint, text, text, text, boolean, text[], boolean
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rss_saga_append_journal(
    uuid, uuid, bigint, bigint, text, text, text, integer, bytea, text
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rss_saga_record_operator_decision(
    uuid, uuid, bigint, bigint, text, text, text, text, text, text
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rss_saga_insert_receipt(
    uuid, uuid, bigint, text, text, text, text, text, text, bytea, text, smallint,
    bytea, text, text, bytea, integer, bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rss_saga_observe_claim(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rss_saga_has_exact_prior_intent(
    uuid, uuid, bigint, bigint, text, text, integer, bytea
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rss_saga_intent_attempt_is_next(
    uuid, uuid, bigint, bigint, text, text, integer
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rss_saga_lease_is_held(uuid, uuid, bigint) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.rss_saga_register(uuid, text, text, text, text, text)
    TO rss_app;
GRANT EXECUTE ON FUNCTION public.rss_saga_claim(
    uuid, text, text, text, text, text, text, text, bigint
) TO rss_app;
GRANT EXECUTE ON FUNCTION public.rss_saga_claim_operator(
    uuid, text, text, text, text, bigint
) TO rss_app;
GRANT EXECUTE ON FUNCTION public.rss_saga_renew_lease(uuid, uuid, bigint, bigint) TO rss_app;
GRANT EXECUTE ON FUNCTION public.rss_saga_release_lease(uuid, uuid, bigint) TO rss_app;
GRANT EXECUTE ON FUNCTION public.rss_saga_apply_lifecycle(
    uuid, uuid, bigint, text, text, text, boolean, text[], boolean
) TO rss_app;
GRANT EXECUTE ON FUNCTION public.rss_saga_append_journal(
    uuid, uuid, bigint, bigint, text, text, text, integer, bytea, text
) TO rss_app;
GRANT EXECUTE ON FUNCTION public.rss_saga_record_operator_decision(
    uuid, uuid, bigint, bigint, text, text, text, text, text, text
) TO rss_app;
GRANT EXECUTE ON FUNCTION public.rss_saga_insert_receipt(
    uuid, uuid, bigint, text, text, text, text, text, text, bytea, text, smallint,
    bytea, text, text, bytea, integer, bigint
) TO rss_app;
GRANT EXECUTE ON FUNCTION public.rss_saga_observe_claim(uuid) TO rss_app;
GRANT EXECUTE ON FUNCTION public.rss_saga_has_exact_prior_intent(
    uuid, uuid, bigint, bigint, text, text, integer, bytea
) TO rss_app;
GRANT EXECUTE ON FUNCTION public.rss_saga_intent_attempt_is_next(
    uuid, uuid, bigint, bigint, text, text, integer
) TO rss_app;
GRANT EXECUTE ON FUNCTION public.rss_saga_lease_is_held(uuid, uuid, bigint) TO rss_app;

REVOKE ALL ON TABLE public.saga_instances, public.saga_journal,
    public.saga_step_receipts, public.saga_operator_decisions FROM rss_app;
GRANT SELECT ON TABLE public.saga_instances, public.saga_journal,
    public.saga_step_receipts, public.saga_operator_decisions TO rss_app;
GRANT SELECT ON TABLE public.saga_operator_decisions TO rss_app_read;
