-- 0084_persist_reconcile_wake_and_device_policy_operations.sql
--
-- Durable reconcile retry/wake authority and append-once device-policy acceptance (#1898).
-- Existing attempts predate captured schedule state, so their new columns are initialized to zero;
-- no retry/result history is inferred from the old ledgers.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

-- Non-rolling cutover fence: wait out any old transaction, prevent new old-world writes, then
-- reject durable held leases rather than changing their scheduling contract underneath a worker.
LOCK TABLE public.reconcile_targets, public.reconcile_leases,
    public.reconcile_attempts, public.reconcile_attempt_results,
    public.reconcile_actions IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.reconcile_leases WHERE state = 'held') THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = '0084 requires every reconcile lease to be free';
    END IF;
END;
$$;

ALTER TABLE public.reconcile_targets
    ADD COLUMN failure_streak bigint NOT NULL DEFAULT 0,
    ADD COLUMN last_result text,
    ADD COLUMN wake_version bigint NOT NULL DEFAULT 0,
    ADD CONSTRAINT reconcile_targets_failure_streak_bounded
        CHECK (failure_streak BETWEEN 0 AND 4294967295),
    ADD CONSTRAINT reconcile_targets_last_result_closed
        CHECK (
            last_result IS NULL
            OR last_result IN ('settled', 'requeue_after', 'transient', 'permanent', 'invariant')
        ),
    ADD CONSTRAINT reconcile_targets_wake_version_bounded
        CHECK (wake_version BETWEEN 0 AND 9223372036854775807);

ALTER TABLE public.reconcile_targets
    DROP CONSTRAINT reconcile_targets_disabled_reason_valid,
    ADD CONSTRAINT reconcile_targets_disabled_reason_valid
        CHECK (
            disabled_reason IS NULL
            OR (
                status = 'disabled'
                AND disabled_reason IN (
                    'fact_conflict',
                    'permanent_failure',
                    'invariant_violation'
                )
            )
        );

CREATE FUNCTION public.rss_reconcile_target_wake_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF (
        NEW.tenant_id,
        NEW.target_id,
        NEW.reconciler_id,
        NEW.resource_kind,
        NEW.resource_id
    ) IS DISTINCT FROM (
        OLD.tenant_id,
        OLD.target_id,
        OLD.reconciler_id,
        OLD.resource_kind,
        OLD.resource_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'reconcile target identity is immutable';
    END IF;
    IF NEW.wake_version < OLD.wake_version THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'reconcile target wake version must be monotonic';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER reconcile_target_wake_monotonic
BEFORE UPDATE ON public.reconcile_targets
FOR EACH ROW EXECUTE FUNCTION public.rss_reconcile_target_wake_guard();

ALTER TABLE public.reconcile_attempts
    ADD COLUMN claimed_failure_streak bigint,
    ADD COLUMN claimed_wake_version bigint;

UPDATE public.reconcile_attempts
SET claimed_failure_streak = 0,
    claimed_wake_version = 0;

ALTER TABLE public.reconcile_attempts
    ALTER COLUMN claimed_failure_streak SET NOT NULL,
    ALTER COLUMN claimed_wake_version SET NOT NULL,
    ADD CONSTRAINT reconcile_attempts_claimed_failure_streak_bounded
        CHECK (claimed_failure_streak BETWEEN 0 AND 4294967295),
    ADD CONSTRAINT reconcile_attempts_claimed_wake_version_bounded
        CHECK (claimed_wake_version BETWEEN 0 AND 9223372036854775807);

CREATE TABLE public.device_certificate_policy_operations (
    tenant_id           uuid        NOT NULL,
    device_id           uuid        NOT NULL,
    idempotency_key     uuid        NOT NULL,
    request_digest      bytea       NOT NULL,
    accepted_generation bigint      NOT NULL,
    accepted_condition  text        NOT NULL,
    accepted_at         timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (tenant_id, device_id, idempotency_key),
    CONSTRAINT device_certificate_policy_operations_digest_sha256
        CHECK (pg_catalog.octet_length(request_digest) = 32),
    CONSTRAINT device_certificate_policy_operations_generation_positive
        CHECK (accepted_generation > 0),
    CONSTRAINT device_certificate_policy_operations_condition_closed
        CHECK (accepted_condition = 'reconciling'),
    CONSTRAINT device_certificate_policy_operations_desired_fk
        FOREIGN KEY (tenant_id, device_id)
        REFERENCES public.device_certificate_desired_states (tenant_id, device_id)
);

ALTER TABLE public.device_certificate_policy_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_certificate_policy_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.device_certificate_policy_operations
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);

REVOKE ALL ON TABLE public.device_certificate_policy_operations
FROM PUBLIC, rss_app, rss_app_read;

GRANT SELECT ON TABLE public.device_certificate_policy_operations TO rss_app, rss_app_read;
GRANT INSERT (
    tenant_id,
    device_id,
    idempotency_key,
    request_digest,
    accepted_generation,
    accepted_condition
) ON public.device_certificate_policy_operations TO rss_app;

REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
ON TABLE public.device_certificate_policy_operations
FROM rss_app, rss_app_read;

REVOKE ALL ON FUNCTION public.rss_reconcile_target_wake_guard()
FROM PUBLIC, rss_app, rss_app_read;

GRANT SELECT ON TABLE
    public.reconcile_targets,
    public.reconcile_leases,
    public.reconcile_attempts,
    public.reconcile_actions,
    public.reconcile_attempt_results
TO rss_app_read;
