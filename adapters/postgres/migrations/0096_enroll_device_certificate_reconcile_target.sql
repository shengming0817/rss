-- 0096_enroll_device_certificate_reconcile_target.sql
-- Exact production enrollment seam for the DeviceLatent certificate pilot (#1904).
--
-- The serving API supplies only a validated tenant/device scope and the first due time. Reconciler
-- identity, resource kind and resource id derivation remain fixed inside this function. Repeated
-- enrollment never reschedules, re-enables or resets an existing lease.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

GRANT INSERT (tenant_id,reconciler_id,resource_kind,resource_id,next_run_at)
ON public.reconcile_targets TO rss_device_certificate_funnel_owner;
GRANT INSERT (tenant_id,target_id)
ON public.reconcile_leases TO rss_device_certificate_funnel_owner;

CREATE FUNCTION public.rss_enroll_device_certificate_reconcile_target(
    p_tenant_id uuid,
    p_device_id uuid,
    p_initial_due_epoch_micros bigint
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    enrolled_target_id uuid;
    target_was_inserted boolean := false;
    lease_was_inserted boolean := false;
BEGIN
    IF p_tenant_id IS DISTINCT FROM
        NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'tenant authority mismatch';
    END IF;
    IF p_device_id IS NULL OR p_initial_due_epoch_micros IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22004', MESSAGE = 'enrollment scope must be non-null';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        p_tenant_id::text || ':identity.device-certificate:' || p_device_id::text,
        0
    ));

    INSERT INTO public.reconcile_targets (
        tenant_id,reconciler_id,resource_kind,resource_id,next_run_at
    ) VALUES (
        p_tenant_id,
        'identity.device-certificate',
        'device-certificate',
        p_device_id::text,
        TIMESTAMPTZ 'epoch' + p_initial_due_epoch_micros * INTERVAL '1 microsecond'
    )
    ON CONFLICT (tenant_id,reconciler_id,resource_kind,resource_id) DO NOTHING
    RETURNING target_id INTO enrolled_target_id;
    target_was_inserted := FOUND;

    IF NOT target_was_inserted THEN
        SELECT target.target_id INTO STRICT enrolled_target_id
        FROM public.reconcile_targets AS target
        WHERE target.tenant_id = p_tenant_id
          AND target.reconciler_id = 'identity.device-certificate'
          AND target.resource_kind = 'device-certificate'
          AND target.resource_id = p_device_id::text
        FOR UPDATE;
    END IF;

    INSERT INTO public.reconcile_leases (tenant_id,target_id)
    VALUES (p_tenant_id,enrolled_target_id)
    ON CONFLICT (tenant_id,target_id) DO NOTHING;
    lease_was_inserted := FOUND;

    IF target_was_inserted AND NOT lease_was_inserted THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'new device certificate target must own a new free lease';
    END IF;

    IF target_was_inserted OR lease_was_inserted THEN
        RETURN 'enrolled';
    END IF;
    RETURN 'already_enrolled';
END;
$$;

ALTER FUNCTION public.rss_enroll_device_certificate_reconcile_target(uuid,uuid,bigint)
OWNER TO rss_device_certificate_funnel_owner;
REVOKE ALL ON FUNCTION public.rss_enroll_device_certificate_reconcile_target(uuid,uuid,bigint)
FROM PUBLIC, rss_app, rss_app_read;
GRANT EXECUTE ON FUNCTION public.rss_enroll_device_certificate_reconcile_target(uuid,uuid,bigint)
TO rss_app;

CREATE FUNCTION public.rss_lock_device_certificate_reconcile_view(
    p_tenant_id uuid,
    p_device_id uuid,
    p_attempt_id uuid,
    p_lease_token uuid,
    p_epoch bigint,
    p_wake_version bigint
)
RETURNS TABLE (target_id text, deletion_requested boolean, generation bigint)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT target.target_id::text, desired.deletion_requested_at IS NOT NULL, desired.generation
    FROM public.reconcile_targets AS target
    JOIN public.reconcile_attempts AS attempt USING (tenant_id,target_id)
    JOIN public.reconcile_leases AS lease USING (tenant_id,target_id)
    JOIN public.device_certificate_desired_states AS desired
      ON desired.tenant_id=target.tenant_id AND desired.device_id::text=target.resource_id
    WHERE target.tenant_id=p_tenant_id
      AND p_tenant_id IS NOT DISTINCT FROM
          NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
      AND target.reconciler_id='identity.device-certificate'
      AND target.resource_kind='device-certificate'
      AND target.resource_id=p_device_id::text
      AND attempt.attempt_id=p_attempt_id
      AND attempt.lease_token=p_lease_token
      AND attempt.epoch=p_epoch
      AND attempt.claimed_wake_version=p_wake_version
      AND target.wake_version=p_wake_version
      AND lease.lease_token=p_lease_token
      AND lease.epoch=p_epoch
      AND lease.state='held'
      AND lease.expires_at>pg_catalog.clock_timestamp()
    FOR UPDATE OF target,lease,desired
$$;

ALTER FUNCTION public.rss_lock_device_certificate_reconcile_view(uuid,uuid,uuid,uuid,bigint,bigint)
OWNER TO rss_device_certificate_funnel_owner;
REVOKE ALL ON FUNCTION public.rss_lock_device_certificate_reconcile_view(uuid,uuid,uuid,uuid,bigint,bigint)
FROM PUBLIC, rss_app, rss_app_read;
GRANT EXECUTE ON FUNCTION public.rss_lock_device_certificate_reconcile_view(uuid,uuid,uuid,uuid,bigint,bigint)
TO rss_app;
