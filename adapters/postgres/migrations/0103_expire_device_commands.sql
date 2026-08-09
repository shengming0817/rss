-- Purpose-specific overall device-command deadline expiry under the serving-role privilege model.
-- PostgreSQL owns selection, locking and time; Rust owns the canonical command FSM transition.
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

CREATE FUNCTION public.rss_select_due_current_device_command_core(
    p_tenant_id uuid,
    p_device_id uuid,
    p_attempt_id uuid,
    p_lease_token uuid,
    p_epoch bigint,
    p_wake_version bigint,
    p_expected_generation bigint,
    p_artifact_eligibility text
)
RETURNS TABLE(
    outcome text,
    artifact_eligibility text,
    command_id text,
    device_id text,
    generation bigint,
    fence_epoch bigint,
    intent_digest bytea,
    deadline_micros bigint,
    state text,
    version bigint,
    queued_at_micros bigint,
    published_at_micros bigint,
    received_at_micros bigint,
    terminal_at_micros bigint,
    authority_time_micros bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    authority_target_id uuid;
    command public.device_commands%ROWTYPE;
    authority_time timestamptz := pg_catalog.transaction_timestamp();
BEGIN
    IF p_tenant_id IS DISTINCT FROM
        NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
        OR p_artifact_eligibility NOT IN ('draft', 'production')
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'invalid command expiry authority';
    END IF;

    SELECT target.target_id INTO authority_target_id
    FROM public.reconcile_targets AS target
    JOIN public.reconcile_attempts AS attempt
      ON attempt.tenant_id=target.tenant_id AND attempt.target_id=target.target_id
    JOIN public.reconcile_leases AS lease
      ON lease.tenant_id=target.tenant_id AND lease.target_id=target.target_id
    JOIN public.device_certificate_desired_states AS desired
      ON desired.tenant_id=target.tenant_id AND desired.device_id=p_device_id
    WHERE target.tenant_id=p_tenant_id
      AND target.reconciler_id='identity.device-certificate'
      AND target.resource_kind='device-certificate'
      AND target.resource_id=p_device_id::text
      AND target.status='active'
      AND target.wake_version=p_wake_version
      AND attempt.attempt_id=p_attempt_id
      AND attempt.lease_token=p_lease_token
      AND attempt.epoch=p_epoch
      AND attempt.claimed_wake_version=p_wake_version
      AND lease.lease_token=p_lease_token
      AND lease.epoch=p_epoch
      AND lease.state='held'
      AND lease.expires_at>pg_catalog.clock_timestamp()
      AND desired.generation=p_expected_generation
      AND desired.deletion_requested_at IS NULL
    FOR UPDATE OF target,lease,desired;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'stale_fence'::text, NULL::text, NULL::text, NULL::text,
            NULL::bigint, NULL::bigint, NULL::bytea, NULL::bigint, NULL::text,
            NULL::bigint, NULL::bigint, NULL::bigint, NULL::bigint, NULL::bigint,
            floor(extract(epoch FROM authority_time) * 1000000)::bigint;
        RETURN;
    END IF;

    SELECT stored.* INTO command
    FROM public.device_commands AS stored
    WHERE stored.tenant_id=p_tenant_id
      AND stored.device_id=p_device_id
      AND stored.generation=p_expected_generation
      AND stored.artifact_eligibility=p_artifact_eligibility
      AND stored.state IN ('queued','published','received','timed_out')
    ORDER BY CASE WHEN stored.state IN ('queued','published','received') THEN 0 ELSE 1 END,
             stored.queued_at DESC, stored.command_id DESC
    LIMIT 1
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'no_current'::text, NULL::text, NULL::text, NULL::text,
            NULL::bigint, NULL::bigint, NULL::bytea, NULL::bigint, NULL::text,
            NULL::bigint, NULL::bigint, NULL::bigint, NULL::bigint, NULL::bigint,
            floor(extract(epoch FROM authority_time) * 1000000)::bigint;
        RETURN;
    END IF;
    IF command.state='timed_out' THEN
        outcome := 'already_expired';
    ELSIF command.deadline>authority_time THEN
        outcome := 'not_due';
    ELSE
        outcome := 'due';
    END IF;

    RETURN QUERY SELECT outcome, command.artifact_eligibility, command.command_id,
        command.device_id::text, command.generation, command.fence_epoch,
        command.intent_digest,
        floor(extract(epoch FROM command.deadline) * 1000000)::bigint,
        command.state, command.version,
        floor(extract(epoch FROM command.queued_at) * 1000000)::bigint,
        floor(extract(epoch FROM command.published_at) * 1000000)::bigint,
        floor(extract(epoch FROM command.received_at) * 1000000)::bigint,
        floor(extract(epoch FROM command.terminal_at) * 1000000)::bigint,
        floor(extract(epoch FROM authority_time) * 1000000)::bigint;
END;
$$;

CREATE FUNCTION public.rss_settle_due_current_device_command_core(
    p_tenant_id uuid,
    p_device_id uuid,
    p_attempt_id uuid,
    p_lease_token uuid,
    p_epoch bigint,
    p_wake_version bigint,
    p_expected_generation bigint,
    p_artifact_eligibility text,
    p_command_id text,
    p_expected_version bigint,
    p_next_version bigint,
    p_terminal_at_micros bigint
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    authority_target_id uuid;
    command public.device_commands%ROWTYPE;
    authority_micros bigint := floor(
        extract(epoch FROM pg_catalog.transaction_timestamp()) * 1000000
    )::bigint;
BEGIN
    IF p_tenant_id IS DISTINCT FROM
        NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
        OR p_artifact_eligibility NOT IN ('draft', 'production')
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'invalid command expiry authority';
    END IF;

    SELECT target.target_id INTO authority_target_id
    FROM public.reconcile_targets AS target
    JOIN public.reconcile_attempts AS attempt
      ON attempt.tenant_id=target.tenant_id AND attempt.target_id=target.target_id
    JOIN public.reconcile_leases AS lease
      ON lease.tenant_id=target.tenant_id AND lease.target_id=target.target_id
    JOIN public.device_certificate_desired_states AS desired
      ON desired.tenant_id=target.tenant_id AND desired.device_id=p_device_id
    WHERE target.tenant_id=p_tenant_id
      AND target.reconciler_id='identity.device-certificate'
      AND target.resource_kind='device-certificate'
      AND target.resource_id=p_device_id::text
      AND target.status='active'
      AND target.wake_version=p_wake_version
      AND attempt.attempt_id=p_attempt_id
      AND attempt.lease_token=p_lease_token
      AND attempt.epoch=p_epoch
      AND attempt.claimed_wake_version=p_wake_version
      AND lease.lease_token=p_lease_token
      AND lease.epoch=p_epoch
      AND lease.state='held'
      AND lease.expires_at>pg_catalog.clock_timestamp()
      AND desired.generation=p_expected_generation
      AND desired.deletion_requested_at IS NULL
    FOR UPDATE OF target,lease,desired;
    IF NOT FOUND THEN RETURN 'stale_fence'; END IF;

    SELECT stored.* INTO command
    FROM public.device_commands AS stored
    WHERE stored.tenant_id=p_tenant_id
      AND stored.device_id=p_device_id
      AND stored.generation=p_expected_generation
      AND stored.artifact_eligibility=p_artifact_eligibility
      AND stored.state IN ('queued','published','received')
    ORDER BY stored.queued_at DESC, stored.command_id DESC
    LIMIT 1
    FOR UPDATE;
    IF NOT FOUND THEN RETURN 'version_conflict'; END IF;

    IF command.command_id IS DISTINCT FROM p_command_id
       OR command.version IS DISTINCT FROM p_expected_version
       OR p_next_version IS DISTINCT FROM p_expected_version + 1
       OR p_terminal_at_micros IS DISTINCT FROM authority_micros
       OR command.deadline>pg_catalog.transaction_timestamp()
    THEN
        RETURN 'version_conflict';
    END IF;

    UPDATE public.device_commands AS stored
    SET state='timed_out', version=p_next_version,
        terminal_at=pg_catalog.transaction_timestamp()
    WHERE stored.tenant_id=p_tenant_id
      AND stored.device_id=p_device_id
      AND stored.command_id=p_command_id
      AND stored.version=p_expected_version
      AND stored.state IN ('queued','published','received');
    IF NOT FOUND THEN RETURN 'version_conflict'; END IF;
    RETURN 'expired';
END;
$$;

CREATE FUNCTION public.rss_select_due_current_device_command_draft(
    p_tenant_id uuid,p_device_id uuid,p_attempt_id uuid,p_lease_token uuid,
    p_epoch bigint,p_wake_version bigint,p_expected_generation bigint
)
RETURNS TABLE(
    outcome text,artifact_eligibility text,command_id text,device_id text,
    generation bigint,fence_epoch bigint,intent_digest bytea,deadline_micros bigint,
    state text,version bigint,queued_at_micros bigint,published_at_micros bigint,
    received_at_micros bigint,terminal_at_micros bigint,authority_time_micros bigint
)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
    SELECT * FROM public.rss_select_due_current_device_command_core(
        p_tenant_id,p_device_id,p_attempt_id,p_lease_token,p_epoch,p_wake_version,
        p_expected_generation,'draft')
$$;

CREATE FUNCTION public.rss_select_due_current_device_command_production(
    p_tenant_id uuid,p_device_id uuid,p_attempt_id uuid,p_lease_token uuid,
    p_epoch bigint,p_wake_version bigint,p_expected_generation bigint
)
RETURNS TABLE(
    outcome text,artifact_eligibility text,command_id text,device_id text,
    generation bigint,fence_epoch bigint,intent_digest bytea,deadline_micros bigint,
    state text,version bigint,queued_at_micros bigint,published_at_micros bigint,
    received_at_micros bigint,terminal_at_micros bigint,authority_time_micros bigint
)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
    SELECT * FROM public.rss_select_due_current_device_command_core(
        p_tenant_id,p_device_id,p_attempt_id,p_lease_token,p_epoch,p_wake_version,
        p_expected_generation,'production')
$$;

CREATE FUNCTION public.rss_settle_due_current_device_command_draft(
    p_tenant_id uuid,p_device_id uuid,p_attempt_id uuid,p_lease_token uuid,
    p_epoch bigint,p_wake_version bigint,p_expected_generation bigint,
    p_command_id text,p_expected_version bigint,p_next_version bigint,p_terminal_at_micros bigint
)
RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
    SELECT public.rss_settle_due_current_device_command_core(
        p_tenant_id,p_device_id,p_attempt_id,p_lease_token,p_epoch,p_wake_version,
        p_expected_generation,'draft',p_command_id,p_expected_version,p_next_version,
        p_terminal_at_micros)
$$;

CREATE FUNCTION public.rss_settle_due_current_device_command_production(
    p_tenant_id uuid,p_device_id uuid,p_attempt_id uuid,p_lease_token uuid,
    p_epoch bigint,p_wake_version bigint,p_expected_generation bigint,
    p_command_id text,p_expected_version bigint,p_next_version bigint,p_terminal_at_micros bigint
)
RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
    SELECT public.rss_settle_due_current_device_command_core(
        p_tenant_id,p_device_id,p_attempt_id,p_lease_token,p_epoch,p_wake_version,
        p_expected_generation,'production',p_command_id,p_expected_version,p_next_version,
        p_terminal_at_micros)
$$;

ALTER FUNCTION public.rss_select_due_current_device_command_core(uuid,uuid,uuid,uuid,bigint,bigint,bigint,text)
OWNER TO rss_device_command_funnel_owner;
ALTER FUNCTION public.rss_settle_due_current_device_command_core(uuid,uuid,uuid,uuid,bigint,bigint,bigint,text,text,bigint,bigint,bigint)
OWNER TO rss_device_command_funnel_owner;
ALTER FUNCTION public.rss_select_due_current_device_command_draft(uuid,uuid,uuid,uuid,bigint,bigint,bigint)
OWNER TO rss_device_command_funnel_owner;
ALTER FUNCTION public.rss_select_due_current_device_command_production(uuid,uuid,uuid,uuid,bigint,bigint,bigint)
OWNER TO rss_device_command_funnel_owner;
ALTER FUNCTION public.rss_settle_due_current_device_command_draft(uuid,uuid,uuid,uuid,bigint,bigint,bigint,text,bigint,bigint,bigint)
OWNER TO rss_device_command_funnel_owner;
ALTER FUNCTION public.rss_settle_due_current_device_command_production(uuid,uuid,uuid,uuid,bigint,bigint,bigint,text,bigint,bigint,bigint)
OWNER TO rss_device_command_funnel_owner;

REVOKE ALL ON FUNCTION
    public.rss_select_due_current_device_command_core(uuid,uuid,uuid,uuid,bigint,bigint,bigint,text),
    public.rss_settle_due_current_device_command_core(uuid,uuid,uuid,uuid,bigint,bigint,bigint,text,text,bigint,bigint,bigint),
    public.rss_select_due_current_device_command_draft(uuid,uuid,uuid,uuid,bigint,bigint,bigint),
    public.rss_select_due_current_device_command_production(uuid,uuid,uuid,uuid,bigint,bigint,bigint),
    public.rss_settle_due_current_device_command_draft(uuid,uuid,uuid,uuid,bigint,bigint,bigint,text,bigint,bigint,bigint),
    public.rss_settle_due_current_device_command_production(uuid,uuid,uuid,uuid,bigint,bigint,bigint,text,bigint,bigint,bigint)
FROM PUBLIC, rss_app, rss_app_read;
GRANT EXECUTE ON FUNCTION
    public.rss_select_due_current_device_command_draft(uuid,uuid,uuid,uuid,bigint,bigint,bigint),
    public.rss_select_due_current_device_command_production(uuid,uuid,uuid,uuid,bigint,bigint,bigint),
    public.rss_settle_due_current_device_command_draft(uuid,uuid,uuid,uuid,bigint,bigint,bigint,text,bigint,bigint,bigint),
    public.rss_settle_due_current_device_command_production(uuid,uuid,uuid,uuid,bigint,bigint,bigint,text,bigint,bigint,bigint)
TO rss_app;
