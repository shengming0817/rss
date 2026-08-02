-- 0095_seal_device_artifact_eligibility.sql
--
-- Pre-GA hard cut to one statically selected artifact-eligibility chain. Existing DeviceLatent
-- rows cannot prove whether they came from the draft simulator or a production-qualified external
-- provider, so this migration purges them instead of guessing or retaining an alternate path.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

LOCK TABLE public.reconcile_targets, public.reconcile_leases, public.reconcile_attempts,
    public.reconcile_attempt_results, public.reconcile_actions,
    public.device_certificate_desired_states, public.device_certificate_reported_states,
    public.device_certificate_conditions, public.device_certificate_policy_operations,
    public.device_certificate_authorized_artifacts, public.device_commands,
    public.device_ingress_receipts, public.command_journal, public.outbox, public.outbox_log
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM public.reconcile_leases AS lease
        JOIN public.reconcile_targets AS target USING (tenant_id, target_id)
        WHERE target.reconciler_id = 'identity.device-certificate'
          AND target.resource_kind = 'device-certificate'
          AND lease.state = 'held'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = '0095 requires every device-certificate lease to be free';
    END IF;
END;
$$;

-- Delete shared ledgers by exact DeviceLatent identities before deleting dedicated state. Target
-- deletion cascades attempts, results, actions, and leases for this reconciler only.
DELETE FROM public.outbox_log
WHERE contract_id IN ('identity.apply-device-certificate', 'identity.device-ingress-receipted');
DELETE FROM public.outbox
WHERE contract_id IN ('identity.apply-device-certificate', 'identity.device-ingress-receipted');
DELETE FROM public.command_journal
WHERE contract_id = 'identity.apply-device-certificate';
DELETE FROM public.device_ingress_receipts;
DELETE FROM public.device_commands;
DELETE FROM public.device_certificate_reported_states;
DELETE FROM public.device_certificate_conditions;
DELETE FROM public.device_certificate_authorized_artifacts;
DELETE FROM public.device_certificate_policy_operations;
DELETE FROM public.device_certificate_desired_states;
DELETE FROM public.reconcile_targets
WHERE reconciler_id = 'identity.device-certificate'
  AND resource_kind = 'device-certificate';

-- Stable-envelope malformed uplinks are immutable rejected facts. They carry no command/report
-- coordinate, so the schema gives this one closed kind an exact zero fence/sequence shape.
ALTER TABLE public.device_ingress_receipts
    DROP CONSTRAINT device_ingress_receipts_kind_closed,
    DROP CONSTRAINT device_ingress_receipts_kind_shape,
    DROP CONSTRAINT device_ingress_receipts_fence_positive,
    ADD CONSTRAINT device_ingress_receipts_kind_closed
        CHECK (kind IN ('ack_received', 'ack_rejected', 'report', 'protocol_violation')),
    ADD CONSTRAINT device_ingress_receipts_kind_shape CHECK (
        (kind IN ('ack_received', 'ack_rejected')
            AND command_id IS NOT NULL
            AND pg_catalog.octet_length(command_id) BETWEEN 1 AND 256)
        OR (kind IN ('report', 'protocol_violation') AND command_id IS NULL)
    ),
    ADD CONSTRAINT device_ingress_receipts_fence_shape CHECK (
        (kind = 'protocol_violation' AND fence_epoch = 0 AND device_sequence = 0)
        OR (kind <> 'protocol_violation' AND fence_epoch > 0)
    );

CREATE FUNCTION public.rss_commit_device_ingress_protocol_violation(
    p_tenant_id uuid, p_device_id uuid, p_event_id text, p_fingerprint bytea,
    p_credential_generation bigint
)
RETURNS TABLE (
    event_id text, device_id text, kind text, command_id text, generation bigint,
    fence_epoch bigint, device_sequence bigint, fingerprint bytea, disposition text,
    received_at_micros bigint, committed_at_micros bigint
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE existing public.device_ingress_receipts%ROWTYPE;
BEGIN
    IF p_tenant_id IS DISTINCT FROM
        NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
       OR p_device_id IS NULL
       OR p_event_id IS NULL
       OR p_fingerprint IS NULL
       OR p_credential_generation IS NULL OR p_credential_generation <= 0
       OR pg_catalog.octet_length(p_event_id) NOT BETWEEN 1 AND 256
       OR pg_catalog.btrim(p_event_id) IS DISTINCT FROM p_event_id
       OR p_event_id ~ '[[:cntrl:]]'
       OR pg_catalog.octet_length(p_fingerprint) <> 32
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501', MESSAGE = 'invalid protocol-violation ingress authority';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        p_tenant_id::text || ':' || p_event_id, 1903));

    SELECT receipt.* INTO existing
    FROM public.device_ingress_receipts AS receipt
    WHERE receipt.tenant_id = p_tenant_id AND receipt.event_id = p_event_id;
    IF FOUND THEN
        IF (existing.device_id, existing.kind, existing.command_id, existing.generation,
            existing.fence_epoch, existing.device_sequence, existing.fingerprint,
            existing.disposition)
           IS DISTINCT FROM
           (p_device_id, 'protocol_violation'::text, NULL::text, p_credential_generation,
            0::bigint, 0::bigint, p_fingerprint, 'rejected'::text)
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '23505', MESSAGE = 'device ingress fact conflict';
        END IF;
    ELSE
        INSERT INTO public.device_ingress_receipts AS receipt
            (tenant_id,event_id,device_id,kind,command_id,generation,fence_epoch,
             device_sequence,fingerprint,disposition)
        VALUES
            (p_tenant_id,p_event_id,p_device_id,'protocol_violation',NULL,
             p_credential_generation,0,0,p_fingerprint,'rejected')
        RETURNING receipt.* INTO existing;
    END IF;

    RETURN QUERY SELECT existing.event_id, existing.device_id::text, existing.kind,
        existing.command_id, existing.generation, existing.fence_epoch,
        existing.device_sequence, existing.fingerprint, existing.disposition,
        pg_catalog.floor(extract(epoch FROM existing.received_at) * 1000000)::bigint,
        pg_catalog.floor(extract(epoch FROM existing.committed_at) * 1000000)::bigint;
END;
$$;

ALTER FUNCTION public.rss_commit_device_ingress_protocol_violation(uuid,uuid,text,bytea,bigint)
OWNER TO rss_device_command_funnel_owner;
REVOKE ALL ON FUNCTION
    public.rss_commit_device_ingress_protocol_violation(uuid,uuid,text,bytea,bigint)
FROM PUBLIC, rss_app_read;
GRANT EXECUTE ON FUNCTION
    public.rss_commit_device_ingress_protocol_violation(uuid,uuid,text,bytea,bigint)
TO rss_app;

ALTER TABLE public.device_certificate_authorized_artifacts
    ADD COLUMN artifact_eligibility text NOT NULL,
    ADD CONSTRAINT device_certificate_artifacts_eligibility_closed
        CHECK (artifact_eligibility IN ('draft', 'production'));

ALTER TABLE public.device_commands
    ADD COLUMN artifact_eligibility text NOT NULL,
    ADD CONSTRAINT device_commands_artifact_eligibility_closed
        CHECK (artifact_eligibility IN ('draft', 'production'));

CREATE FUNCTION public.rss_device_command_eligibility_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.artifact_eligibility IS DISTINCT FROM OLD.artifact_eligibility
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'device command artifact eligibility is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER device_command_artifact_eligibility_immutable
BEFORE UPDATE ON public.device_commands
FOR EACH ROW EXECUTE FUNCTION public.rss_device_command_eligibility_guard();

REVOKE ALL ON FUNCTION public.rss_device_command_eligibility_guard()
FROM PUBLIC, rss_app, rss_app_read;

DROP FUNCTION public.rss_append_device_certificate_artifact(
    uuid,uuid,uuid,uuid,bigint,bigint,bigint,bytea,bytea,bytea,bytea,text,bytea,bigint
);

-- Private shared core. Callers cannot execute it or select the eligibility label; the only public
-- provider entry points below bind one literal marker each.
CREATE FUNCTION public.rss_append_device_certificate_artifact_core(
    p_tenant_id uuid, p_device_id uuid, p_attempt_id uuid, p_lease_token uuid,
    p_epoch bigint, p_wake_version bigint, p_generation bigint, p_policy_hash bytea,
    p_public_key_digest bytea, p_expected_state_hash bytea, p_artifact_digest bytea,
    p_artifact_id text, p_serial bytea, p_not_after_epoch_seconds bigint,
    p_artifact_eligibility text
)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE existing public.device_certificate_authorized_artifacts%ROWTYPE;
BEGIN
    IF p_artifact_eligibility NOT IN ('draft', 'production') THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid artifact eligibility';
    END IF;
    IF p_tenant_id IS DISTINCT FROM
        NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'tenant authority mismatch';
    END IF;
    PERFORM 1 FROM public.reconcile_targets target
    JOIN public.reconcile_attempts attempt USING (tenant_id, target_id)
    JOIN public.reconcile_leases lease USING (tenant_id, target_id)
    JOIN public.device_certificate_desired_states desired
      ON desired.tenant_id=target.tenant_id AND desired.device_id::text=target.resource_id
    WHERE target.tenant_id=p_tenant_id AND target.reconciler_id='identity.device-certificate'
      AND target.resource_kind='device-certificate' AND target.resource_id=p_device_id::text
      AND attempt.attempt_id=p_attempt_id AND attempt.lease_token=p_lease_token
      AND attempt.epoch=p_epoch AND attempt.claimed_wake_version=p_wake_version
      AND target.wake_version=p_wake_version AND lease.lease_token=p_lease_token
      AND lease.epoch=p_epoch AND lease.state='held'
      AND lease.expires_at>pg_catalog.clock_timestamp() AND desired.generation=p_generation
    FOR UPDATE OF target, lease, desired;
    IF NOT FOUND THEN RETURN 'stale_fence'; END IF;

    INSERT INTO public.device_certificate_authorized_artifacts
        (tenant_id, device_id, generation, artifact_eligibility, policy_hash,
         public_key_digest, expected_state_hash, artifact_digest, artifact_id, serial, not_after)
    VALUES (p_tenant_id, p_device_id, p_generation, p_artifact_eligibility, p_policy_hash,
        p_public_key_digest, p_expected_state_hash, p_artifact_digest, p_artifact_id, p_serial,
        TIMESTAMPTZ 'epoch' + p_not_after_epoch_seconds * INTERVAL '1 second')
    ON CONFLICT DO NOTHING;
    IF FOUND THEN RETURN 'appended'; END IF;
    SELECT * INTO existing FROM public.device_certificate_authorized_artifacts
    WHERE tenant_id=p_tenant_id AND device_id=p_device_id AND generation=p_generation;
    IF (existing.artifact_eligibility, existing.policy_hash, existing.public_key_digest,
        existing.expected_state_hash, existing.artifact_digest, existing.artifact_id,
        existing.serial, pg_catalog.floor(extract(epoch FROM existing.not_after))::bigint)
       IS NOT DISTINCT FROM
       (p_artifact_eligibility, p_policy_hash, p_public_key_digest, p_expected_state_hash,
        p_artifact_digest, p_artifact_id, p_serial, p_not_after_epoch_seconds)
    THEN RETURN 'replayed'; END IF;
    RETURN 'conflict';
END;
$$;

CREATE FUNCTION public.rss_append_device_certificate_artifact_draft(
    p_tenant_id uuid, p_device_id uuid, p_attempt_id uuid, p_lease_token uuid,
    p_epoch bigint, p_wake_version bigint, p_generation bigint, p_policy_hash bytea,
    p_public_key_digest bytea, p_expected_state_hash bytea, p_artifact_digest bytea,
    p_artifact_id text, p_serial bytea, p_not_after_epoch_seconds bigint
)
RETURNS text
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT public.rss_append_device_certificate_artifact_core(
        p_tenant_id,p_device_id,p_attempt_id,p_lease_token,p_epoch,p_wake_version,p_generation,
        p_policy_hash,p_public_key_digest,p_expected_state_hash,p_artifact_digest,p_artifact_id,
        p_serial,p_not_after_epoch_seconds,'draft')
$$;

CREATE FUNCTION public.rss_append_device_certificate_artifact_production(
    p_tenant_id uuid, p_device_id uuid, p_attempt_id uuid, p_lease_token uuid,
    p_epoch bigint, p_wake_version bigint, p_generation bigint, p_policy_hash bytea,
    p_public_key_digest bytea, p_expected_state_hash bytea, p_artifact_digest bytea,
    p_artifact_id text, p_serial bytea, p_not_after_epoch_seconds bigint
)
RETURNS text
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT public.rss_append_device_certificate_artifact_core(
        p_tenant_id,p_device_id,p_attempt_id,p_lease_token,p_epoch,p_wake_version,p_generation,
        p_policy_hash,p_public_key_digest,p_expected_state_hash,p_artifact_digest,p_artifact_id,
        p_serial,p_not_after_epoch_seconds,'production')
$$;

ALTER FUNCTION public.rss_append_device_certificate_artifact_core(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bytea,bytea,bytea,bytea,text,bytea,bigint,text)
OWNER TO rss_device_certificate_funnel_owner;
ALTER FUNCTION public.rss_append_device_certificate_artifact_draft(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bytea,bytea,bytea,bytea,text,bytea,bigint)
OWNER TO rss_device_certificate_funnel_owner;
ALTER FUNCTION public.rss_append_device_certificate_artifact_production(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bytea,bytea,bytea,bytea,text,bytea,bigint)
OWNER TO rss_device_certificate_funnel_owner;

REVOKE ALL ON FUNCTION public.rss_append_device_certificate_artifact_core(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bytea,bytea,bytea,bytea,text,bytea,bigint,text)
FROM PUBLIC, rss_app, rss_app_read;
REVOKE ALL ON FUNCTION public.rss_append_device_certificate_artifact_draft(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bytea,bytea,bytea,bytea,text,bytea,bigint)
FROM PUBLIC, rss_app_read;
REVOKE ALL ON FUNCTION public.rss_append_device_certificate_artifact_production(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bytea,bytea,bytea,bytea,text,bytea,bigint)
FROM PUBLIC, rss_app, rss_app_read;
GRANT EXECUTE ON FUNCTION public.rss_append_device_certificate_artifact_draft(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bytea,bytea,bytea,bytea,text,bytea,bigint)
TO rss_app;

-- Cross-funnel lookup exposes only the one immutable marker selected by an exact artifact
-- coordinate. The command funnel receives EXECUTE on this function, never table SELECT.
CREATE FUNCTION public.rss_resolve_device_certificate_artifact_eligibility(
    p_tenant_id uuid, p_device_id uuid, p_generation bigint,
    p_artifact_id text, p_artifact_digest bytea, p_policy_hash bytea
)
RETURNS text
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT artifact.artifact_eligibility
    FROM public.device_certificate_authorized_artifacts AS artifact
    WHERE artifact.tenant_id = p_tenant_id
      AND artifact.device_id = p_device_id
      AND artifact.generation = p_generation
      AND artifact.artifact_id = p_artifact_id
      AND artifact.artifact_digest = p_artifact_digest
      AND artifact.policy_hash = p_policy_hash
$$;

ALTER FUNCTION public.rss_resolve_device_certificate_artifact_eligibility(uuid,uuid,bigint,text,bytea,bytea)
OWNER TO rss_device_certificate_funnel_owner;
REVOKE ALL ON FUNCTION public.rss_resolve_device_certificate_artifact_eligibility(uuid,uuid,bigint,text,bytea,bytea)
FROM PUBLIC, rss_app, rss_app_read, rss_device_command_funnel_owner;
GRANT EXECUTE ON FUNCTION public.rss_resolve_device_certificate_artifact_eligibility(uuid,uuid,bigint,text,bytea,bytea)
TO rss_device_command_funnel_owner;

-- The command funnel rechecks the exact attempt itself instead of trusting the Rust caller's
-- earlier lock. Its NOLOGIN/NOBYPASSRLS owner receives only the coordinates needed for that join.
GRANT SELECT (tenant_id,target_id,attempt_id,lease_token,epoch,claimed_wake_version)
ON public.reconcile_attempts TO rss_device_command_funnel_owner;

DROP FUNCTION public.rss_install_fenced_device_command(uuid,uuid,text,bigint,bigint,bytea,bigint);

-- The command install entry receives artifact coordinates, never an eligibility label. It locks
-- the exact immutable receipt and copies its static eligibility into the command row.
CREATE FUNCTION public.rss_install_fenced_device_command(
    p_tenant_id uuid,
    p_device_id uuid,
    p_attempt_id uuid,
    p_lease_token uuid,
    p_epoch bigint,
    p_wake_version bigint,
    p_command_id text,
    p_generation bigint,
    p_intent_digest bytea,
    p_deadline_epoch_seconds bigint,
    p_artifact_id text,
    p_artifact_digest bytea,
    p_policy_hash bytea
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    existing_digest bytea;
    existing_eligibility text;
    persisted_eligibility text;
BEGIN
    IF p_tenant_id IS DISTINCT FROM
        NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'tenant authority mismatch';
    END IF;

    PERFORM 1
    FROM public.reconcile_targets AS target
    JOIN public.reconcile_attempts AS attempt USING (tenant_id,target_id)
    JOIN public.reconcile_leases AS lease USING (tenant_id,target_id)
    JOIN public.device_certificate_desired_states AS desired
      ON desired.tenant_id=target.tenant_id AND desired.device_id::text=target.resource_id
    WHERE target.tenant_id = p_tenant_id
      AND target.reconciler_id = 'identity.device-certificate'
      AND target.resource_kind = 'device-certificate'
      AND target.resource_id = p_device_id::text
      AND attempt.attempt_id=p_attempt_id
      AND attempt.lease_token=p_lease_token
      AND attempt.epoch=p_epoch
      AND attempt.claimed_wake_version=p_wake_version
      AND target.wake_version=p_wake_version
      AND lease.lease_token=p_lease_token
      AND lease.epoch=p_epoch
      AND lease.state='held'
      AND lease.expires_at>pg_catalog.clock_timestamp()
      AND desired.generation=p_generation
    FOR UPDATE OF target, lease, desired;
    IF NOT FOUND THEN RETURN 'lost'; END IF;

    persisted_eligibility := public.rss_resolve_device_certificate_artifact_eligibility(
        p_tenant_id, p_device_id, p_generation, p_artifact_id, p_artifact_digest, p_policy_hash
    );
    IF persisted_eligibility IS NULL THEN RETURN 'lost'; END IF;

    SELECT command.intent_digest, command.artifact_eligibility
    INTO existing_digest, existing_eligibility
    FROM public.device_commands AS command
    WHERE command.tenant_id = p_tenant_id AND command.device_id = p_device_id
      AND command.generation = p_generation
    ORDER BY command.fence_epoch DESC
    LIMIT 1
    FOR UPDATE;
    IF FOUND AND (existing_digest, existing_eligibility) IS DISTINCT FROM
        (p_intent_digest, persisted_eligibility)
    THEN
        RETURN 'fact_conflict';
    END IF;

    UPDATE public.device_commands AS command
    SET state = 'superseded', version = command.version + 1,
        terminal_at = pg_catalog.transaction_timestamp()
    WHERE command.tenant_id = p_tenant_id AND command.device_id = p_device_id
      AND command.state IN ('queued', 'published', 'received')
      AND command.generation <= p_generation AND command.fence_epoch < p_epoch;

    SELECT command.intent_digest, command.artifact_eligibility
    INTO existing_digest, existing_eligibility
    FROM public.device_commands AS command
    WHERE command.tenant_id = p_tenant_id AND command.device_id = p_device_id
      AND command.generation = p_generation AND command.fence_epoch = p_epoch
    FOR UPDATE;
    IF FOUND THEN
        IF (existing_digest, existing_eligibility) IS NOT DISTINCT FROM
            (p_intent_digest, persisted_eligibility)
        THEN RETURN 'duplicate'; END IF;
        RETURN 'fact_conflict';
    END IF;

    INSERT INTO public.device_commands
        (tenant_id, command_id, device_id, generation, fence_epoch,
         artifact_eligibility, intent_digest, deadline, state, version)
    VALUES
        (p_tenant_id, p_command_id, p_device_id, p_generation, p_epoch,
         persisted_eligibility, p_intent_digest,
         TIMESTAMPTZ 'epoch' + p_deadline_epoch_seconds * INTERVAL '1 second', 'queued', 1)
    ON CONFLICT DO NOTHING;
    IF FOUND THEN RETURN 'inserted'; END IF;
    RETURN 'fact_conflict';
END;
$$;

ALTER FUNCTION public.rss_install_fenced_device_command(uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,bytea,bigint,text,bytea,bytea)
OWNER TO rss_device_command_funnel_owner;
REVOKE ALL ON FUNCTION public.rss_install_fenced_device_command(uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,bytea,bigint,text,bytea,bytea)
FROM PUBLIC, rss_app_read;
GRANT EXECUTE ON FUNCTION public.rss_install_fenced_device_command(uuid,uuid,uuid,uuid,bigint,bigint,text,bigint,bytea,bigint,text,bytea,bytea)
TO rss_app;

-- Publication settlement is eligibility-bound too. The shared core is not executable by either
-- serving role; each public wrapper fixes the only eligibility value it can settle.
CREATE FUNCTION public.rss_settle_device_command_published_core(
    p_tenant_id uuid,
    p_device_id uuid,
    p_command_id text,
    p_expected_version bigint,
    p_artifact_eligibility text
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    command public.device_commands%ROWTYPE;
BEGIN
    IF p_artifact_eligibility NOT IN ('draft', 'production') THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid artifact eligibility';
    END IF;
    IF p_tenant_id IS DISTINCT FROM
        NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'tenant authority mismatch';
    END IF;

    SELECT * INTO command
    FROM public.device_commands AS stored
    WHERE stored.tenant_id = p_tenant_id
      AND stored.device_id = p_device_id
      AND stored.command_id = p_command_id
    FOR UPDATE;
    IF NOT FOUND THEN RETURN 'missing'; END IF;
    IF command.artifact_eligibility <> p_artifact_eligibility THEN
        RETURN 'eligibility_mismatch';
    END IF;
    IF command.version <> p_expected_version THEN
        -- Retrying the exact publication after losing the commit acknowledgement is a stable
        -- replay, while every other stale/ahead version remains a zero-write conflict.
        IF command.state = 'published' AND command.version - 1 = p_expected_version THEN
            RETURN 'no_change';
        END IF;
        RETURN 'version_conflict';
    END IF;
    IF command.state <> 'queued' THEN RETURN 'no_change'; END IF;

    UPDATE public.device_commands AS stored
    SET state = 'published',
        version = stored.version + 1,
        published_at = pg_catalog.transaction_timestamp()
    WHERE stored.tenant_id = p_tenant_id
      AND stored.device_id = p_device_id
      AND stored.command_id = p_command_id;
    RETURN 'advanced';
END;
$$;

CREATE FUNCTION public.rss_settle_device_command_published_draft(
    p_tenant_id uuid, p_device_id uuid, p_command_id text, p_expected_version bigint
)
RETURNS text
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT public.rss_settle_device_command_published_core(
        p_tenant_id,p_device_id,p_command_id,p_expected_version,'draft')
$$;

CREATE FUNCTION public.rss_settle_device_command_published_production(
    p_tenant_id uuid, p_device_id uuid, p_command_id text, p_expected_version bigint
)
RETURNS text
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT public.rss_settle_device_command_published_core(
        p_tenant_id,p_device_id,p_command_id,p_expected_version,'production')
$$;

ALTER FUNCTION public.rss_settle_device_command_published_core(uuid,uuid,text,bigint,text)
OWNER TO rss_device_command_funnel_owner;
ALTER FUNCTION public.rss_settle_device_command_published_draft(uuid,uuid,text,bigint)
OWNER TO rss_device_command_funnel_owner;
ALTER FUNCTION public.rss_settle_device_command_published_production(uuid,uuid,text,bigint)
OWNER TO rss_device_command_funnel_owner;

REVOKE ALL ON FUNCTION public.rss_settle_device_command_published_core(uuid,uuid,text,bigint,text)
FROM PUBLIC, rss_app, rss_app_read;
REVOKE ALL ON FUNCTION public.rss_settle_device_command_published_draft(uuid,uuid,text,bigint),
    public.rss_settle_device_command_published_production(uuid,uuid,text,bigint)
FROM PUBLIC, rss_app, rss_app_read;

-- Narrow cross-owner projection for global outbox claiming. Its isolated NOLOGIN owner can bypass
-- tenant RLS but receives only the seven columns needed to validate one already-owned outbox
-- tenant/event coordinate. Neither the serving role nor the general outbox owner receives raw
-- device-command SELECT.
DO $$
DECLARE owner_oid oid;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                   WHERE rolname = 'rss_device_mqtt_outbox_owner') THEN
        CREATE ROLE rss_device_mqtt_outbox_owner
            NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
    ELSE
        ALTER ROLE rss_device_mqtt_outbox_owner
            NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
    END IF;

    SELECT oid INTO STRICT owner_oid
    FROM pg_catalog.pg_roles
    WHERE rolname = 'rss_device_mqtt_outbox_owner';
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members AS membership
        WHERE membership.roleid = owner_oid OR membership.member = owner_oid
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'rss_device_mqtt_outbox_owner must have no role memberships';
    END IF;

    ALTER ROLE rss_device_mqtt_outbox_owner
        NOLOGIN NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
END;
$$;

GRANT SELECT (tenant_id, command_id, device_id, generation, version, state, artifact_eligibility)
ON public.device_commands TO rss_device_mqtt_outbox_owner;

CREATE FUNCTION public.rss_load_draft_device_mqtt_command_claim(
    p_tenant_id uuid,
    p_event_id text
)
RETURNS TABLE(device_id text, credential_generation bigint, expected_version bigint)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT command.device_id::text, command.generation, command.version
    FROM public.device_commands AS command
    WHERE command.tenant_id = p_tenant_id
      AND command.command_id = p_event_id
      AND command.artifact_eligibility = 'draft'
      AND command.state = 'queued'
$$;

ALTER FUNCTION public.rss_load_draft_device_mqtt_command_claim(uuid,text)
OWNER TO rss_device_mqtt_outbox_owner;
REVOKE ALL ON FUNCTION public.rss_load_draft_device_mqtt_command_claim(uuid,text)
FROM PUBLIC, rss_app, rss_app_read, rss_outbox_maintenance;
GRANT EXECUTE ON FUNCTION public.rss_load_draft_device_mqtt_command_claim(uuid,text)
TO rss_outbox_maintenance;

-- The durable MQTT boundary is the only serving publication authority. It leases only the two
-- DeviceLatent contracts and never acquires a generic identity event before classifying it. Draft
-- eligibility is fixed here because #1904 is the draft pilot; production activation owns a later
-- independently verified closure.
CREATE FUNCTION public.rss_claim_device_mqtt_outbox(
    p_kind smallint,
    p_limit bigint,
    p_lease_ttl_ms bigint,
    p_required_budget_ms bigint
)
RETURNS TABLE(
    tenant_id text,
    device_id text,
    credential_generation bigint,
    contract_id text,
    event_id text,
    payload bytea,
    expected_command_version bigint,
    claimed_at_epoch_seconds bigint,
    lease_token text,
    deadline_epoch_micros bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_automatic_window_seconds bigint;
    v_lease_ttl_ms bigint;
    v_publish_timeout_ms bigint;
    v_settle_timeout_ms bigint;
    v_safety_margin_ms bigint;
    v_required_budget_ms bigint;
BEGIN
    IF p_kind NOT IN (1, 2) THEN
        RAISE EXCEPTION 'rss_claim_device_mqtt_outbox kind must be command(1) or receipt(2)';
    END IF;
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 10000 THEN
        RAISE EXCEPTION 'rss_claim_device_mqtt_outbox limit must be in range [1, 10000]';
    END IF;
    IF p_lease_ttl_ms IS NULL OR p_required_budget_ms IS NULL THEN
        RAISE EXCEPTION 'rss_claim_device_mqtt_outbox relay budget must be non-null';
    END IF;

    SELECT policy.automatic_retry_window_seconds,
           policy.relay_lease_ttl_ms,
           policy.relay_publish_timeout_ms,
           policy.relay_settle_timeout_ms,
           policy.relay_safety_margin_ms
    INTO STRICT v_automatic_window_seconds,
                v_lease_ttl_ms,
                v_publish_timeout_ms,
                v_settle_timeout_ms,
                v_safety_margin_ms
    FROM public.event_delivery_policy AS policy
    WHERE policy.singleton;
    v_required_budget_ms := v_publish_timeout_ms + v_settle_timeout_ms + v_safety_margin_ms;
    IF p_lease_ttl_ms <> v_lease_ttl_ms OR p_required_budget_ms <> v_required_budget_ms THEN
        RAISE EXCEPTION 'rss_claim_device_mqtt_outbox relay budget does not match governed policy';
    END IF;

    RETURN QUERY
    WITH claim_clock AS MATERIALIZED (
        SELECT pg_catalog.clock_timestamp() AS claimed_at
    ),
    eligible AS MATERIALIZED (
        SELECT o.id, o.seq, claim_clock.claimed_at
        FROM public.outbox AS o
        LEFT JOIN LATERAL public.rss_load_draft_device_mqtt_command_claim(
            o.tenant_id, o.event_id
        ) AS command ON true
        CROSS JOIN claim_clock
        WHERE o.domain = 'identity'
          AND (
                (
                    p_kind = 1
                    AND
                    o.contract_id = 'identity.apply-device-certificate'
                    AND command.device_id::text = o.metadata->>'subjectId'
                )
                OR (
                    p_kind = 2
                    AND o.contract_id = 'identity.device-ingress-receipted'
                    AND o.metadata->>'credentialGeneration' ~ '^[1-9][0-9]*$'
                    AND (o.metadata->>'credentialGeneration')::numeric <= 9223372036854775807
                )
          )
          AND (
                (o.status = 'pending'
                 AND (o.retry_after IS NULL OR o.retry_after <= claim_clock.claimed_at))
             OR (o.status = 'publishing' AND o.lease_until <= claim_clock.claimed_at)
          )
          AND (
                o.partition_key IS NULL
             OR NOT EXISTS (
                    SELECT 1
                    FROM public.outbox AS blocker
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
        UPDATE public.outbox AS o
        SET status = 'publishing',
            lease_token = pg_catalog.gen_random_uuid(),
            lease_until = eligible.claimed_at + v_lease_ttl_ms * interval '1 millisecond',
            automatic_retry_deadline = COALESCE(
                o.automatic_retry_deadline,
                eligible.claimed_at
                    + pg_catalog.make_interval(secs => v_automatic_window_seconds::double precision)
            ),
            published_at = NULL,
            dlx_at = NULL,
            updated_at = eligible.claimed_at
        FROM eligible
        WHERE o.id = eligible.id
        RETURNING o.seq, o.tenant_id, o.contract_id, o.event_id, o.payload, o.metadata,
                  eligible.claimed_at, o.lease_token, o.lease_until
    )
    SELECT claimed.tenant_id::text,
           CASE
               WHEN claimed.contract_id = 'identity.apply-device-certificate'
               THEN command.device_id::text
               ELSE claimed.metadata->>'subjectId'
           END,
           CASE
               WHEN claimed.contract_id = 'identity.apply-device-certificate'
               THEN command.credential_generation
               ELSE (claimed.metadata->>'credentialGeneration')::bigint
           END,
           claimed.contract_id,
           claimed.event_id,
           claimed.payload,
           CASE
               WHEN claimed.contract_id = 'identity.apply-device-certificate'
               THEN command.expected_version
               ELSE NULL
           END,
           EXTRACT(EPOCH FROM claimed.claimed_at)::bigint,
           claimed.lease_token::text,
           (EXTRACT(EPOCH FROM claimed.lease_until) * 1000000)::bigint
    FROM claimed
    LEFT JOIN LATERAL public.rss_load_draft_device_mqtt_command_claim(
        claimed.tenant_id, claimed.event_id
    ) AS command ON true
    ORDER BY claimed.seq;
END;
$$;

-- Exact command PUBACK settlement composes the existing outbox lease CAS with the private command
-- eligibility core in one PostgreSQL statement. Any command invariant failure raises and rolls the
-- already attempted outbox update back, so no second authoritative command mutation can escape.
CREATE FUNCTION public.rss_settle_device_mqtt_command_puback(
    p_event_id text,
    p_lease_token uuid,
    p_lease_deadline_epoch_micros bigint,
    p_expected_command_version bigint
)
RETURNS public.rss_outbox_settlement_outcome
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    locked public.outbox%ROWTYPE;
    outbox_outcome public.rss_outbox_settlement_outcome;
    command_outcome text;
BEGIN
    SELECT * INTO locked
    FROM public.outbox AS candidate
    WHERE candidate.event_id = p_event_id
      AND candidate.domain = 'identity'
      AND candidate.contract_id = 'identity.apply-device-certificate'
      AND candidate.status = 'publishing'
      AND candidate.lease_token = p_lease_token
      AND candidate.lease_until = TIMESTAMPTZ 'epoch'
          + p_lease_deadline_epoch_micros * INTERVAL '1 microsecond'
    FOR UPDATE;
    IF NOT FOUND THEN RETURN 'lost_lease'; END IF;
    IF locked.tenant_id IS DISTINCT FROM
        NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'tenant authority mismatch';
    END IF;

    outbox_outcome := public.rss_outbox_settle_published(
        p_event_id, p_lease_token, p_lease_deadline_epoch_micros
    );
    IF outbox_outcome <> 'settled' THEN RETURN outbox_outcome; END IF;

    command_outcome := public.rss_settle_device_command_published_core(
        locked.tenant_id,
        (locked.metadata->>'subjectId')::uuid,
        locked.event_id,
        p_expected_command_version,
        'draft'
    );
    IF command_outcome <> 'advanced' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'device mqtt command publication invariant violated';
    END IF;
    RETURN 'settled';
END;
$$;

-- Receipt PUBACK settlement has no command side effect. The exact contract predicate lives before
-- the lease CAS, so a generic identity row can never be claim-then-rejected by this path.
CREATE FUNCTION public.rss_settle_device_mqtt_receipt_puback(
    p_event_id text,
    p_lease_token uuid,
    p_lease_deadline_epoch_micros bigint
)
RETURNS public.rss_outbox_settlement_outcome
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    locked public.outbox%ROWTYPE;
BEGIN
    SELECT * INTO locked
    FROM public.outbox AS candidate
    WHERE candidate.event_id = p_event_id
      AND candidate.domain = 'identity'
      AND candidate.contract_id = 'identity.device-ingress-receipted'
      AND candidate.status = 'publishing'
      AND candidate.lease_token = p_lease_token
      AND candidate.lease_until = TIMESTAMPTZ 'epoch'
          + p_lease_deadline_epoch_micros * INTERVAL '1 microsecond'
    FOR UPDATE;
    IF NOT FOUND THEN RETURN 'lost_lease'; END IF;
    IF locked.tenant_id IS DISTINCT FROM
        NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'tenant authority mismatch';
    END IF;
    RETURN public.rss_outbox_settle_published(
        p_event_id, p_lease_token, p_lease_deadline_epoch_micros
    );
END;
$$;

ALTER FUNCTION public.rss_claim_device_mqtt_outbox(smallint,bigint,bigint,bigint)
OWNER TO rss_outbox_maintenance;
ALTER FUNCTION public.rss_settle_device_mqtt_command_puback(text,uuid,bigint,bigint)
OWNER TO rss_outbox_maintenance;
ALTER FUNCTION public.rss_settle_device_mqtt_receipt_puback(text,uuid,bigint)
OWNER TO rss_outbox_maintenance;

REVOKE ALL ON FUNCTION public.rss_claim_device_mqtt_outbox(smallint,bigint,bigint,bigint),
    public.rss_settle_device_mqtt_command_puback(text,uuid,bigint,bigint),
    public.rss_settle_device_mqtt_receipt_puback(text,uuid,bigint)
FROM PUBLIC, rss_app, rss_app_read;
GRANT EXECUTE ON FUNCTION public.rss_claim_device_mqtt_outbox(smallint,bigint,bigint,bigint),
    public.rss_settle_device_mqtt_command_puback(text,uuid,bigint,bigint),
    public.rss_settle_device_mqtt_receipt_puback(text,uuid,bigint)
TO rss_app;

-- The outbox owner can advance a device command only through the eligibility-checked private core;
-- it receives no command-table SELECT or UPDATE grant.
GRANT EXECUTE ON FUNCTION public.rss_settle_device_command_published_core(uuid,uuid,text,bigint,text)
TO rss_outbox_maintenance;

GRANT INSERT (artifact_eligibility)
ON public.device_commands TO rss_device_command_funnel_owner;
GRANT UPDATE (published_at)
ON public.device_commands TO rss_device_command_funnel_owner;
GRANT INSERT (artifact_eligibility)
ON public.device_certificate_authorized_artifacts TO rss_device_certificate_funnel_owner;
