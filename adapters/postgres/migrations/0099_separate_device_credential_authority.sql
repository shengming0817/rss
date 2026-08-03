-- 0099_separate_device_credential_authority.sql
-- Forward-only correction: the authenticated MQTT credential generation proves which
-- transport credential entered the funnel; it is not the desired certificate generation
-- that the device is being commanded to install.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

CREATE OR REPLACE FUNCTION public.rss_device_command_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    authority_generation bigint;
    authority_epoch bigint;
    authority_target_id uuid;
    generation_intent_digest bytea;
    retains_received_report_authority boolean := false;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        retains_received_report_authority :=
            OLD.state = 'received'
            AND NEW.state = 'applied'
            AND (
                NEW.tenant_id, NEW.command_id, NEW.device_id, NEW.generation,
                NEW.fence_epoch, NEW.intent_digest, NEW.deadline, NEW.queued_at
            ) IS NOT DISTINCT FROM (
                OLD.tenant_id, OLD.command_id, OLD.device_id, OLD.generation,
                OLD.fence_epoch, OLD.intent_digest, OLD.deadline, OLD.queued_at
            );
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'queued' OR NEW.version <> 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device command must be inserted in queued version one';
        END IF;
        NEW.queued_at := pg_catalog.transaction_timestamp();
    ELSE
        IF (
            NEW.tenant_id, NEW.command_id, NEW.device_id, NEW.generation,
            NEW.fence_epoch, NEW.intent_digest, NEW.deadline, NEW.queued_at
        ) IS DISTINCT FROM (
            OLD.tenant_id, OLD.command_id, OLD.device_id, OLD.generation,
            OLD.fence_epoch, OLD.intent_digest, OLD.deadline, OLD.queued_at
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device command immutable fields cannot change';
        END IF;
        IF NEW.version <> OLD.version + 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device command version must advance exactly once';
        END IF;
        IF (OLD.published_at IS NOT NULL AND NEW.published_at IS DISTINCT FROM OLD.published_at)
            OR (OLD.received_at IS NOT NULL AND NEW.received_at IS DISTINCT FROM OLD.received_at)
            OR (OLD.terminal_at IS NOT NULL AND NEW.terminal_at IS DISTINCT FROM OLD.terminal_at)
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device command historical timestamps are immutable';
        END IF;
        IF (NEW.published_at IS DISTINCT FROM OLD.published_at
                AND NEW.published_at IS DISTINCT FROM pg_catalog.transaction_timestamp())
            OR (NEW.received_at IS DISTINCT FROM OLD.received_at
                AND NEW.received_at IS DISTINCT FROM pg_catalog.transaction_timestamp())
            OR (NEW.terminal_at IS DISTINCT FROM OLD.terminal_at
                AND NEW.terminal_at IS DISTINCT FROM pg_catalog.transaction_timestamp())
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device command transition timestamps must use transaction time';
        END IF;
        IF NOT (
            (OLD.state = 'queued' AND NEW.state IN (
                'published', 'timed_out', 'superseded', 'cancelled'
            ))
            OR (OLD.state = 'published' AND NEW.state IN (
                'received', 'rejected', 'timed_out', 'superseded', 'cancelled'
            ))
            OR (OLD.state = 'received' AND NEW.state IN (
                'applied', 'timed_out', 'superseded', 'cancelled'
            ))
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device command transition is not canonical';
        END IF;
    END IF;

    SELECT target.target_id
    INTO authority_target_id
    FROM public.reconcile_targets AS target
    WHERE target.tenant_id = NEW.tenant_id
      AND target.reconciler_id = 'identity.device-certificate'
      AND target.resource_kind = 'device-certificate'
      AND target.resource_id = NEW.device_id::text
    FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'device command has no canonical target authority';
    END IF;

    SELECT lease.epoch
    INTO authority_epoch
    FROM public.reconcile_leases AS lease
    WHERE lease.tenant_id = NEW.tenant_id
      AND lease.target_id = authority_target_id
    FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'device command has no canonical lease authority';
    END IF;

    SELECT desired.generation
    INTO authority_generation
    FROM public.device_certificate_desired_states AS desired
    WHERE desired.tenant_id = NEW.tenant_id
      AND desired.device_id = NEW.device_id
    FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'device command has no canonical desired authority';
    END IF;

    IF TG_OP = 'UPDATE' AND NEW.state = 'superseded' THEN
        IF NOT (
            authority_generation >= OLD.generation
            AND authority_epoch > OLD.fence_epoch
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device command supersede requires strictly dominating authority';
        END IF;
    ELSIF NEW.generation <> authority_generation
        OR (
            NEW.fence_epoch <> authority_epoch
            AND NOT retains_received_report_authority
        )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'device command coordinate does not match current authority';
    END IF;

    IF TG_OP = 'INSERT' THEN
        -- Serialize even direct SQL writers that do not use the scheduler's desired-state row lock.
        PERFORM pg_catalog.pg_advisory_xact_lock(
            pg_catalog.hashtextextended(
                NEW.tenant_id::text || ':' || NEW.device_id::text || ':' || NEW.generation::text,
                87
            )
        );
        SELECT command.intent_digest
        INTO generation_intent_digest
        FROM public.device_commands AS command
        WHERE command.tenant_id = NEW.tenant_id
          AND command.device_id = NEW.device_id
          AND command.generation = NEW.generation
        LIMIT 1;
        IF FOUND AND generation_intent_digest IS DISTINCT FROM NEW.intent_digest THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device command takeover must preserve generation intent digest';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.rss_device_command_guard()
FROM PUBLIC,rss_app,rss_app_read;


CREATE OR REPLACE FUNCTION public.rss_device_certificate_reported_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    authority_generation bigint;
    authority_epoch bigint;
    authority_target_id uuid;
    character_index integer;
    codepoint integer;
    first_codepoint integer;
    last_codepoint integer;
BEGIN
    first_codepoint := pg_catalog.ascii(pg_catalog.substr(NEW.report_envelope_id, 1, 1));
    last_codepoint := pg_catalog.ascii(
        pg_catalog.substr(
            NEW.report_envelope_id,
            pg_catalog.char_length(NEW.report_envelope_id),
            1
        )
    );
    IF first_codepoint IN (9, 10, 11, 12, 13, 32, 133, 160, 5760, 8232, 8233, 8239, 8287, 12288)
        OR first_codepoint BETWEEN 8192 AND 8202
        OR last_codepoint IN (9, 10, 11, 12, 13, 32, 133, 160, 5760, 8232, 8233, 8239, 8287, 12288)
        OR last_codepoint BETWEEN 8192 AND 8202
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'device certificate report envelope must be trimmed';
    END IF;

    FOR character_index IN 1..pg_catalog.char_length(NEW.report_envelope_id) LOOP
        codepoint := pg_catalog.ascii(
            pg_catalog.substr(NEW.report_envelope_id, character_index, 1)
        );
        IF codepoint BETWEEN 0 AND 31 OR codepoint BETWEEN 127 AND 159 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device certificate report envelope must not contain control characters';
        END IF;
    END LOOP;

    IF TG_OP = 'UPDATE' THEN
        IF NEW.tenant_id <> OLD.tenant_id OR NEW.device_id <> OLD.device_id THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device certificate reported identity is immutable';
        END IF;
        IF (
            NEW.observed_generation, NEW.fence_epoch, NEW.state_hash,
            NEW.artifact_digest, NEW.report_envelope_id, NEW.device_sequence,
            NEW.expires_at, NEW.device_observed_at
        ) IS NOT DISTINCT FROM (
            OLD.observed_generation, OLD.fence_epoch, OLD.state_hash,
            OLD.artifact_digest, OLD.report_envelope_id, OLD.device_sequence,
            OLD.expires_at, OLD.device_observed_at
        ) THEN
            RETURN NULL;
        END IF;
        IF NEW.observed_generation < OLD.observed_generation
            OR NEW.fence_epoch < OLD.fence_epoch
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'device certificate reported coordinate must not regress';
        END IF;
        IF NEW.device_sequence <= OLD.device_sequence THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'changed device certificate report must advance sequence';
        END IF;
    END IF;

    SELECT target.target_id
    INTO authority_target_id
    FROM public.reconcile_targets AS target
    WHERE target.tenant_id = NEW.tenant_id
      AND target.reconciler_id = 'identity.device-certificate'
      AND target.resource_kind = 'device-certificate'
      AND target.resource_id = NEW.device_id::text
    FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'device certificate report has no canonical target authority';
    END IF;

    SELECT lease.epoch
    INTO authority_epoch
    FROM public.reconcile_leases AS lease
    WHERE lease.tenant_id = NEW.tenant_id
      AND lease.target_id = authority_target_id
    FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'device certificate report has no canonical lease authority';
    END IF;

    SELECT desired.generation
    INTO authority_generation
    FROM public.device_certificate_desired_states AS desired
    WHERE desired.tenant_id = NEW.tenant_id
      AND desired.device_id = NEW.device_id
    FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'device certificate report has no canonical desired authority';
    END IF;
    IF NEW.observed_generation <> authority_generation THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'device certificate report generation does not match current authority';
    END IF;
    IF NEW.fence_epoch <> authority_epoch
        AND NOT EXISTS (
            SELECT 1
            FROM public.device_commands AS command
            WHERE command.tenant_id = NEW.tenant_id
              AND command.device_id = NEW.device_id
              AND command.generation = NEW.observed_generation
              AND command.fence_epoch = NEW.fence_epoch
              AND command.state = 'received'
        )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'device certificate report fence does not match current command authority';
    END IF;

    NEW.received_at := pg_catalog.clock_timestamp();
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.rss_device_certificate_reported_guard()
FROM PUBLIC,rss_app,rss_app_read;


CREATE OR REPLACE FUNCTION public.rss_commit_device_command_ack_ingress(
    p_tenant_id uuid, p_device_id uuid, p_event_id text, p_command_id text,
    p_generation bigint, p_fence_epoch bigint, p_device_sequence bigint,
    p_fingerprint bytea, p_kind text, p_credential_generation bigint,
    p_scope_matches boolean
)
RETURNS TABLE (
    event_id text, device_id text, kind text, command_id text, generation bigint,
    fence_epoch bigint, device_sequence bigint, fingerprint bytea, disposition text,
    received_at_micros bigint, committed_at_micros bigint
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
    existing public.device_ingress_receipts%ROWTYPE;
    authority_target_id uuid;
    authority_generation bigint;
    authority_epoch bigint;
    command_device uuid;
    command_state text;
    command_generation bigint;
    command_epoch bigint;
    high_water bigint;
    decided text;
BEGIN
    IF p_tenant_id IS DISTINCT FROM NULLIF(pg_catalog.current_setting('rss.tenant_id',true),'')::uuid
       OR p_kind NOT IN ('ack_received','ack_rejected') OR p_device_sequence<0
       OR pg_catalog.octet_length(p_fingerprint)<>32 OR p_scope_matches IS NULL OR p_credential_generation IS NULL
       OR p_credential_generation<=0
    THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid device ingress authority'; END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        p_tenant_id::text||':'||p_event_id,1903));

    SELECT receipt.* INTO existing FROM public.device_ingress_receipts receipt
    WHERE receipt.tenant_id=p_tenant_id AND receipt.event_id=p_event_id;
    IF FOUND THEN
        IF (existing.device_id,existing.kind,existing.command_id,existing.generation,
            existing.fence_epoch,existing.device_sequence,existing.fingerprint)
           IS DISTINCT FROM
           (p_device_id,p_kind,p_command_id,p_generation,p_fence_epoch,p_device_sequence,p_fingerprint)
        THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='device ingress fact conflict'; END IF;
        RETURN QUERY SELECT existing.event_id,existing.device_id::text,existing.kind,
            existing.command_id,existing.generation,existing.fence_epoch,existing.device_sequence,
            existing.fingerprint,existing.disposition,
            pg_catalog.floor(extract(epoch FROM existing.received_at)*1000000)::bigint,
            pg_catalog.floor(extract(epoch FROM existing.committed_at)*1000000)::bigint;
        RETURN;
    END IF;

    SELECT target.target_id INTO authority_target_id FROM public.reconcile_targets target
    WHERE target.tenant_id=p_tenant_id AND target.reconciler_id='identity.device-certificate'
      AND target.resource_kind='device-certificate' AND target.resource_id=p_device_id::text FOR UPDATE;
    IF authority_target_id IS NOT NULL THEN
        SELECT lease.epoch INTO authority_epoch FROM public.reconcile_leases lease
        WHERE lease.tenant_id=p_tenant_id AND lease.target_id=authority_target_id FOR UPDATE;
        SELECT desired.generation INTO authority_generation FROM public.device_certificate_desired_states desired
        WHERE desired.tenant_id=p_tenant_id AND desired.device_id=p_device_id FOR UPDATE;
    END IF;
    SELECT command.device_id,command.state,command.generation,command.fence_epoch
    INTO command_device,command_state,command_generation,command_epoch
    FROM public.device_commands command
    WHERE command.tenant_id=p_tenant_id AND command.command_id=p_command_id FOR UPDATE;
    SELECT max(receipt.device_sequence) INTO high_water FROM public.device_ingress_receipts receipt
    WHERE receipt.tenant_id=p_tenant_id AND receipt.device_id=p_device_id
      AND receipt.generation=p_generation AND receipt.fence_epoch=p_fence_epoch
      AND receipt.disposition IN ('advanced','device_rejected');

    decided := CASE
      WHEN p_scope_matches IS NOT TRUE THEN 'scope_mismatch'
      WHEN authority_generation IS NULL OR authority_epoch IS NULL THEN 'scope_mismatch'
      WHEN command_state IS NULL OR command_device<>p_device_id THEN 'scope_mismatch'
      WHEN p_generation<authority_generation THEN 'stale_generation'
      WHEN p_generation>authority_generation THEN 'rejected'
      WHEN p_fence_epoch<authority_epoch THEN 'stale_fence'
      WHEN p_fence_epoch>authority_epoch THEN 'rejected'
      WHEN command_generation<>p_generation OR command_epoch<>p_fence_epoch THEN 'scope_mismatch'
      WHEN (p_kind='ack_received' AND command_state='received')
        OR (p_kind='ack_rejected' AND command_state='rejected') THEN 'duplicate'
      WHEN high_water IS NOT NULL AND p_device_sequence<=high_water THEN 'stale_sequence'
      WHEN p_kind='ack_received' AND command_state='published' THEN 'advanced'
      WHEN p_kind='ack_rejected' AND command_state='published' THEN 'device_rejected'
      WHEN command_state='queued' THEN 'out_of_order'
      WHEN command_state IN ('applied','rejected','timed_out','superseded','cancelled') THEN 'late'
      ELSE 'out_of_order' END;

    IF decided IN ('advanced','device_rejected') THEN
        UPDATE public.device_commands command SET
            state=CASE decided WHEN 'advanced' THEN 'received' ELSE 'rejected' END,
            version=command.version+1,
            received_at=CASE decided WHEN 'advanced' THEN pg_catalog.transaction_timestamp()
                ELSE command.received_at END,
            terminal_at=CASE decided WHEN 'device_rejected' THEN pg_catalog.transaction_timestamp()
                ELSE command.terminal_at END
        WHERE command.tenant_id=p_tenant_id AND command.device_id=p_device_id
          AND command.command_id=p_command_id AND command.state='published';
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ACK command changed'; END IF;
        INSERT INTO public.device_certificate_conditions
          (tenant_id,device_id,condition_type,status,reason,observed_generation,last_transition_at)
        VALUES
          (p_tenant_id,p_device_id,'Ready','False',CASE decided WHEN 'advanced' THEN 'AwaitingDevice' ELSE 'CommandRejected' END,p_generation,pg_catalog.transaction_timestamp()),
          (p_tenant_id,p_device_id,'Reconciling',CASE decided WHEN 'advanced' THEN 'True' ELSE 'False' END,CASE decided WHEN 'advanced' THEN 'CommandQueued' ELSE 'StateDrift' END,p_generation,pg_catalog.transaction_timestamp()),
          (p_tenant_id,p_device_id,'PendingDevice',CASE decided WHEN 'advanced' THEN 'True' ELSE 'False' END,'AwaitingDevice',p_generation,pg_catalog.transaction_timestamp())
        ON CONFLICT ON CONSTRAINT device_certificate_conditions_pkey DO UPDATE SET
          status=EXCLUDED.status,reason=EXCLUDED.reason,observed_generation=EXCLUDED.observed_generation,
          last_transition_at=CASE WHEN (device_certificate_conditions.status,device_certificate_conditions.reason,device_certificate_conditions.observed_generation)
            IS DISTINCT FROM (EXCLUDED.status,EXCLUDED.reason,EXCLUDED.observed_generation)
            THEN pg_catalog.transaction_timestamp() ELSE device_certificate_conditions.last_transition_at END;
        IF decided='device_rejected' THEN
          INSERT INTO public.device_certificate_conditions
            (tenant_id,device_id,condition_type,status,reason,observed_generation,last_transition_at)
          VALUES (p_tenant_id,p_device_id,'Degraded','True','CommandRejected',p_generation,pg_catalog.transaction_timestamp())
          ON CONFLICT ON CONSTRAINT device_certificate_conditions_pkey DO UPDATE SET
            status='True',reason='CommandRejected',observed_generation=p_generation,
            last_transition_at=pg_catalog.transaction_timestamp();
        END IF;
        UPDATE public.reconcile_targets SET wake_version=wake_version+1,
          next_run_at=LEAST(next_run_at,pg_catalog.transaction_timestamp()),updated_at=pg_catalog.transaction_timestamp()
        WHERE tenant_id=p_tenant_id AND target_id=authority_target_id;
    END IF;

    INSERT INTO public.device_ingress_receipts AS receipt
      (tenant_id,event_id,device_id,kind,command_id,generation,fence_epoch,device_sequence,fingerprint,disposition)
    VALUES (p_tenant_id,p_event_id,p_device_id,p_kind,p_command_id,p_generation,p_fence_epoch,p_device_sequence,p_fingerprint,decided)
    RETURNING receipt.* INTO existing;
    RETURN QUERY SELECT existing.event_id,existing.device_id::text,existing.kind,existing.command_id,
      existing.generation,existing.fence_epoch,existing.device_sequence,existing.fingerprint,existing.disposition,
      pg_catalog.floor(extract(epoch FROM existing.received_at)*1000000)::bigint,
      pg_catalog.floor(extract(epoch FROM existing.committed_at)*1000000)::bigint;
END; $$;

CREATE OR REPLACE FUNCTION public.rss_commit_device_certificate_report_ingress(
    p_tenant_id uuid,p_device_id uuid,p_event_id text,p_generation bigint,p_fence_epoch bigint,
    p_device_sequence bigint,p_fingerprint bytea,p_state_hash bytea,p_artifact_digest bytea,
    p_expires_at_micros bigint,p_device_observed_at_micros bigint,
    p_credential_generation bigint,p_scope_matches boolean
)
RETURNS TABLE (
    event_id text, device_id text, kind text, command_id text, generation bigint,
    fence_epoch bigint, device_sequence bigint, fingerprint bytea, disposition text,
    received_at_micros bigint, committed_at_micros bigint
)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
    existing public.device_ingress_receipts%ROWTYPE;
    authority_target_id uuid; authority_generation bigint; authority_epoch bigint;
    command_key text; command_state text; high_water bigint; decided text;
    reported_generation bigint; reported_epoch bigint; reported_state_hash bytea;
    reported_artifact_digest bytea;
BEGIN
    IF p_tenant_id IS DISTINCT FROM NULLIF(pg_catalog.current_setting('rss.tenant_id',true),'')::uuid
       OR p_device_sequence<0 OR pg_catalog.octet_length(p_fingerprint)<>32
       OR p_scope_matches IS NULL OR p_credential_generation IS NULL
       OR p_credential_generation<=0
    THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid device ingress authority'; END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_tenant_id::text||':'||p_event_id,1903));
    SELECT receipt.* INTO existing FROM public.device_ingress_receipts receipt
    WHERE receipt.tenant_id=p_tenant_id AND receipt.event_id=p_event_id;
    IF FOUND THEN
      IF (existing.device_id,existing.kind,existing.command_id,existing.generation,existing.fence_epoch,
          existing.device_sequence,existing.fingerprint)
        IS DISTINCT FROM (p_device_id,'report',NULL::text,p_generation,p_fence_epoch,p_device_sequence,p_fingerprint)
      THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='device ingress fact conflict'; END IF;
      RETURN QUERY SELECT existing.event_id,existing.device_id::text,existing.kind,existing.command_id,
        existing.generation,existing.fence_epoch,existing.device_sequence,existing.fingerprint,existing.disposition,
        pg_catalog.floor(extract(epoch FROM existing.received_at)*1000000)::bigint,
        pg_catalog.floor(extract(epoch FROM existing.committed_at)*1000000)::bigint;
      RETURN;
    END IF;
    SELECT target.target_id INTO authority_target_id FROM public.reconcile_targets target
    WHERE target.tenant_id=p_tenant_id AND target.reconciler_id='identity.device-certificate'
      AND target.resource_kind='device-certificate' AND target.resource_id=p_device_id::text FOR UPDATE;
    IF authority_target_id IS NOT NULL THEN
      SELECT lease.epoch INTO authority_epoch FROM public.reconcile_leases lease
      WHERE lease.tenant_id=p_tenant_id AND lease.target_id=authority_target_id FOR UPDATE;
      SELECT desired.generation INTO authority_generation FROM public.device_certificate_desired_states desired
      WHERE desired.tenant_id=p_tenant_id AND desired.device_id=p_device_id FOR UPDATE;
    END IF;
    SELECT command.command_id,command.state INTO command_key,command_state FROM public.device_commands command
    WHERE command.tenant_id=p_tenant_id AND command.device_id=p_device_id
      AND command.generation=p_generation AND command.fence_epoch=p_fence_epoch
    ORDER BY command.queued_at DESC LIMIT 1 FOR UPDATE;
    SELECT max(receipt.device_sequence) INTO high_water FROM public.device_ingress_receipts receipt
    WHERE receipt.tenant_id=p_tenant_id AND receipt.device_id=p_device_id
      AND receipt.generation=p_generation AND receipt.fence_epoch=p_fence_epoch
      AND receipt.disposition IN ('advanced','device_rejected');
    SELECT reported.observed_generation,reported.fence_epoch,reported.state_hash,
      reported.artifact_digest
    INTO reported_generation,reported_epoch,reported_state_hash,reported_artifact_digest
    FROM public.device_certificate_reported_states reported
    WHERE reported.tenant_id=p_tenant_id AND reported.device_id=p_device_id FOR UPDATE;
    decided := CASE
      WHEN p_scope_matches IS NOT TRUE THEN 'scope_mismatch'
      WHEN authority_generation IS NULL OR authority_epoch IS NULL THEN 'scope_mismatch'
      WHEN p_generation<authority_generation THEN 'stale_generation'
      WHEN p_generation>authority_generation THEN 'rejected'
      WHEN p_fence_epoch<authority_epoch AND command_state IS DISTINCT FROM 'received'
        THEN 'stale_fence'
      WHEN p_fence_epoch>authority_epoch THEN 'rejected'
      WHEN command_state IS NULL THEN 'scope_mismatch'
      WHEN command_state='applied'
        AND (reported_generation,reported_epoch,reported_state_hash,reported_artifact_digest)
          IS NOT DISTINCT FROM (p_generation,p_fence_epoch,p_state_hash,p_artifact_digest)
        THEN 'duplicate'
      WHEN high_water IS NOT NULL AND p_device_sequence<=high_water THEN 'stale_sequence'
      WHEN command_state='received' THEN 'advanced'
      WHEN command_state IN ('queued','published') THEN 'out_of_order'
      WHEN command_state IN ('applied','rejected','timed_out','superseded','cancelled') THEN 'late'
      ELSE 'scope_mismatch' END;
    IF decided='advanced' THEN
      INSERT INTO public.device_certificate_reported_states AS reported
        (tenant_id,device_id,observed_generation,fence_epoch,state_hash,artifact_digest,
         report_envelope_id,device_sequence,expires_at,device_observed_at)
      VALUES (p_tenant_id,p_device_id,p_generation,p_fence_epoch,p_state_hash,p_artifact_digest,
        p_event_id,p_device_sequence,
        CASE WHEN p_expires_at_micros IS NULL THEN NULL ELSE TIMESTAMPTZ 'epoch'+p_expires_at_micros*INTERVAL '1 microsecond' END,
        CASE WHEN p_device_observed_at_micros IS NULL THEN NULL ELSE TIMESTAMPTZ 'epoch'+p_device_observed_at_micros*INTERVAL '1 microsecond' END)
      ON CONFLICT ON CONSTRAINT device_certificate_reported_states_pkey DO UPDATE SET observed_generation=EXCLUDED.observed_generation,
        fence_epoch=EXCLUDED.fence_epoch,state_hash=EXCLUDED.state_hash,artifact_digest=EXCLUDED.artifact_digest,
        report_envelope_id=EXCLUDED.report_envelope_id,device_sequence=EXCLUDED.device_sequence,
        expires_at=EXCLUDED.expires_at,device_observed_at=EXCLUDED.device_observed_at;
      UPDATE public.device_commands command SET state='applied',version=command.version+1,
        terminal_at=pg_catalog.transaction_timestamp()
      WHERE command.tenant_id=p_tenant_id AND command.command_id=command_key AND command.state='received';
      IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='report command changed'; END IF;
      INSERT INTO public.device_certificate_conditions
        (tenant_id,device_id,condition_type,status,reason,observed_generation,last_transition_at)
      VALUES
        (p_tenant_id,p_device_id,'Ready','False','AwaitingDevice',p_generation,pg_catalog.transaction_timestamp()),
        (p_tenant_id,p_device_id,'Reconciling','True','DeviceReported',p_generation,pg_catalog.transaction_timestamp()),
        (p_tenant_id,p_device_id,'PendingDevice','False','AwaitingDevice',p_generation,pg_catalog.transaction_timestamp())
      ON CONFLICT ON CONSTRAINT device_certificate_conditions_pkey DO UPDATE SET status=EXCLUDED.status,
        reason=EXCLUDED.reason,observed_generation=EXCLUDED.observed_generation,
        last_transition_at=CASE WHEN (device_certificate_conditions.status,device_certificate_conditions.reason,device_certificate_conditions.observed_generation)
          IS DISTINCT FROM (EXCLUDED.status,EXCLUDED.reason,EXCLUDED.observed_generation)
          THEN pg_catalog.transaction_timestamp() ELSE device_certificate_conditions.last_transition_at END;
      UPDATE public.reconcile_targets SET wake_version=wake_version+1,
        next_run_at=LEAST(next_run_at,pg_catalog.transaction_timestamp()),updated_at=pg_catalog.transaction_timestamp()
      WHERE tenant_id=p_tenant_id AND target_id=authority_target_id;
    END IF;
    INSERT INTO public.device_ingress_receipts AS receipt
      (tenant_id,event_id,device_id,kind,command_id,generation,fence_epoch,device_sequence,fingerprint,disposition)
    VALUES (p_tenant_id,p_event_id,p_device_id,'report',NULL,p_generation,p_fence_epoch,p_device_sequence,p_fingerprint,decided)
    RETURNING receipt.* INTO existing;
    RETURN QUERY SELECT existing.event_id,existing.device_id::text,existing.kind,existing.command_id,
      existing.generation,existing.fence_epoch,existing.device_sequence,existing.fingerprint,existing.disposition,
      pg_catalog.floor(extract(epoch FROM existing.received_at)*1000000)::bigint,
      pg_catalog.floor(extract(epoch FROM existing.committed_at)*1000000)::bigint;
END; $$;

ALTER FUNCTION public.rss_commit_device_command_ack_ingress(uuid,uuid,text,text,bigint,bigint,bigint,bytea,text,bigint,boolean)
OWNER TO rss_device_command_funnel_owner;
ALTER FUNCTION public.rss_commit_device_certificate_report_ingress(uuid,uuid,text,bigint,bigint,bigint,bytea,bytea,bytea,bigint,bigint,bigint,boolean)
OWNER TO rss_device_command_funnel_owner;
REVOKE ALL ON FUNCTION
 public.rss_commit_device_command_ack_ingress(uuid,uuid,text,text,bigint,bigint,bigint,bytea,text,bigint,boolean),
 public.rss_commit_device_certificate_report_ingress(uuid,uuid,text,bigint,bigint,bigint,bytea,bytea,bytea,bigint,bigint,bigint,boolean)
FROM PUBLIC,rss_app_read;
GRANT EXECUTE ON FUNCTION
 public.rss_commit_device_command_ack_ingress(uuid,uuid,text,text,bigint,bigint,bigint,bytea,text,bigint,boolean),
 public.rss_commit_device_certificate_report_ingress(uuid,uuid,text,bigint,bigint,bigint,bytea,bytea,bytea,bigint,bigint,bigint,boolean)
TO rss_app;
