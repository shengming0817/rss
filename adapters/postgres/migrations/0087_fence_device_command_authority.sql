-- 0087_fence_device_command_authority.sql
--
-- Non-rolling hard cutover from intent-local command uniqueness to the canonical
-- (desired generation, reconcile lease epoch) authority fence. Legacy rows are never inferred,
-- rewritten, or discarded: ambiguous authority fails the migration before any new-world DDL.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

-- Stop every old-world writer participating in reconcile action/command/outbox coordination or
-- authenticated device ingress before examining durable authority. The target mapping is the
-- repository-owned canonical tuple:
--   reconciler_id = identity.device-certificate
--   resource_kind = device-certificate
--   resource_id   = device_id::text
LOCK TABLE public.reconcile_targets, public.reconcile_leases, public.reconcile_attempts,
    public.reconcile_actions, public.reconcile_attempt_results,
    public.device_certificate_desired_states, public.device_certificate_reported_states,
    public.device_commands, public.device_ingress_receipts, public.outbox, public.command_journal
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM public.reconcile_leases
        WHERE state = 'held'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = '0087 requires every reconcile lease to be free';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM public.device_commands
        WHERE state IN ('queued', 'published', 'received')
        GROUP BY tenant_id, device_id
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = '0087 refuses multiple nonterminal device commands';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM public.device_commands
        GROUP BY tenant_id, device_id, generation, fence_epoch
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = '0087 refuses duplicate device command fence coordinates';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM public.device_commands
        GROUP BY tenant_id, device_id, generation
        HAVING count(DISTINCT intent_digest) > 1
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = '0087 refuses multiple intent digests for one device generation';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM public.device_commands AS command
        LEFT JOIN public.device_certificate_desired_states AS desired
          ON desired.tenant_id = command.tenant_id
         AND desired.device_id = command.device_id
        LEFT JOIN public.reconcile_targets AS target
          ON target.tenant_id = command.tenant_id
         AND target.reconciler_id = 'identity.device-certificate'
         AND target.resource_kind = 'device-certificate'
         AND target.resource_id = command.device_id::text
        LEFT JOIN public.reconcile_leases AS lease
          ON lease.tenant_id = target.tenant_id
         AND lease.target_id = target.target_id
        WHERE command.state IN ('queued', 'published', 'received')
          AND (
              desired.generation = command.generation
              AND lease.epoch = command.fence_epoch
              OR desired.generation >= command.generation
              AND lease.epoch > command.fence_epoch
          ) IS NOT TRUE
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = '0087 refuses nonterminal command outside canonical authority';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM public.device_certificate_reported_states AS reported
        LEFT JOIN public.device_certificate_desired_states AS desired
          ON desired.tenant_id = reported.tenant_id
         AND desired.device_id = reported.device_id
        LEFT JOIN public.reconcile_targets AS target
          ON target.tenant_id = reported.tenant_id
         AND target.reconciler_id = 'identity.device-certificate'
         AND target.resource_kind = 'device-certificate'
         AND target.resource_id = reported.device_id::text
        LEFT JOIN public.reconcile_leases AS lease
          ON lease.tenant_id = target.tenant_id
         AND lease.target_id = target.target_id
        WHERE (
            desired.generation >= reported.observed_generation
            AND lease.epoch >= reported.fence_epoch
        ) IS NOT TRUE
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = '0087 refuses reported state outside canonical authority';
    END IF;
END;
$$;

DROP INDEX public.device_commands_one_active_intent;

CREATE UNIQUE INDEX device_commands_fence_coordinate_unique
    ON public.device_commands (tenant_id, device_id, generation, fence_epoch);

CREATE UNIQUE INDEX device_commands_one_nonterminal_per_device
    ON public.device_commands (tenant_id, device_id)
    WHERE state IN ('queued', 'published', 'received');

ALTER TABLE public.device_ingress_receipts
    DROP CONSTRAINT device_ingress_receipts_disposition_closed,
    ADD CONSTRAINT device_ingress_receipts_disposition_closed
        CHECK (disposition IN (
            'advanced', 'duplicate', 'late', 'rejected', 'device_rejected',
            'scope_mismatch', 'out_of_order',
            'stale_generation', 'stale_fence', 'stale_sequence'
        ));

DROP TRIGGER device_command_lifecycle_guard ON public.device_commands;

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
BEGIN
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
        OR NEW.fence_epoch <> authority_epoch
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

CREATE TRIGGER device_command_lifecycle_guard
BEFORE INSERT OR UPDATE ON public.device_commands
FOR EACH ROW EXECUTE FUNCTION public.rss_device_command_guard();

DROP TRIGGER device_certificate_reported_monotonic
ON public.device_certificate_reported_states;

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
    IF NEW.observed_generation <> authority_generation
        OR NEW.fence_epoch <> authority_epoch
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'device certificate report coordinate does not match current authority';
    END IF;

    NEW.received_at := pg_catalog.clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER device_certificate_reported_monotonic
BEFORE INSERT OR UPDATE ON public.device_certificate_reported_states
FOR EACH ROW EXECUTE FUNCTION public.rss_device_certificate_reported_guard();

-- Direct serving-role command/report DML cannot prove authority-first lock order: an UPDATE can
-- acquire the row lock before the trigger runs. Route the two #1900 command mutations through a
-- fixed, NOLOGIN-owned funnel which locks target -> lease -> desired before touching command rows.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rss_device_command_funnel_owner'
    ) THEN
        CREATE ROLE rss_device_command_funnel_owner
            NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
    END IF;
END
$$;

ALTER ROLE rss_device_command_funnel_owner
    NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;

GRANT SELECT ON TABLE public.reconcile_targets, public.reconcile_leases,
    public.device_certificate_desired_states, public.device_certificate_reported_states,
    public.device_commands
TO rss_device_command_funnel_owner;
GRANT UPDATE (target_id) ON public.reconcile_targets TO rss_device_command_funnel_owner;
GRANT UPDATE (epoch) ON public.reconcile_leases TO rss_device_command_funnel_owner;
GRANT UPDATE (generation) ON public.device_certificate_desired_states
TO rss_device_command_funnel_owner;
GRANT INSERT (
    tenant_id, command_id, device_id, generation, fence_epoch,
    intent_digest, deadline, state, version
) ON public.device_commands TO rss_device_command_funnel_owner;
GRANT UPDATE (state, version, received_at, terminal_at)
ON public.device_commands TO rss_device_command_funnel_owner;
GRANT INSERT (
    tenant_id, device_id, observed_generation, fence_epoch, state_hash,
    artifact_digest, report_envelope_id, device_sequence, expires_at, device_observed_at
) ON public.device_certificate_reported_states TO rss_device_command_funnel_owner;
GRANT UPDATE (
    observed_generation, fence_epoch, state_hash, artifact_digest,
    report_envelope_id, device_sequence, expires_at, device_observed_at
) ON public.device_certificate_reported_states TO rss_device_command_funnel_owner;

CREATE FUNCTION public.rss_install_fenced_device_command(
    p_tenant_id uuid,
    p_device_id uuid,
    p_command_id text,
    p_generation bigint,
    p_fence_epoch bigint,
    p_intent_digest bytea,
    p_deadline_epoch_seconds bigint
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    authority_target_id uuid;
    authority_epoch bigint;
    authority_generation bigint;
    existing_digest bytea;
BEGIN
    IF p_tenant_id IS DISTINCT FROM
        NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'tenant authority mismatch';
    END IF;

    SELECT target.target_id INTO authority_target_id
    FROM public.reconcile_targets AS target
    WHERE target.tenant_id = p_tenant_id
      AND target.reconciler_id = 'identity.device-certificate'
      AND target.resource_kind = 'device-certificate'
      AND target.resource_id = p_device_id::text
    FOR UPDATE;
    IF NOT FOUND THEN RETURN 'lost'; END IF;

    SELECT lease.epoch INTO authority_epoch
    FROM public.reconcile_leases AS lease
    WHERE lease.tenant_id = p_tenant_id AND lease.target_id = authority_target_id
    FOR UPDATE;
    IF NOT FOUND THEN RETURN 'lost'; END IF;

    SELECT desired.generation INTO authority_generation
    FROM public.device_certificate_desired_states AS desired
    WHERE desired.tenant_id = p_tenant_id AND desired.device_id = p_device_id
    FOR UPDATE;
    IF NOT FOUND OR authority_generation <> p_generation OR authority_epoch <> p_fence_epoch THEN
        RETURN 'lost';
    END IF;

    SELECT command.intent_digest INTO existing_digest
    FROM public.device_commands AS command
    WHERE command.tenant_id = p_tenant_id AND command.device_id = p_device_id
      AND command.generation = p_generation
    ORDER BY command.fence_epoch DESC
    LIMIT 1
    FOR UPDATE;
    IF FOUND AND existing_digest IS DISTINCT FROM p_intent_digest THEN
        RETURN 'fact_conflict';
    END IF;

    UPDATE public.device_commands AS command
    SET state = 'superseded', version = command.version + 1,
        terminal_at = pg_catalog.transaction_timestamp()
    WHERE command.tenant_id = p_tenant_id AND command.device_id = p_device_id
      AND command.state IN ('queued', 'published', 'received')
      AND command.generation <= p_generation AND command.fence_epoch < p_fence_epoch;

    SELECT command.intent_digest INTO existing_digest
    FROM public.device_commands AS command
    WHERE command.tenant_id = p_tenant_id AND command.device_id = p_device_id
      AND command.generation = p_generation AND command.fence_epoch = p_fence_epoch
    FOR UPDATE;
    IF FOUND THEN
        IF existing_digest IS NOT DISTINCT FROM p_intent_digest THEN RETURN 'duplicate'; END IF;
        RETURN 'fact_conflict';
    END IF;

    INSERT INTO public.device_commands
        (tenant_id, command_id, device_id, generation, fence_epoch,
         intent_digest, deadline, state, version)
    VALUES
        (p_tenant_id, p_command_id, p_device_id, p_generation, p_fence_epoch,
         p_intent_digest,
         TIMESTAMPTZ 'epoch' + p_deadline_epoch_seconds * INTERVAL '1 second', 'queued', 1)
    ON CONFLICT DO NOTHING;
    IF FOUND THEN RETURN 'inserted'; END IF;
    RETURN 'fact_conflict';
END;
$$;

CREATE FUNCTION public.rss_apply_device_command_ack(
    p_tenant_id uuid,
    p_device_id uuid,
    p_command_id text,
    p_generation bigint,
    p_fence_epoch bigint,
    p_kind text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    authority_target_id uuid;
    authority_epoch bigint;
    authority_generation bigint;
BEGIN
    IF p_tenant_id IS DISTINCT FROM
        NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
        OR p_kind NOT IN ('ack_received', 'ack_rejected')
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'invalid command ACK authority';
    END IF;

    SELECT target.target_id INTO authority_target_id
    FROM public.reconcile_targets AS target
    WHERE target.tenant_id = p_tenant_id
      AND target.reconciler_id = 'identity.device-certificate'
      AND target.resource_kind = 'device-certificate'
      AND target.resource_id = p_device_id::text
    FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    SELECT lease.epoch INTO authority_epoch
    FROM public.reconcile_leases AS lease
    WHERE lease.tenant_id = p_tenant_id AND lease.target_id = authority_target_id
    FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    SELECT desired.generation INTO authority_generation
    FROM public.device_certificate_desired_states AS desired
    WHERE desired.tenant_id = p_tenant_id AND desired.device_id = p_device_id
    FOR UPDATE;
    IF NOT FOUND OR authority_generation <> p_generation OR authority_epoch <> p_fence_epoch THEN
        RETURN false;
    END IF;

    UPDATE public.device_commands AS command
    SET state = CASE p_kind WHEN 'ack_received' THEN 'received' ELSE 'rejected' END,
        version = command.version + 1,
        received_at = CASE WHEN p_kind = 'ack_received'
            THEN pg_catalog.transaction_timestamp() ELSE command.received_at END,
        terminal_at = CASE WHEN p_kind = 'ack_rejected'
            THEN pg_catalog.transaction_timestamp() ELSE command.terminal_at END
    WHERE command.tenant_id = p_tenant_id AND command.device_id = p_device_id
      AND command.command_id = p_command_id AND command.generation = p_generation
      AND command.fence_epoch = p_fence_epoch AND command.state = 'published';
    RETURN FOUND;
END;
$$;

CREATE FUNCTION public.rss_upsert_device_certificate_report(
    p_tenant_id uuid,
    p_device_id uuid,
    p_observed_generation bigint,
    p_fence_epoch bigint,
    p_state_hash bytea,
    p_artifact_digest bytea,
    p_report_envelope_id text,
    p_device_sequence bigint,
    p_expires_at_micros bigint,
    p_device_observed_at_micros bigint
)
RETURNS TABLE (
    observed_generation bigint,
    fence_epoch bigint,
    state_hash bytea,
    artifact_digest bytea,
    report_envelope_id text,
    device_sequence bigint,
    expires_at_micros bigint,
    device_observed_at_micros bigint,
    received_at_micros bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    authority_target_id uuid;
    authority_epoch bigint;
    authority_generation bigint;
BEGIN
    IF p_tenant_id IS DISTINCT FROM
        NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'tenant authority mismatch';
    END IF;
    SELECT target.target_id INTO authority_target_id
    FROM public.reconcile_targets AS target
    WHERE target.tenant_id = p_tenant_id
      AND target.reconciler_id = 'identity.device-certificate'
      AND target.resource_kind = 'device-certificate'
      AND target.resource_id = p_device_id::text
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'report target authority missing';
    END IF;
    SELECT lease.epoch INTO authority_epoch
    FROM public.reconcile_leases AS lease
    WHERE lease.tenant_id = p_tenant_id AND lease.target_id = authority_target_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'report lease authority missing';
    END IF;
    SELECT desired.generation INTO authority_generation
    FROM public.device_certificate_desired_states AS desired
    WHERE desired.tenant_id = p_tenant_id AND desired.device_id = p_device_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'report desired authority missing';
    END IF;
    IF p_observed_generation <> authority_generation OR p_fence_epoch <> authority_epoch THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'report coordinate is not authoritative';
    END IF;

    RETURN QUERY
    INSERT INTO public.device_certificate_reported_states AS reported
        (tenant_id, device_id, observed_generation, fence_epoch, state_hash,
         artifact_digest, report_envelope_id, device_sequence, expires_at, device_observed_at)
    VALUES
        (p_tenant_id, p_device_id, p_observed_generation, p_fence_epoch, p_state_hash,
         p_artifact_digest, p_report_envelope_id, p_device_sequence,
         TIMESTAMPTZ 'epoch' + p_expires_at_micros * INTERVAL '1 microsecond',
         TIMESTAMPTZ 'epoch' + p_device_observed_at_micros * INTERVAL '1 microsecond')
    ON CONFLICT (tenant_id, device_id) DO UPDATE SET
        observed_generation = EXCLUDED.observed_generation,
        fence_epoch = EXCLUDED.fence_epoch,
        state_hash = EXCLUDED.state_hash,
        artifact_digest = EXCLUDED.artifact_digest,
        report_envelope_id = EXCLUDED.report_envelope_id,
        device_sequence = EXCLUDED.device_sequence,
        expires_at = EXCLUDED.expires_at,
        device_observed_at = EXCLUDED.device_observed_at
    RETURNING reported.observed_generation, reported.fence_epoch, reported.state_hash,
        reported.artifact_digest, reported.report_envelope_id, reported.device_sequence,
        pg_catalog.floor(extract(epoch FROM reported.expires_at) * 1000000)::bigint,
        pg_catalog.floor(extract(epoch FROM reported.device_observed_at) * 1000000)::bigint,
        pg_catalog.floor(extract(epoch FROM reported.received_at) * 1000000)::bigint;
END;
$$;

ALTER FUNCTION public.rss_install_fenced_device_command(uuid, uuid, text, bigint, bigint, bytea, bigint)
OWNER TO rss_device_command_funnel_owner;
ALTER FUNCTION public.rss_apply_device_command_ack(uuid, uuid, text, bigint, bigint, text)
OWNER TO rss_device_command_funnel_owner;
ALTER FUNCTION public.rss_upsert_device_certificate_report(
    uuid, uuid, bigint, bigint, bytea, bytea, text, bigint, bigint, bigint
) OWNER TO rss_device_command_funnel_owner;

REVOKE ALL ON FUNCTION
    public.rss_install_fenced_device_command(uuid, uuid, text, bigint, bigint, bytea, bigint),
    public.rss_apply_device_command_ack(uuid, uuid, text, bigint, bigint, text),
    public.rss_upsert_device_certificate_report(
        uuid, uuid, bigint, bigint, bytea, bytea, text, bigint, bigint, bigint
    )
FROM PUBLIC, rss_app_read;
GRANT EXECUTE ON FUNCTION
    public.rss_install_fenced_device_command(uuid, uuid, text, bigint, bigint, bytea, bigint),
    public.rss_apply_device_command_ack(uuid, uuid, text, bigint, bigint, text),
    public.rss_upsert_device_certificate_report(
        uuid, uuid, bigint, bigint, bytea, bytea, text, bigint, bigint, bigint
    )
TO rss_app;

REVOKE INSERT, UPDATE ON public.device_commands FROM rss_app;
REVOKE INSERT, UPDATE ON public.device_certificate_reported_states FROM rss_app;

-- CREATE OR REPLACE preserves the existing table ACL/RLS and function ownership. Revoke again so
-- no role gains a trigger function execution surface through future default-privilege drift.
REVOKE ALL ON FUNCTION public.rss_device_command_guard()
FROM PUBLIC, rss_app, rss_app_read;

REVOKE ALL ON FUNCTION public.rss_device_certificate_reported_guard()
FROM PUBLIC, rss_app, rss_app_read;
