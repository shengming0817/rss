-- Typed Settings v3 active-generation serving and atomic swap (#1921).

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

DO $migration$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rss_projection_serving_owner'
    ) THEN
        CREATE ROLE rss_projection_serving_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
    END IF;
END
$migration$;

DO $preflight$
DECLARE
    serving_role oid := 'rss_projection_serving_owner'::regrole::oid;
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_auth_members AS membership
        WHERE membership.member = serving_role OR membership.roleid = serving_role
    ) THEN
        RAISE EXCEPTION 'projection serving owner must have no memberships';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_shdepend AS dependency
        WHERE dependency.refclassid = 'pg_catalog.pg_authid'::regclass
          AND dependency.refobjid = serving_role
          AND dependency.deptype IN ('o', 'a')
    ) THEN
        RAISE EXCEPTION 'projection serving owner must have no pre-existing dependencies';
    END IF;
END
$preflight$;

ALTER ROLE rss_projection_serving_owner
    NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;

-- Pre-GA hard cut: derived Settings generations are replayable from the retained source log.
DELETE FROM public.settings_projection_dedupe_receipts
WHERE projection_id = 'settings.config-projection';
DELETE FROM public.settings_config_projection_rows
WHERE projection_id = 'settings.config-projection';
DELETE FROM public.projection_worker_tenant_quarantine
WHERE projection_id = 'settings.config-projection';
DELETE FROM public.checkpoint
WHERE owner LIKE 'projection:%'
  AND checkpoint_id LIKE 'settings.config-projection@%:shadow';
DELETE FROM public.settings_projection_generations
WHERE projection_id = 'settings.config-projection';
DELETE FROM public.distributed_cas
WHERE cas_key LIKE 'projection-active/%';

ALTER TABLE public.distributed_cas
    ADD CONSTRAINT distributed_cas_projection_active_namespace_retired
    CHECK (cas_key NOT LIKE 'projection-active/%');

DROP FUNCTION public.rss_projection_operator_read_active_pointer(uuid, text);
DROP FUNCTION public.rss_projection_operator_cas_active_pointer(uuid, text, bytea, bytea, bigint);

ALTER TABLE public.settings_projection_dedupe_receipts
    DROP CONSTRAINT settings_projection_dedupe_receipts_execution_pair,
    ADD CONSTRAINT settings_projection_dedupe_receipts_execution_pair CHECK (
        (actor = 'rss-projection-worker' AND purpose = 'background-worker')
        OR (actor = 'rss-projection-replay' AND purpose = 'operator-replay')
    );

CREATE TABLE public.settings_projection_active_pointer (
    tenant_id                  uuid        NOT NULL,
    projection_id              text        NOT NULL,
    generation                 text        NOT NULL,
    promoted_high_water_lsn    bigint      NOT NULL,
    token                      bigint      NOT NULL,
    created_at                 timestamptz NOT NULL DEFAULT pg_catalog.now(),
    updated_at                 timestamptz NOT NULL DEFAULT pg_catalog.now(),
    PRIMARY KEY (tenant_id, projection_id),
    CHECK (projection_id = 'settings.config-projection'),
    CHECK (generation ~ '^[a-z0-9][a-z0-9._-]*$'),
    CHECK (pg_catalog.octet_length(generation) BETWEEN 1 AND 256),
    CHECK (promoted_high_water_lsn >= 0),
    CHECK (token >= 1),
    CHECK (created_at <= updated_at),
    FOREIGN KEY (tenant_id, projection_id, generation)
        REFERENCES public.settings_projection_generations (tenant_id, projection_id, generation)
        ON DELETE RESTRICT
);

ALTER TABLE public.settings_projection_active_pointer ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.settings_projection_active_pointer FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.settings_projection_active_pointer
    USING (
        tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid
    );
ALTER TABLE public.settings_projection_active_pointer OWNER TO rss_projection_serving_owner;

CREATE FUNCTION public.rss_settings_projection_apply_current(
    p_actor text,
    p_purpose text,
    p_tenant_id uuid,
    p_projection_id text,
    p_generation text,
    p_definition_version text,
    p_definition_schema_digest text,
    p_input_generation text,
    p_config_key text,
    p_config_version bigint,
    p_change_kind text,
    p_source_event_id text,
    p_source_lsn bigint,
    p_source_occurred_at_secs bigint,
    p_fact_digest bytea
) RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    v_session_tenant text;
    v_definition_version text;
    v_definition_schema_digest text;
    v_input_generation text;
    v_high_water_lsn bigint;
    v_existing_digest bytea;
    v_existing_actor text;
    v_existing_purpose text;
    v_current_version bigint;
BEGIN
    IF NOT (
        (session_user = 'rss_projection_worker'
         AND p_actor = 'rss-projection-worker' AND p_purpose = 'background-worker')
        OR
        (session_user = 'rss_projection_operator'
         AND p_actor = 'rss-projection-replay' AND p_purpose = 'operator-replay')
    )
       OR p_projection_id <> 'settings.config-projection'
       OR p_generation IS NULL OR p_generation !~ '^[a-z0-9][a-z0-9._-]*$'
       OR pg_catalog.octet_length(p_generation) NOT BETWEEN 1 AND 256
       OR p_definition_version <> 'v3'
       OR p_definition_schema_digest <> 'sha256:ce6e2126b5d5831f67955d1db29fc7c0c1cc339cdf4cec1ad2486f5fb778b4d8'
       OR p_input_generation <> 'sha256:ff7c69626735495640031695caf9c053830aa6efdcb8c3efa038d68d0cd25801' THEN
        RAISE EXCEPTION USING ERRCODE = 'P1901', MESSAGE = 'settings projection identity mismatch';
    END IF;
    v_session_tenant := pg_catalog.current_setting('rss.tenant_id', true);
    IF v_session_tenant IS NULL OR v_session_tenant = ''
       OR v_session_tenant::uuid <> p_tenant_id THEN
        RAISE EXCEPTION USING ERRCODE = 'P1902', MESSAGE = 'settings projection tenant mismatch';
    END IF;

    INSERT INTO public.settings_projection_generations (
        tenant_id, projection_id, generation, definition_version,
        definition_schema_digest, input_generation, high_water_lsn
    ) VALUES (
        p_tenant_id, p_projection_id, p_generation, p_definition_version,
        p_definition_schema_digest, p_input_generation, NULL
    ) ON CONFLICT (tenant_id, projection_id, generation) DO NOTHING;

    SELECT definition_version, definition_schema_digest, input_generation, high_water_lsn
      INTO STRICT v_definition_version, v_definition_schema_digest,
                  v_input_generation, v_high_water_lsn
      FROM public.settings_projection_generations
     WHERE tenant_id = p_tenant_id
       AND projection_id = p_projection_id
       AND generation = p_generation
     FOR UPDATE;
    IF v_definition_version <> p_definition_version
       OR v_definition_schema_digest <> p_definition_schema_digest
       OR v_input_generation <> p_input_generation THEN
        RAISE EXCEPTION USING ERRCODE = 'P1901', MESSAGE = 'settings projection definition identity mismatch';
    END IF;

    SELECT fact_digest, actor, purpose
      INTO v_existing_digest, v_existing_actor, v_existing_purpose
      FROM public.settings_projection_dedupe_receipts
     WHERE tenant_id = p_tenant_id
       AND projection_id = p_projection_id
       AND generation = p_generation
       AND source_event_id = p_source_event_id;
    IF FOUND THEN
        IF v_existing_digest = p_fact_digest
           AND v_existing_actor = p_actor
           AND v_existing_purpose = p_purpose THEN
            RETURN 'duplicate';
        END IF;
        RAISE EXCEPTION USING ERRCODE = 'P1903', MESSAGE = 'settings projection receipt conflict';
    END IF;
    IF v_high_water_lsn IS NOT NULL AND p_source_lsn < v_high_water_lsn THEN
        RAISE EXCEPTION USING ERRCODE = 'P1904', MESSAGE = 'settings projection source order violation';
    END IF;

    SELECT config_version INTO v_current_version
      FROM public.settings_config_projection_rows
     WHERE tenant_id = p_tenant_id
       AND projection_id = p_projection_id
       AND generation = p_generation
       AND config_key = p_config_key
     FOR UPDATE;
    IF FOUND AND p_config_version <= v_current_version THEN
        RAISE EXCEPTION USING ERRCODE = 'P1905', MESSAGE = 'settings projection version regression';
    END IF;

    INSERT INTO public.settings_config_projection_rows (
        tenant_id, projection_id, generation, config_key, config_version, change_kind,
        source_event_id, source_lsn, source_occurred_at_secs
    ) VALUES (
        p_tenant_id, p_projection_id, p_generation, p_config_key, p_config_version, p_change_kind,
        p_source_event_id, p_source_lsn, p_source_occurred_at_secs
    ) ON CONFLICT (tenant_id, projection_id, generation, config_key) DO UPDATE SET
        config_version = EXCLUDED.config_version,
        change_kind = EXCLUDED.change_kind,
        source_event_id = EXCLUDED.source_event_id,
        source_lsn = EXCLUDED.source_lsn,
        source_occurred_at_secs = EXCLUDED.source_occurred_at_secs,
        updated_at = pg_catalog.now();

    BEGIN
        INSERT INTO public.settings_projection_dedupe_receipts (
            tenant_id, projection_id, generation, source_event_id, source_lsn, fact_digest,
            actor, purpose
        ) VALUES (
            p_tenant_id, p_projection_id, p_generation, p_source_event_id, p_source_lsn,
            p_fact_digest, p_actor, p_purpose
        );
    EXCEPTION WHEN unique_violation THEN
        RAISE EXCEPTION USING ERRCODE = 'P1903', MESSAGE = 'settings projection receipt conflict';
    END;

    UPDATE public.settings_projection_generations
       SET high_water_lsn = p_source_lsn, updated_at = pg_catalog.now()
     WHERE tenant_id = p_tenant_id
       AND projection_id = p_projection_id
       AND generation = p_generation;
    RETURN 'applied';
END;
$function$;

CREATE FUNCTION public.rss_settings_projection_worker_plan_is_current(
    p_projection_id text,
    p_definition_version text,
    p_definition_schema_digest text,
    p_input_generation text
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT session_user = 'rss_projection_worker'
       AND p_projection_id = 'settings.config-projection'
       AND p_definition_version = 'v3'
       AND p_definition_schema_digest = 'sha256:ce6e2126b5d5831f67955d1db29fc7c0c1cc339cdf4cec1ad2486f5fb778b4d8'
       AND p_input_generation = 'sha256:ff7c69626735495640031695caf9c053830aa6efdcb8c3efa038d68d0cd25801'
       AND EXISTS (
           SELECT 1 FROM public.projection_input_bindings AS binding
           WHERE binding.generation = p_input_generation
             AND binding.projection_id = p_projection_id
             AND binding.projection_definition_version = p_definition_version
             AND binding.projection_definition_schema_digest = p_definition_schema_digest
       );
$function$;

CREATE FUNCTION public.rss_settings_projection_worker_tenant_scope_is_active(
    p_tenant_id uuid,
    p_projection_id text,
    p_target_generation text,
    p_definition_version text,
    p_definition_schema_digest text,
    p_input_generation text
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT public.rss_settings_projection_worker_plan_is_current(
               p_projection_id, p_definition_version,
               p_definition_schema_digest, p_input_generation)
       AND p_tenant_id IS NOT NULL
       AND p_tenant_id <> '00000000-0000-0000-0000-000000000000'::uuid
       AND pg_catalog.current_setting('rss.tenant_id', true) = p_tenant_id::text
       AND p_target_generation ~ '^[a-z0-9][a-z0-9._-]*$'
       AND pg_catalog.octet_length(p_target_generation) BETWEEN 1 AND 256
       AND EXISTS (
           SELECT 1
           FROM public.settings_projection_active_pointer AS pointer
           JOIN public.settings_projection_generations AS target
             ON target.tenant_id = pointer.tenant_id
            AND target.projection_id = pointer.projection_id
            AND target.generation = pointer.generation
           WHERE pointer.tenant_id = p_tenant_id
             AND pointer.projection_id = p_projection_id
             AND pointer.generation = p_target_generation
             AND target.definition_version = p_definition_version
             AND target.definition_schema_digest = p_definition_schema_digest
             AND target.input_generation = p_input_generation
       );
$function$;

CREATE OR REPLACE FUNCTION public.rss_projection_worker_quarantine_tenant(
    p_tenant_id uuid, p_projection_id text, p_target_generation text,
    p_definition_version text, p_definition_schema_digest text, p_input_generation text,
    p_reason text, p_failed_lsn bigint
)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF NOT public.rss_settings_projection_worker_tenant_scope_is_active(
           p_tenant_id, p_projection_id, p_target_generation, p_definition_version,
           p_definition_schema_digest, p_input_generation)
       OR p_reason NOT IN (
           'target_definition_drift', 'input_binding_drift', 'tenant_drift', 'payload_malformed',
           'payload_value_invalid', 'version_regression', 'provider_invariant',
           'provider_permanent', 'conflict', 'apply_out_of_order', 'rollback_failed',
           'source_out_of_order'
       )
       OR p_failed_lsn < 0 THEN
        RAISE EXCEPTION 'invalid projection worker quarantine' USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.projection_worker_tenant_quarantine (
        tenant_scope_id, projection_id, target_generation, state, reason, failed_lsn
    ) VALUES (
        p_tenant_id, p_projection_id, p_target_generation, 'quarantined', p_reason, p_failed_lsn
    )
    ON CONFLICT (tenant_scope_id, projection_id, target_generation) DO UPDATE
    SET state = 'quarantined', reason = EXCLUDED.reason, failed_lsn = EXCLUDED.failed_lsn,
        quarantined_at = pg_catalog.now(), updated_at = pg_catalog.now();
END;
$function$;

CREATE FUNCTION public.rss_projection_worker_tenant_is_quarantined(
    p_tenant_id uuid, p_projection_id text, p_target_generation text,
    p_definition_version text, p_definition_schema_digest text, p_input_generation text
)
RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF NOT public.rss_settings_projection_worker_tenant_scope_is_active(
           p_tenant_id, p_projection_id, p_target_generation, p_definition_version,
           p_definition_schema_digest, p_input_generation) THEN
        RAISE EXCEPTION 'invalid projection worker scope' USING ERRCODE = '22023';
    END IF;
    RETURN EXISTS (
        SELECT 1 FROM public.projection_worker_tenant_quarantine AS quarantine
        WHERE quarantine.tenant_scope_id = p_tenant_id
          AND quarantine.projection_id = p_projection_id
          AND quarantine.target_generation = p_target_generation
          AND quarantine.state = 'quarantined'
    );
END;
$function$;

CREATE OR REPLACE FUNCTION public.rss_projection_operator_recover_tenant(
    p_tenant_id uuid, p_projection_id text, p_target_generation text,
    p_expected_failed_lsn bigint
)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    changed bigint;
BEGIN
    IF session_user <> 'rss_projection_operator'
       OR p_projection_id <> 'settings.config-projection'
       OR p_target_generation !~ '^[a-z0-9][a-z0-9._-]*$'
       OR pg_catalog.octet_length(p_target_generation) NOT BETWEEN 1 AND 256
       OR p_expected_failed_lsn < 0 THEN
        RAISE EXCEPTION 'invalid projection operator recovery' USING ERRCODE = '22023';
    END IF;
    UPDATE public.projection_worker_tenant_quarantine
       SET state = 'released', updated_at = pg_catalog.now()
     WHERE tenant_scope_id = p_tenant_id
       AND projection_id = p_projection_id
       AND target_generation = p_target_generation
       AND failed_lsn = p_expected_failed_lsn
       AND state = 'quarantined';
    GET DIAGNOSTICS changed = ROW_COUNT;
    RETURN changed = 1;
END;
$function$;

CREATE OR REPLACE FUNCTION public.rss_projection_worker_list_tenants(
    p_projection_id text, p_definition_version text,
    p_definition_schema_digest text, p_input_generation text,
    p_after_tenant uuid, p_limit integer
)
RETURNS TABLE (tenant_id uuid)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF NOT public.rss_settings_projection_worker_plan_is_current(
           p_projection_id, p_definition_version,
           p_definition_schema_digest, p_input_generation)
       OR p_limit <> 100 THEN
        RAISE EXCEPTION 'invalid projection worker scope' USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
    SELECT DISTINCT (event.metadata ->> 'tenantId')::uuid
    FROM public.projection_events AS event
    WHERE (event.metadata ->> 'tenantId') ~
              '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      AND (p_after_tenant IS NULL OR (event.metadata ->> 'tenantId')::uuid > p_after_tenant)
      AND EXISTS (
          SELECT 1 FROM public.projection_input_bindings AS binding
          WHERE binding.generation = p_input_generation
            AND binding.projection_id = p_projection_id
            AND binding.projection_definition_version = p_definition_version
            AND binding.projection_definition_schema_digest = p_definition_schema_digest
            AND binding.source_domain = event.domain
            AND binding.contract_id = event.contract_id
            AND binding.contract_version = event.contract_version
            AND binding.schema_hash = event.schema_hash
            AND binding.topic = event.event_type
      )
    ORDER BY 1
    LIMIT p_limit;
END;
$function$;

CREATE OR REPLACE FUNCTION public.rss_projection_worker_read_events(
    p_tenant_id uuid, p_projection_id text, p_target_generation text,
    p_definition_version text, p_definition_schema_digest text, p_input_generation text,
    p_after bigint, p_limit integer
)
RETURNS TABLE (
    id bigint, event_id text, domain text, aggregate_id text, event_type text, payload bytea,
    contract_id text, contract_version text, schema_hash text, metadata jsonb,
    partition_key text, causation_id text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF NOT public.rss_settings_projection_worker_tenant_scope_is_active(
           p_tenant_id, p_projection_id, p_target_generation, p_definition_version,
           p_definition_schema_digest, p_input_generation)
       OR pg_catalog.current_setting('rss.tenant_id', true) IS DISTINCT FROM p_tenant_id::text
       OR p_after IS NULL OR p_after < 0
       OR p_limit IS NULL OR p_limit < 1 OR p_limit > 1000 THEN
        RAISE EXCEPTION 'invalid projection worker scope' USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
    SELECT event.id, event.event_id, event.domain, event.aggregate_id, event.event_type,
           event.payload, event.contract_id, event.contract_version, event.schema_hash,
           event.metadata, event.partition_key, event.causation_id
    FROM public.projection_events AS event
    WHERE event.id > p_after
      AND event.metadata ->> 'tenantId' = p_tenant_id::text
      AND EXISTS (
          SELECT 1 FROM public.projection_input_bindings AS binding
          WHERE binding.generation = p_input_generation
            AND binding.projection_id = p_projection_id
            AND binding.projection_definition_version = p_definition_version
            AND binding.projection_definition_schema_digest = p_definition_schema_digest
            AND binding.source_domain = event.domain
            AND binding.contract_id = event.contract_id
            AND binding.contract_version = event.contract_version
            AND binding.schema_hash = event.schema_hash
            AND binding.topic = event.event_type
      )
    ORDER BY event.id ASC
    LIMIT p_limit;
END;
$function$;

CREATE OR REPLACE FUNCTION public.rss_projection_worker_source_high_water(
    p_tenant_id uuid, p_projection_id text, p_target_generation text,
    p_definition_version text, p_definition_schema_digest text, p_input_generation text
)
RETURNS bigint
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    high_water bigint;
BEGIN
    IF NOT public.rss_settings_projection_worker_tenant_scope_is_active(
           p_tenant_id, p_projection_id, p_target_generation, p_definition_version,
           p_definition_schema_digest, p_input_generation)
       OR pg_catalog.current_setting('rss.tenant_id', true) IS DISTINCT FROM p_tenant_id::text THEN
        RAISE EXCEPTION 'invalid projection worker scope' USING ERRCODE = '22023';
    END IF;
    SELECT pg_catalog.max(event.id) INTO high_water
    FROM public.projection_events AS event
    WHERE event.metadata ->> 'tenantId' = p_tenant_id::text
      AND EXISTS (
          SELECT 1 FROM public.projection_input_bindings AS binding
          WHERE binding.generation = p_input_generation
            AND binding.projection_id = p_projection_id
            AND binding.projection_definition_version = p_definition_version
            AND binding.projection_definition_schema_digest = p_definition_schema_digest
            AND binding.source_domain = event.domain
            AND binding.contract_id = event.contract_id
            AND binding.contract_version = event.contract_version
            AND binding.schema_hash = event.schema_hash
            AND binding.topic = event.event_type
      );
    RETURN high_water;
END;
$function$;

CREATE OR REPLACE FUNCTION public.rss_projection_worker_get_checkpoint(
    p_tenant_id uuid, p_projection_id text, p_target_generation text,
    p_definition_version text, p_definition_schema_digest text, p_input_generation text
)
RETURNS TABLE (offset_lsn bigint, version bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF NOT public.rss_settings_projection_worker_tenant_scope_is_active(
           p_tenant_id, p_projection_id, p_target_generation, p_definition_version,
           p_definition_schema_digest, p_input_generation)
       OR pg_catalog.current_setting('rss.tenant_id', true) IS DISTINCT FROM p_tenant_id::text THEN
        RAISE EXCEPTION 'invalid projection worker scope' USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
    SELECT checkpoint.offset_lsn, checkpoint.version
    FROM public.checkpoint
    WHERE checkpoint.owner = 'projection:' || p_tenant_id::text
      AND checkpoint.checkpoint_id = p_projection_id || '@' || p_target_generation || ':shadow';
END;
$function$;

CREATE OR REPLACE FUNCTION public.rss_projection_worker_save_checkpoint(
    p_tenant_id uuid, p_projection_id text, p_target_generation text,
    p_definition_version text, p_definition_schema_digest text, p_input_generation text,
    p_offset_lsn bigint, p_expected_version bigint
)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    changed bigint;
    v_owner text := 'projection:' || p_tenant_id::text;
    v_checkpoint text := p_projection_id || '@' || p_target_generation || ':shadow';
BEGIN
    IF NOT public.rss_settings_projection_worker_tenant_scope_is_active(
           p_tenant_id, p_projection_id, p_target_generation, p_definition_version,
           p_definition_schema_digest, p_input_generation)
       OR pg_catalog.current_setting('rss.tenant_id', true) IS DISTINCT FROM p_tenant_id::text
       OR p_offset_lsn < 0 OR p_expected_version < 0 THEN
        RAISE EXCEPTION 'invalid projection worker checkpoint' USING ERRCODE = '22023';
    END IF;
    IF p_expected_version = 0 THEN
        INSERT INTO public.checkpoint (owner, checkpoint_id, offset_lsn, version)
        VALUES (v_owner, v_checkpoint, p_offset_lsn, 1)
        ON CONFLICT (owner, checkpoint_id) DO NOTHING;
    ELSE
        UPDATE public.checkpoint
           SET offset_lsn = p_offset_lsn, version = checkpoint.version + 1,
               updated_at = pg_catalog.now()
         WHERE owner = v_owner AND checkpoint_id = v_checkpoint
           AND version = p_expected_version AND offset_lsn <= p_offset_lsn;
    END IF;
    GET DIAGNOSTICS changed = ROW_COUNT;
    RETURN changed = 1;
END;
$function$;

CREATE OR REPLACE FUNCTION public.rss_projection_worker_insert_dead_letter(
    p_tenant_id uuid, p_projection_id text, p_target_generation text,
    p_definition_version text, p_definition_schema_digest text, p_input_generation text,
    p_message_id text, p_producer_domain text, p_consumer_domain text, p_contract_id text,
    p_topic text, p_consumer_group text, p_replay_capsule jsonb,
    p_replay_capsule_key_ref text, p_payload_len bigint, p_replay_capsule_encoding text,
    p_metadata_digest bytea, p_error_summary text, p_num_attempts integer, p_source_kind text
)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF NOT public.rss_settings_projection_worker_tenant_scope_is_active(
           p_tenant_id, p_projection_id, p_target_generation, p_definition_version,
           p_definition_schema_digest, p_input_generation)
       OR pg_catalog.current_setting('rss.tenant_id', true) IS DISTINCT FROM p_tenant_id::text
       OR p_source_kind <> public.rss_projection_dead_letter_source_kind()
       OR p_consumer_domain <> 'projection:' || p_tenant_id::text
       OR p_consumer_group <> p_projection_id || '@' || p_target_generation || ':shadow'
       OR p_payload_len < 0 OR p_num_attempts < 0
       OR p_replay_capsule_encoding <> 'key-provider-v3' THEN
        RAISE EXCEPTION 'invalid projection worker dead letter' USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.dead_letter (
        tenant_id, message_id, producer_domain, consumer_domain, contract_id, topic,
        consumer_group, replay_capsule, replay_capsule_key_ref, payload_len,
        replay_capsule_encoding, metadata_digest, error_summary, num_attempts, source_kind
    ) VALUES (
        p_tenant_id, p_message_id, p_producer_domain, p_consumer_domain, p_contract_id, p_topic,
        p_consumer_group, p_replay_capsule, p_replay_capsule_key_ref, p_payload_len,
        p_replay_capsule_encoding, p_metadata_digest, p_error_summary, p_num_attempts,
        p_source_kind
    ) ON CONFLICT (tenant_id, source_kind, consumer_group, message_id)
      WHERE source_kind = 'projection' DO NOTHING;
END;
$function$;

CREATE OR REPLACE FUNCTION public.rss_settings_projection_apply_worker(
    p_tenant_id uuid, p_projection_id text, p_generation text,
    p_definition_version text, p_definition_schema_digest text, p_input_generation text,
    p_config_key text, p_config_version bigint, p_change_kind text, p_source_event_id text,
    p_source_lsn bigint, p_source_occurred_at_secs bigint, p_fact_digest bytea
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF session_user <> 'rss_projection_worker' THEN
        RAISE EXCEPTION 'settings projection worker authority mismatch' USING ERRCODE = '42501';
    END IF;
    IF NOT public.rss_settings_projection_worker_tenant_scope_is_active(
           p_tenant_id, p_projection_id, p_generation, p_definition_version,
           p_definition_schema_digest, p_input_generation) THEN
        RAISE EXCEPTION 'settings projection worker identity mismatch' USING ERRCODE = 'P1901';
    END IF;
    RETURN public.rss_settings_projection_apply_current(
        'rss-projection-worker', 'background-worker', p_tenant_id, p_projection_id, p_generation,
        p_definition_version, p_definition_schema_digest, p_input_generation, p_config_key,
        p_config_version, p_change_kind, p_source_event_id, p_source_lsn,
        p_source_occurred_at_secs, p_fact_digest
    );
END;
$function$;

CREATE OR REPLACE FUNCTION public.rss_settings_projection_apply_operator(
    p_tenant_id uuid, p_projection_id text, p_generation text,
    p_definition_version text, p_definition_schema_digest text, p_input_generation text,
    p_config_key text, p_config_version bigint, p_change_kind text, p_source_event_id text,
    p_source_lsn bigint, p_source_occurred_at_secs bigint, p_fact_digest bytea
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF session_user <> 'rss_projection_operator' THEN
        RAISE EXCEPTION 'settings projection operator authority mismatch' USING ERRCODE = '42501';
    END IF;
    IF p_definition_version <> 'v3'
       OR p_definition_schema_digest <> 'sha256:ce6e2126b5d5831f67955d1db29fc7c0c1cc339cdf4cec1ad2486f5fb778b4d8'
       OR p_input_generation <> 'sha256:ff7c69626735495640031695caf9c053830aa6efdcb8c3efa038d68d0cd25801' THEN
        RAISE EXCEPTION 'settings projection operator identity mismatch' USING ERRCODE = 'P1901';
    END IF;
    RETURN public.rss_settings_projection_apply_current(
        'rss-projection-replay', 'operator-replay', p_tenant_id, p_projection_id, p_generation,
        p_definition_version, p_definition_schema_digest, p_input_generation, p_config_key,
        p_config_version, p_change_kind, p_source_event_id, p_source_lsn,
        p_source_occurred_at_secs, p_fact_digest
    );
END;
$function$;

CREATE FUNCTION public.rss_settings_projection_resolve_active()
RETURNS TABLE (
    generation text,
    definition_version text,
    definition_schema_digest text,
    input_generation text,
    promoted_high_water_lsn bigint,
    token bigint
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    v_tenant_id uuid;
    v_generation text;
    v_promoted_high_water_lsn bigint;
    v_token bigint;
    v_definition_version text;
    v_definition_schema_digest text;
    v_input_generation text;
BEGIN
    IF session_user NOT IN ('rss_app_read', 'rss_projection_worker') THEN
        RAISE EXCEPTION 'settings active resolver authority mismatch' USING ERRCODE = '42501';
    END IF;
    BEGIN
        v_tenant_id := NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid;
    EXCEPTION WHEN invalid_text_representation THEN
        RAISE EXCEPTION 'settings active resolver tenant mismatch' USING ERRCODE = '22023';
    END;
    IF v_tenant_id IS NULL OR v_tenant_id = '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'settings active resolver tenant mismatch' USING ERRCODE = '22023';
    END IF;

    SELECT pointer.generation, pointer.promoted_high_water_lsn, pointer.token
      INTO v_generation, v_promoted_high_water_lsn, v_token
      FROM public.settings_projection_active_pointer AS pointer
     WHERE pointer.tenant_id = v_tenant_id
       AND pointer.projection_id = 'settings.config-projection';
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT target.definition_version, target.definition_schema_digest, target.input_generation
      INTO STRICT v_definition_version, v_definition_schema_digest, v_input_generation
      FROM public.settings_projection_generations AS target
     WHERE target.tenant_id = v_tenant_id
       AND target.projection_id = 'settings.config-projection'
       AND target.generation = v_generation;
    IF v_definition_version <> 'v3'
       OR v_definition_schema_digest <> 'sha256:ce6e2126b5d5831f67955d1db29fc7c0c1cc339cdf4cec1ad2486f5fb778b4d8'
       OR v_input_generation <> 'sha256:ff7c69626735495640031695caf9c053830aa6efdcb8c3efa038d68d0cd25801' THEN
        RAISE EXCEPTION 'settings active resolver identity mismatch' USING ERRCODE = 'P1901';
    END IF;
    RETURN QUERY SELECT v_generation, v_definition_version, v_definition_schema_digest,
                        v_input_generation, v_promoted_high_water_lsn, v_token;
END;
$function$;

CREATE FUNCTION public.rss_projection_operator_status_active(p_tenant_id uuid)
RETURNS TABLE (generation text, promoted_high_water_lsn bigint, token bigint)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    v_generation text;
    v_promoted_high_water_lsn bigint;
    v_token bigint;
    v_definition_version text;
    v_definition_schema_digest text;
    v_input_generation text;
BEGIN
    IF session_user <> 'rss_projection_operator'
       OR p_tenant_id IS NULL
       OR p_tenant_id = '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'settings active status authority mismatch' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_catalog.set_config('rss.tenant_id', p_tenant_id::text, true);
    SELECT pointer.generation, pointer.promoted_high_water_lsn, pointer.token
      INTO v_generation, v_promoted_high_water_lsn, v_token
      FROM public.settings_projection_active_pointer AS pointer
     WHERE pointer.tenant_id = p_tenant_id
       AND pointer.projection_id = 'settings.config-projection';
    IF NOT FOUND THEN
        RETURN;
    END IF;
    SELECT target.definition_version, target.definition_schema_digest, target.input_generation
      INTO STRICT v_definition_version, v_definition_schema_digest, v_input_generation
      FROM public.settings_projection_generations AS target
     WHERE target.tenant_id = p_tenant_id
       AND target.projection_id = 'settings.config-projection'
       AND target.generation = v_generation;
    IF v_definition_version <> 'v3'
       OR v_definition_schema_digest <> 'sha256:ce6e2126b5d5831f67955d1db29fc7c0c1cc339cdf4cec1ad2486f5fb778b4d8'
       OR v_input_generation <> 'sha256:ff7c69626735495640031695caf9c053830aa6efdcb8c3efa038d68d0cd25801' THEN
        RAISE EXCEPTION 'settings active status identity mismatch' USING ERRCODE = 'P1901';
    END IF;
    RETURN QUERY SELECT v_generation, v_promoted_high_water_lsn, v_token;
END;
$function$;

CREATE FUNCTION public.rss_projection_operator_swap_active(
    p_tenant_id uuid,
    p_target_generation text,
    p_expected_active_generation text,
    p_expected_token bigint,
    p_definition_version text,
    p_definition_schema_digest text,
    p_input_generation text
)
RETURNS TABLE (
    outcome text,
    reason text,
    previous_generation text,
    active_generation text,
    result_token bigint,
    promoted_high_water_lsn bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    v_target_definition_version text;
    v_target_definition_schema_digest text;
    v_target_input_generation text;
    v_generation_high_water_lsn bigint;
    v_checkpoint_high_water_lsn bigint;
    v_source_high_water_lsn bigint;
    v_previous_generation text;
    v_stored_token bigint;
    v_result_token bigint;
BEGIN
    IF session_user <> 'rss_projection_operator'
       OR p_tenant_id IS NULL
       OR p_tenant_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_target_generation IS NULL
       OR p_target_generation !~ '^[a-z0-9][a-z0-9._-]*$'
       OR pg_catalog.octet_length(p_target_generation) NOT BETWEEN 1 AND 256
       OR (p_expected_active_generation IS NULL) <> (p_expected_token IS NULL)
       OR (p_expected_active_generation IS NOT NULL AND (
           p_expected_active_generation !~ '^[a-z0-9][a-z0-9._-]*$'
           OR pg_catalog.octet_length(p_expected_active_generation) NOT BETWEEN 1 AND 256
           OR p_expected_token < 1
       ))
       OR p_definition_version <> 'v3'
       OR p_definition_schema_digest <> 'sha256:ce6e2126b5d5831f67955d1db29fc7c0c1cc339cdf4cec1ad2486f5fb778b4d8'
       OR p_input_generation <> 'sha256:ff7c69626735495640031695caf9c053830aa6efdcb8c3efa038d68d0cd25801' THEN
        RAISE EXCEPTION 'invalid Settings active swap request' USING ERRCODE = '22023';
    END IF;

    -- Serialize against append before reading source HWM; all later locks follow one fixed order.
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('rss.projection_events.append', 0)
    );
    PERFORM pg_catalog.set_config('rss.tenant_id', p_tenant_id::text, true);

    PERFORM 1
      FROM public.projection_input_bindings AS binding
     WHERE binding.generation = p_input_generation
       AND binding.projection_id = 'settings.config-projection'
       AND binding.projection_definition_version = p_definition_version
       AND binding.projection_definition_schema_digest = p_definition_schema_digest
     LIMIT 1;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'rejected', 'input_generation_mismatch', NULL::text, NULL::text,
                            NULL::bigint, NULL::bigint;
        RETURN;
    END IF;

    SELECT target.definition_version, target.definition_schema_digest,
           target.input_generation, target.high_water_lsn
      INTO v_target_definition_version, v_target_definition_schema_digest,
           v_target_input_generation, v_generation_high_water_lsn
      FROM public.settings_projection_generations AS target
     WHERE target.tenant_id = p_tenant_id
       AND target.projection_id = 'settings.config-projection'
       AND target.generation = p_target_generation
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'rejected', 'generation_missing', NULL::text, NULL::text,
                            NULL::bigint, NULL::bigint;
        RETURN;
    END IF;
    IF v_target_definition_version <> p_definition_version
       OR v_target_definition_schema_digest <> p_definition_schema_digest THEN
        RETURN QUERY SELECT 'rejected', 'definition_mismatch', NULL::text, NULL::text,
                            NULL::bigint, NULL::bigint;
        RETURN;
    END IF;
    IF v_target_input_generation <> p_input_generation THEN
        RETURN QUERY SELECT 'rejected', 'input_generation_mismatch', NULL::text, NULL::text,
                            NULL::bigint, NULL::bigint;
        RETURN;
    END IF;

    SELECT checkpoint.offset_lsn
      INTO v_checkpoint_high_water_lsn
      FROM public.checkpoint
     WHERE checkpoint.owner = 'projection:' || p_tenant_id::text
       AND checkpoint.checkpoint_id =
           'settings.config-projection@' || p_target_generation || ':shadow'
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'rejected', 'checkpoint_missing', NULL::text, NULL::text,
                            NULL::bigint, NULL::bigint;
        RETURN;
    END IF;

    PERFORM 1
      FROM public.projection_worker_tenant_quarantine AS quarantine
     WHERE quarantine.tenant_scope_id = p_tenant_id
       AND quarantine.projection_id = 'settings.config-projection'
       AND quarantine.target_generation = p_target_generation
       AND quarantine.state = 'quarantined'
     FOR UPDATE;
    IF FOUND THEN
        RETURN QUERY SELECT 'rejected', 'target_quarantined', NULL::text, NULL::text,
                            NULL::bigint, NULL::bigint;
        RETURN;
    END IF;

    SELECT pg_catalog.max(event.id)
      INTO v_source_high_water_lsn
      FROM public.projection_events AS event
     WHERE event.metadata ->> 'tenantId' = p_tenant_id::text
       AND EXISTS (
           SELECT 1 FROM public.projection_input_bindings AS binding
           WHERE binding.generation = p_input_generation
             AND binding.projection_id = 'settings.config-projection'
             AND binding.projection_definition_version = p_definition_version
             AND binding.projection_definition_schema_digest = p_definition_schema_digest
             AND binding.source_domain = event.domain
             AND binding.contract_id = event.contract_id
             AND binding.contract_version = event.contract_version
             AND binding.schema_hash = event.schema_hash
             AND binding.topic = event.event_type
       );
    IF v_source_high_water_lsn IS NULL THEN
        RETURN QUERY SELECT 'rejected', 'source_missing', NULL::text, NULL::text,
                            NULL::bigint, NULL::bigint;
        RETURN;
    END IF;
    IF v_checkpoint_high_water_lsn < v_source_high_water_lsn THEN
        RETURN QUERY SELECT 'rejected', 'checkpoint_stale', NULL::text, NULL::text,
                            NULL::bigint, NULL::bigint;
        RETURN;
    END IF;
    IF v_checkpoint_high_water_lsn > v_source_high_water_lsn THEN
        RETURN QUERY SELECT 'rejected', 'checkpoint_ahead', NULL::text, NULL::text,
                            NULL::bigint, NULL::bigint;
        RETURN;
    END IF;
    IF v_generation_high_water_lsn IS DISTINCT FROM v_checkpoint_high_water_lsn THEN
        RETURN QUERY SELECT 'rejected', 'generation_high_water_mismatch', NULL::text, NULL::text,
                            NULL::bigint, NULL::bigint;
        RETURN;
    END IF;

    SELECT pointer.generation, pointer.token
      INTO v_previous_generation, v_stored_token
      FROM public.settings_projection_active_pointer AS pointer
     WHERE pointer.tenant_id = p_tenant_id
       AND pointer.projection_id = 'settings.config-projection'
     FOR UPDATE;
    IF NOT FOUND THEN
        IF p_expected_active_generation IS NOT NULL THEN
            RETURN QUERY SELECT 'conflict', NULL::text, NULL::text, NULL::text,
                                NULL::bigint, NULL::bigint;
            RETURN;
        END IF;
        INSERT INTO public.settings_projection_active_pointer (
            tenant_id, projection_id, generation, promoted_high_water_lsn, token
        ) VALUES (
            p_tenant_id, 'settings.config-projection', p_target_generation,
            v_checkpoint_high_water_lsn, 1
        );
        RETURN QUERY SELECT 'applied', NULL::text, NULL::text, p_target_generation,
                            1::bigint, v_checkpoint_high_water_lsn;
        RETURN;
    END IF;

    IF p_expected_active_generation IS NULL THEN
        RETURN QUERY SELECT 'conflict', NULL::text, v_previous_generation, v_previous_generation,
                            v_stored_token, NULL::bigint;
        RETURN;
    END IF;
    IF p_expected_token <> v_stored_token THEN
        RETURN QUERY SELECT 'fenced', NULL::text, v_previous_generation, v_previous_generation,
                            v_stored_token, NULL::bigint;
        RETURN;
    END IF;
    IF p_expected_active_generation <> v_previous_generation THEN
        RETURN QUERY SELECT 'conflict', NULL::text, v_previous_generation, v_previous_generation,
                            v_stored_token, NULL::bigint;
        RETURN;
    END IF;
    IF v_stored_token = 9223372036854775807 THEN
        RAISE EXCEPTION 'Settings active pointer token overflow' USING ERRCODE = '22003';
    END IF;
    v_result_token := v_stored_token + 1;
    UPDATE public.settings_projection_active_pointer
       SET generation = p_target_generation,
           promoted_high_water_lsn = v_checkpoint_high_water_lsn,
           token = v_result_token,
           updated_at = pg_catalog.now()
     WHERE tenant_id = p_tenant_id
       AND projection_id = 'settings.config-projection';
    RETURN QUERY SELECT 'applied', NULL::text, v_previous_generation, p_target_generation,
                        v_result_token, v_checkpoint_high_water_lsn;
END;
$function$;

DROP FUNCTION public.rss_projection_worker_list_tenants(text, text, text, text, text, uuid, integer);
DROP FUNCTION public.rss_projection_worker_has_quarantined_tenants(text, text, text, text, text);

ALTER FUNCTION public.rss_settings_projection_apply_current(
    text, text, uuid, text, text, text, text, text, text, bigint, text, text,
    bigint, bigint, bytea
) OWNER TO rss_projection_operator_owner;
ALTER FUNCTION public.rss_settings_projection_apply_worker(
    uuid, text, text, text, text, text, text, bigint, text, text, bigint, bigint, bytea
) OWNER TO rss_projection_worker_owner;
ALTER FUNCTION public.rss_settings_projection_apply_operator(
    uuid, text, text, text, text, text, text, bigint, text, text, bigint, bigint, bytea
) OWNER TO rss_projection_operator_owner;
ALTER FUNCTION public.rss_settings_projection_worker_plan_is_current(text, text, text, text)
    OWNER TO rss_projection_worker_owner;
ALTER FUNCTION public.rss_settings_projection_worker_tenant_scope_is_active(
    uuid, text, text, text, text, text
)
    OWNER TO rss_projection_worker_owner;
ALTER FUNCTION public.rss_projection_worker_quarantine_tenant(
    uuid, text, text, text, text, text, text, bigint
) OWNER TO rss_projection_worker_owner;
ALTER FUNCTION public.rss_projection_worker_tenant_is_quarantined(
    uuid, text, text, text, text, text
) OWNER TO rss_projection_worker_owner;
ALTER FUNCTION public.rss_projection_operator_recover_tenant(uuid, text, text, bigint)
    OWNER TO rss_projection_operator_owner;
ALTER FUNCTION public.rss_projection_worker_list_tenants(text, text, text, text, uuid, integer)
    OWNER TO rss_projection_worker_owner;
ALTER FUNCTION public.rss_projection_worker_read_events(
    uuid, text, text, text, text, text, bigint, integer
) OWNER TO rss_projection_worker_owner;
ALTER FUNCTION public.rss_projection_worker_source_high_water(uuid, text, text, text, text, text)
    OWNER TO rss_projection_worker_owner;
ALTER FUNCTION public.rss_projection_worker_get_checkpoint(uuid, text, text, text, text, text)
    OWNER TO rss_projection_worker_owner;
ALTER FUNCTION public.rss_projection_worker_save_checkpoint(
    uuid, text, text, text, text, text, bigint, bigint
) OWNER TO rss_projection_worker_owner;
ALTER FUNCTION public.rss_projection_worker_insert_dead_letter(
    uuid, text, text, text, text, text, text, text, text, text, text, text, jsonb, text, bigint,
    text, bytea, text, integer, text
) OWNER TO rss_projection_worker_owner;
ALTER FUNCTION public.rss_settings_projection_resolve_active()
    OWNER TO rss_projection_serving_owner;
ALTER FUNCTION public.rss_projection_operator_status_active(uuid)
    OWNER TO rss_projection_operator_owner;
ALTER FUNCTION public.rss_projection_operator_swap_active(uuid, text, text, bigint, text, text, text)
    OWNER TO rss_projection_operator_owner;

REVOKE ALL ON TABLE public.settings_projection_active_pointer
FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator, rss_projection_worker;
GRANT SELECT ON TABLE public.settings_projection_generations
    TO rss_projection_serving_owner;
GRANT SELECT ON TABLE public.settings_projection_active_pointer, public.settings_projection_generations
    TO rss_projection_worker_owner;
GRANT SELECT, INSERT, UPDATE ON TABLE public.settings_projection_active_pointer
    TO rss_projection_operator_owner;
GRANT SELECT ON TABLE public.projection_events, public.projection_input_bindings
    TO rss_projection_operator_owner;

REVOKE ALL ON FUNCTION public.rss_settings_projection_apply_current(
    text, text, uuid, text, text, text, text, text, text, bigint, text, text,
    bigint, bigint, bytea
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator, rss_projection_worker;
GRANT EXECUTE ON FUNCTION public.rss_settings_projection_apply_current(
    text, text, uuid, text, text, text, text, text, text, bigint, text, text,
    bigint, bigint, bytea
) TO rss_projection_operator_owner, rss_projection_worker_owner;

REVOKE ALL ON FUNCTION public.rss_settings_projection_worker_plan_is_current(
    text, text, text, text
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator, rss_projection_worker;
GRANT EXECUTE ON FUNCTION public.rss_settings_projection_worker_plan_is_current(
    text, text, text, text
) TO rss_projection_worker_owner;

REVOKE ALL ON FUNCTION public.rss_settings_projection_worker_tenant_scope_is_active(
    uuid, text, text, text, text, text
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator, rss_projection_worker;
GRANT EXECUTE ON FUNCTION public.rss_settings_projection_worker_tenant_scope_is_active(
    uuid, text, text, text, text, text
) TO rss_projection_worker_owner;

REVOKE ALL ON FUNCTION public.rss_projection_worker_list_tenants(
    text, text, text, text, uuid, integer
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator, rss_projection_worker;
GRANT EXECUTE ON FUNCTION public.rss_projection_worker_list_tenants(
    text, text, text, text, uuid, integer
) TO rss_projection_worker;

REVOKE ALL ON FUNCTION public.rss_projection_worker_tenant_is_quarantined(
    uuid, text, text, text, text, text
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator, rss_projection_worker;
GRANT EXECUTE ON FUNCTION public.rss_projection_worker_tenant_is_quarantined(
    uuid, text, text, text, text, text
) TO rss_projection_worker;

REVOKE ALL ON FUNCTION public.rss_settings_projection_resolve_active()
FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator, rss_projection_worker;
GRANT EXECUTE ON FUNCTION public.rss_settings_projection_resolve_active()
TO rss_app_read, rss_projection_worker;

REVOKE ALL ON FUNCTION public.rss_projection_operator_status_active(uuid)
FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator, rss_projection_worker;
GRANT EXECUTE ON FUNCTION public.rss_projection_operator_status_active(uuid)
TO rss_projection_operator;

REVOKE ALL ON FUNCTION public.rss_projection_operator_swap_active(
    uuid, text, text, bigint, text, text, text
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator, rss_projection_worker;
GRANT EXECUTE ON FUNCTION public.rss_projection_operator_swap_active(
    uuid, text, text, bigint, text, text, text
) TO rss_projection_operator;

REVOKE ALL ON FUNCTION public.rss_settings_projection_apply_worker(
    uuid, text, text, text, text, text, text, bigint, text, text, bigint, bigint, bytea
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator, rss_projection_worker;
GRANT EXECUTE ON FUNCTION public.rss_settings_projection_apply_worker(
    uuid, text, text, text, text, text, text, bigint, text, text, bigint, bigint, bytea
) TO rss_projection_worker;

REVOKE ALL ON FUNCTION public.rss_settings_projection_apply_operator(
    uuid, text, text, text, text, text, text, bigint, text, text, bigint, bigint, bytea
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator, rss_projection_worker;
GRANT EXECUTE ON FUNCTION public.rss_settings_projection_apply_operator(
    uuid, text, text, text, text, text, text, bigint, text, text, bigint, bigint, bytea
) TO rss_projection_operator;

GRANT USAGE ON SCHEMA public TO rss_projection_serving_owner;
