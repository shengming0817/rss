-- Advance Settings v3 serving to the current generated projection-input generation (#1289).
--
-- The projection registry generation covers every committed projection input. Tightening the
-- audit session-created input therefore changes the global generation even though the Settings
-- source contract is unchanged. Derived Settings state is replayable, so this is an intentional
-- hard cut: retain the source log and registry, discard stale derived generations, and reinstall
-- every fixed serving function that pins the generation.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

LOCK TABLE public.settings_projection_active_pointer,
           public.settings_projection_generations,
           public.settings_projection_dedupe_receipts,
           public.settings_config_projection_rows,
           public.projection_worker_tenant_quarantine,
           public.checkpoint IN ACCESS EXCLUSIVE MODE;

DELETE FROM public.settings_projection_dedupe_receipts
WHERE projection_id = 'settings.config-projection';
DELETE FROM public.settings_config_projection_rows
WHERE projection_id = 'settings.config-projection';
DELETE FROM public.projection_worker_tenant_quarantine
WHERE projection_id = 'settings.config-projection';
DELETE FROM public.checkpoint
WHERE owner LIKE 'projection:%'
  AND checkpoint_id LIKE 'settings.config-projection@%:shadow';
DELETE FROM public.settings_projection_active_pointer
WHERE projection_id = 'settings.config-projection';
DELETE FROM public.settings_projection_generations
WHERE projection_id = 'settings.config-projection';

CREATE OR REPLACE FUNCTION public.rss_settings_projection_apply_current(
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
       OR p_input_generation <> 'sha256:0ee8ef28ba5d0d69f12efbf2fa114a5bcfaccec3739c7f97dcc4131ca9890bd0' THEN
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
CREATE OR REPLACE FUNCTION public.rss_settings_projection_worker_plan_is_current(
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
       AND p_input_generation = 'sha256:0ee8ef28ba5d0d69f12efbf2fa114a5bcfaccec3739c7f97dcc4131ca9890bd0'
       AND EXISTS (
           SELECT 1 FROM public.projection_input_bindings AS binding
           WHERE binding.generation = p_input_generation
             AND binding.projection_id = p_projection_id
             AND binding.projection_definition_version = p_definition_version
             AND binding.projection_definition_schema_digest = p_definition_schema_digest
       );
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
       OR p_input_generation <> 'sha256:0ee8ef28ba5d0d69f12efbf2fa114a5bcfaccec3739c7f97dcc4131ca9890bd0' THEN
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

CREATE OR REPLACE FUNCTION public.rss_settings_projection_resolve_active()
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
       OR v_input_generation <> 'sha256:0ee8ef28ba5d0d69f12efbf2fa114a5bcfaccec3739c7f97dcc4131ca9890bd0' THEN
        RAISE EXCEPTION 'settings active resolver identity mismatch' USING ERRCODE = 'P1901';
    END IF;
    RETURN QUERY SELECT v_generation, v_definition_version, v_definition_schema_digest,
                        v_input_generation, v_promoted_high_water_lsn, v_token;
END;
$function$;

CREATE OR REPLACE FUNCTION public.rss_projection_operator_status_active(p_tenant_id uuid)
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
       OR v_input_generation <> 'sha256:0ee8ef28ba5d0d69f12efbf2fa114a5bcfaccec3739c7f97dcc4131ca9890bd0' THEN
        RAISE EXCEPTION 'settings active status identity mismatch' USING ERRCODE = 'P1901';
    END IF;
    RETURN QUERY SELECT v_generation, v_promoted_high_water_lsn, v_token;
END;
$function$;

CREATE OR REPLACE FUNCTION public.rss_projection_operator_swap_active(
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
       OR p_input_generation <> 'sha256:0ee8ef28ba5d0d69f12efbf2fa114a5bcfaccec3739c7f97dcc4131ca9890bd0' THEN
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
