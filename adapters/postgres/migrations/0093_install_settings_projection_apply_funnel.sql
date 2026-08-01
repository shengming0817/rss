-- One metadata-only mutation funnel for serving and operator Settings projection apply (#1919).

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

CREATE FUNCTION public.rss_settings_projection_apply(
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
    v_current_version bigint;
BEGIN
    IF p_projection_id <> 'settings.config-projection'
       OR p_definition_version <> 'v3'
       OR p_definition_schema_digest <> 'sha256:3504a1f33b4e2765fff012fd263ed9a317d24cbe200382c364e4220d7bf05baa'
       OR p_input_generation <> 'sha256:f0c8804d298ce326e5e22b6f8585dbce7cbe794546305cfecd2613985fbeb43e' THEN
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

    SELECT fact_digest
      INTO v_existing_digest
      FROM public.settings_projection_dedupe_receipts
     WHERE tenant_id = p_tenant_id
       AND projection_id = p_projection_id
       AND generation = p_generation
       AND source_event_id = p_source_event_id;
    IF FOUND THEN
        IF v_existing_digest = p_fact_digest THEN
            RETURN 'duplicate';
        END IF;
        RAISE EXCEPTION USING ERRCODE = 'P1903', MESSAGE = 'settings projection receipt conflict';
    END IF;

    IF v_high_water_lsn IS NOT NULL AND p_source_lsn < v_high_water_lsn THEN
        RAISE EXCEPTION USING ERRCODE = 'P1904', MESSAGE = 'settings projection source order violation';
    END IF;

    SELECT config_version
      INTO v_current_version
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
            tenant_id, projection_id, generation, source_event_id, source_lsn, fact_digest
        ) VALUES (
            p_tenant_id, p_projection_id, p_generation, p_source_event_id, p_source_lsn,
            p_fact_digest
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

-- Candidate events for a known binding must not disappear when only version/schema identity
-- drifts. Return their metadata identity with an empty payload so the sealed target emits a typed
-- Invariant poison without releasing raw bytes to Rust. Exact binding rows retain their payload.
CREATE OR REPLACE FUNCTION public.rss_read_projection_events_scoped(
    p_capability_first uuid,
    p_capability_second uuid,
    p_tenant_id uuid,
    p_projection_id text,
    p_definition_version text,
    p_definition_schema_digest text,
    p_input_generation text,
    p_after bigint,
    p_limit integer
)
RETURNS TABLE (
    id bigint, event_id text, domain text, aggregate_id text, event_type text, payload bytea,
    contract_id text, contract_version text, schema_hash text, metadata jsonb,
    partition_key text, causation_id text
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF p_after IS NULL OR p_after < 0
        OR p_limit IS NULL OR p_limit < 1 OR p_limit > 1000
    THEN
        RAISE EXCEPTION 'invalid projection source scope' USING ERRCODE = '22023';
    END IF;
    PERFORM public.rss_assert_projection_source_scope(
        true, p_capability_first, p_capability_second, p_tenant_id, p_projection_id,
        p_definition_version, p_definition_schema_digest, p_input_generation
    );

    RETURN QUERY
    SELECT event.id,
           event.event_id,
           event.domain,
           event.aggregate_id,
           event.event_type,
           CASE WHEN EXISTS (
               SELECT 1
               FROM public.projection_input_bindings AS exact_binding
               WHERE exact_binding.generation = p_input_generation
                 AND exact_binding.projection_id = p_projection_id
                 AND exact_binding.projection_definition_version = p_definition_version
                 AND exact_binding.projection_definition_schema_digest = p_definition_schema_digest
                 AND exact_binding.source_domain = event.domain
                 AND exact_binding.contract_id = event.contract_id
                 AND exact_binding.contract_version = event.contract_version
                 AND exact_binding.schema_hash = event.schema_hash
                 AND exact_binding.topic = event.event_type
           ) THEN event.payload ELSE ''::bytea END,
           event.contract_id,
           event.contract_version,
           event.schema_hash,
           event.metadata,
           event.partition_key,
           event.causation_id
    FROM public.projection_events AS event
    WHERE event.id > p_after
      AND event.metadata ->> 'tenantId' = p_tenant_id::text
      AND EXISTS (
          SELECT 1
          FROM public.projection_input_bindings AS candidate_binding
          WHERE candidate_binding.generation = p_input_generation
            AND candidate_binding.projection_id = p_projection_id
            AND candidate_binding.projection_definition_version = p_definition_version
            AND candidate_binding.projection_definition_schema_digest = p_definition_schema_digest
            AND candidate_binding.source_domain = event.domain
            AND candidate_binding.contract_id = event.contract_id
            AND candidate_binding.topic = event.event_type
      )
    ORDER BY event.id ASC
    LIMIT p_limit;
END;
$function$;

CREATE OR REPLACE FUNCTION public.rss_projection_source_high_water_scoped(
    p_capability_first uuid,
    p_capability_second uuid,
    p_tenant_id uuid,
    p_projection_id text,
    p_definition_version text,
    p_definition_schema_digest text,
    p_input_generation text
)
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET plan_cache_mode = force_custom_plan
AS $function$
DECLARE
    high_water bigint;
BEGIN
    PERFORM public.rss_assert_projection_source_scope(
        true, p_capability_first, p_capability_second, p_tenant_id, p_projection_id,
        p_definition_version, p_definition_schema_digest, p_input_generation
    );
    SELECT pg_catalog.max(event.id)
      INTO high_water
      FROM public.projection_events AS event
     WHERE event.metadata ->> 'tenantId' = p_tenant_id::text
       AND EXISTS (
           SELECT 1
           FROM public.projection_input_bindings AS candidate_binding
           WHERE candidate_binding.generation = p_input_generation
             AND candidate_binding.projection_id = p_projection_id
             AND candidate_binding.projection_definition_version = p_definition_version
             AND candidate_binding.projection_definition_schema_digest = p_definition_schema_digest
             AND candidate_binding.source_domain = event.domain
             AND candidate_binding.contract_id = event.contract_id
             AND candidate_binding.topic = event.event_type
       );
    RETURN high_water;
END;
$function$;

ALTER FUNCTION public.rss_settings_projection_apply(
    uuid, text, text, text, text, text, text, bigint, text, text, bigint, bigint, bytea
) OWNER TO rss_projection_operator_owner;

ALTER ROLE rss_projection_operator_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;

REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE
    public.settings_projection_generations,
    public.settings_config_projection_rows,
    public.settings_projection_dedupe_receipts
FROM rss_app, rss_app_read, rss_projection_operator;

REVOKE INSERT (
    tenant_id, projection_id, generation, definition_version,
    definition_schema_digest, input_generation, high_water_lsn
) ON public.settings_projection_generations FROM rss_app, rss_app_read;
REVOKE UPDATE (high_water_lsn, updated_at)
    ON public.settings_projection_generations FROM rss_app, rss_app_read;
REVOKE INSERT (
    tenant_id, projection_id, generation, config_key, config_version, change_kind,
    source_event_id, source_lsn, source_occurred_at_secs
) ON public.settings_config_projection_rows FROM rss_app, rss_app_read;
REVOKE UPDATE (
    config_version, change_kind, source_event_id, source_lsn,
    source_occurred_at_secs, updated_at
) ON public.settings_config_projection_rows FROM rss_app, rss_app_read;
REVOKE INSERT (
    tenant_id, projection_id, generation, source_event_id, source_lsn, fact_digest
) ON public.settings_projection_dedupe_receipts FROM rss_app, rss_app_read;

GRANT SELECT, INSERT, UPDATE ON TABLE
    public.settings_projection_generations,
    public.settings_config_projection_rows,
    public.settings_projection_dedupe_receipts
TO rss_projection_operator_owner;

-- Evaluated by the dead_letter projection-only CHECK/index while the operator DLQ definer
-- inserts. Admit only the non-login function owner; callers still cannot execute raw DLQ DML.
GRANT EXECUTE ON FUNCTION public.rss_projection_dead_letter_source_kind()
TO rss_projection_operator_owner;
-- `ON CONFLICT ... DO NOTHING` checks the projection idempotency key and therefore requires
-- SELECT for the definer owner; the login operator retains no raw table privilege.
GRANT SELECT ON TABLE public.dead_letter TO rss_projection_operator_owner;

REVOKE ALL ON FUNCTION public.rss_settings_projection_apply(
    uuid, text, text, text, text, text, text, bigint, text, text, bigint, bigint, bytea
) FROM PUBLIC, rss_app_read, rss_projection_reader, rss_projection_operator, rss_app;
GRANT EXECUTE ON FUNCTION public.rss_settings_projection_apply(
    uuid, text, text, text, text, text, text, bigint, text, text, bigint, bigint, bytea
) TO rss_app, rss_projection_operator;
