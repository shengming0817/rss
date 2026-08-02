-- Dedicated function-only Projection worker lifecycle and purpose-bound Settings apply (#1920).

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

DO $migration$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rss_projection_worker'
    ) THEN
        CREATE ROLE rss_projection_worker NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rss_projection_worker_owner'
    ) THEN
        CREATE ROLE rss_projection_worker_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
    END IF;
END
$migration$;

-- projection worker preflight: reject a pre-existing role collision before the hard cut mutates
-- receipts or drops the legacy apply function. ACL/ownership dependencies are cluster-catalog
-- facts and therefore remain visible even when the colliding role cannot inspect the object.
DO $preflight$
DECLARE
    checked_role oid;
BEGIN
    FOREACH checked_role IN ARRAY ARRAY[
        'rss_projection_worker'::regrole::oid,
        'rss_projection_worker_owner'::regrole::oid
    ] LOOP
        IF EXISTS (
            SELECT 1 FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = checked_role OR membership.roleid = checked_role
        ) THEN
            RAISE EXCEPTION 'projection worker roles must have no memberships';
        END IF;
        IF EXISTS (
            SELECT 1 FROM pg_catalog.pg_shdepend AS dependency
            WHERE dependency.refclassid = 'pg_catalog.pg_authid'::regclass
              AND dependency.refobjid = checked_role
              AND dependency.deptype = 'o'
        ) THEN
            RAISE EXCEPTION 'projection worker roles must own no database objects';
        END IF;
        IF EXISTS (
            SELECT 1 FROM pg_catalog.pg_shdepend AS dependency
            WHERE dependency.refclassid = 'pg_catalog.pg_authid'::regclass
              AND dependency.refobjid = checked_role
              AND dependency.deptype = 'a'
        ) THEN
            RAISE EXCEPTION 'projection worker roles must have no pre-existing privileges';
        END IF;
    END LOOP;
END
$preflight$;

ALTER ROLE rss_projection_worker
    NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
ALTER ROLE rss_projection_worker_owner
    NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
ALTER ROLE rss_projection_worker SET search_path = pg_catalog, public;

ALTER TABLE public.settings_projection_dedupe_receipts
    ADD COLUMN actor text,
    ADD COLUMN purpose text;

UPDATE public.settings_projection_dedupe_receipts
SET actor = 'rss-projection-replay', purpose = 'operator-replay';

ALTER TABLE public.settings_projection_dedupe_receipts
    ALTER COLUMN actor SET NOT NULL,
    ALTER COLUMN purpose SET NOT NULL,
    ADD CONSTRAINT settings_projection_dedupe_receipts_execution_pair CHECK (
        (actor = 'rss-projection-worker' AND purpose = 'background-shadow')
        OR (actor = 'rss-projection-replay' AND purpose = 'operator-replay')
    );

CREATE TABLE public.projection_worker_tenant_quarantine (
    -- This is a cross-tenant worker-control catalog exposed only through fixed SECURITY DEFINER
    -- functions, not a serving tenant row. Keep the scope key distinct from the tenant_id column
    -- contract used by ordinary tenant tables and their per-session RLS policy.
    tenant_scope_id uuid NOT NULL,
    projection_id text NOT NULL,
    target_generation text NOT NULL,
    state text NOT NULL CHECK (state IN ('quarantined', 'released')),
    reason text NOT NULL CHECK (reason IN (
        'target_definition_drift', 'input_binding_drift', 'tenant_drift', 'payload_malformed',
        'payload_value_invalid', 'version_regression', 'provider_invariant', 'provider_permanent',
        'conflict', 'apply_out_of_order', 'rollback_failed', 'source_out_of_order'
    )),
    failed_lsn bigint NOT NULL CHECK (failed_lsn >= 0),
    quarantined_at timestamptz NOT NULL DEFAULT pg_catalog.now(),
    updated_at timestamptz NOT NULL DEFAULT pg_catalog.now(),
    PRIMARY KEY (tenant_scope_id, projection_id, target_generation)
);

DROP FUNCTION public.rss_settings_projection_apply(
    uuid, text, text, text, text, text, text, bigint, text, text, bigint, bigint, bytea
);

CREATE FUNCTION public.rss_settings_projection_apply_worker(
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
    IF session_user <> 'rss_projection_worker'
       OR p_projection_id <> 'settings.config-projection'
       OR p_generation <> 'v3'
       OR p_definition_version <> 'v3'
       OR p_definition_schema_digest <> 'sha256:11cd811ed051254c6ea2c8e6aa659b8b2d32c606f635456ece9ee56695cc0103'
       OR p_input_generation <> 'sha256:a5e8aabe65e02bc07bc6c0168396d537246669a8344814a63b5ed972f5a81bb8' THEN
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
           AND v_existing_actor = 'rss-projection-worker'
           AND v_existing_purpose = 'background-shadow' THEN
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
            tenant_id, projection_id, generation, source_event_id, source_lsn, fact_digest,
            actor, purpose
        ) VALUES (
            p_tenant_id, p_projection_id, p_generation, p_source_event_id, p_source_lsn,
            p_fact_digest, 'rss-projection-worker', 'background-shadow'
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

CREATE FUNCTION public.rss_settings_projection_apply_operator(
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
    IF session_user <> 'rss_projection_operator'
       OR p_projection_id <> 'settings.config-projection'
       OR p_definition_version <> 'v3'
       OR p_definition_schema_digest <> 'sha256:11cd811ed051254c6ea2c8e6aa659b8b2d32c606f635456ece9ee56695cc0103'
       OR p_input_generation <> 'sha256:a5e8aabe65e02bc07bc6c0168396d537246669a8344814a63b5ed972f5a81bb8' THEN
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
           AND v_existing_actor = 'rss-projection-replay'
           AND v_existing_purpose = 'operator-replay' THEN
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
            tenant_id, projection_id, generation, source_event_id, source_lsn, fact_digest,
            actor, purpose
        ) VALUES (
            p_tenant_id, p_projection_id, p_generation, p_source_event_id, p_source_lsn,
            p_fact_digest, 'rss-projection-replay', 'operator-replay'
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

CREATE FUNCTION public.rss_projection_worker_quarantine_tenant(
    p_tenant_id uuid,
    p_projection_id text,
    p_target_generation text,
    p_definition_version text,
    p_definition_schema_digest text,
    p_input_generation text,
    p_reason text,
    p_failed_lsn bigint
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF session_user <> 'rss_projection_worker'
       OR p_projection_id <> 'settings.config-projection'
       OR p_target_generation <> 'v3'
       OR p_definition_version <> 'v3'
       OR p_definition_schema_digest <> 'sha256:11cd811ed051254c6ea2c8e6aa659b8b2d32c606f635456ece9ee56695cc0103'
       OR p_input_generation <> 'sha256:a5e8aabe65e02bc07bc6c0168396d537246669a8344814a63b5ed972f5a81bb8'
       OR p_reason NOT IN (
           'target_definition_drift', 'input_binding_drift', 'tenant_drift', 'payload_malformed',
           'payload_value_invalid', 'version_regression', 'provider_invariant', 'provider_permanent',
           'conflict', 'apply_out_of_order', 'rollback_failed', 'source_out_of_order'
       )
       OR p_failed_lsn < 0 THEN
        RAISE EXCEPTION 'invalid projection worker quarantine' USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.projection_input_bindings AS binding
        WHERE binding.generation = p_input_generation
          AND binding.projection_id = p_projection_id
          AND binding.projection_definition_version = p_definition_version
          AND binding.projection_definition_schema_digest = p_definition_schema_digest
    ) THEN
        RAISE EXCEPTION 'invalid projection worker scope' USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.projection_worker_tenant_quarantine (
        tenant_scope_id, projection_id, target_generation, state, reason, failed_lsn
    ) VALUES (
        p_tenant_id, p_projection_id, p_target_generation, 'quarantined', p_reason, p_failed_lsn
    )
    ON CONFLICT (tenant_scope_id, projection_id, target_generation) DO UPDATE
    SET state = 'quarantined',
        reason = EXCLUDED.reason,
        failed_lsn = EXCLUDED.failed_lsn,
        quarantined_at = pg_catalog.now(),
        updated_at = pg_catalog.now();
END;
$function$;

CREATE FUNCTION public.rss_projection_worker_has_quarantined_tenants(
    p_projection_id text,
    p_target_generation text,
    p_definition_version text,
    p_definition_schema_digest text,
    p_input_generation text
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF session_user <> 'rss_projection_worker'
       OR p_projection_id <> 'settings.config-projection'
       OR p_target_generation <> 'v3'
       OR p_definition_version <> 'v3'
       OR p_definition_schema_digest <> 'sha256:11cd811ed051254c6ea2c8e6aa659b8b2d32c606f635456ece9ee56695cc0103'
       OR p_input_generation <> 'sha256:a5e8aabe65e02bc07bc6c0168396d537246669a8344814a63b5ed972f5a81bb8' THEN
        RAISE EXCEPTION 'invalid projection worker scope' USING ERRCODE = '22023';
    END IF;
    RETURN EXISTS (
        SELECT 1 FROM public.projection_worker_tenant_quarantine AS quarantine
        WHERE quarantine.projection_id = p_projection_id
          AND quarantine.target_generation = p_target_generation
          AND quarantine.state = 'quarantined'
    );
END;
$function$;

CREATE FUNCTION public.rss_projection_operator_recover_tenant(
    p_tenant_id uuid,
    p_projection_id text,
    p_target_generation text,
    p_expected_failed_lsn bigint
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    changed bigint;
BEGIN
    IF session_user <> 'rss_projection_operator'
       OR p_projection_id <> 'settings.config-projection'
       OR p_target_generation <> 'v3'
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

CREATE FUNCTION public.rss_projection_worker_list_tenants(
    p_projection_id text,
    p_target_generation text,
    p_definition_version text,
    p_definition_schema_digest text,
    p_input_generation text,
    p_after_tenant uuid,
    p_limit integer
)
RETURNS TABLE (tenant_id uuid)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF session_user <> 'rss_projection_worker'
       OR p_projection_id <> 'settings.config-projection'
       OR p_target_generation <> 'v3'
       OR p_definition_version <> 'v3'
       OR p_definition_schema_digest <> 'sha256:11cd811ed051254c6ea2c8e6aa659b8b2d32c606f635456ece9ee56695cc0103'
       OR p_input_generation <> 'sha256:a5e8aabe65e02bc07bc6c0168396d537246669a8344814a63b5ed972f5a81bb8'
       OR p_limit <> 100 THEN
        RAISE EXCEPTION 'invalid projection worker scope' USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.projection_input_bindings AS binding
        WHERE binding.generation = p_input_generation
          AND binding.projection_id = p_projection_id
          AND binding.projection_definition_version = p_definition_version
          AND binding.projection_definition_schema_digest = p_definition_schema_digest
    ) THEN
        RAISE EXCEPTION 'invalid projection worker scope' USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
    SELECT DISTINCT (event.metadata ->> 'tenantId')::uuid
    FROM public.projection_events AS event
    WHERE (event.metadata ->> 'tenantId') ~
              '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      AND (p_after_tenant IS NULL OR (event.metadata ->> 'tenantId')::uuid > p_after_tenant)
      AND EXISTS (
          SELECT 1 FROM public.projection_input_bindings AS candidate_binding
          WHERE candidate_binding.generation = p_input_generation
            AND candidate_binding.projection_id = p_projection_id
            AND candidate_binding.projection_definition_version = p_definition_version
            AND candidate_binding.projection_definition_schema_digest = p_definition_schema_digest
            AND candidate_binding.source_domain = event.domain
            AND candidate_binding.contract_id = event.contract_id
            AND candidate_binding.topic = event.event_type
      )
      AND NOT EXISTS (
          SELECT 1 FROM public.projection_worker_tenant_quarantine AS quarantine
          WHERE quarantine.tenant_scope_id = (event.metadata ->> 'tenantId')::uuid
            AND quarantine.projection_id = p_projection_id
            AND quarantine.target_generation = p_target_generation
            AND quarantine.state = 'quarantined'
      )
    ORDER BY 1
    LIMIT p_limit;
END;
$function$;

CREATE FUNCTION public.rss_projection_worker_read_events(
    p_tenant_id uuid,
    p_projection_id text,
    p_target_generation text,
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
DECLARE
    v_session_tenant text;
BEGIN
    IF session_user <> 'rss_projection_worker'
       OR p_projection_id <> 'settings.config-projection'
       OR p_target_generation <> 'v3'
       OR p_definition_version <> 'v3'
       OR p_definition_schema_digest <> 'sha256:11cd811ed051254c6ea2c8e6aa659b8b2d32c606f635456ece9ee56695cc0103'
       OR p_input_generation <> 'sha256:a5e8aabe65e02bc07bc6c0168396d537246669a8344814a63b5ed972f5a81bb8'
       OR p_after IS NULL OR p_after < 0
       OR p_limit IS NULL OR p_limit < 1 OR p_limit > 1000 THEN
        RAISE EXCEPTION 'invalid projection worker scope' USING ERRCODE = '22023';
    END IF;
    v_session_tenant := pg_catalog.current_setting('rss.tenant_id', true);
    IF v_session_tenant IS NULL OR v_session_tenant = ''
       OR v_session_tenant::uuid <> p_tenant_id THEN
        RAISE EXCEPTION 'invalid projection worker tenant' USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.projection_input_bindings AS binding
        WHERE binding.generation = p_input_generation
          AND binding.projection_id = p_projection_id
          AND binding.projection_definition_version = p_definition_version
          AND binding.projection_definition_schema_digest = p_definition_schema_digest
    ) THEN
        RAISE EXCEPTION 'invalid projection worker scope' USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
    SELECT event.id, event.event_id, event.domain, event.aggregate_id, event.event_type,
           event.payload,
           event.contract_id, event.contract_version, event.schema_hash, event.metadata,
           event.partition_key, event.causation_id
    FROM public.projection_events AS event
    WHERE event.id > p_after
      AND event.metadata ->> 'tenantId' = p_tenant_id::text
      AND EXISTS (
          SELECT 1 FROM public.projection_input_bindings AS candidate_binding
          WHERE candidate_binding.generation = p_input_generation
            AND candidate_binding.projection_id = p_projection_id
            AND candidate_binding.projection_definition_version = p_definition_version
            AND candidate_binding.projection_definition_schema_digest = p_definition_schema_digest
            AND candidate_binding.source_domain = event.domain
            AND candidate_binding.contract_id = event.contract_id
            AND candidate_binding.contract_version = event.contract_version
            AND candidate_binding.schema_hash = event.schema_hash
            AND candidate_binding.topic = event.event_type
      )
    ORDER BY event.id ASC
    LIMIT p_limit;
END;
$function$;

CREATE FUNCTION public.rss_projection_worker_source_high_water(
    p_tenant_id uuid,
    p_projection_id text,
    p_target_generation text,
    p_definition_version text,
    p_definition_schema_digest text,
    p_input_generation text
)
RETURNS bigint
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    v_session_tenant text;
    high_water bigint;
BEGIN
    IF session_user <> 'rss_projection_worker'
       OR p_projection_id <> 'settings.config-projection'
       OR p_target_generation <> 'v3'
       OR p_definition_version <> 'v3'
       OR p_definition_schema_digest <> 'sha256:11cd811ed051254c6ea2c8e6aa659b8b2d32c606f635456ece9ee56695cc0103'
       OR p_input_generation <> 'sha256:a5e8aabe65e02bc07bc6c0168396d537246669a8344814a63b5ed972f5a81bb8' THEN
        RAISE EXCEPTION 'invalid projection worker scope' USING ERRCODE = '22023';
    END IF;
    v_session_tenant := pg_catalog.current_setting('rss.tenant_id', true);
    IF v_session_tenant IS NULL OR v_session_tenant = ''
       OR v_session_tenant::uuid <> p_tenant_id THEN
        RAISE EXCEPTION 'invalid projection worker tenant' USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.projection_input_bindings AS binding
        WHERE binding.generation = p_input_generation
          AND binding.projection_id = p_projection_id
          AND binding.projection_definition_version = p_definition_version
          AND binding.projection_definition_schema_digest = p_definition_schema_digest
    ) THEN
        RAISE EXCEPTION 'invalid projection worker scope' USING ERRCODE = '22023';
    END IF;
    SELECT pg_catalog.max(event.id) INTO high_water
    FROM public.projection_events AS event
    WHERE event.metadata ->> 'tenantId' = p_tenant_id::text
      AND EXISTS (
          SELECT 1 FROM public.projection_input_bindings AS candidate_binding
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

CREATE FUNCTION public.rss_projection_worker_get_checkpoint(
    p_tenant_id uuid,
    p_projection_id text,
    p_target_generation text,
    p_definition_version text,
    p_definition_schema_digest text,
    p_input_generation text
)
RETURNS TABLE (offset_lsn bigint, version bigint)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    v_session_tenant text;
BEGIN
    IF session_user <> 'rss_projection_worker'
       OR p_projection_id <> 'settings.config-projection'
       OR p_target_generation <> 'v3'
       OR p_definition_version <> 'v3'
       OR p_definition_schema_digest <> 'sha256:11cd811ed051254c6ea2c8e6aa659b8b2d32c606f635456ece9ee56695cc0103'
       OR p_input_generation <> 'sha256:a5e8aabe65e02bc07bc6c0168396d537246669a8344814a63b5ed972f5a81bb8' THEN
        RAISE EXCEPTION 'invalid projection worker scope' USING ERRCODE = '22023';
    END IF;
    v_session_tenant := pg_catalog.current_setting('rss.tenant_id', true);
    IF v_session_tenant IS NULL OR v_session_tenant = ''
       OR v_session_tenant::uuid <> p_tenant_id THEN
        RAISE EXCEPTION 'invalid projection worker tenant' USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.projection_input_bindings AS binding
        WHERE binding.generation = p_input_generation
          AND binding.projection_id = p_projection_id
          AND binding.projection_definition_version = p_definition_version
          AND binding.projection_definition_schema_digest = p_definition_schema_digest
    ) THEN
        RAISE EXCEPTION 'invalid projection worker scope' USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
    SELECT checkpoint.offset_lsn, checkpoint.version
    FROM public.checkpoint
    WHERE checkpoint.owner = 'projection:' || p_tenant_id::text
      AND checkpoint.checkpoint_id = p_projection_id || '@' || p_target_generation || ':shadow';
END;
$function$;

CREATE FUNCTION public.rss_projection_worker_save_checkpoint(
    p_tenant_id uuid,
    p_projection_id text,
    p_target_generation text,
    p_definition_version text,
    p_definition_schema_digest text,
    p_input_generation text,
    p_offset_lsn bigint,
    p_expected_version bigint
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    v_session_tenant text;
    changed bigint;
    v_checkpoint_owner text;
    v_checkpoint_id text;
BEGIN
    IF session_user <> 'rss_projection_worker'
       OR p_projection_id <> 'settings.config-projection'
       OR p_target_generation <> 'v3'
       OR p_definition_version <> 'v3'
       OR p_definition_schema_digest <> 'sha256:11cd811ed051254c6ea2c8e6aa659b8b2d32c606f635456ece9ee56695cc0103'
       OR p_input_generation <> 'sha256:a5e8aabe65e02bc07bc6c0168396d537246669a8344814a63b5ed972f5a81bb8'
       OR p_offset_lsn < 0 OR p_expected_version < 0 THEN
        RAISE EXCEPTION 'invalid projection worker checkpoint' USING ERRCODE = '22023';
    END IF;
    v_session_tenant := pg_catalog.current_setting('rss.tenant_id', true);
    IF v_session_tenant IS NULL OR v_session_tenant = ''
       OR v_session_tenant::uuid <> p_tenant_id THEN
        RAISE EXCEPTION 'invalid projection worker tenant' USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.projection_input_bindings AS binding
        WHERE binding.generation = p_input_generation
          AND binding.projection_id = p_projection_id
          AND binding.projection_definition_version = p_definition_version
          AND binding.projection_definition_schema_digest = p_definition_schema_digest
    ) THEN
        RAISE EXCEPTION 'invalid projection worker scope' USING ERRCODE = '22023';
    END IF;
    v_checkpoint_owner := 'projection:' || p_tenant_id::text;
    v_checkpoint_id := p_projection_id || '@' || p_target_generation || ':shadow';
    IF p_expected_version = 0 THEN
        INSERT INTO public.checkpoint (owner, checkpoint_id, offset_lsn, version)
        VALUES (v_checkpoint_owner, v_checkpoint_id, p_offset_lsn, 1)
        ON CONFLICT (owner, checkpoint_id) DO NOTHING;
    ELSE
        UPDATE public.checkpoint
        SET offset_lsn = p_offset_lsn,
            version = public.checkpoint.version + 1,
            updated_at = pg_catalog.now()
        WHERE owner = v_checkpoint_owner
          AND public.checkpoint.checkpoint_id = v_checkpoint_id
          AND public.checkpoint.version = p_expected_version
          AND public.checkpoint.offset_lsn <= p_offset_lsn;
    END IF;
    GET DIAGNOSTICS changed = ROW_COUNT;
    RETURN changed = 1;
END;
$function$;

CREATE FUNCTION public.rss_projection_worker_insert_dead_letter(
    p_tenant_id uuid,
    p_projection_id text,
    p_target_generation text,
    p_definition_version text,
    p_definition_schema_digest text,
    p_input_generation text,
    p_message_id text,
    p_producer_domain text,
    p_consumer_domain text,
    p_contract_id text,
    p_topic text,
    p_consumer_group text,
    p_replay_capsule jsonb,
    p_replay_capsule_key_ref text,
    p_payload_len bigint,
    p_replay_capsule_encoding text,
    p_metadata_digest bytea,
    p_error_summary text,
    p_num_attempts integer,
    p_source_kind text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    v_session_tenant text;
BEGIN
    IF session_user <> 'rss_projection_worker'
       OR p_projection_id <> 'settings.config-projection'
       OR p_target_generation <> 'v3'
       OR p_definition_version <> 'v3'
       OR p_definition_schema_digest <> 'sha256:11cd811ed051254c6ea2c8e6aa659b8b2d32c606f635456ece9ee56695cc0103'
       OR p_input_generation <> 'sha256:a5e8aabe65e02bc07bc6c0168396d537246669a8344814a63b5ed972f5a81bb8'
       OR p_source_kind <> public.rss_projection_dead_letter_source_kind()
       OR p_consumer_domain <> 'projection:' || p_tenant_id::text
       OR p_consumer_group <> p_projection_id || '@' || p_target_generation || ':shadow'
       OR p_payload_len < 0 OR p_num_attempts < 0
       OR p_replay_capsule_encoding <> 'key-provider-v3' THEN
        RAISE EXCEPTION 'invalid projection worker dead letter' USING ERRCODE = '22023';
    END IF;
    v_session_tenant := pg_catalog.current_setting('rss.tenant_id', true);
    IF v_session_tenant IS NULL OR v_session_tenant = ''
       OR v_session_tenant::uuid <> p_tenant_id THEN
        RAISE EXCEPTION 'invalid projection worker tenant' USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.projection_input_bindings AS binding
        WHERE binding.generation = p_input_generation
          AND binding.projection_id = p_projection_id
          AND binding.projection_definition_version = p_definition_version
          AND binding.projection_definition_schema_digest = p_definition_schema_digest
    ) THEN
        RAISE EXCEPTION 'invalid projection worker scope' USING ERRCODE = '22023';
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
    )
    ON CONFLICT (tenant_id, source_kind, consumer_group, message_id)
    WHERE source_kind = 'projection'
    DO NOTHING;
END;
$function$;

ALTER FUNCTION public.rss_settings_projection_apply_worker(
    uuid, text, text, text, text, text, text, bigint, text, text, bigint, bigint, bytea
) OWNER TO rss_projection_worker_owner;
ALTER FUNCTION public.rss_settings_projection_apply_operator(
    uuid, text, text, text, text, text, text, bigint, text, text, bigint, bigint, bytea
) OWNER TO rss_projection_operator_owner;
ALTER FUNCTION public.rss_projection_worker_list_tenants(text, text, text, text, text, uuid, integer)
    OWNER TO rss_projection_worker_owner;
ALTER FUNCTION public.rss_projection_worker_quarantine_tenant(
    uuid, text, text, text, text, text, text, bigint
) OWNER TO rss_projection_worker_owner;
ALTER FUNCTION public.rss_projection_worker_has_quarantined_tenants(text, text, text, text, text)
    OWNER TO rss_projection_worker_owner;
ALTER FUNCTION public.rss_projection_operator_recover_tenant(uuid, text, text, bigint)
    OWNER TO rss_projection_operator_owner;
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

REVOKE ALL ON TABLE
    public.projection_events,
    public.projection_input_bindings,
    public.projection_source_capabilities,
    public.checkpoint,
    public.dead_letter,
    public.settings_projection_generations,
    public.settings_config_projection_rows,
    public.settings_projection_dedupe_receipts,
    public.projection_worker_tenant_quarantine,
    public._sqlx_migrations
FROM rss_projection_worker, rss_projection_operator;

GRANT SELECT ON TABLE public.projection_events, public.projection_input_bindings
    TO rss_projection_worker_owner;
GRANT SELECT, INSERT, UPDATE ON TABLE public.checkpoint
    TO rss_projection_worker_owner;
GRANT SELECT, INSERT ON TABLE public.dead_letter
    TO rss_projection_worker_owner;
GRANT SELECT, INSERT, UPDATE ON TABLE
    public.settings_projection_generations,
    public.settings_config_projection_rows,
    public.settings_projection_dedupe_receipts
TO rss_projection_worker_owner;
GRANT SELECT, INSERT, UPDATE ON TABLE public.projection_worker_tenant_quarantine
    TO rss_projection_worker_owner;
GRANT SELECT, UPDATE ON TABLE public.projection_worker_tenant_quarantine
    TO rss_projection_operator_owner;
GRANT EXECUTE ON FUNCTION public.rss_projection_dead_letter_source_kind()
    TO rss_projection_worker_owner;

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

REVOKE ALL ON FUNCTION public.rss_projection_worker_list_tenants(
    text, text, text, text, text, uuid, integer
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator, rss_projection_worker;
GRANT EXECUTE ON FUNCTION public.rss_projection_worker_list_tenants(
    text, text, text, text, text, uuid, integer
) TO rss_projection_worker;
REVOKE ALL ON FUNCTION public.rss_projection_worker_quarantine_tenant(
    uuid, text, text, text, text, text, text, bigint
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator, rss_projection_worker;
GRANT EXECUTE ON FUNCTION public.rss_projection_worker_quarantine_tenant(
    uuid, text, text, text, text, text, text, bigint
) TO rss_projection_worker;
REVOKE ALL ON FUNCTION public.rss_projection_worker_has_quarantined_tenants(
    text, text, text, text, text
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator, rss_projection_worker;
GRANT EXECUTE ON FUNCTION public.rss_projection_worker_has_quarantined_tenants(
    text, text, text, text, text
) TO rss_projection_worker;
REVOKE ALL ON FUNCTION public.rss_projection_operator_recover_tenant(
    uuid, text, text, bigint
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator, rss_projection_worker;
GRANT EXECUTE ON FUNCTION public.rss_projection_operator_recover_tenant(
    uuid, text, text, bigint
) TO rss_projection_operator;
REVOKE ALL ON FUNCTION public.rss_projection_worker_read_events(
    uuid, text, text, text, text, text, bigint, integer
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator, rss_projection_worker;
GRANT EXECUTE ON FUNCTION public.rss_projection_worker_read_events(
    uuid, text, text, text, text, text, bigint, integer
) TO rss_projection_worker;
REVOKE ALL ON FUNCTION public.rss_projection_worker_source_high_water(
    uuid, text, text, text, text, text
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator, rss_projection_worker;
GRANT EXECUTE ON FUNCTION public.rss_projection_worker_source_high_water(
    uuid, text, text, text, text, text
) TO rss_projection_worker;
REVOKE ALL ON FUNCTION public.rss_projection_worker_get_checkpoint(
    uuid, text, text, text, text, text
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator, rss_projection_worker;
GRANT EXECUTE ON FUNCTION public.rss_projection_worker_get_checkpoint(
    uuid, text, text, text, text, text
) TO rss_projection_worker;
REVOKE ALL ON FUNCTION public.rss_projection_worker_save_checkpoint(
    uuid, text, text, text, text, text, bigint, bigint
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator, rss_projection_worker;
GRANT EXECUTE ON FUNCTION public.rss_projection_worker_save_checkpoint(
    uuid, text, text, text, text, text, bigint, bigint
) TO rss_projection_worker;
REVOKE ALL ON FUNCTION public.rss_projection_worker_insert_dead_letter(
    uuid, text, text, text, text, text, text, text, text, text, text, text, jsonb, text, bigint,
    text, bytea, text, integer, text
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator, rss_projection_worker;
GRANT EXECUTE ON FUNCTION public.rss_projection_worker_insert_dead_letter(
    uuid, text, text, text, text, text, text, text, text, text, text, text, jsonb, text, bigint,
    text, bytea, text, integer, text
) TO rss_projection_worker;

REVOKE ALL ON FUNCTION public.rss_projection_operator_record_audit(
    bigint, integer, text, text, text, text, text
) FROM rss_projection_worker;
REVOKE ALL ON FUNCTION public.rss_projection_operator_get_checkpoint(uuid, text, text)
    FROM rss_projection_worker;
REVOKE ALL ON FUNCTION public.rss_projection_operator_save_checkpoint(
    uuid, text, text, bigint, bigint
) FROM rss_projection_worker;
REVOKE ALL ON FUNCTION public.rss_projection_operator_read_active_pointer(uuid, text)
    FROM rss_projection_worker;
REVOKE ALL ON FUNCTION public.rss_projection_operator_cas_active_pointer(
    uuid, text, bytea, bytea, bigint
) FROM rss_projection_worker;
REVOKE ALL ON FUNCTION public.rss_projection_operator_sweep_source_capabilities()
    FROM rss_projection_worker;
REVOKE ALL ON FUNCTION public.rss_projection_operator_issue_source_capability(
    uuid, text, text, text, text
) FROM rss_projection_worker;
REVOKE ALL ON FUNCTION public.rss_projection_operator_insert_dead_letter(
    uuid, text, text, text, text, text, text, jsonb, text, bigint, text, bytea, text, integer, text
) FROM rss_projection_worker;
REVOKE ALL ON FUNCTION public.rss_read_projection_events_scoped(
    uuid, uuid, uuid, text, text, text, text, bigint, integer
) FROM rss_projection_worker;
REVOKE ALL ON FUNCTION public.rss_projection_source_high_water_scoped(
    uuid, uuid, uuid, text, text, text, text
) FROM rss_projection_worker;

GRANT USAGE ON SCHEMA public TO rss_projection_worker;
