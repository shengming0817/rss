-- 0085_projection_privilege_boundaries.sql
--
-- Pre-GA hard cutover for Projection source capabilities. The predecessor migrator wrote one
-- generated, derived registry after applying 0084. Only that exact canonical set may be retired;
-- unknown, missing, or additional rows fail closed. There is no business data to backfill and no
-- old function, role, schema, grant, or binary compatibility after this transaction commits.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

LOCK TABLE public.projection_input_bindings IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.projection_input_bindings LIMIT 1) THEN
        IF (SELECT count(*) FROM public.projection_input_bindings) <> 2
            OR NOT EXISTS (
                SELECT 1
                FROM public.projection_input_bindings
                WHERE generation = 'sha256:c6789652a2531938d416f1097e997fddc6ff74a81e3a636038107ef05162f895'
                  AND contract_id = 'identity.session-created'
                  AND contract_version = 'v1'
                  AND schema_hash = 'sha256:999d2b098e6c89de6d1841416099942cad21279843456dfc287b1fcaa67a7516'
                  AND topic = 'identity.session-created'
            )
            OR NOT EXISTS (
                SELECT 1
                FROM public.projection_input_bindings
                WHERE generation = 'sha256:c6789652a2531938d416f1097e997fddc6ff74a81e3a636038107ef05162f895'
                  AND contract_id = 'settings.config-version-changed'
                  AND contract_version = 'v1'
                  AND schema_hash = 'sha256:b74288de6fd13213cb6676431f4833a7c921ec9ffe2825ad244cad49c52d17e4'
                  AND topic = 'settings.config-version-changed'
            )
        THEN
            RAISE EXCEPTION
                'projection_input_bindings does not match the exact predecessor generated set';
        END IF;
        PERFORM pg_catalog.set_config(
            'rss.projection_registry_retire_generation',
            'sha256:c6789652a2531938d416f1097e997fddc6ff74a81e3a636038107ef05162f895',
            true
        );
        DELETE FROM public.projection_input_bindings
        WHERE generation = 'sha256:c6789652a2531938d416f1097e997fddc6ff74a81e3a636038107ef05162f895';
        PERFORM pg_catalog.set_config('rss.projection_registry_retire_generation', '', true);
    END IF;
END
$$;

ALTER TABLE public.projection_input_bindings
    DROP CONSTRAINT projection_input_bindings_pkey,
    ADD COLUMN projection_id text NOT NULL,
    ADD COLUMN projection_definition_version text NOT NULL,
    ADD COLUMN projection_definition_schema_digest text NOT NULL,
    ADD COLUMN source_domain text NOT NULL,
    ADD CONSTRAINT chk_projection_binding_projection_id
        CHECK (projection_id ~ '^[a-z0-9._-]+$'),
    ADD CONSTRAINT chk_projection_binding_definition_version
        CHECK (projection_definition_version ~ '^[a-z0-9._-]+$'),
    ADD CONSTRAINT chk_projection_binding_definition_schema_digest
        CHECK (projection_definition_schema_digest ~ '^sha256:[0-9a-f]{64}$'),
    ADD CONSTRAINT chk_projection_binding_source_domain
        CHECK (source_domain ~ '^[a-z0-9._-]+$'),
    ADD CONSTRAINT projection_input_bindings_pkey PRIMARY KEY (
        generation,
        projection_id,
        projection_definition_version,
        projection_definition_schema_digest,
        source_domain,
        contract_id,
        contract_version,
        schema_hash,
        topic
    );

DROP FUNCTION public.rss_read_projection_events(bigint, integer);
DROP FUNCTION public.rss_read_projection_input_generation(text);
DROP FUNCTION public.rss_register_projection_input_binding(text, text, text, text, text);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rss_projection_event_writer_owner'
    ) THEN
        CREATE ROLE rss_projection_event_writer_owner
            NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rss_projection_registry_owner'
    ) THEN
        CREATE ROLE rss_projection_registry_owner
            NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rss_projection_source_reader_owner'
    ) THEN
        CREATE ROLE rss_projection_source_reader_owner
            NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rss_projection_operator_owner'
    ) THEN
        CREATE ROLE rss_projection_operator_owner
            NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rss_projection_reader'
    ) THEN
        CREATE ROLE rss_projection_reader
            NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rss_projection_operator'
    ) THEN
        CREATE ROLE rss_projection_operator
            NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
    END IF;
END
$$;

ALTER ROLE rss_projection_event_writer_owner
    NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
ALTER ROLE rss_projection_registry_owner
    NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
ALTER ROLE rss_projection_source_reader_owner
    NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
ALTER ROLE rss_projection_operator_owner
    NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
DO $$
DECLARE
    owner_name text;
    owner_oid oid;
BEGIN
    FOREACH owner_name IN ARRAY ARRAY[
        'rss_projection_event_writer_owner',
        'rss_projection_registry_owner',
        'rss_projection_source_reader_owner',
        'rss_projection_operator_owner'
    ]
    LOOP
        SELECT role.oid INTO STRICT owner_oid
        FROM pg_catalog.pg_roles AS role
        WHERE role.rolname = owner_name;
        IF EXISTS (
            SELECT 1
            FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = owner_oid OR membership.roleid = owner_oid
        ) THEN
            RAISE EXCEPTION '% must have no role memberships', owner_name
                USING ERRCODE = '55000';
        END IF;
    END LOOP;
END
$$;
ALTER ROLE rss_projection_reader SET default_transaction_read_only = on;
ALTER ROLE rss_projection_reader SET search_path = pg_catalog, public;
ALTER ROLE rss_projection_operator SET search_path = pg_catalog, public;

CREATE OR REPLACE FUNCTION public.rss_is_canonical_non_nil_uuid(p_value text)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    parsed uuid;
BEGIN
    IF p_value = '' THEN
        RETURN false;
    END IF;
    parsed := p_value::uuid;
    RETURN parsed::text = p_value
        AND parsed <> '00000000-0000-0000-0000-000000000000'::uuid;
EXCEPTION WHEN invalid_text_representation THEN
    RETURN false;
END;
$$;

CREATE OR REPLACE FUNCTION public.rss_metadata_has_canonical_tenant_id(p_metadata jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    tenant_key CONSTANT text := 'tenantId';
BEGIN
    RETURN pg_catalog.jsonb_typeof(p_metadata) = 'object'
        AND p_metadata ? tenant_key
        AND pg_catalog.jsonb_typeof(p_metadata -> tenant_key) = 'string'
        AND public.rss_is_canonical_non_nil_uuid(p_metadata ->> tenant_key);
END;
$$;

CREATE OR REPLACE FUNCTION public.rss_projection_dead_letter_source_kind()
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT 'projection'::text
$$;

CREATE OR REPLACE FUNCTION public.rss_append_projection_event(
    p_event_id text,
    p_domain text,
    p_aggregate_id text,
    p_event_type text,
    p_payload bytea,
    p_correlation_id text,
    p_contract_id text,
    p_contract_version text,
    p_schema_hash text,
    p_metadata jsonb,
    p_partition_key text,
    p_causation_id text
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    inserted_id bigint;
BEGIN
    IF p_metadata IS NULL
        OR NOT public.rss_metadata_has_canonical_tenant_id(p_metadata)
    THEN
        RAISE EXCEPTION 'projection event metadata must contain canonical non-nil tenantId'
            USING ERRCODE = '22023';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM public.outbox AS outbox_row
        JOIN public.projection_input_bindings AS binding
          ON binding.source_domain = outbox_row.domain
         AND binding.contract_id = outbox_row.contract_id
         AND binding.contract_version = outbox_row.contract_version
         AND binding.schema_hash = outbox_row.schema_hash
         AND binding.topic = outbox_row.topic
        WHERE outbox_row.event_id = p_event_id
          AND outbox_row.domain = p_domain
          AND outbox_row.topic = p_event_type
          AND outbox_row.payload = p_payload
          AND outbox_row.contract_id = p_contract_id
          AND outbox_row.contract_version = p_contract_version
          AND outbox_row.schema_hash = p_schema_hash
          AND outbox_row.metadata = p_metadata
          AND outbox_row.partition_key IS NOT DISTINCT FROM p_partition_key
          AND outbox_row.causation_id IS NOT DISTINCT FROM p_causation_id
          AND COALESCE(outbox_row.partition_key, outbox_row.event_id) = p_aggregate_id
          AND p_correlation_id IS NOT DISTINCT FROM p_causation_id
    ) THEN
        RAISE EXCEPTION 'projection event append must match a generated-bound outbox row'
            USING ERRCODE = '42501';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('rss.projection_events.append', 0)
    );

    INSERT INTO public.projection_events (
        event_id, domain, aggregate_id, event_type, payload, correlation_id,
        contract_id, contract_version, schema_hash, metadata, partition_key, causation_id
    ) VALUES (
        p_event_id, p_domain, p_aggregate_id, p_event_type, p_payload, p_correlation_id,
        p_contract_id, p_contract_version, p_schema_hash, p_metadata, p_partition_key,
        p_causation_id
    )
    ON CONFLICT (event_id) DO NOTHING
    RETURNING id INTO inserted_id;

    IF inserted_id IS NULL THEN
        SELECT event.id INTO inserted_id
        FROM public.projection_events AS event
        WHERE event.event_id = p_event_id;
    END IF;
    RETURN inserted_id;
END;
$$;

CREATE FUNCTION public.rss_register_projection_input_binding(
    p_generation text,
    p_projection_id text,
    p_projection_definition_version text,
    p_projection_definition_schema_digest text,
    p_source_domain text,
    p_contract_id text,
    p_contract_version text,
    p_schema_hash text,
    p_topic text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF p_generation IS NULL OR p_generation !~ '^sha256:[0-9a-f]{64}$'
        OR p_projection_id IS NULL OR p_projection_id !~ '^[a-z0-9._-]+$'
        OR p_projection_definition_version IS NULL
        OR p_projection_definition_version !~ '^[a-z0-9._-]+$'
        OR p_projection_definition_schema_digest IS NULL
        OR p_projection_definition_schema_digest !~ '^sha256:[0-9a-f]{64}$'
        OR p_source_domain IS NULL OR p_source_domain !~ '^[a-z0-9._-]+$'
        OR p_contract_id IS NULL OR p_contract_id !~ '^[a-z0-9._-]+$'
        OR p_contract_version IS NULL OR p_contract_version !~ '^[a-z0-9._-]+$'
        OR p_schema_hash IS NULL OR p_schema_hash !~ '^sha256:[0-9a-f]{64}$'
        OR p_topic IS NULL OR p_topic !~ '^[a-z0-9._-]+$'
    THEN
        RAISE EXCEPTION 'invalid projection input binding' USING ERRCODE = '22023';
    END IF;

    INSERT INTO public.projection_input_bindings (
        generation, projection_id, projection_definition_version,
        projection_definition_schema_digest, source_domain, contract_id,
        contract_version, schema_hash, topic
    ) VALUES (
        p_generation, p_projection_id, p_projection_definition_version,
        p_projection_definition_schema_digest, p_source_domain, p_contract_id,
        p_contract_version, p_schema_hash, p_topic
    )
    ON CONFLICT DO NOTHING;
END;
$$;

CREATE OR REPLACE FUNCTION public.rss_guard_projection_input_delete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF pg_catalog.current_setting('rss.projection_registry_retire_generation', true)
        IS DISTINCT FROM OLD.generation
    THEN
        RAISE EXCEPTION 'projection input bindings may only be retired by exact generation'
            USING ERRCODE = '42501';
    END IF;
    RETURN OLD;
END;
$$;

CREATE OR REPLACE FUNCTION public.rss_retire_projection_input_generation(p_generation text)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    deleted_count bigint;
BEGIN
    IF p_generation IS NULL OR p_generation !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid projection input generation' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_catalog.set_config('rss.projection_registry_retire_generation', p_generation, true);
    DELETE FROM public.projection_input_bindings AS binding
    WHERE binding.generation = p_generation;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    PERFORM pg_catalog.set_config('rss.projection_registry_retire_generation', '', true);
    RETURN deleted_count;
END;
$$;

CREATE FUNCTION public.rss_read_projection_input_generation(p_generation text)
RETURNS TABLE (
    projection_id text,
    projection_definition_version text,
    projection_definition_schema_digest text,
    source_domain text,
    contract_id text,
    contract_version text,
    schema_hash text,
    topic text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF p_generation IS NULL OR p_generation !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid projection input generation' USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
    SELECT binding.projection_id,
           binding.projection_definition_version,
           binding.projection_definition_schema_digest,
           binding.source_domain,
           binding.contract_id,
           binding.contract_version,
           binding.schema_hash,
           binding.topic
    FROM public.projection_input_bindings AS binding
    WHERE binding.generation = p_generation
    ORDER BY binding.projection_id,
             binding.projection_definition_version,
             binding.projection_definition_schema_digest,
             binding.source_domain,
             binding.contract_id,
             binding.contract_version,
             binding.schema_hash,
             binding.topic;
END;
$$;

CREATE FUNCTION public.rss_read_projection_events_scoped(
    p_tenant_id uuid,
    p_projection_id text,
    p_definition_version text,
    p_definition_schema_digest text,
    p_input_generation text,
    p_after bigint,
    p_limit integer
)
RETURNS TABLE (
    id bigint,
    event_id text,
    domain text,
    aggregate_id text,
    event_type text,
    payload bytea,
    contract_id text,
    contract_version text,
    schema_hash text,
    metadata jsonb,
    partition_key text,
    causation_id text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF p_tenant_id IS NULL
        OR p_tenant_id = '00000000-0000-0000-0000-000000000000'::uuid
        OR p_projection_id IS NULL OR p_projection_id !~ '^[a-z0-9._-]+$'
        OR p_definition_version IS NULL OR p_definition_version !~ '^[a-z0-9._-]+$'
        OR p_definition_schema_digest IS NULL
        OR p_definition_schema_digest !~ '^sha256:[0-9a-f]{64}$'
        OR p_input_generation IS NULL OR p_input_generation !~ '^sha256:[0-9a-f]{64}$'
        OR p_after IS NULL OR p_after < 0
        OR p_limit IS NULL OR p_limit < 1 OR p_limit > 1000
    THEN
        RAISE EXCEPTION 'invalid projection source scope' USING ERRCODE = '22023';
    END IF;

    RETURN QUERY
    SELECT event.id,
           event.event_id,
           event.domain,
           event.aggregate_id,
           event.event_type,
           event.payload,
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
          FROM public.projection_input_bindings AS binding
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
$$;

CREATE FUNCTION public.rss_projection_operator_record_audit(
    p_occurred_at_secs bigint,
    p_occurred_at_nanos integer,
    p_operator_subject text,
    p_resource_id text,
    p_action text,
    p_outcome text,
    p_failure_reason text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF p_occurred_at_secs < 0
        OR p_occurred_at_nanos < 0 OR p_occurred_at_nanos >= 1000000000
        OR p_operator_subject IS NULL OR p_operator_subject = ''
        OR p_resource_id IS NULL OR p_resource_id = ''
        OR p_action IS NULL OR p_action !~ '^projection\.[a-z]+\.(start|finish)$'
        OR p_outcome NOT IN ('success', 'failure')
        OR ((p_outcome = 'failure') IS DISTINCT FROM (p_failure_reason IS NOT NULL))
    THEN
        RAISE EXCEPTION 'invalid projection operator audit record' USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.auth_audit_events (
        occurred_at_secs, occurred_at_nanos, principal_id, principal_kind, tenant_context,
        resource_kind, resource_id, action, outcome, failure_reason, request_id, correlation_id
    ) VALUES (
        p_occurred_at_secs, p_occurred_at_nanos, p_operator_subject, 'service', NULL,
        'projection.maintenance', p_resource_id, p_action, p_outcome, p_failure_reason, NULL, NULL
    );
END;
$$;

CREATE FUNCTION public.rss_projection_operator_get_checkpoint(
    p_tenant_id uuid,
    p_projection_id text,
    p_version text
)
RETURNS TABLE (offset_lsn bigint, version bigint)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF p_tenant_id IS NULL
        OR p_tenant_id = '00000000-0000-0000-0000-000000000000'::uuid
        OR p_projection_id IS NULL OR p_projection_id !~ '^[a-z0-9._-]+$'
        OR p_version IS NULL OR p_version !~ '^[a-z0-9._-]+$'
    THEN
        RAISE EXCEPTION 'invalid projection checkpoint scope' USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
    SELECT checkpoint.offset_lsn, checkpoint.version
    FROM public.checkpoint
    WHERE checkpoint.owner = 'projection:' || p_tenant_id::text
      AND checkpoint.checkpoint_id = p_projection_id || '@' || p_version || ':shadow';
END;
$$;

CREATE FUNCTION public.rss_projection_operator_save_checkpoint(
    p_tenant_id uuid,
    p_projection_id text,
    p_version text,
    p_offset_lsn bigint,
    p_expected_version bigint
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    changed bigint;
    v_checkpoint_owner text;
    v_checkpoint_id text;
BEGIN
    IF p_tenant_id IS NULL
        OR p_tenant_id = '00000000-0000-0000-0000-000000000000'::uuid
        OR p_projection_id IS NULL OR p_projection_id !~ '^[a-z0-9._-]+$'
        OR p_version IS NULL OR p_version !~ '^[a-z0-9._-]+$'
        OR p_offset_lsn < 0 OR p_expected_version < 0
    THEN
        RAISE EXCEPTION 'invalid projection checkpoint mutation' USING ERRCODE = '22023';
    END IF;
    v_checkpoint_owner := 'projection:' || p_tenant_id::text;
    v_checkpoint_id := p_projection_id || '@' || p_version || ':shadow';
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
$$;

CREATE FUNCTION public.rss_projection_operator_read_active_pointer(
    p_tenant_id uuid,
    p_projection_id text
)
RETURNS TABLE (value bytea, token bigint)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF p_tenant_id IS NULL
        OR p_tenant_id = '00000000-0000-0000-0000-000000000000'::uuid
        OR p_projection_id IS NULL OR p_projection_id !~ '^[a-z0-9._-]+$'
    THEN
        RAISE EXCEPTION 'invalid projection pointer scope' USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
    SELECT pointer.value, pointer.token
    FROM public.distributed_cas AS pointer
    WHERE pointer.cas_key = 'projection-active/' || p_tenant_id::text || '/' || p_projection_id;
END;
$$;

CREATE FUNCTION public.rss_projection_operator_cas_active_pointer(
    p_tenant_id uuid,
    p_projection_id text,
    p_expected_value bytea,
    p_new_value bytea,
    p_expected_token bigint
)
RETURNS TABLE (outcome text, current_value bytea, result_token bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    pointer_key text;
    stored_value bytea;
    stored_token bigint;
    next_token bigint;
BEGIN
    IF p_tenant_id IS NULL
        OR p_tenant_id = '00000000-0000-0000-0000-000000000000'::uuid
        OR p_projection_id IS NULL OR p_projection_id !~ '^[a-z0-9._-]+$'
        OR p_new_value IS NULL
        OR (p_expected_token IS NOT NULL AND p_expected_token < 1)
    THEN
        RAISE EXCEPTION 'invalid projection pointer mutation' USING ERRCODE = '22023';
    END IF;
    pointer_key := 'projection-active/' || p_tenant_id::text || '/' || p_projection_id;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(pointer_key, 0));
    SELECT pointer.value, pointer.token INTO stored_value, stored_token
    FROM public.distributed_cas AS pointer
    WHERE pointer.cas_key = pointer_key;

    IF NOT FOUND THEN
        IF p_expected_value IS NOT NULL OR p_expected_token IS NOT NULL THEN
            RETURN QUERY SELECT 'conflict'::text, NULL::bytea, NULL::bigint;
            RETURN;
        END IF;
        INSERT INTO public.distributed_cas (cas_key, value, token)
        VALUES (pointer_key, p_new_value, 1);
        RETURN QUERY SELECT 'applied'::text, NULL::bytea, 1::bigint;
        RETURN;
    END IF;
    IF p_expected_token IS DISTINCT FROM stored_token THEN
        RETURN QUERY SELECT 'fenced'::text, NULL::bytea, stored_token;
        RETURN;
    END IF;
    IF p_expected_value IS NULL OR p_expected_value <> stored_value THEN
        RETURN QUERY SELECT 'conflict'::text, stored_value, stored_token;
        RETURN;
    END IF;
    next_token := stored_token + 1;
    IF next_token < 1 THEN
        RAISE EXCEPTION 'projection pointer token overflow' USING ERRCODE = '22003';
    END IF;
    UPDATE public.distributed_cas
    SET value = p_new_value, token = next_token, updated_at = pg_catalog.now()
    WHERE cas_key = pointer_key;
    RETURN QUERY SELECT 'applied'::text, NULL::bytea, next_token;
END;
$$;

CREATE FUNCTION public.rss_projection_operator_insert_dead_letter(
    p_tenant_id uuid,
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
AS $$
BEGIN
    IF p_tenant_id IS NULL
        OR p_tenant_id = '00000000-0000-0000-0000-000000000000'::uuid
        OR p_source_kind <> 'projection'
        OR p_payload_len < 0 OR p_num_attempts < 0
        OR p_replay_capsule_encoding <> 'key-provider-v3'
    THEN
        RAISE EXCEPTION 'invalid projection dead letter' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_catalog.set_config('rss.tenant_id', p_tenant_id::text, true);
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
$$;

-- PostgreSQL grants EXECUTE on newly created functions to PUBLIC by default. Projection roles
-- cannot be function-only while that ambient authority exists, so remove it globally at this
-- pre-GA cutover; every supported caller keeps or receives an explicit grant below.
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

ALTER FUNCTION public.rss_is_canonical_non_nil_uuid(text)
    OWNER TO rss_projection_event_writer_owner;
ALTER FUNCTION public.rss_metadata_has_canonical_tenant_id(jsonb)
    OWNER TO rss_projection_event_writer_owner;
ALTER FUNCTION public.rss_projection_dead_letter_source_kind()
    OWNER TO rss_projection_event_writer_owner;
ALTER FUNCTION public.rss_append_projection_event(
    text, text, text, text, bytea, text, text, text, text, jsonb, text, text
) OWNER TO rss_projection_event_writer_owner;
ALTER FUNCTION public.rss_register_projection_input_binding(
    text, text, text, text, text, text, text, text, text
) OWNER TO rss_projection_registry_owner;
ALTER FUNCTION public.rss_guard_projection_input_delete()
    OWNER TO rss_projection_registry_owner;
ALTER FUNCTION public.rss_retire_projection_input_generation(text)
    OWNER TO rss_projection_registry_owner;
ALTER FUNCTION public.rss_read_projection_input_generation(text)
    OWNER TO rss_projection_source_reader_owner;
ALTER FUNCTION public.rss_read_projection_events_scoped(
    uuid, text, text, text, text, bigint, integer
) OWNER TO rss_projection_source_reader_owner;
ALTER FUNCTION public.rss_projection_operator_record_audit(
    bigint, integer, text, text, text, text, text
) OWNER TO rss_projection_operator_owner;
ALTER FUNCTION public.rss_projection_operator_get_checkpoint(uuid, text, text)
    OWNER TO rss_projection_operator_owner;
ALTER FUNCTION public.rss_projection_operator_save_checkpoint(uuid, text, text, bigint, bigint)
    OWNER TO rss_projection_operator_owner;
ALTER FUNCTION public.rss_projection_operator_read_active_pointer(uuid, text)
    OWNER TO rss_projection_operator_owner;
ALTER FUNCTION public.rss_projection_operator_cas_active_pointer(uuid, text, bytea, bytea, bigint)
    OWNER TO rss_projection_operator_owner;
ALTER FUNCTION public.rss_projection_operator_insert_dead_letter(
    uuid, text, text, text, text, text, text, jsonb, text, bigint, text, bytea, text, integer, text
) OWNER TO rss_projection_operator_owner;

REVOKE ALL ON TABLE public.projection_events FROM
    PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator,
    rss_projection_events_runtime;
REVOKE ALL ON TABLE public.projection_input_bindings FROM
    PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator,
    rss_projection_events_runtime;
REVOKE ALL ON TABLE public.outbox FROM
    rss_projection_event_writer_owner, rss_projection_source_reader_owner,
    rss_projection_registry_owner, rss_projection_operator_owner,
    rss_projection_reader, rss_projection_operator, rss_projection_events_runtime;
REVOKE ALL ON SEQUENCE public.projection_events_id_seq FROM
    PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator,
    rss_projection_events_runtime;
REVOKE ALL ON TABLE public.auth_audit_events, public.checkpoint,
    public.distributed_cas, public.dead_letter FROM rss_projection_operator;
REVOKE ALL ON SEQUENCE public.auth_audit_events_id_seq FROM rss_projection_operator;

GRANT SELECT, INSERT ON TABLE public.projection_events TO rss_projection_event_writer_owner;
GRANT USAGE, SELECT ON SEQUENCE public.projection_events_id_seq
    TO rss_projection_event_writer_owner;
GRANT SELECT ON TABLE public.projection_input_bindings, public.outbox
    TO rss_projection_event_writer_owner;
GRANT SELECT, INSERT, DELETE ON TABLE public.projection_input_bindings
    TO rss_projection_registry_owner;
GRANT SELECT ON TABLE public.projection_events, public.projection_input_bindings
    TO rss_projection_source_reader_owner;
GRANT INSERT ON TABLE public.auth_audit_events TO rss_projection_operator_owner;
GRANT USAGE, SELECT ON SEQUENCE public.auth_audit_events_id_seq
    TO rss_projection_operator_owner;
GRANT SELECT, INSERT, UPDATE ON TABLE public.checkpoint, public.distributed_cas
    TO rss_projection_operator_owner;
GRANT INSERT ON TABLE public.dead_letter TO rss_projection_operator_owner;

REVOKE ALL ON FUNCTION public.rss_is_canonical_non_nil_uuid(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rss_metadata_has_canonical_tenant_id(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rss_append_projection_event(
    text, text, text, text, bytea, text, text, text, text, jsonb, text, text
) FROM PUBLIC, rss_app_read, rss_projection_reader, rss_projection_operator;
REVOKE ALL ON FUNCTION public.rss_register_projection_input_binding(
    text, text, text, text, text, text, text, text, text
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator;
REVOKE ALL ON FUNCTION public.rss_retire_projection_input_generation(text)
    FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader, rss_projection_operator;
REVOKE ALL ON FUNCTION public.rss_read_projection_input_generation(text)
    FROM PUBLIC, rss_app_read, rss_projection_reader, rss_projection_operator;
REVOKE ALL ON FUNCTION public.rss_read_projection_events_scoped(
    uuid, text, text, text, text, bigint, integer
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_operator;
REVOKE ALL ON FUNCTION public.rss_projection_operator_record_audit(
    bigint, integer, text, text, text, text, text
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader;
REVOKE ALL ON FUNCTION public.rss_projection_operator_get_checkpoint(uuid, text, text)
    FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader;
REVOKE ALL ON FUNCTION public.rss_projection_operator_save_checkpoint(
    uuid, text, text, bigint, bigint
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader;
REVOKE ALL ON FUNCTION public.rss_projection_operator_read_active_pointer(uuid, text)
    FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader;
REVOKE ALL ON FUNCTION public.rss_projection_operator_cas_active_pointer(
    uuid, text, bytea, bytea, bigint
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader;
REVOKE ALL ON FUNCTION public.rss_projection_operator_insert_dead_letter(
    uuid, text, text, text, text, text, text, jsonb, text, bigint, text, bytea, text, integer, text
) FROM PUBLIC, rss_app, rss_app_read, rss_projection_reader;

GRANT EXECUTE ON FUNCTION public.rss_append_projection_event(
    text, text, text, text, bytea, text, text, text, text, jsonb, text, text
) TO rss_app;
GRANT EXECUTE ON FUNCTION public.rss_read_projection_input_generation(text) TO rss_app;
GRANT EXECUTE ON FUNCTION public.rss_read_projection_events_scoped(
    uuid, text, text, text, text, bigint, integer
) TO rss_projection_reader;
GRANT SELECT ON TABLE public._sqlx_migrations TO rss_projection_reader;
GRANT SELECT ON TABLE public._sqlx_migrations TO rss_projection_operator;
GRANT EXECUTE ON FUNCTION public.rss_service_token_replay_check_and_record(bytea, timestamptz)
    TO rss_projection_operator;
GRANT EXECUTE ON FUNCTION public.rss_projection_operator_record_audit(
    bigint, integer, text, text, text, text, text
) TO rss_projection_operator;
GRANT EXECUTE ON FUNCTION public.rss_projection_operator_get_checkpoint(uuid, text, text)
    TO rss_projection_operator;
GRANT EXECUTE ON FUNCTION public.rss_projection_operator_save_checkpoint(
    uuid, text, text, bigint, bigint
) TO rss_projection_operator;
GRANT EXECUTE ON FUNCTION public.rss_projection_operator_read_active_pointer(uuid, text)
    TO rss_projection_operator;
GRANT EXECUTE ON FUNCTION public.rss_projection_operator_cas_active_pointer(
    uuid, text, bytea, bytea, bigint
) TO rss_projection_operator;
GRANT EXECUTE ON FUNCTION public.rss_projection_operator_insert_dead_letter(
    uuid, text, text, text, text, text, text, jsonb, text, bigint, text, bytea, text, integer, text
) TO rss_projection_operator;
GRANT USAGE ON SCHEMA public TO rss_projection_reader, rss_projection_operator;

DO $$
DECLARE
    migration_role name := current_user;
BEGIN
    EXECUTE pg_catalog.format(
        'GRANT EXECUTE ON FUNCTION public.rss_register_projection_input_binding(text, text, text, text, text, text, text, text, text) TO %I',
        migration_role
    );
    EXECUTE pg_catalog.format(
        'GRANT EXECUTE ON FUNCTION public.rss_retire_projection_input_generation(text) TO %I',
        migration_role
    );
END
$$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_depend AS dependency
        JOIN pg_catalog.pg_roles AS role ON role.oid = dependency.refobjid
        WHERE role.rolname = 'rss_projection_events_runtime'
          AND dependency.deptype = 'o'
    ) THEN
        RAISE EXCEPTION 'rss_projection_events_runtime still owns database objects';
    END IF;
END
$$;

DROP ROLE rss_projection_events_runtime;
