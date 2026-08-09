-- 0088_projection_scoped_high_water.sql
--
-- Hard-cut Projection source reads to a fixed-cost scope whose tenant authority is independently
-- verifiable by PostgreSQL.  The reader credential never receives the capability catalog, issuer,
-- or assertion helper; it receives only the two fixed read functions and presents an opaque
-- 256-bit token whose SHA-256 digest is stored at rest.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

-- Single-use capability consumption is the only mutation reachable by this otherwise
-- function-only login. A role-level read-only default would reject the SECURITY DEFINER DELETE.
ALTER ROLE rss_projection_reader RESET default_transaction_read_only;

DROP FUNCTION public.rss_read_projection_events_scoped(
    uuid, text, text, text, text, bigint, integer
);

CREATE INDEX idx_projection_events_scoped_tail
ON public.projection_events (
    domain,
    contract_id,
    contract_version,
    schema_hash,
    event_type,
    (metadata ->> 'tenantId'),
    id DESC NULLS LAST
);

CREATE TABLE public.projection_source_capabilities (
    capability_digest bytea PRIMARY KEY,
    scope_tenant_id uuid NOT NULL,
    projection_id text NOT NULL,
    projection_definition_version text NOT NULL,
    projection_definition_schema_digest text NOT NULL,
    input_generation text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT chk_projection_source_capability_digest
        CHECK (pg_catalog.octet_length(capability_digest) = 32),
    CONSTRAINT chk_projection_source_capability_projection_id
        CHECK (projection_id ~ '^[a-z0-9._-]+$'),
    CONSTRAINT chk_projection_source_capability_definition_version
        CHECK (projection_definition_version ~ '^[a-z0-9._-]+$'),
    CONSTRAINT chk_projection_source_capability_definition_digest
        CHECK (projection_definition_schema_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT chk_projection_source_capability_input_generation
        CHECK (input_generation ~ '^sha256:[0-9a-f]{64}$')
);

CREATE INDEX idx_projection_source_capabilities_expiry
ON public.projection_source_capabilities (expires_at, capability_digest);

ALTER TABLE public.projection_source_capabilities
    OWNER TO rss_projection_source_reader_owner;
REVOKE ALL ON TABLE public.projection_source_capabilities FROM PUBLIC,
    rss_app, rss_app_read, rss_projection_reader, rss_projection_operator,
    rss_projection_event_writer_owner;
GRANT SELECT, INSERT, DELETE ON TABLE public.projection_source_capabilities
    TO rss_projection_operator_owner;

CREATE FUNCTION public.rss_assert_projection_source_scope(
    p_require_capability boolean,
    p_capability_first uuid,
    p_capability_second uuid,
    p_tenant_id uuid,
    p_projection_id text,
    p_definition_version text,
    p_definition_schema_digest text,
    p_input_generation text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    actual_input_generation text;
    expected_capability_digest bytea;
    consumed_digest bytea;
BEGIN
    IF p_require_capability IS NULL
        OR (p_require_capability AND (
            p_capability_first IS NULL OR p_capability_second IS NULL
        ))
        OR p_tenant_id IS NULL
        OR p_tenant_id = '00000000-0000-0000-0000-000000000000'::uuid
        OR p_projection_id IS NULL OR p_projection_id !~ '^[a-z0-9._-]+$'
        OR p_definition_version IS NULL OR p_definition_version !~ '^[a-z0-9._-]+$'
        OR p_definition_schema_digest IS NULL
        OR p_definition_schema_digest !~ '^sha256:[0-9a-f]{64}$'
        OR p_input_generation IS NULL OR p_input_generation !~ '^sha256:[0-9a-f]{64}$'
    THEN
        RAISE EXCEPTION 'invalid projection source scope' USING ERRCODE = '22023';
    END IF;

    IF p_require_capability THEN
        expected_capability_digest := pg_catalog.sha256(
            pg_catalog.uuid_send(p_capability_first)
            || pg_catalog.uuid_send(p_capability_second)
        );
    END IF;
    IF p_require_capability THEN
        DELETE FROM public.projection_source_capabilities AS capability
        WHERE capability.capability_digest = expected_capability_digest
          AND capability.scope_tenant_id = p_tenant_id
          AND capability.projection_id = p_projection_id
          AND capability.projection_definition_version = p_definition_version
          AND capability.projection_definition_schema_digest = p_definition_schema_digest
          AND capability.input_generation = p_input_generation
          AND capability.expires_at > pg_catalog.clock_timestamp()
        RETURNING capability.capability_digest INTO consumed_digest;
        IF consumed_digest IS NULL THEN
            RAISE EXCEPTION 'invalid projection source scope' USING ERRCODE = '22023';
        END IF;
    END IF;

    SELECT 'sha256:' || pg_catalog.encode(
        pg_catalog.sha256(
            pg_catalog.string_agg(
                pg_catalog.int8send(
                    pg_catalog.octet_length(
                        pg_catalog.convert_to(binding.projection_id, 'UTF8')
                    )::bigint
                ) || pg_catalog.convert_to(binding.projection_id, 'UTF8')
                || pg_catalog.int8send(
                    pg_catalog.octet_length(
                        pg_catalog.convert_to(binding.projection_definition_version, 'UTF8')
                    )::bigint
                ) || pg_catalog.convert_to(binding.projection_definition_version, 'UTF8')
                || pg_catalog.int8send(
                    pg_catalog.octet_length(
                        pg_catalog.convert_to(binding.projection_definition_schema_digest, 'UTF8')
                    )::bigint
                ) || pg_catalog.convert_to(binding.projection_definition_schema_digest, 'UTF8')
                || pg_catalog.int8send(
                    pg_catalog.octet_length(
                        pg_catalog.convert_to(binding.source_domain, 'UTF8')
                    )::bigint
                ) || pg_catalog.convert_to(binding.source_domain, 'UTF8')
                || pg_catalog.int8send(
                    pg_catalog.octet_length(
                        pg_catalog.convert_to(binding.contract_id, 'UTF8')
                    )::bigint
                ) || pg_catalog.convert_to(binding.contract_id, 'UTF8')
                || pg_catalog.int8send(
                    pg_catalog.octet_length(
                        pg_catalog.convert_to(binding.contract_version, 'UTF8')
                    )::bigint
                ) || pg_catalog.convert_to(binding.contract_version, 'UTF8')
                || pg_catalog.int8send(
                    pg_catalog.octet_length(
                        pg_catalog.convert_to(binding.schema_hash, 'UTF8')
                    )::bigint
                ) || pg_catalog.convert_to(binding.schema_hash, 'UTF8')
                || pg_catalog.int8send(
                    pg_catalog.octet_length(
                        pg_catalog.convert_to(binding.topic, 'UTF8')
                    )::bigint
                ) || pg_catalog.convert_to(binding.topic, 'UTF8'),
                ''::bytea
                ORDER BY pg_catalog.convert_to(binding.projection_id, 'UTF8'),
                         pg_catalog.convert_to(binding.projection_definition_version, 'UTF8'),
                         pg_catalog.convert_to(
                             binding.projection_definition_schema_digest, 'UTF8'
                         ),
                         pg_catalog.convert_to(binding.source_domain, 'UTF8'),
                         pg_catalog.convert_to(binding.contract_id, 'UTF8'),
                         pg_catalog.convert_to(binding.contract_version, 'UTF8'),
                         pg_catalog.convert_to(binding.schema_hash, 'UTF8'),
                         pg_catalog.convert_to(binding.topic, 'UTF8')
            )
        ),
        'hex'
    )
    INTO actual_input_generation
    FROM public.projection_input_bindings AS binding
    WHERE binding.generation = p_input_generation;

    IF actual_input_generation IS DISTINCT FROM p_input_generation
        OR NOT EXISTS (
            SELECT 1
            FROM public.projection_input_bindings AS binding
            WHERE binding.generation = p_input_generation
              AND binding.projection_id = p_projection_id
              AND binding.projection_definition_version = p_definition_version
              AND binding.projection_definition_schema_digest = p_definition_schema_digest
        )
    THEN
        RAISE EXCEPTION 'invalid projection source scope' USING ERRCODE = '22023';
    END IF;
END;
$$;

CREATE FUNCTION public.rss_projection_operator_sweep_source_capabilities()
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    swept bigint;
BEGIN
    WITH expired AS (
        SELECT capability.capability_digest
        FROM public.projection_source_capabilities AS capability
        WHERE capability.expires_at <= pg_catalog.clock_timestamp()
        ORDER BY capability.expires_at, capability.capability_digest
        LIMIT 1000
    ), deleted AS (
        DELETE FROM public.projection_source_capabilities AS capability
        USING expired
        WHERE capability.capability_digest = expired.capability_digest
        RETURNING 1
    )
    SELECT count(*)::bigint INTO swept FROM deleted;
    RETURN swept;
END;
$$;

CREATE FUNCTION public.rss_projection_operator_issue_source_capability(
    p_tenant_id uuid,
    p_projection_id text,
    p_definition_version text,
    p_definition_schema_digest text,
    p_input_generation text
)
RETURNS TABLE (capability_first uuid, capability_second uuid)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    issued_first uuid := pg_catalog.gen_random_uuid();
    issued_second uuid := pg_catalog.gen_random_uuid();
BEGIN
    PERFORM public.rss_projection_operator_sweep_source_capabilities();
    PERFORM public.rss_assert_projection_source_scope(
        false, NULL, NULL, p_tenant_id, p_projection_id,
        p_definition_version, p_definition_schema_digest, p_input_generation
    );
    INSERT INTO public.projection_source_capabilities (
        capability_digest, scope_tenant_id, projection_id, projection_definition_version,
        projection_definition_schema_digest, input_generation, expires_at
    ) VALUES (
        pg_catalog.sha256(
            pg_catalog.uuid_send(issued_first) || pg_catalog.uuid_send(issued_second)
        ),
        p_tenant_id, p_projection_id, p_definition_version,
        p_definition_schema_digest, p_input_generation,
        pg_catalog.clock_timestamp() + interval '30 seconds'
    );
    RETURN QUERY SELECT issued_first, issued_second;
END;
$$;

CREATE FUNCTION public.rss_read_projection_events_scoped(
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
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
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
$$;

CREATE FUNCTION public.rss_projection_source_high_water_scoped(
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
AS $$
DECLARE
    high_water bigint;
    binding_high_water bigint;
    binding_row record;
BEGIN
    PERFORM public.rss_assert_projection_source_scope(
        true, p_capability_first, p_capability_second, p_tenant_id, p_projection_id,
        p_definition_version, p_definition_schema_digest, p_input_generation
    );

    FOR binding_row IN
        SELECT binding.source_domain,
               binding.contract_id,
               binding.contract_version,
               binding.schema_hash,
               binding.topic
        FROM public.projection_input_bindings AS binding
        WHERE binding.generation = p_input_generation
          AND binding.projection_id = p_projection_id
          AND binding.projection_definition_version = p_definition_version
          AND binding.projection_definition_schema_digest = p_definition_schema_digest
    LOOP
        SELECT event.id
        INTO binding_high_water
        FROM public.projection_events AS event
        WHERE event.metadata ->> 'tenantId' = p_tenant_id::text
          AND event.domain = binding_row.source_domain
          AND event.contract_id = binding_row.contract_id
          AND event.contract_version = binding_row.contract_version
          AND event.schema_hash = binding_row.schema_hash
          AND event.event_type = binding_row.topic
        ORDER BY event.id DESC NULLS LAST
        LIMIT 1;

        IF binding_high_water IS NOT NULL
            AND (high_water IS NULL OR binding_high_water > high_water)
        THEN
            high_water := binding_high_water;
        END IF;
    END LOOP;

    RETURN high_water;
END;
$$;

ALTER FUNCTION public.rss_assert_projection_source_scope(
    boolean, uuid, uuid, uuid, text, text, text, text
) OWNER TO rss_projection_source_reader_owner;
ALTER FUNCTION public.rss_projection_operator_sweep_source_capabilities()
    OWNER TO rss_projection_operator_owner;
ALTER FUNCTION public.rss_projection_operator_issue_source_capability(
    uuid, text, text, text, text
) OWNER TO rss_projection_operator_owner;
ALTER FUNCTION public.rss_read_projection_events_scoped(
    uuid, uuid, uuid, text, text, text, text, bigint, integer
) OWNER TO rss_projection_source_reader_owner;
ALTER FUNCTION public.rss_projection_source_high_water_scoped(
    uuid, uuid, uuid, text, text, text, text
) OWNER TO rss_projection_source_reader_owner;

REVOKE ALL ON FUNCTION public.rss_assert_projection_source_scope(
    boolean, uuid, uuid, uuid, text, text, text, text
) FROM PUBLIC, rss_projection_reader, rss_projection_operator;
REVOKE ALL ON FUNCTION public.rss_projection_operator_sweep_source_capabilities()
    FROM PUBLIC, rss_projection_reader;
REVOKE ALL ON FUNCTION public.rss_projection_operator_issue_source_capability(
    uuid, text, text, text, text
) FROM PUBLIC, rss_projection_reader;
REVOKE ALL ON FUNCTION public.rss_read_projection_events_scoped(
    uuid, uuid, uuid, text, text, text, text, bigint, integer
) FROM PUBLIC, rss_projection_operator;
REVOKE ALL ON FUNCTION public.rss_projection_source_high_water_scoped(
    uuid, uuid, uuid, text, text, text, text
) FROM PUBLIC, rss_projection_operator;

GRANT EXECUTE ON FUNCTION public.rss_assert_projection_source_scope(
    boolean, uuid, uuid, uuid, text, text, text, text
) TO rss_projection_operator_owner;
GRANT EXECUTE ON FUNCTION public.rss_projection_operator_sweep_source_capabilities()
    TO rss_projection_operator;
GRANT EXECUTE ON FUNCTION public.rss_projection_operator_issue_source_capability(
    uuid, text, text, text, text
) TO rss_projection_operator;
GRANT EXECUTE ON FUNCTION public.rss_read_projection_events_scoped(
    uuid, uuid, uuid, text, text, text, text, bigint, integer
) TO rss_projection_reader;
GRANT EXECUTE ON FUNCTION public.rss_projection_source_high_water_scoped(
    uuid, uuid, uuid, text, text, text, text
) TO rss_projection_reader;
