-- 0040_projection_events_funnel_and_projection_dlx.sql
--
-- Projection events are now written only through the outbox writer funnel and fixed
-- SECURITY DEFINER functions. This is a pre-GA breaking schema cut: existing rows from the
-- old naked append shape are rejected instead of backfilled.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM projection_events LIMIT 1) THEN
        RAISE EXCEPTION 'projection_events must be empty before enabling projection writer funnel';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION rss_is_canonical_non_nil_uuid(p_value text)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = public, pg_temp
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

CREATE OR REPLACE FUNCTION rss_metadata_has_canonical_tenant_id(p_metadata jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = public, pg_temp
AS $$
DECLARE
    tenant_key CONSTANT text := 'tenantId';
BEGIN
    RETURN jsonb_typeof(p_metadata) = 'object'
        AND p_metadata ? tenant_key
        AND jsonb_typeof(p_metadata -> tenant_key) = 'string'
        AND rss_is_canonical_non_nil_uuid(p_metadata ->> tenant_key);
END;
$$;

CREATE OR REPLACE FUNCTION rss_projection_dead_letter_source_kind()
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = public, pg_temp
AS $$
    SELECT 'projection'::text
$$;

ALTER TABLE projection_events
    ADD COLUMN event_id text NOT NULL,
    ADD COLUMN contract_id text NOT NULL,
    ADD COLUMN contract_version text NOT NULL,
    ADD COLUMN schema_hash text NOT NULL,
    ADD COLUMN metadata jsonb NOT NULL,
    ADD COLUMN partition_key text NULL,
    ADD COLUMN causation_id text NULL,
    ADD CONSTRAINT uq_projection_events_event_id UNIQUE (event_id),
    ADD CONSTRAINT chk_projection_events_metadata_object
        CHECK (jsonb_typeof(metadata) = 'object'),
    ADD CONSTRAINT chk_projection_events_metadata_tenant
        CHECK (rss_metadata_has_canonical_tenant_id(metadata));

CREATE TABLE projection_input_bindings (
    contract_id text NOT NULL,
    contract_version text NOT NULL,
    schema_hash text NOT NULL,
    topic text NOT NULL,
    PRIMARY KEY (contract_id, contract_version, schema_hash, topic)
);

ALTER TABLE dead_letter
    DROP CONSTRAINT IF EXISTS chk_dead_letter_source_kind;

ALTER TABLE dead_letter
    ADD CONSTRAINT chk_dead_letter_source_kind
        CHECK (source_kind IN (
            'legacy',
            'consumer',
            'outbox_relay',
            'saga',
            rss_projection_dead_letter_source_kind()
        )),
    ADD CONSTRAINT chk_dead_letter_projection_consumer_group
        CHECK (source_kind <> rss_projection_dead_letter_source_kind()
            OR consumer_group IS NOT NULL);

CREATE UNIQUE INDEX idx_dead_letter_projection_poison_unique
    ON dead_letter (tenant_id, source_kind, consumer_group, message_id)
    WHERE source_kind = rss_projection_dead_letter_source_kind();

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rss_projection_events_runtime') THEN
        CREATE ROLE rss_projection_events_runtime NOLOGIN BYPASSRLS;
    ELSE
        ALTER ROLE rss_projection_events_runtime NOLOGIN BYPASSRLS;
    END IF;
END
$$;

GRANT SELECT, INSERT ON projection_events TO rss_projection_events_runtime;
GRANT USAGE, SELECT ON SEQUENCE projection_events_id_seq TO rss_projection_events_runtime;
GRANT SELECT ON projection_input_bindings TO rss_projection_events_runtime;
GRANT SELECT ON outbox TO rss_projection_events_runtime;
ALTER FUNCTION rss_is_canonical_non_nil_uuid(text) OWNER TO rss_projection_events_runtime;
ALTER FUNCTION rss_metadata_has_canonical_tenant_id(jsonb) OWNER TO rss_projection_events_runtime;
ALTER FUNCTION rss_projection_dead_letter_source_kind() OWNER TO rss_projection_events_runtime;

CREATE OR REPLACE FUNCTION rss_append_projection_event(
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
SET search_path = public, pg_temp
AS $$
DECLARE
    inserted_id bigint;
BEGIN
    IF p_metadata IS NULL
        OR NOT rss_metadata_has_canonical_tenant_id(p_metadata)
    THEN
        RAISE EXCEPTION 'projection event metadata must contain canonical non-nil tenantId';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM outbox o
        JOIN projection_input_bindings b
          ON b.contract_id = o.contract_id
         AND b.contract_version = o.contract_version
         AND b.schema_hash = o.schema_hash
         AND b.topic = o.topic
        WHERE o.event_id = p_event_id
          AND o.domain = p_domain
          AND o.topic = p_event_type
          AND o.payload = p_payload
          AND o.contract_id = p_contract_id
          AND o.contract_version = p_contract_version
          AND o.schema_hash = p_schema_hash
          AND o.metadata = p_metadata
          AND o.partition_key IS NOT DISTINCT FROM p_partition_key
          AND o.causation_id IS NOT DISTINCT FROM p_causation_id
          AND COALESCE(o.partition_key, o.event_id) = p_aggregate_id
          AND p_correlation_id IS NOT DISTINCT FROM p_causation_id
    ) THEN
        RAISE EXCEPTION 'projection event append must match a generated-bound outbox row';
    END IF;

    -- Serialize projection journal id allocation across concurrent transactions. Because this is
    -- an xact advisory lock, the lock is released at commit/rollback and the inserted identity
    -- order follows committed projection append order.
    PERFORM pg_advisory_xact_lock(hashtextextended('rss.projection_events.append', 0));

    INSERT INTO projection_events (
        event_id, domain, aggregate_id, event_type, payload, correlation_id,
        contract_id, contract_version, schema_hash, metadata, partition_key, causation_id
    )
    VALUES (
        p_event_id, p_domain, p_aggregate_id, p_event_type, p_payload, p_correlation_id,
        p_contract_id, p_contract_version, p_schema_hash, p_metadata, p_partition_key, p_causation_id
    )
    ON CONFLICT (event_id) DO NOTHING
    RETURNING id INTO inserted_id;

    IF inserted_id IS NULL THEN
        SELECT id INTO inserted_id
        FROM projection_events
        WHERE event_id = p_event_id;
    END IF;

    RETURN inserted_id;
END;
$$;

CREATE OR REPLACE FUNCTION rss_read_projection_events(p_after bigint, p_limit integer)
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
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF p_after IS NULL OR p_after < 0 THEN
        RAISE EXCEPTION 'invalid projection read cursor'
            USING ERRCODE = '22023';
    END IF;
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1000 THEN
        RAISE EXCEPTION 'invalid projection read limit'
            USING ERRCODE = '22023';
    END IF;

    RETURN QUERY
    SELECT pe.id,
           pe.event_id,
           pe.domain,
           pe.aggregate_id,
           pe.event_type,
           pe.payload,
           pe.contract_id,
           pe.contract_version,
           pe.schema_hash,
           pe.metadata,
           pe.partition_key,
           pe.causation_id
    FROM projection_events pe
    WHERE pe.id > p_after
    ORDER BY pe.id ASC
    LIMIT p_limit;
END;
$$;

ALTER FUNCTION rss_append_projection_event(
    text, text, text, text, bytea, text, text, text, text, jsonb, text, text
) OWNER TO rss_projection_events_runtime;
ALTER FUNCTION rss_read_projection_events(bigint, integer) OWNER TO rss_projection_events_runtime;

REVOKE ALL ON FUNCTION rss_append_projection_event(
    text, text, text, text, bytea, text, text, text, text, jsonb, text, text
) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_read_projection_events(bigint, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_is_canonical_non_nil_uuid(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION rss_metadata_has_canonical_tenant_id(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION rss_append_projection_event(
    text, text, text, text, bytea, text, text, text, text, jsonb, text, text
) TO rss_app;
GRANT EXECUTE ON FUNCTION rss_read_projection_events(bigint, integer) TO rss_app;

REVOKE SELECT, INSERT, UPDATE, DELETE ON projection_events FROM PUBLIC;
REVOKE SELECT, INSERT, UPDATE, DELETE ON projection_events FROM rss_app;
REVOKE UPDATE, DELETE ON projection_events FROM rss_projection_events_runtime;
REVOKE SELECT, INSERT, UPDATE, DELETE ON projection_input_bindings FROM PUBLIC;
REVOKE SELECT, INSERT, UPDATE, DELETE ON projection_input_bindings FROM rss_app;
REVOKE INSERT, UPDATE, DELETE ON projection_input_bindings FROM rss_projection_events_runtime;
REVOKE INSERT, UPDATE, DELETE ON outbox FROM rss_projection_events_runtime;
REVOKE USAGE, SELECT ON SEQUENCE projection_events_id_seq FROM PUBLIC;
REVOKE USAGE, SELECT ON SEQUENCE projection_events_id_seq FROM rss_app;
