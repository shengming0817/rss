-- 0042_create_outbox_log.sql
--
-- CDC-facing append-only outbox ledger. Relay mode remains on the mutable `outbox`
-- status table and rss_outbox_* functions; this table is for opt-in logical decoding.

CREATE TABLE outbox_log (
    event_id text NOT NULL,
    tenant_id uuid NOT NULL,
    aggregate_type text NOT NULL,
    aggregate_id text NOT NULL,
    topic text NOT NULL,
    contract_id text NOT NULL,
    contract_version text NOT NULL,
    schema_hash text NOT NULL,
    payload bytea NOT NULL,
    metadata jsonb NOT NULL,
    causation_id text NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT outbox_log_event_id_unique UNIQUE (event_id),
    CONSTRAINT outbox_log_event_id_nonempty
        CHECK (length(event_id) > 0 AND octet_length(event_id) <= 256),
    CONSTRAINT outbox_log_aggregate_type_nonempty
        CHECK (length(aggregate_type) > 0 AND octet_length(aggregate_type) <= 128),
    CONSTRAINT outbox_log_aggregate_id_nonempty
        CHECK (length(aggregate_id) > 0 AND octet_length(aggregate_id) <= 256),
    CONSTRAINT outbox_log_topic_nonempty
        CHECK (length(topic) > 0 AND octet_length(topic) <= 256),
    CONSTRAINT outbox_log_contract_id_nonempty
        CHECK (length(contract_id) > 0 AND octet_length(contract_id) <= 256),
    CONSTRAINT outbox_log_contract_version_valid
        CHECK (contract_version ~ '^v[0-9]+$'),
    CONSTRAINT outbox_log_schema_hash_valid
        CHECK (schema_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT outbox_log_metadata_object
        CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT outbox_log_metadata_tenant_matches_column
        CHECK (
            metadata ? 'tenantId'
            AND jsonb_typeof(metadata->'tenantId') = 'string'
            AND metadata->>'tenantId' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            AND metadata->>'tenantId' <> '00000000-0000-0000-0000-000000000000'
            AND metadata->>'tenantId' = tenant_id::text
        ),
    CONSTRAINT outbox_log_metadata_schema_matches_columns
        CHECK (
            metadata ? 'schemaVersion'
            AND metadata ? 'schemaHash'
            AND jsonb_typeof(metadata->'schemaVersion') = 'string'
            AND metadata->>'schemaVersion' = contract_version
            AND jsonb_typeof(metadata->'schemaHash') = 'string'
            AND metadata->>'schemaHash' = schema_hash
        ),
    CONSTRAINT outbox_log_causation_id_valid
        CHECK (causation_id IS NULL OR (length(causation_id) > 0 AND octet_length(causation_id) <= 256))
);

CREATE INDEX idx_outbox_log_contract_schema
    ON outbox_log (aggregate_type, contract_id, contract_version, schema_hash);

CREATE INDEX idx_outbox_log_aggregate
    ON outbox_log (tenant_id, aggregate_type, aggregate_id, created_at);

REVOKE SELECT, INSERT, UPDATE, DELETE ON outbox_log FROM PUBLIC;
GRANT SELECT, INSERT ON outbox_log TO rss_app;
REVOKE UPDATE, DELETE ON outbox_log FROM rss_app;

ALTER TABLE outbox_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox_log FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON outbox_log
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
