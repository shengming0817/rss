-- 0051_create_command_journal.sql
--
-- Tenant-scoped command journal foundation (#1441). The table protects producer/handler-side
-- command idempotency and stores stable replay outcomes. It is deliberately separate from
-- inbox_receipts, which protects broker delivery handling.

CREATE TABLE command_journal (
    tenant_id            uuid        NOT NULL,
    command_id           text        NOT NULL,
    idempotency_key      text        NOT NULL,
    topic                text        NOT NULL,
    contract_id          text        NOT NULL,
    contract_version     text        NOT NULL,
    schema_hash          text        NOT NULL,
    request_fingerprint  text        NOT NULL,
    outbox_event_id      text        NOT NULL,
    status               text        NOT NULL DEFAULT 'in_flight',
    attempt              integer     NOT NULL DEFAULT 1,
    result_summary       text,
    error_summary        text,
    trace                text,
    correlation_id       text,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, command_id),
    CONSTRAINT command_journal_idempotency_unique
        UNIQUE (tenant_id, topic, idempotency_key),
    CONSTRAINT command_journal_command_id_valid
        CHECK (command_id ~ '^command:v1:sha256:[0-9a-f]{64}$'),
    CONSTRAINT command_journal_idempotency_key_valid
        CHECK (idempotency_key ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT command_journal_topic_nonempty
        CHECK (length(topic) > 0 AND octet_length(topic) <= 256),
    CONSTRAINT command_journal_contract_id_nonempty
        CHECK (length(contract_id) > 0 AND octet_length(contract_id) <= 256),
    CONSTRAINT command_journal_contract_version_valid
        CHECK (contract_version ~ '^v[0-9]+$'),
    CONSTRAINT command_journal_schema_hash_valid
        CHECK (schema_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT command_journal_fingerprint_valid
        CHECK (request_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT command_journal_outbox_event_id_valid
        CHECK (outbox_event_id ~ '^command:v1:sha256:[0-9a-f]{64}$'),
    CONSTRAINT command_journal_status_valid
        CHECK (status IN ('in_flight', 'completed', 'failed')),
    CONSTRAINT command_journal_attempt_positive
        CHECK (attempt >= 1),
    CONSTRAINT command_journal_result_summary_valid
        CHECK (result_summary IS NULL OR result_summary IN ('command enqueued')),
    CONSTRAINT command_journal_error_summary_valid
        CHECK (error_summary IS NULL OR error_summary IN ('command failed')),
    CONSTRAINT command_journal_terminal_summary_matches_status
        CHECK (
            (status = 'in_flight' AND result_summary IS NULL AND error_summary IS NULL)
            OR (status = 'completed' AND result_summary IS NOT NULL AND error_summary IS NULL)
            OR (status = 'failed' AND result_summary IS NULL AND error_summary IS NOT NULL)
        ),
    CONSTRAINT command_journal_trace_valid
        CHECK (trace IS NULL OR (length(trace) > 0 AND octet_length(trace) <= 512)),
    CONSTRAINT command_journal_correlation_id_valid
        CHECK (correlation_id IS NULL OR (length(correlation_id) > 0 AND octet_length(correlation_id) <= 256))
);

CREATE INDEX idx_command_journal_status
    ON command_journal (tenant_id, status, updated_at);

CREATE INDEX idx_command_journal_contract_schema
    ON command_journal (tenant_id, contract_id, contract_version, schema_hash);

REVOKE SELECT, INSERT, UPDATE, DELETE ON command_journal FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON command_journal TO rss_app;
REVOKE DELETE ON command_journal FROM rss_app;

ALTER TABLE command_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE command_journal FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON command_journal
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
