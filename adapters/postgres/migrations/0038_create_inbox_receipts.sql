-- 0038_create_inbox_receipts.sql
-- Tenant-scoped target inbox receipt table (#1626).
--
-- This is the final schema for the follow-up runtime cutover from the global
-- inbox_dedup table. Runtime wiring remains a later PR; this migration only
-- establishes the DB hard boundary: tenant-first keying, closed status labels,
-- schema header columns, lease CAS state, and FORCE RLS.

CREATE TABLE inbox_receipts (
    tenant_id        uuid        NOT NULL,
    event_id         text        NOT NULL,
    consumer_group   text        NOT NULL,
    domain           text        NOT NULL,
    topic            text        NOT NULL,
    contract_id      text        NOT NULL,
    contract_version text        NOT NULL,
    schema_hash      text        NOT NULL,
    trace            text,
    correlation_id   text,
    status           text        NOT NULL DEFAULT 'claimed',
    lease_token      uuid        NOT NULL,
    receive_count    integer     NOT NULL DEFAULT 1,
    claimed_at       timestamptz NOT NULL DEFAULT now(),
    committed_at     timestamptz,
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, event_id, consumer_group),
    CONSTRAINT inbox_receipts_status_valid
        CHECK (status IN ('claimed', 'done')),
    CONSTRAINT inbox_receipts_contract_version_valid
        CHECK (contract_version ~ '^v[0-9]+$'),
    CONSTRAINT inbox_receipts_schema_hash_valid
        CHECK (schema_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT inbox_receipts_trace_valid
        CHECK (trace IS NULL OR (length(trace) > 0 AND octet_length(trace) <= 512)),
    CONSTRAINT inbox_receipts_correlation_id_valid
        CHECK (correlation_id IS NULL OR (length(correlation_id) > 0 AND octet_length(correlation_id) <= 256)),
    CONSTRAINT inbox_receipts_receive_count_positive
        CHECK (receive_count >= 1),
    CONSTRAINT inbox_receipts_commit_timestamp_matches_status
        CHECK (
            (status = 'claimed' AND committed_at IS NULL)
            OR (status = 'done' AND committed_at IS NOT NULL)
        )
);

CREATE INDEX idx_inbox_receipts_stale_claims
    ON inbox_receipts (tenant_id, consumer_group, claimed_at)
    WHERE status = 'claimed';

CREATE INDEX idx_inbox_receipts_done_retention
    ON inbox_receipts (status, committed_at)
    WHERE status = 'done';

CREATE INDEX idx_inbox_receipts_contract_schema
    ON inbox_receipts (tenant_id, domain, contract_id, contract_version, schema_hash);

GRANT SELECT, INSERT, UPDATE, DELETE ON inbox_receipts TO rss_app;

ALTER TABLE inbox_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE inbox_receipts FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON inbox_receipts
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
