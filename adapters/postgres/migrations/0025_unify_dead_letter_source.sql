-- 0025_unify_dead_letter_source.sql — unified DLQ source + replay metadata (#1214).
--
-- `dead_letter` is now the unified DLQ audit table for consumer dead-letter,
-- saga compensation failures, and outbox relay DLX registration. `outbox.status='dlx'`
-- remains the relay state / partition-ordering gate; the audit row records source_kind.

ALTER TABLE dead_letter
    ADD COLUMN source_kind text NOT NULL DEFAULT 'legacy',
    ADD COLUMN metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD CONSTRAINT chk_dead_letter_source_kind
        CHECK (source_kind IN ('legacy', 'consumer', 'outbox_relay', 'saga'));

CREATE INDEX idx_dead_letter_tenant_source_last_attempt
    ON dead_letter (tenant_id, source_kind, last_attempt_at DESC);

CREATE INDEX idx_dead_letter_tenant_domain_source
    ON dead_letter (tenant_id, domain, source_kind, last_attempt_at DESC);
