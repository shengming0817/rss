-- 0052_dead_letter_provenance_v2.sql
--
-- Producer and consumer domains are distinct security/replay dimensions. The AAD wire version is
-- replaced directly; encrypted legacy rows cannot be authenticated under the new context.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM dead_letter LIMIT 1) THEN
        RAISE EXCEPTION 'dead_letter must be empty before enabling provenance and AAD v2';
    END IF;
END
$$;

DROP INDEX IF EXISTS idx_dead_letter_scan;
DROP INDEX IF EXISTS idx_dead_letter_tenant_domain_source;

ALTER TABLE dead_letter RENAME COLUMN domain TO producer_domain;

ALTER TABLE dead_letter
    ADD COLUMN consumer_domain text NULL,
    DROP CONSTRAINT chk_dead_letter_source_kind,
    DROP CONSTRAINT chk_dead_letter_original_entry_encoding,
    ADD CONSTRAINT chk_dead_letter_source_kind
        CHECK (source_kind IN ('consumer', 'outbox_relay', 'saga', 'projection')),
    ADD CONSTRAINT chk_dead_letter_provenance_shape
        CHECK (
            length(producer_domain) > 0
            AND (
                (source_kind IN ('consumer', 'projection')
                    AND consumer_domain IS NOT NULL AND length(consumer_domain) > 0)
                OR (source_kind IN ('outbox_relay', 'saga') AND consumer_domain IS NULL)
            )
        ),
    ADD CONSTRAINT chk_dead_letter_original_entry_encoding
        CHECK (original_entry_encoding = 'key-provider-v2');

CREATE INDEX idx_dead_letter_producer_scan
    ON dead_letter (producer_domain, last_attempt_at);
CREATE INDEX idx_dead_letter_tenant_producer_source
    ON dead_letter (tenant_id, producer_domain, source_kind, last_attempt_at DESC);
CREATE INDEX idx_dead_letter_tenant_consumer_source
    ON dead_letter (tenant_id, consumer_domain, source_kind, last_attempt_at DESC)
    WHERE consumer_domain IS NOT NULL;
