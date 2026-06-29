-- 0028_encrypt_dead_letter_original_entry.sql
-- DLX payload encryption is a pre-GA breaking change: existing plaintext DLX rows must be
-- removed or migrated out-of-band before applying this migration. Runtime code has no plaintext
-- decoder fallback.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM dead_letter LIMIT 1) THEN
        RAISE EXCEPTION 'dead_letter must be empty before enabling encrypted original_entry';
    END IF;
END $$;

ALTER TABLE dead_letter
    ADD COLUMN consumer_group text NULL,
    ADD COLUMN original_entry_key_ref text NOT NULL,
    ADD COLUMN original_entry_payload_len bigint NOT NULL,
    ADD COLUMN original_entry_encoding text NOT NULL,
    ADD CONSTRAINT chk_dead_letter_original_entry_encoding
        CHECK (original_entry_encoding = 'key-provider-v1'),
    ADD CONSTRAINT chk_dead_letter_original_entry_ciphertext_only
        CHECK (
            jsonb_typeof(original_entry) = 'object'
            AND original_entry ? 'ciphertext'
            AND NOT (original_entry ? 'bytes')
        ),
    ADD CONSTRAINT chk_dead_letter_original_entry_payload_len_nonnegative
        CHECK (original_entry_payload_len >= 0);

CREATE INDEX idx_dead_letter_consumer_group_message
    ON dead_letter (tenant_id, consumer_group, message_id)
    WHERE consumer_group IS NOT NULL;
