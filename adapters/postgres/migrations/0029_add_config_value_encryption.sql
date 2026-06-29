-- settings ConfigValue at-rest encryption (#1477).
--
-- Representation:
-- - protection_scheme = 0: legacy plaintext row; value is present, encrypted columns are absent.
-- - protection_scheme = 1: encrypted row; plaintext value is NULL, value_enc + key_id are present.
--
-- No backfill/lazy migration is performed in this PR. Legacy rows remain readable by adapter code,
-- but new writes use scheme 1 only.

ALTER TABLE config_entries
    ALTER COLUMN value DROP NOT NULL,
    ADD COLUMN protection_scheme integer NOT NULL DEFAULT 0,
    ADD COLUMN value_enc bytea NULL,
    ADD COLUMN key_id text NULL;

ALTER TABLE config_entries
    ALTER COLUMN protection_scheme DROP DEFAULT;

ALTER TABLE config_entries
    ADD CONSTRAINT config_entries_value_representation_chk
    CHECK (
        (
            protection_scheme = 0
            AND value IS NOT NULL
            AND value_enc IS NULL
            AND key_id IS NULL
        )
        OR
        (
            protection_scheme = 1
            AND value IS NULL
            AND value_enc IS NOT NULL
            AND key_id IS NOT NULL
        )
    );
