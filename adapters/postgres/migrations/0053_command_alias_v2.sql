-- 0053_command_alias_v2.sql
--
-- Direct replacement of deterministic command:v1 identities with random canonical v2 ids and
-- keyed blind-index aliases. Pre-GA policy intentionally rejects unverifiable legacy rows.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM command_journal LIMIT 1)
        OR EXISTS (SELECT 1 FROM outbox WHERE event_id LIKE 'command:%' LIMIT 1)
    THEN
        RAISE EXCEPTION 'command journal and command outbox rows must be empty before enabling command aliases v2';
    END IF;
END
$$;

ALTER TABLE command_journal
    DROP CONSTRAINT command_journal_idempotency_unique,
    DROP CONSTRAINT command_journal_command_id_valid,
    DROP CONSTRAINT command_journal_idempotency_key_valid,
    DROP CONSTRAINT command_journal_outbox_event_id_valid,
    DROP COLUMN idempotency_key,
    ADD CONSTRAINT command_journal_command_id_valid
        CHECK (command_id ~ '^command:v2:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    ADD CONSTRAINT command_journal_outbox_event_id_valid
        CHECK (outbox_event_id = command_id);

CREATE TABLE command_idempotency_aliases (
    tenant_id    uuid        NOT NULL,
    topic        text        NOT NULL,
    key_id       text        NOT NULL,
    alias_digest bytea       NOT NULL,
    command_id   text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, topic, key_id, alias_digest),
    CONSTRAINT command_alias_topic_nonempty
        CHECK (length(topic) > 0 AND octet_length(topic) <= 256),
    CONSTRAINT command_alias_key_id_valid
        CHECK (length(key_id) > 0 AND octet_length(key_id) <= 128),
    CONSTRAINT command_alias_digest_256bit
        CHECK (octet_length(alias_digest) = 32),
    CONSTRAINT command_alias_command_id_valid
        CHECK (command_id ~ '^command:v2:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
);

CREATE INDEX idx_command_alias_canonical
    ON command_idempotency_aliases (tenant_id, command_id);

REVOKE SELECT, INSERT, UPDATE, DELETE ON command_idempotency_aliases FROM PUBLIC;
GRANT SELECT, INSERT ON command_idempotency_aliases TO rss_app;
REVOKE UPDATE, DELETE ON command_idempotency_aliases FROM rss_app;

ALTER TABLE command_idempotency_aliases ENABLE ROW LEVEL SECURITY;
ALTER TABLE command_idempotency_aliases FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON command_idempotency_aliases
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
