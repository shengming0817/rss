-- 0043_create_saga_instance_store.sql
--
-- Tenant-scoped saga instance/lease store and forward tenantization of saga_journal (#1632).

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM saga_journal LIMIT 1) THEN
        RAISE EXCEPTION 'cannot tenantize non-empty legacy saga_journal without tenant backfill';
    END IF;
END
$$;

CREATE TABLE saga_instances (
    tenant_id    uuid        NOT NULL,
    saga_id      uuid        NOT NULL,
    owner        text        NOT NULL,
    contract_id  text        NOT NULL,
    status       text        NOT NULL DEFAULT 'ready',
    lease_token  uuid,
    holder_id    text,
    epoch        bigint      NOT NULL DEFAULT 0,
    acquired_at  timestamptz,
    expires_at   timestamptz,
    heartbeat_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, saga_id),
    CONSTRAINT saga_instances_owner_valid
        CHECK (length(owner) > 0 AND octet_length(owner) <= 128),
    CONSTRAINT saga_instances_contract_id_valid
        CHECK (length(contract_id) > 0 AND octet_length(contract_id) <= 256),
    CONSTRAINT saga_instances_status_valid
        CHECK (status IN ('ready', 'running', 'succeeded', 'compensating', 'compensated', 'failed', 'degraded')),
    CONSTRAINT saga_instances_epoch_non_negative
        CHECK (epoch >= 0),
    CONSTRAINT saga_instances_holder_id_valid
        CHECK (holder_id IS NULL OR (length(holder_id) > 0 AND octet_length(holder_id) <= 256)),
    CONSTRAINT saga_instances_lease_fields_consistent
        CHECK (
            (
                lease_token IS NULL
                AND holder_id IS NULL
                AND acquired_at IS NULL
                AND expires_at IS NULL
                AND heartbeat_at IS NULL
            )
            OR (
                lease_token IS NOT NULL
                AND holder_id IS NOT NULL
                AND acquired_at IS NOT NULL
                AND expires_at IS NOT NULL
                AND heartbeat_at IS NOT NULL
                AND expires_at > acquired_at
            )
        )
);

CREATE INDEX idx_saga_instances_owner_status
    ON saga_instances (tenant_id, owner, status, updated_at);

CREATE INDEX idx_saga_instances_lease_expiry
    ON saga_instances (tenant_id, expires_at)
    WHERE lease_token IS NOT NULL;

ALTER TABLE saga_journal ADD COLUMN tenant_id uuid;
ALTER TABLE saga_journal ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE saga_journal DROP CONSTRAINT saga_journal_pkey;
ALTER TABLE saga_journal ADD PRIMARY KEY (tenant_id, saga_id, seq);
ALTER TABLE saga_journal
    ADD CONSTRAINT saga_journal_instance_fk
    FOREIGN KEY (tenant_id, saga_id)
    REFERENCES saga_instances (tenant_id, saga_id)
    ON DELETE CASCADE;

GRANT SELECT, INSERT, UPDATE ON saga_instances TO rss_app;
REVOKE DELETE ON saga_instances FROM rss_app;

GRANT SELECT, INSERT ON saga_journal TO rss_app;
REVOKE UPDATE, DELETE ON saga_journal FROM rss_app;

ALTER TABLE saga_instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE saga_instances FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON saga_instances
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);

ALTER TABLE saga_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE saga_journal FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON saga_journal
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
