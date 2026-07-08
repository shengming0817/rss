-- 0046 Durable resource attribute store（identity ResourceAttributeRepo；TENANCY-13 / #1590）。
--
-- Resource attributes are tenant-scoped PIP rows for route ABAC. Shared/global routes opt out at
-- contract level; the database never stores tenant_id NULL rows and never falls back to a global
-- attribute table.
CREATE TABLE resource_attributes (
    tenant_id       uuid        NOT NULL,
    contract_id     text        NOT NULL,
    permission      text        NOT NULL,
    resource_id     uuid        NOT NULL,
    attribute_key   text        NOT NULL,
    attribute_value text        NOT NULL,
    version         integer     NOT NULL DEFAULT 1 CHECK (version > 0),
    effective_from  timestamptz NOT NULL,
    effective_until timestamptz,
    deleted_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, contract_id, permission, resource_id, attribute_key),
    CONSTRAINT resource_attributes_effective_window
        CHECK (effective_until IS NULL OR effective_until > effective_from),
    CONSTRAINT resource_attributes_dynamic_key
        CHECK (
            attribute_key LIKE 'resource.%'
            AND attribute_key <> 'resource.id'
            AND length(attribute_key) > length('resource.')
        )
);

CREATE INDEX idx_resource_attributes_effective
    ON resource_attributes (tenant_id, contract_id, permission, resource_id, effective_from, effective_until)
    WHERE deleted_at IS NULL;

GRANT SELECT, INSERT, UPDATE ON resource_attributes TO rss_app;

ALTER TABLE resource_attributes ENABLE ROW LEVEL SECURITY;
ALTER TABLE resource_attributes FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON resource_attributes
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
