-- 0034 Durable ABAC policy store（identity PolicyRepo；TENANCY-11 / #1588）。
--
-- 策略是 tenant-scoped + route-scoped 的授权输入，不是数据租户隔离替代品。读写仍经
-- PgTenantPool SET LOCAL rss.tenant_id + FORCE RLS 双重收敛；未设置 tenant GUC 时 fail-closed 不可见。
CREATE TABLE abac_policies (
    tenant_id       uuid        NOT NULL,
    id              text        NOT NULL,
    version         integer     NOT NULL DEFAULT 1 CHECK (version > 0),
    contract_id     text        NOT NULL,
    permission      text        NOT NULL,
    effective_from  timestamptz NOT NULL,
    effective_until timestamptz,
    rules           jsonb       NOT NULL,
    deleted_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT abac_policies_effective_window
        CHECK (effective_until IS NULL OR effective_until > effective_from)
);

CREATE INDEX idx_abac_policies_effective
    ON abac_policies (tenant_id, contract_id, permission, effective_from, effective_until)
    WHERE deleted_at IS NULL;

GRANT SELECT, INSERT, UPDATE ON abac_policies TO rss_app;

ALTER TABLE abac_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE abac_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON abac_policies
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
