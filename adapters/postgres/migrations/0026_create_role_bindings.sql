-- 角色绑定持久化表（identity RoleBindingLifecycle persistence；L2 OutboxFact，#1190 PR5b）。
--
-- PgRoleBindingLifecycle 是 RBAC assign/revoke HTTP handler 的生产闭环：binding 行写/删与
-- identity.role-{assigned,revoked} outbox 行同一本地事务提交。audit consumer 仍由 #1017 跟进。
CREATE TABLE role_bindings (
    tenant_id   uuid        NOT NULL,
    role_id     text        NOT NULL,
    subject     text        NOT NULL,
    assigned_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, role_id, subject),
    CONSTRAINT fk_role_bindings_role
        FOREIGN KEY (tenant_id, role_id)
        REFERENCES roles (tenant_id, id)
        ON DELETE CASCADE
);

CREATE INDEX idx_role_bindings_tenant ON role_bindings (tenant_id);
CREATE INDEX idx_role_bindings_tenant_subject ON role_bindings (tenant_id, subject);

GRANT SELECT, INSERT, UPDATE, DELETE ON role_bindings TO rss_app;

ALTER TABLE role_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE role_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON role_bindings
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
