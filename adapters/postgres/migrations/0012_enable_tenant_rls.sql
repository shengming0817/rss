-- DB 层租户隔离：sessions / config_entries / roles / role_revisions / secret_refs 落地 RLS + FORCE RLS + tenant-isolation policy +
-- 非 owner serving role（#1298）。tenancy.md §RLS 与 PG scope（目标态单源）。
--
-- 0005/0006 落地起 pre-GA 推迟 RLS infra，本迁移补齐其 DB 强制层。0009 与本文件中的角色定义部分
-- 由 ADR-011 §2.7 的 #1291 未部署窄例外直接收敛为 fresh-install 最终态。
--
-- 每表三件套：
--   ENABLE ROW LEVEL SECURITY  —— 开启行级安全。
--   FORCE ROW LEVEL SECURITY   —— owner 亦受 policy 约束（纵深防御；否则 owner 默认绕过 RLS）。
--     注：superuser 连接永远绕过 RLS（含 FORCE）；生产 owner 角色须为非 superuser，或业务池切
--     rss_app 连接（dual-pool follow-up）方有 DB 层强制力。
--   CREATE POLICY tenant_isolation ... USING/WITH CHECK (tenant_id = current_setting('rss.tenant_id', true)::uuid)
--     —— 当前事务 SET LOCAL rss.tenant_id 之外的行不可见 / 拒写；未设 → current_setting 返 NULL → 行不可见（fail-closed）。
--
-- serving role rss_app：非 owner、NOBYPASSRLS、NOLOGIN（生产 LOGIN+密码 out-of-band，committed SQL 不放密码）；
--   普通 tenant 表授 DML；角色两表只读且没有 mutation function EXECUTE（无 DDL / 无 BYPASSRLS）。业务池以 rss_app 连接的
--   dual-pool 接线属 follow-up（bootstrap 接线本身未落地）；本迁移先 provision 角色 + policy，集成测试经 SET ROLE 证明强制力。

-- 非 owner serving role（幂等：已存在则 no-op）。
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'rss_app') THEN
        CREATE ROLE rss_app NOLOGIN NOBYPASSRLS;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO rss_app;
-- 普通 tenant 表保留 DML；角色定义只读。当前没有生产 role-definition consumer，因此通用
-- serving role 不取得可自报 actor 的 mutation function EXECUTE。
GRANT SELECT, INSERT, UPDATE, DELETE ON sessions, config_entries, secret_refs TO rss_app;
GRANT SELECT ON roles, role_revisions TO rss_app;

-- sessions
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON sessions
    USING (tenant_id = current_setting('rss.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('rss.tenant_id', true)::uuid);

-- config_entries
ALTER TABLE config_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE config_entries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON config_entries
    USING (tenant_id = current_setting('rss.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('rss.tenant_id', true)::uuid);

-- roles
ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE roles FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON roles
    USING (tenant_id = current_setting('rss.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('rss.tenant_id', true)::uuid);

-- role_revisions
ALTER TABLE role_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE role_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON role_revisions
    USING (tenant_id = current_setting('rss.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('rss.tenant_id', true)::uuid);

-- secret_refs（同 config_entries 范式；#1298 合入 secrets 功能后纳入同一 RLS regime）
ALTER TABLE secret_refs ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_refs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON secret_refs
    USING (tenant_id = current_setting('rss.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('rss.tenant_id', true)::uuid);
