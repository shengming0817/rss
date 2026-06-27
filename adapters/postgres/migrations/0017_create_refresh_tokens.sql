-- 0017: refresh token 持久化表（identity refresh token store；L1 LocalTx 哈希存储 + CAS rotation + RLS 隔离，#1325）。
-- CHECK 约束（DB 层 defense-in-depth，Rust hydrate fail-close 之外；review #284 F4）：
--   status  — 闭值集静态守（'active'/'consumed'/'revoked'），防非法状态行入库。
--   kind    — 与 identity `kind_to_db` 闭值集一致，防无效 kind 落库导致 hydrate 失败。
--   token_hash — SHA-256 固定 32 字节，防截断 / 错位 hash 绕过唯一索引误判。
--
-- 安全设计：
--   token_hash bytea(32) — SHA-256 摘要，不存明文；攻陷 store 不泄露可用 token。
--   status text           — 闭值集：'active' / 'consumed' / 'revoked'。
--   parent_id / lineage_id — 轮换谱系（reuse-detection 级联撤销锚点；签发根 lineage_id == id，parent_id NULL）。
--
-- 主键设计：
--   id uuid               — 服务端 mint 的 UUID v4，NOT NULL；与 tenant_id 组成复合 PK（多租唯一，跨租无冲突）。
--   PRIMARY KEY (tenant_id, id) — 复合 PK 隔离租户 + 行内唯一性。
--
-- 索引设计（pre-GA 新空表 → 普通 CREATE INDEX，事务型迁移，README §索引形态；post-GA 已填充表用 CONCURRENTLY）：
--   idx_refresh_tokens_hash    — (tenant_id, token_hash) UNIQUE：find_by_hash 唯一查找键（单次呈递精确匹配）。
--   idx_refresh_tokens_lineage — (tenant_id, lineage_id)：revoke_lineage 批量撤销扫描。
--
-- RLS 三件套（同 0012_enable_tenant_rls.sql 范式）：
--   ENABLE ROW LEVEL SECURITY — 开启行级安全。
--   FORCE ROW LEVEL SECURITY  — owner 亦受 policy 约束（纵深防御；superuser 绕过 FORCE，生产需切 rss_app 连接）。
--   CREATE POLICY tenant_isolation — USING/WITH CHECK：当前 SET LOCAL rss.tenant_id 之外行不可见/拒写；
--     未设 rss.tenant_id → NULL → fail-closed（全行过滤）。
-- rss_app 角色由 0012 创建（NOLOGIN NOBYPASSRLS）；此处直接 GRANT DML，无需重建角色。

CREATE TABLE refresh_tokens (
    id          uuid        NOT NULL,
    tenant_id   uuid        NOT NULL,
    subject     text        NOT NULL,
    kind        text        NOT NULL CHECK (kind IN ('user','device','admin','super_admin','service','anonymous')),
    token_hash  bytea       NOT NULL CHECK (octet_length(token_hash) = 32),
    parent_id   uuid,
    lineage_id  uuid        NOT NULL,
    status      text        NOT NULL DEFAULT 'active' CHECK (status IN ('active','consumed','revoked')),
    issued_at   timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id)
);

-- find_by_hash 唯一查找（SHA-256 摘要 + 租户，唯一约束防止同 tenant 重复签发相同 hash）。
CREATE UNIQUE INDEX idx_refresh_tokens_hash ON refresh_tokens (tenant_id, token_hash);
-- revoke_lineage 批量撤销扫描（按 lineage_id 家族全量 UPDATE）。
CREATE INDEX idx_refresh_tokens_lineage ON refresh_tokens (tenant_id, lineage_id);

-- RLS 三件套（同 0012 范式：ENABLE + FORCE + tenant_isolation policy）。
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON refresh_tokens
    USING (tenant_id = current_setting('rss.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('rss.tenant_id', true)::uuid);

-- rss_app（0012 创建，NOLOGIN NOBYPASSRLS）：授 DML（无 DDL / 无 BYPASSRLS，app 被攻陷也无法关 RLS / 跨租读）。
GRANT SELECT, INSERT, UPDATE, DELETE ON refresh_tokens TO rss_app;
