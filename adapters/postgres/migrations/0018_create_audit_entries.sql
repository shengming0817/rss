-- 审计链持久化表（audit AuditRepo persistence；append-only per-tenant keyed-HMAC chain，#1230 Part A step 5）。
--
-- adapter `PgAuditRepo`（adapters/postgres/src/audit_repo.rs）impl `audit::ports::AuditRepo`：
-- append（advisory-lock 串行 + tail 续链 + INSERT）/ list（游标分页 + 增量 verify_window）/
-- verify_tail（末窗口 + 前驱 verify_window，非全扫）。
--
-- 安全不变式：
--   * **append-only**：rss_app 仅 SELECT + INSERT，NO UPDATE / DELETE；DB 层阻止直接覆写。
--   * **bytea 哈希 32B**：prev_hash / entry_hash CHECK octet_length=32；截断 / 错位 hash 被 DB 硬拒。
--   * **recorded_at secs+nanos 两列**（非 timestamptz）：timestamptz 截断纳秒精度；keyed HMAC 链
--     canonical_message 以 secs(u64 BE) + nanos(u32 BE) 为输入（INVARIANT: AUDIT-LEDGER-BYTES-01），
--     timestamptz 往返会改变 nanos → 重算 entry_hash 不匹配 → verify 假阳。两列编码与哈希输入精确对称。
--   * **actor_kind / outcome 闭值集 CHECK**：DB 层防止未知变体落库，与 Rust actor_kind_to_db / AuditOutcome::to_db 对齐。
--   * **seq CHECK >= 0**：映射 Rust u64，非负；回读 i64 → u64 via try_from fail-closed。
--
-- 索引设计：PRIMARY KEY (tenant_id, seq)——按租户 + seq 唯一，是 append 尾读（ORDER BY seq DESC LIMIT 1）
-- 与分页（seq >= $cursor ORDER BY seq ASC LIMIT n）的高效路径，无需额外索引（pre-GA 空表，PK 已足）。
--
-- RLS 三件套（与 0012_enable_tenant_rls.sql + 0015_create_credentials.sql 同范式）：
--   ENABLE ROW LEVEL SECURITY — 开启行级安全。
--   FORCE ROW LEVEL SECURITY  — owner 亦受 policy 约束（纵深防御）。
--   CREATE POLICY tenant_isolation — USING/WITH CHECK：current_setting('rss.tenant_id',true)::uuid；
--     未设 rss.tenant_id → NULL → fail-closed（全行过滤/拒写）。
-- rss_app 角色由 0012 创建（NOLOGIN NOBYPASSRLS）；SELECT+INSERT only（无 UPDATE/DELETE）。

CREATE TABLE audit_entries (
    tenant_id           uuid        NOT NULL,
    seq                 bigint      NOT NULL CHECK (seq >= 0),
    prev_hash           bytea       NOT NULL CHECK (octet_length(prev_hash) = 32),
    entry_hash          bytea       NOT NULL CHECK (octet_length(entry_hash) = 32),
    actor               uuid        NOT NULL,
    actor_kind          text        NOT NULL CHECK (actor_kind IN ('user','device','admin','super_admin','service','anonymous')),
    action              text        NOT NULL,
    resource_kind       text        NOT NULL,
    resource_id         text        NOT NULL,
    outcome             text        NOT NULL CHECK (outcome IN ('success','denied','error')),
    recorded_at_secs    bigint      NOT NULL CHECK (recorded_at_secs >= 0),
    recorded_at_nanos   integer     NOT NULL CHECK (recorded_at_nanos >= 0 AND recorded_at_nanos < 1000000000),
    key_id              smallint    NOT NULL DEFAULT 1,
    created_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, seq)
);

-- append-only: rss_app 仅 SELECT + INSERT，不授 UPDATE / DELETE。
-- REVOKE FROM PUBLIC 兜底（DB 默认 public schema USAGE 可能残留；defense-in-depth）。
GRANT SELECT, INSERT ON audit_entries TO rss_app;
REVOKE UPDATE, DELETE ON audit_entries FROM PUBLIC;

-- RLS 三件套（同 0012 / 0015 / 0017 范式）。
ALTER TABLE audit_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_entries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_entries
    USING (tenant_id = current_setting('rss.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('rss.tenant_id', true)::uuid);
