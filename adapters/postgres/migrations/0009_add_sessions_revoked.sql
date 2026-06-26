-- sessions 表追加软撤销列（identity SessionLifecycle durable find/revoke，#1278；前向迁移，0004 只增不改）。
--
-- adapter `PgSessionLifecycle`（adapters/postgres/src/session_lifecycle.rs）impl `identity::ports::SessionLifecycle`
-- 的 `find` / `revoke`（合并端口后 postgres provider 须交付完整生命周期，#1278——补齐原 #1116 durable 闭合）：
-- `find` = 按 (tenant, session_id) 读非撤销会话（`WHERE revoked = false`，跨租 → 0 行 → None，fail-closed）；
-- `revoke` = tenant-scoped 事务内 `UPDATE ... SET revoked = true`（幂等：未知 / 跨租 / 已撤销均 0 行影响、仍 Ok）。
--
-- `revoked boolean NOT NULL DEFAULT false`：默认值保证既有 co-tx INSERT（写路径不显式写本列）与历史行向后
-- 兼容（rust-standards §migration：新字段须有默认值或允许 NULL）。软撤销**不删行**（保留审计 / 幂等），与 in-mem
-- `InMemSessionLifecycle` / demo `MemSessionLifecycle` 的 revoked-flag 语义一致（provider 行为对齐，#1278）。
-- 软撤销不硬吊销已颁 JWT（TTL 内仍有效，硬吊销延 #1003）。
--
-- 索引：find 按 PK `session_id` 单行定位 + 单行 `revoked` 过滤，无需二级索引（同 0004 §索引形态）。

ALTER TABLE sessions
    ADD COLUMN revoked boolean NOT NULL DEFAULT false;
