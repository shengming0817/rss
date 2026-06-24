-- 会话持久化表（identity session persistence；L2 OutboxFact co-tx，#1083 / #1192）。
--
-- co-tx 原子性（FR-003）：session 行与 outbox(`identity.session-created`) 行在**同一本地事务**写入，
-- 由 adapter `PgSessionUnitOfWork` 在 `PgStore::run_in_transaction` 闭包内先注入 tenant scope
-- （`set_config('rss.tenant_id', $1, true)` = SET LOCAL，tenancy.md §RLS 与 PG scope）后 INSERT，再
-- `append_outbox`，单 commit（INVARIANT OUTBOX-COTX-SESSION-01；both-or-neither）。
--
-- session_id 用 `text`（绑域内 `SessionId` newtype，本质 opaque UUID 串，不强绑 PG `uuid` 类型——避免
--   格式耦合 + 不给 sqlx 加 uuid feature，同 `outbox.event_id` 范式见 0002）。PRIMARY KEY ⇒ 重试登录
--   `ON CONFLICT (session_id) DO NOTHING` 幂等（同 append_outbox 范式）。
-- subject 是 **opaque** 主体标识（FR-020；非完整 Principal / email / 姓名等 PII，observability.md §PII 边界）。
-- tenant_id `uuid NOT NULL`：每行租户戳记——SET LOCAL 注入锚点 + 未来 RLS policy 的 current_setting 比对锚点。
-- expires_at / created_at：由应用注入 `Clock` 派生（不取 DB `now()`，与域 Clock 注入一致，application.rs）；
--   `created_at DEFAULT now()` 仅作兜底（应用恒显式提供）。
--
-- 本表预 GA **不**建 RLS policy（仓内尚无 RLS infra：非 owner serving role / FORCE RLS / schema guard 未
--   provision）；tenant_id 列 + SET LOCAL 已保证写入 tenant-correct，RLS policy 由后续前向迁移按
--   tenancy.md 叠加（`current_setting('rss.tenant_id')` 比对，零数据迁移）。

CREATE TABLE sessions (
    session_id   text        PRIMARY KEY,
    subject      text        NOT NULL,
    tenant_id    uuid        NOT NULL,
    expires_at   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- 租户内枚举索引（pre-GA 新空表 → 普通 CREATE INDEX，事务型迁移，README §索引形态）。
CREATE INDEX idx_sessions_tenant ON sessions (tenant_id);
-- 过期会话清理（sweep）扫描索引（未来 session GC，对齐 outbox sweep 索引 0002）。
CREATE INDEX idx_sessions_expiry ON sessions (expires_at);
