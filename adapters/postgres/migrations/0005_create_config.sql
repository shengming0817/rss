-- 版本化配置持久化表（settings ConfigRepo persistence；L2 OutboxFact co-tx，#1249）。
--
-- co-tx 原子性（#1232）：config 行与 outbox(`settings.config-version-changed`) 行在**同一本地事务**写入，
-- 由 adapter `PgConfigUnitOfWork` 经通用 `co_tx_with_outbox`（begin → SET LOCAL tenant → CAS INSERT →
-- append_outbox → 单 commit）保证 both-or-neither——消除 emit-after-save 的 write-without-event 窗口。
--
-- 版本历史模型：每 (tenant, key) 保留**全部**版本行（append-only，不 update-in-place）；当前活跃 =
-- max(version) 且**非 tombstone**，find_version 取精确版本（回滚读旧值用）。PRIMARY KEY
-- (tenant_id, config_key, version) 防重复版本写，并服务全部读路径（max via 反向扫描 / 精确等值 / 前缀范围），
-- 无需额外索引。
-- CAS（etcd 版本模型，settings ports.rs）：save 要求新版本 = 当前最高 + 1（首版 = 1），由
--   `INSERT ... SELECT ... WHERE $v = 1 + COALESCE(max(version),0)` 单语句守——0 行 affected ⇒ VersionConflict；
--   并发同版本写经 PK unique violation(23505) 亦映射 VersionConflict（adapter 侧）。
-- **删除 = tombstone 软删除（#1249 review F1）**：delete **不**物理移除版本行（否则 version 重置 →
--   `event_id = {topic}:{tenant}:{key}:v{version}` 跨 delete+republish 复用 → outbox `ON CONFLICT DO NOTHING`
--   吞事件 = write-without-event 重现）。改为在 `max+1` **追加一条 `deleted=true` tombstone**（幂等：latest 已
--   tombstone 则 no-op）→ version 单调不重置 → republish 取更高版本 → event_id 不复用。`find`/`find_version`
--   排除 tombstone（latest 为 tombstone ⇒ 视为已删 `None`；历史值行保留可经 find_version 读，audit 友好）。
--   tombstone 自身**不发**删除事件——consumer 感知删除的 `config-version-deleted` 留订阅缓存单元 #1120。
--
-- config_key 用 `text`（绑域内 `SettingKey` newtype，opaque 不透明串，namespace 校验在域层；不强绑 PG 类型，
--   同 outbox.event_id / sessions.session_id 范式见 0002/0004）。
-- value 用 `text`（opaque 配置值原始串——`ConfigValue` 不保证合法 JSON 故非 jsonb；可能含 secret，redaction
--   在域 `ConfigValue` Debug + 日志层，落库为脱敏边界外的持久态，tenant scope 隔离读取）。
-- version 用 `bigint`（域 u64 版本号 wire i64；从 1 单调递增）。
-- tenant_id `uuid NOT NULL`：每行租户戳记——SET LOCAL 注入锚点 + 未来 RLS policy current_setting 比对锚点。
-- created_at `DEFAULT now()`：落库兜底时间戳（版本号即业务时序，应用不显式写 created_at）。
--
-- 本表预 GA **不**建 RLS policy（同 sessions 0004：仓内尚无 RLS infra）；tenant_id 列 + 写路径 SET LOCAL +
--   读路径显式 `WHERE tenant_id` 已保证 tenant-correct，RLS policy 由后续前向迁移按 tenancy.md 叠加（零数据迁移）。

CREATE TABLE config_entries (
    tenant_id    uuid        NOT NULL,
    config_key   text        NOT NULL,
    version      bigint      NOT NULL,
    value        text        NOT NULL,
    deleted      boolean     NOT NULL DEFAULT false,  -- tombstone 标记（true ⇒ 该版本是删除墓碑，find 视为已删）
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, config_key, version)
);
