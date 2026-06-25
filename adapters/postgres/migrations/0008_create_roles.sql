-- 角色持久化表（identity RoleRepo persistence；L1 LocalTx，#1250）。
--
-- adapter `PgRoleRepo`（adapters/postgres/src/role_repo.rs）impl `identity::ports::RoleRepo`：
-- `find` = 按 (tenant, id) 读单角色；`save` = upsert（ON CONFLICT (tenant_id, id) DO UPDATE）。
-- 写经 tenant-scoped 事务先注入 tenant scope（`set_config('rss.tenant_id', $1, true)` = SET LOCAL，
-- tenancy.md §RLS 与 PG scope，与 config / session 写路径统一收口）后再 INSERT/UPSERT。
--
-- id 用 `text`（绑域内 `RoleId` newtype，本质 opaque 已校验 ID 串，不强绑 PG 类型）。
-- PRIMARY KEY (tenant_id, id)：角色 id **租户内**唯一；同 id 可跨租户共存（每租户独立角色空间）。
--   ⇒ `find`/`save` 必带 tenant，跨租天然隔离（`find` 跨租 → 0 行 → None）。
-- name `text NOT NULL`：角色显示名（非 PII）。
-- permissions `text[] NOT NULL DEFAULT '{}'`：序列化权限 ID 列表（无独立 Permission 表持久化，#1250 决策）；
--   read 时 adapter 经 `Role::hydrate` 逐个 `PermissionId::parse` 复核还原（损坏值 → Storage 错误，fail-closed）。
-- tenant_id `uuid NOT NULL`：每行租户戳记——SET LOCAL 注入锚点 + 未来 RLS policy 的 current_setting 比对锚点。
-- 预 GA **不**建 RLS policy（仓内尚无 RLS infra；同 sessions / config 表）；tenant_id 列 + SET LOCAL 已保证写入
-- tenant-correct，读经显式 `WHERE tenant_id` scope。
CREATE TABLE roles (
    tenant_id   uuid        NOT NULL,
    id          text        NOT NULL,
    name        text        NOT NULL,
    permissions text[]      NOT NULL DEFAULT '{}',
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);

-- 租户内角色枚举 / RLS scope 锚点（pre-GA 新表，普通 CREATE INDEX 留事务型 migration；非 CONCURRENTLY）。
CREATE INDEX idx_roles_tenant ON roles (tenant_id);
