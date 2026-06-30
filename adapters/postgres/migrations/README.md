# postgres migrations

`adapters/postgres/migrations/` 是 postgres adapter 的迁移单源，由 `PgStore::run_migrations`
经 `sqlx::migrate!("./migrations")`（编译期 `include_str!` 内嵌）应用。eventexec durable 拓扑
（outbox / inbox_dedup / dead_letter / saga_journal / checkpoint / projection_events）的表由 P4–P10
各自的迁移按需新增；`0001_init_schema.sql` 是基线占位（不建表）。

## 命名

`{序号}_{动词}_{对象}.sql`（`rust-standards.md` §数据库迁移）。

- `序号`：4 位零填充、单调递增、**全局唯一**（`0001`、`0002`…）。sqlx 解析 `{version}_{description}`，`version` 须能 parse 为正 `i64`。
  序号唯一性由 `cargo xtask migrations`（接入 `cargo xtask verify` / `ci`，Medium，INVARIANT `MIGRATION-SERIAL-UNIQUE-01`）机器守——
  两文件同序号即门红（sqlx 按 `version` 键迁移，重号会让 `run_migrations` 在任意 fresh DB 上 `VersionMismatch`／重复主键，#1134 修复）。
- `动词_对象`：如 `create_outbox`、`add_lease_token_to_outbox`。下划线在 sqlx 展示时转空格。
- 例：`0003_create_outbox.sql`、`0016_add_seq_and_partition_to_outbox.sql`。

本仓只用**前向**迁移（不写 `.up.sql` / `.down.sql` 可逆对）——pre-GA、无外部消费方、回滚靠新前向迁移修正。

## 只增不改

已提交的迁移文件**只增不改**（`rust-standards.md`）。例外须 ADR 说明。

机器守卫：sqlx 在 `_sqlx_migrations` 表记每个已应用迁移的 `checksum`；改动已应用文件的内容会在下次
`run_migrations` 触发 `VersionMismatch` 报错（Medium，运行期 fail-fast）。改顺序 / 删文件触发 `VersionMissing`。

> **例外（#1134，pre-GA append-only carve-out）**：本次把 4 对历史重复序号（旧 `0002`/`0008`/`0009`/`0013`，
> 各两文件同号）整体重编为唯一连续 `0001`–`0018`。依据：pre-GA 无外部消费方、无已部署 DB（`_sqlx_migrations`
> 无历史 checksum 可冲突），重号本就让迁移在任意 fresh DB 上无法应用（非「只增不改」要保护的演进，而是 bug 修复）。
> 同批新增 `cargo xtask migrations` 唯一性门（见 §命名），杜绝再发生。ADR 见
> `docs/architecture/202606271500-011-migration-serial-renumber.md`。
>
> **例外扩展（#1255，pre-GA residual duplicate carve-out）**：PR329 后 `develop` 再次残留两个 `0020`
>（`0020_add_inbox_dedup_sweep_index.sql` / `0020_harden_dead_letter_rls.sql`）。本 PR 仅重编号后者及其后续
> dead-letter sweep migration（`0021`/`0022`），不改 SQL 语义；RLS predicate 修复改用新的 `0024` 前向迁移。
> 依据同 ADR-011：pre-GA 且重号本身已让 fresh DB migration 不可应用。
>
> **例外扩展（#1477，pre-GA residual duplicate carve-out）**：`develop` 仍残留两个 `0026`
>（`0026_create_role_bindings.sql` / `0026_grant_distributed_cas.sql`）。后者仅一条 grant，本 PR 将该 grant
> 并入唯一的 `0026_create_role_bindings.sql` 并删除重复文件，不改授权语义；依据同上，重号本身已让 fresh DB
> migration 不可应用。
>
> **例外扩展（#1579，pre-GA residual duplicate carve-out）**：`develop` 残留两个 `0028`
>（`0028_encrypt_dead_letter_original_entry.sql` / `0028_grant_runtime_serving.sql`）。后者仅为 serving
> role 补 runtime DML grant，本 PR 将其重编号为 `0030_grant_runtime_serving.sql`，不改 SQL 语义；依据同上，
> 重号本身已让 fresh DB migration 不可应用。

## 索引形态（阶段约定）

- pre-GA / 有序迁移集 / 新建或空表：用普通 `CREATE INDEX`（留在事务型迁移内）。
- `CREATE INDEX CONCURRENTLY`：**仅** post-GA 给已填充、有在线流量的生产表加索引（不可在事务块内，
  需 `no_tx` 迁移）。pre-GA 阶段禁用。

## Tenant 表 RLS（行级安全）

新增含 `tenant_id` 列的表（tenant 表）必须随附 RLS 三件套，可在同一迁移或后续前向迁移中落地：

1. `ENABLE ROW LEVEL SECURITY`
2. `FORCE ROW LEVEL SECURITY`（使 owner 连接亦受 policy 约束）
3. tenant-isolation policy：`USING/WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)`

`cargo xtask schema-rls`（INVARIANT `TENANCY-RLS-FORCE-01`，接入 `cargo xtask verify` / `ci`，
Medium）扫描 schema 快照，缺三件套即门红。

`0005` / `0006` / `0009` 建表时注释「预 GA 不建 RLS」；依「只增不改」规则不可回改——
`0012_enable_tenant_rls.sql` 补齐四张 tenant 表（sessions / config_entries / roles / secret_refs）的 RLS；
`0024_harden_tenant_rls_empty_setting.sql` 将旧 policy 前向升级为 NULLIF 形态，避免空 GUC cast 在 policy 判定前报错。

非 owner serving role `rss_app`（NOLOGIN、NOBYPASSRLS）由 `0012` provision，并随各表落地按最小权限
**forward-only 增量授权**（不回改历史迁移，新增表在其建表迁移内补 grant）：

- `0012`：原四张 tenant 表（`sessions` / `config_entries` / `roles` / `secret_refs`）DML（SELECT/INSERT/UPDATE/DELETE）。
  `sessions` 过期清理由 `0032` 的窄 `rss_sweep_expired_sessions()` SECURITY DEFINER 函数授权给
  `rss_app`，函数按 `expires_at, session_id` 固定删除单批最多 1000 条 `expires_at <= now()` 的 session；
  函数 owner 是 NOLOGIN `rss_session_maintenance`（BYPASSRLS），用于 FORCE RLS 下的全域 expired-only sweep。
  `0032` 同时 `REVOKE DELETE ON sessions FROM rss_app`，不保留 `rss_app` 表级删除权限或 tenant/raw SQL/retain
  参数入口。
- `0015` `credentials`、`0017` `refresh_tokens`：补全 DML（tenant 表）。
- append-only 表只授 SELECT + INSERT（无 UPDATE/DELETE）：`0018` `audit_entries`、`0019` `auth_audit_events`（+ 其 id 序列）、`0021` `dead_letter`。`dead_letter` 保留期清理由 `0030` 的窄 `rss_sweep_dead_letter(bigint)` SECURITY DEFINER 函数授权给 `rss_app`，不授直接 DELETE；该函数 owner 是 NOLOGIN `rss_dead_letter_maintenance`，仅用于 FORCE RLS 下的全域 30 天 retention sweep。

生产 `rss_app` LOGIN 凭据 out-of-band 注入，committed SQL 不含密码。后续新增 tenant / append-only 表须在其
建表迁移内为 `rss_app` 补最小授权（tenant 表 DML、append-only 表 SELECT+INSERT），与上表同范式。

## Append-only 表（REVOKE 强制）

append-only 表（如 `projection_events`）在前向迁移内用 `REVOKE UPDATE, DELETE ON <table> FROM <role>` 强制 DB
引擎层不可绕的只追加约束（Hard 主守卫，INVARIANT PROJECTION-APPEND-ONLY-01）。
forward-only 原则同样适用：`REVOKE` 不写 `.down.sql`，逆转须新前向迁移 `GRANT`，不改历史迁移文件。

**Retention / 旧数据清理**：append-only 表（`projection_events` 等）的旧数据删除须经 DBA（表 owner 角色）
或新前向迁移显式 `GRANT DELETE TO <清理角色>`，不可由应用 serving role（已 REVOKE DELETE）直接执行。
forward-only 不写 `.down.sql`；当前 pre-GA 无自动 retention 策略或分区，表膨胀治理待后续规划。

## 新字段

新增列必须有默认值或允许 `NULL`（避免对已有行的 `NOT NULL` 回填失败）。

## 调用时机与行为

- **时机**：`PgStore::run_migrations()` 在组合根 / bootstrap 中、`Domain::init` **之前**调用（init 不做外部 I/O，`domain-patterns.md` §Init fail-fast）。本基座 PR 只提供方法，接线到 bootstrap 属后续。
- **失败传播**：迁移失败返回 `PgError::Migrate(MigrateError)`，调用方应 **fail-fast**（启动中止），不静默继续。adapter 内已 `error!` 记账失败、`info!` 记账成功。
- **多实例并发**：`sqlx::migrate!` 默认 `locking = true`（pg advisory lock）——多实例同时启动时只有一个实例真正执行迁移，其余等待锁释放后看到已应用、各自 no-op。
- **编译期内嵌**：`sqlx::migrate!("./migrations")` 在编译时把每个 `.sql` 内嵌进二进制（不依赖运行时文件系统）。**改动迁移文件后须重编 postgres crate**，否则旧 binary 跑的是旧 SQL。

## 本地应用 / 测试

集成测试（`tests/pg_integration.rs`，`integration` feature 门控）对真实 postgres 跑 `run_migrations`
并验证幂等。本地用 docker postgres + libpq 标准 env（`PGHOST` / `PGPORT` / `PGDATABASE` / `PGUSER` /
`PGPASSWORD`）：

```bash
PGHOST=127.0.0.1 PGPORT=5432 PGDATABASE=rss PGUSER=rss PGPASSWORD=... \
  cargo nextest run -p postgres --features integration
```

`PGHOST` 未设时集成测试整组跳过（azure 无 CI，不阻塞 `cargo xtask verify`）。
