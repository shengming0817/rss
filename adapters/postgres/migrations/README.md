# postgres migrations

`adapters/postgres/migrations/` 是 postgres adapter 的迁移单源，由 `PgStore::run_migrations`
经 `sqlx::migrate!("./migrations")`（编译期 `include_str!` 内嵌）应用。eventexec durable 拓扑
（outbox / inbox_dedup / dead_letter / saga_journal / checkpoint / projection_events）的表由 P4–P10
各自的迁移按需新增；`0001_init_schema.sql` 是基线占位（不建表）。

## 命名

`{序号}_{动词}_{对象}.sql`（`rust-standards.md` §数据库迁移）。

- `序号`：4 位零填充、单调递增（`0001`、`0002`…）。sqlx 解析 `{version}_{description}`，`version` 须能 parse 为正 `i64`。
- `动词_对象`：如 `create_outbox`、`add_lease_token_to_outbox`。下划线在 sqlx 展示时转空格。
- 例：`0002_create_outbox.sql`、`0003_add_retry_after_to_outbox.sql`。

本仓只用**前向**迁移（不写 `.up.sql` / `.down.sql` 可逆对）——pre-GA、无外部消费方、回滚靠新前向迁移修正。

## 只增不改

已提交的迁移文件**只增不改**（`rust-standards.md`）。例外须 ADR 说明。

机器守卫：sqlx 在 `_sqlx_migrations` 表记每个已应用迁移的 `checksum`；改动已应用文件的内容会在下次
`run_migrations` 触发 `VersionMismatch` 报错（Medium，运行期 fail-fast）。改顺序 / 删文件触发 `VersionMissing`。

## 索引形态（阶段约定）

- pre-GA / 有序迁移集 / 新建或空表：用普通 `CREATE INDEX`（留在事务型迁移内）。
- `CREATE INDEX CONCURRENTLY`：**仅** post-GA 给已填充、有在线流量的生产表加索引（不可在事务块内，
  需 `no_tx` 迁移）。pre-GA 阶段禁用。

## Tenant 表 RLS（行级安全）

新增含 `tenant_id` 列的表（tenant 表）必须随附 RLS 三件套，可在同一迁移或后续前向迁移中落地：

1. `ENABLE ROW LEVEL SECURITY`
2. `FORCE ROW LEVEL SECURITY`（使 owner 连接亦受 policy 约束）
3. tenant-isolation policy：`USING/WITH CHECK (tenant_id = current_setting('rss.tenant_id', true)::uuid)`

`cargo xtask schema-rls`（INVARIANT `TENANCY-RLS-FORCE-01`，接入 `cargo xtask verify` / `ci`，
Medium）扫描 schema 快照，缺三件套即门红。

`0004` / `0005` / `0008` 建表时注释「预 GA 不建 RLS」；依「只增不改」规则不可回改——
`0009_enable_tenant_rls.sql` 补齐三张 tenant 表（sessions / config_entries / roles）的 RLS，
0009 起三表均受 policy 保护。

非 owner serving role `rss_app`（NOLOGIN、NOBYPASSRLS，仅三张 tenant 表的 DML grant）由 `0009`
provision；生产 LOGIN 凭据 out-of-band 注入，committed SQL 不含密码。

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
