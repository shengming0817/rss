# postgres migrations

`adapters/postgres/migrations/` 是 postgres adapter 的迁移单源，由 `PgStore::run_migrations`
经 `sqlx::migrate!("./migrations")`（编译期 `include_str!` 内嵌）应用。eventexec durable 拓扑
（outbox / inbox_receipts / dead_letter / saga_journal / checkpoint / projection_events）的表由 P4–P10
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

`rss_audit_admin` 是指定租户 audit read 的专用只读 LOGIN 角色，由 `0033` provision 为 `LOGIN NOBYPASSRLS`
并重置为只拥有 `audit_entries` SELECT；密码由部署 out-of-band 注入，committed SQL 不含密码。runtime 如配置
`RSS_PG_AUDIT_ADMIN_USERNAME/PASSWORD`，启动期会要求连接直连固定角色 `rss_audit_admin`、非 superuser、
非 BYPASSRLS、无其它 public relation 权限，并在只读事务内 `SET LOCAL rss.tenant_id = targetTenant` 复用现有
tenant-isolation policy。

`0034` 新增 `abac_policies` tenant 表并授予 `rss_app` SELECT/INSERT/UPDATE；policy delete 经 versioned
tombstone UPDATE，不授表级 DELETE，防止同 id 删除后重建把 CAS version 水位重置。

`0046` 新增 `resource_attributes` tenant 表并授予 `rss_app` SELECT/INSERT/UPDATE；resource attribute
expire 经 versioned tombstone UPDATE，不授表级 DELETE。主键为
`(tenant_id, contract_id, permission, resource_id, attribute_key)`，只允许动态 `resource.*` key，且
`resource.id` 保留给 HTTP route synthetic resource id，不可落库。

`0047` 前向替换 `rss_outbox_sample_backlog(text)`，在既有 `depth` / `oldest_age_seconds` 基础上返回
`partition_blocked_depth`。该值只统计同 tenant/domain/partition 前序未 published 导致被队头阻塞的行数；
函数不返回 `partition_key`，避免把业务分区键带入 metrics 或 operator 输出。

`0048` 新增 `service_token_replay_nonces` 平台表，供一次性 maintenance/operator CLI 的 service-token `jti`
防重放使用。该表不带 `tenant_id`：auth 完成前还没有可信 tenant RLS 上下文，且 `jti` replay 检查必须跨
CLI 进程全局生效。唯一键 `(nonce)` 提供原子 insert-if-absent；`expires_at` 索引用于 opportunistic prune。

`0038` 新增 `inbox_receipts` tenant 表作为 runtime durable consumer 的 receipt schema：tenant-first
主键、contract/schema header、trace/correlation、lease CAS 状态与 `FORCE RLS` 同迁移落地。该表是可变
claim/commit 状态，不是 append-only ledger，因此授予 `rss_app` SELECT/INSERT/UPDATE/DELETE。

`0039` 安装 `rss_sweep_inbox_receipts(bigint)` SECURITY DEFINER 保留期维护函数，随后完成 #1650 pre-GA
runtime receipt storage cutover；不引入 dual write、兼容 shim 或回填迁移。

`0041` 新增 `reconcile_targets` / `reconcile_leases` / `reconcile_attempts` /
`reconcile_actions` tenant 表，作为 L4 reconcile 的 durable target / lease / append-only ledger schema。
target 唯一键为 `(tenant_id, reconciler_id, resource_kind, resource_id)`；child 表均带 `tenant_id` 并通过
composite FK 指回 target。`reconcile_targets` / `reconcile_leases` 是租户内可变状态，授予 `rss_app`
SELECT/INSERT/UPDATE 且不授 DELETE；`reconcile_attempts` / `reconcile_actions` 是 append-only ledger，仅授
SELECT/INSERT 并显式 `REVOKE UPDATE, DELETE`。四表均在同一迁移内落 `FORCE RLS` 与标准 tenant policy。
本切片只提供 schema 与最小 PG API，不接 reconcile runtime worker。

`0042` 新增 `outbox_log` tenant-scoped append-only ledger，供显式 opt-in CDC outbox adapter 写入；
默认 relay outbox 仍使用 mutable `outbox` 状态表与 `rss_outbox_*` 函数。`outbox_log` 字段按 CDC 消费面固定：
`event_id`、`aggregate_type`、`aggregate_id`、topic、contract id/version、`schema_hash`、`payload bytea`、
`metadata jsonb`、`tenant_id` 与 `causation_id`。该表只授 `rss_app` SELECT/INSERT，显式 `REVOKE UPDATE,
DELETE`，并在建表迁移内落 `FORCE RLS` 与标准 tenant policy。tenant/schema header 与物理列的一致性由
DB CHECK 强制，不依赖应用约定。

`0049` 在 `outbox_log` 上新增 `occurred_at`、`trace`、`correlation_id` 三个 stored generated columns，
全部从 sealed `metadata` 单源派生；应用写路径不得单独赋值这些列。Debezium EventRouter skeleton 只把强制
非空的 `occurred_at` 发布为 broker header，nullable trace/correlation 保持 persisted-only，直到有 reviewed
null-stripping SMT/等价机制。迁移同时用 CHECK 强制 `occurredAt` 必填且为数字，trace/correlation 若存在则为非空字符串并受
长度限制。使用 `pgoutput` 的 CDC deployment 必须运行在 PostgreSQL 18+，并用
`CREATE PUBLICATION ... WITH (publish_generated_columns = stored)` 发布 stored generated columns；低于
PostgreSQL 18 的 logical replication 不发布这些 generated columns，不得启用该 CDC skeleton。

`0051` 新增 `command_journal` tenant 表，作为 durable command 的 producer-side journal / idempotency
foundation。主键为 `(tenant_id, command_id)`，另以 `(tenant_id, topic, idempotency_key)` UNIQUE 锁同租户同
topic 的幂等 claim；`command_id` / `idempotency_key` 存 storage-safe `sha256` digest，不落 raw caller key；
`request_fingerprint` 区分真实重放与 same-key payload conflict；`status` / `result_summary` /
`error_summary` 由 CHECK 固定闭值集和终态一致性。该表授予 `rss_app`
SELECT/INSERT/UPDATE 且不授 DELETE，并在建表迁移内落 `FORCE RLS` 与标准 tenant policy。业务写、
command journal claim 和 relay outbox append 必须在同一个 tenant-scoped transaction 内提交，不提供
dual-write、旧字段 fallback 或 raw pool path。

`0043` 新增 `saga_instances` tenant 表，并前向 tenantize `saga_journal`。`saga_instances` 保存
instance status 与 lease token/holder/epoch/expiry，授予 `rss_app` SELECT/INSERT/UPDATE 且不授 DELETE；
`saga_journal` 主键改为 `(tenant_id, saga_id, seq)`，通过 composite FK 指回 instance，仍是 append-only，
仅授 `rss_app` SELECT/INSERT 并显式 `REVOKE UPDATE, DELETE`。两表均在迁移内落 `FORCE RLS` 与标准 tenant
policy。legacy global `saga_journal` 若非空则 fail-fast，不做隐式 backfill。

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
