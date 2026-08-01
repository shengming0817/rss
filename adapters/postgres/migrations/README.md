# postgres migrations

`adapters/postgres/migrations/` 是 postgres adapter 的迁移单源，仅由 `postgres-migration`
operator crate 经 `sqlx::migrate!` 编译期内嵌并应用；SQL-text-free
`postgres-migration-inventory` 基础 crate 单次生成 typed version/checksum facts，供 operator、serving
ledger gate 与部署生成共同消费。serving postgres adapter 不包含 SQL 或迁移执行能力。eventexec durable 拓扑
（outbox / inbox_receipts / dead_letter / saga_journal / checkpoint / projection_events）的表由 P4–P10
各自的迁移按需新增；`0001_init_schema.sql` 是基线占位（不建表）。

## 命名

`{序号}_{动词}_{对象}.sql`（`rust-standards.md` §数据库迁移）。

- `序号`：4 位零填充、单调递增、**全局唯一**（`0001`、`0002`…）。sqlx 解析 `{version}_{description}`，`version` 须能 parse 为正 `i64`。
  序号唯一性由 `cargo xtask migrations`（接入 `cargo xtask verify` / `ci`，Medium，INVARIANT `MIGRATION-SERIAL-UNIQUE-01`）机器守——
  两文件同序号即门红（sqlx 按 `version` 键迁移，重号会让 `rss postgres migrate-all` 在任意 fresh DB 上 `VersionMismatch`／重复主键，#1134 修复）。
- `动词_对象`：如 `create_outbox`、`add_lease_token_to_outbox`。下划线在 sqlx 展示时转空格。
- 例：`0003_create_outbox.sql`、`0016_add_seq_and_partition_to_outbox.sql`。

本仓只用**前向**迁移（不写 `.up.sql` / `.down.sql` 可逆对）——pre-GA、无外部消费方、回滚靠新前向迁移修正。

## 只增不改

已提交的迁移文件**只增不改**（`rust-standards.md`）。例外须 ADR 说明。

机器守卫：sqlx 在 `_sqlx_migrations` 表记每个已应用迁移的 `checksum`；改动已应用文件的内容会在下次
`rss postgres migrate-all` 触发 `VersionMismatch` 报错（Medium，运行期 fail-fast）。改顺序 / 删文件触发 `VersionMissing`。

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
- append-only 表只授 SELECT + INSERT（无 UPDATE/DELETE）：`0018` `audit_entries`、`0019` `auth_audit_events`（+ 其 id 序列）、`0021` `dead_letter`。`0030` 的历史 retention-only 删除面已由 `0063` 破坏式移除；当前 `rss_app` 不可执行任何 DLX lifecycle 函数，HOT 删除只能由独立 `rss_dlx_archiver` 经 archive-before-purge 固定函数完成。

生产 `rss_app` LOGIN 凭据 out-of-band 注入，committed SQL 不含密码。后续新增 tenant / append-only 表须在其
建表迁移内为 `rss_app` 补最小授权（tenant 表 DML、append-only 表 SELECT+INSERT），与上表同范式。

`rss_audit_admin` 是指定租户 audit read 的专用只读 LOGIN 角色，由 `0033` provision 为 `LOGIN NOBYPASSRLS`
并重置为只拥有 `audit_entries` SELECT；密码由部署 out-of-band 注入，committed SQL 不含密码。runtime 如配置
`RSS_PG_AUDIT_ADMIN_USERNAME/PASSWORD`，启动期会要求连接直连固定角色 `rss_audit_admin`、非 superuser、
非 BYPASSRLS、无其它 public relation 权限，并在只读事务内 `SET LOCAL rss.tenant_id = targetTenant` 复用现有
tenant-isolation policy。

`0067` 新增 LocalOnly tenant read lane 固定角色 `rss_app_read`。它是 `LOGIN NOINHERIT`，无 superuser、
`BYPASSRLS`、建库、建角色、replication、membership 或 object ownership 能力；role config 精确固定
`default_transaction_read_only=on` 且 `search_path=pg_catalog, public`。迁移先清空该角色在当前数据库的 relation/column/sequence/function/schema、
large-object 与 parameter ACL（同时收敛会影响 reader 的 PUBLIC LO/parameter ACL），再动态只给当前 `public`
下含 `tenant_id` 的 base/partition relations 授 SELECT；不使用
`ALTER DEFAULT PRIVILEGES`，后续 tenant relation 必须在自己的迁移中显式授 reader SELECT。密码继续由部署
out-of-band 注入。runtime 还会用显式 `BEGIN READ ONLY`，并在 mint reader capability 前核验角色、有效 ACL、
`lo_compat_privileges=off`、tenant GUC 与全部 tenant relation 的 FORCE RLS/policy 真实 catalog dependency，
任一漂移均拒绝启动。
由于 PostgreSQL 没有针对单一角色的 ACL DENY，`0067` 同时撤销当前数据库的 PUBLIC TEMPORARY，并把该权限
显式回授既有 writer `rss_app`；reader 只获 CONNECT，因此不改变 writer 行为，也不让 PUBLIC TEMP 绕过 reader
的精确数据库权限门。
存量库由待发布镜像的 `rss postgres migrate-all` forward-only migration Job 在 serving phase 前推进至
当前 HEAD；reader 密码随后 provision。旧的 0067 专用 reader-lane 命令已删除，不保留版本特判入口。

### 0068 service-token replay store 破坏性切换

`0068` 删除存放 raw `jti` 的 `service_token_replay_nonces`，只保留固定 32-byte
`SHA-256(issuer, audience, verified kid, jti)` digest。不存在兼容视图、双写或旧表读取。
旧行缺少 issuer/audience/kid，无法安全转换；只要旧表仍有未过期行，迁移就以固定错误失败并完整回滚。

这是 non-rolling、forward-only cutover。唯一受支持的迁移入口是待发布镜像中的
`rss postgres migrate-all` migration Job；serving 进程绝不执行迁移，只读核验 ledger 精确等于 HEAD。
不得用旧镜像、maintenance CLI 或手工 `psql -f` 替代。按以下顺序执行：

1. **停止旧世界**：停止签发旧 operator token，等待其最长 TTL 到期；随后把所有旧 runtime 实例缩容到
   0，并停止 projection、audit-ledger、DLQ、reconcile 和 settings maintenance CLI。确认数据库中不再有
   `application_name IN ('rss-postgres-writer', 'rss-postgres-maintenance')` 的旧进程；不得手工删除仍有效的
   防重放证据。
2. **迁移前探针**：用 migrator 凭据运行下列只读 SQL。结果必须依次为 migration version `67`、active
   legacy rows `0`、旧 writer/maintenance sessions `0`、旧表上的冲突锁 `0`；任一不满足均中止。

   ```sql
   SELECT max(version) FROM public._sqlx_migrations;
   SELECT count(*) FROM public.service_token_replay_nonces
    WHERE expires_at > pg_catalog.clock_timestamp();
   SELECT count(*) FROM pg_catalog.pg_stat_activity
    WHERE application_name IN ('rss-postgres-writer', 'rss-postgres-maintenance');
   SELECT count(*) FROM pg_catalog.pg_locks AS held
    WHERE held.relation = 'public.service_token_replay_nonces'::regclass
      AND held.granted;
   ```

3. **唯一 migration runner**：只启动 1 个待发布镜像的 `rss postgres migrate-all` Job，不并行启动第二个实例或任何
   maintenance CLI。等待 Job 完成；migration 非零退出即进入步骤 7，
   不得继续扩容。
4. **迁移后 catalog / ACL 探针**：仍以 migrator 凭据确认 ledger 为 `68`、旧表消失、新表存在；两个函数
   owner 均为 `rss_service_token_replay_owner`、`pg_proc.proconfig` 中 search path 精确为
   `search_path=pg_catalog, pg_temp`，`rss_app` 仅有函数 EXECUTE、没有新表权限。

   ```sql
   SELECT max(version) FROM public._sqlx_migrations;
   SELECT to_regclass('public.service_token_replay_nonces') IS NULL,
          to_regclass('public.service_token_replay_keys') IS NOT NULL;
   SELECT proc.proname,
          pg_catalog.pg_get_userbyid(proc.proowner) AS owner,
          proc.proconfig,
          has_function_privilege('rss_app', proc.oid, 'EXECUTE') AS rss_app_can_execute
     FROM pg_catalog.pg_proc AS proc
    WHERE proc.oid IN (
      'public.rss_service_token_replay_check_and_record(bytea,timestamptz)'::regprocedure,
      'public.rss_service_token_replay_sweep_expired()'::regprocedure
    )
    ORDER BY proc.proname;
   SELECT has_table_privilege('rss_app', 'public.service_token_replay_keys', 'SELECT')
       OR has_table_privilege('rss_app', 'public.service_token_replay_keys', 'INSERT')
       OR has_table_privilege('rss_app', 'public.service_token_replay_keys', 'UPDATE')
       OR has_table_privilege('rss_app', 'public.service_token_replay_keys', 'DELETE')
      AS forbidden_table_access;
   ```

5. **以 `rss_app` 实测固定函数**：用 migrator 会话在回滚事务内切换角色，验证 consume/sweep 可执行且
   不留下探针行；任一错误均中止。

   ```sql
   BEGIN;
   SET LOCAL ROLE rss_app;
   SELECT public.rss_service_token_replay_check_and_record(
     decode(repeat('00', 32), 'hex'),
     pg_catalog.clock_timestamp() + interval '10 minutes'
   );
   SELECT public.rss_service_token_replay_sweep_expired();
   ROLLBACK;
   ```

6. **只启动新世界**：确认 singleton 的 `/readyz` 响应 healthy，且
   `service_token_replay_sweeper` probe 已注册并 healthy；保留该实例，再逐步扩容同一待发布镜像。迁移成功后
   严禁重启旧 binary 或旧 CLI。
7. **失败恢复**：若 singleton 在提交 `0068` 前退出，只在重新执行步骤 2 并确认 ledger 仍为 `67`、旧表存在、
   新表不存在后，才可恢复旧实例和旧 token 签发；保留失败日志并修正 active row/lock 等前置条件后重试。
   若 ledger 已为 `68`，这是已提交的 forward-only 状态：不得启动旧 binary；修复新版本的启动配置，重启同一
   待发布镜像并重新执行步骤 4–6。

认证热路径只可执行固定函数 `rss_service_token_replay_check_and_record(bytea, timestamptz)`，以单条
`INSERT ... ON CONFLICT DO NOTHING` 原子消费。`rss_app` 没有新表的直接权限。过期清理必须由独立维护任务
调用 `rss_service_token_replay_sweep_expired()`；每次最多删除 1000 行，并保留 5 分钟安全余量，禁止在每次
认证时附带清理。

### 0069 account security state 原子切换

`0069` 为每个 credential 建立唯一 durable lifecycle 真源
`account_security_states`。迁移先阻断 credential writer，再把全部既有 credential 一次性回填为
`active / authn_epoch=0 / version=1`；随后安装双向复合 FK：security→credential 使用
`ON DELETE CASCADE`，credential→security 使用 `DEFERRABLE INITIALLY DEFERRED`。因此事务提交时两表严格
一对一，credential save 可以在同一事务内按 credential→security 顺序写入，但缺失 state、跨主体 rebind
或单独删除 state 都无法提交。status、epoch、version 与时间顺序同时由 closed CHECK/NOT NULL 固定。

这是 non-rolling、forward-only cutover：执行 migration 前必须停止仍会单表写 credential 的旧 binary；
迁移成功后只能启动在同一 writer 事务内共同写入 credential/security 的新 binary，不提供 trigger、默认
state、双写或自动补行 fallback。表启用并强制 RLS，policy 使用 canonical
`NULLIF(current_setting('rss.tenant_id', true), '')::uuid`；`rss_app` 仅获 SELECT/INSERT/UPDATE，
`rss_app_read` 仅获 SELECT，两者都没有 security DELETE。

既有 refresh family 无法可靠反推出签发时的 authentication epoch。切换前必须在旧 binary 仍运行时通过正常
撤销流程把所有 `status='active'` legacy family 置为 revoked，再停止 writer。迁移锁定 `refresh_tokens` 后
若仍有 active 行就 fail-closed；通过门后在同一事务删除已 consumed/revoked 的无 epoch 历史行，再增加非负、
非空 `authn_epoch_at_issue`。它不会用当前 account epoch 猜测回填，也不保留 legacy decoder；新 binary 的
初始签发和每次轮换都继承该 family epoch。

唯一正式 runner 是待发布镜像的 `rss postgres migrate-all` Job；不得使用旧 binary、maintenance CLI、手工
`psql -f` 或通用迁移脚本。按以下 non-rolling runbook 执行：

1. **停止旧 writer 并做迁移前探针。** 将全部旧 runtime 缩容到 0。用 migrator 凭据确认 ledger 为 `68`，
   `pg_stat_activity` 中没有 `rss-postgres-writer` / `rss-postgres-maintenance` 会话，并确认
   `pg_locks` 中没有授予在 `public.credentials` / `public.refresh_tokens` 上的冲突锁，并确认 active legacy
   refresh family 已全部通过正常流程撤销；任一结果不满足即中止。已 consumed/revoked 的历史行由 `0069`
   锁内清理，不得手工 DELETE。

   ```sql
   SELECT max(version) FROM public._sqlx_migrations;
   SELECT count(*) FROM pg_catalog.pg_stat_activity
    WHERE application_name IN ('rss-postgres-writer', 'rss-postgres-maintenance');
   SELECT count(*) FROM pg_catalog.pg_locks
    WHERE relation IN ('public.credentials'::regclass, 'public.refresh_tokens'::regclass)
      AND granted
      AND mode IN ('RowExclusiveLock', 'ShareUpdateExclusiveLock',
                   'ShareLock', 'ShareRowExclusiveLock',
                   'ExclusiveLock', 'AccessExclusiveLock');
   SELECT count(*) AS active_legacy_refresh_families
     FROM public.refresh_tokens
    WHERE status = 'active';
   ```

2. **容量与复制 fail-closed gate。** 在旧 writer 已停止、singleton 尚未启动时，在 primary DB host
   运行 [`docs/ops/0069-account-security-capacity-gate.sh`](../../../docs/ops/0069-account-security-capacity-gate.sh)。
   `EXPECTED_REPLICAS` 必须来自部署 inventory，`MAINTENANCE_WINDOW_SECONDS` 是此刻剩余窗口；gate 会拒绝
   credential 行数/字节超过演练 envelope、data/`pg_wal`/archive 余量不足、archive 不可读、replica
   数量或 streaming/byte/replay lag 不符，以及不足 8 分钟的剩余窗口。凭据只能经 named libpq service
   与 `0600` passfile 提供。只有打印 `0069 account-security capacity gate: PASS` 的同次运行可授权下一步，
   输出须随 rollout receipt 保存；不得复用旧 PASS。

   ```sh
   PGSERVICE=rss-owner \
   PGSERVICEFILE=/run/rss/pg_service.conf \
   PGPASSFILE=/run/rss/pgpass \
   EXPECTED_REPLICAS=2 \
   MAINTENANCE_WINDOW_SECONDS=900 \
   WAL_ARCHIVE_DIR=/var/lib/postgresql/wal-archive \
   docs/ops/0069-account-security-capacity-gate.sh
   docs/ops/0069-account-security-capacity-gate.selftest.sh
   ```

3. **运行 singleton。** 只启动一个待发布镜像的 `rss postgres migrate-all` Job；`0069` 内置
   `lock_timeout=5s`、`statement_timeout=5min`，任一超时或 migration 非零退出都不得继续扩容。运行期间若 data、`pg_wal`、archive 或 replica 指标越过
   gate receipt 的预算，立即停止扩容流程并等待该事务按 timeout 回滚；不得把已失效的 preflight 当作授权。
4. **迁移后验证。** 仍以 migrator 凭据确认 `_sqlx_migrations=69`，credential/security 缺失计数为 0，
   双向 FK（含 deferred 反向 FK）、四项 CHECK、FORCE RLS/policy 均存在；同时确认 `rss_app` 只有
   SELECT/INSERT/UPDATE、`rss_app_read` 只有 SELECT，二者均无 DELETE，并确认 refresh epoch 列及 CHECK
   已安装。至少执行：

   ```sql
   SELECT max(version) AS _sqlx_migrations FROM public._sqlx_migrations;
   SELECT count(*) AS missing_state
     FROM public.credentials AS credential
     LEFT JOIN public.account_security_states AS security
       USING (tenant_id, user_id)
    WHERE security.user_id IS NULL;
   SELECT conname, contype, condeferrable, condeferred,
          pg_catalog.pg_get_constraintdef(oid)
     FROM pg_catalog.pg_constraint
    WHERE conrelid IN ('public.credentials'::regclass,
                       'public.account_security_states'::regclass)
      AND (contype = 'f' OR conname LIKE 'account_security_states_%')
    ORDER BY conname;
   SELECT relrowsecurity, relforcerowsecurity
     FROM pg_catalog.pg_class
    WHERE oid = 'public.account_security_states'::regclass;
   SELECT policyname, qual, with_check
     FROM pg_catalog.pg_policies
    WHERE schemaname = 'public' AND tablename = 'account_security_states';
   SELECT grantee, privilege_type
     FROM information_schema.role_table_grants
    WHERE table_schema = 'public' AND table_name = 'account_security_states'
      AND grantee IN ('rss_app', 'rss_app_read')
    ORDER BY grantee, privilege_type;
   SELECT column_name, is_nullable, data_type
     FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'refresh_tokens'
      AND column_name = 'authn_epoch_at_issue';
   ```

5. **恢复分支。** 若 singleton 在提交 `0069` 前失败，只在重跑步骤 1–2 并确认 ledger 仍为 `68` 后修复锁或
   容量前置条件并重跑；需要恢复服务时只能恢复旧 binary。若 ledger 已为 `69`，禁止启动旧 binary：完成
   步骤 4 的 catalog/ACL/缺失-state 验证后，只能修复新版本启动配置并启动同一待发布镜像。

`0034` 新增 `abac_policies` tenant 表并授予 `rss_app` SELECT/INSERT/UPDATE；policy delete 经 versioned
tombstone UPDATE，不授表级 DELETE，防止同 id 删除后重建把 CAS version 水位重置。

`0046` 新增 `resource_attributes` tenant 表并授予 `rss_app` SELECT/INSERT/UPDATE；resource attribute
expire 经 versioned tombstone UPDATE，不授表级 DELETE。主键为
`(tenant_id, contract_id, permission, resource_id, attribute_key)`，只允许动态 `resource.*` key，且
`resource.id` 保留给 HTTP route synthetic resource id，不可落库。

`0047` 前向替换 `rss_outbox_sample_backlog(text)`，在既有 `depth` / `oldest_age_seconds` 基础上返回
`partition_blocked_depth`。该值只统计同 tenant/domain/partition 前序未 published 导致被队头阻塞的行数；
函数不返回 `partition_key`，避免把业务分区键带入 metrics 或 operator 输出。

`0048` 曾新增 raw `jti` 的 `service_token_replay_nonces` 平台表；这是只用于重放历史 ledger 的迁移态。
`0068` 已将其破坏性删除，当前代码和权限不得再次读写该表，也不得恢复 opportunistic auth-path prune。

`0038` 新增 `inbox_receipts` tenant 表作为 runtime durable consumer 的 receipt schema：tenant-first
主键、contract/schema header、trace/correlation、lease CAS 状态与 `FORCE RLS` 同迁移落地。该表是可变
claim/commit 状态，不是 append-only ledger，因此授予 `rss_app` SELECT/INSERT/UPDATE/DELETE。

`0039` 最初安装 `rss_sweep_inbox_receipts(bigint)` SECURITY DEFINER 保留期维护函数，随后完成 #1650 pre-GA
runtime receipt storage cutover；`0060` 破坏式删除该签名并以 policy-bound 零参数函数取代，不保留 overload。

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

`0055` 为 mutable `outbox` 与 CDC `outbox_log` 安装同一 `rss-outbox-fact-v1` canonical
fingerprint；`fact_fingerprint` 是 32-byte stored generated column，应用不可显式写入。同
`event_id` 只有 fingerprint 相等时才是 `SameFact`，不等则是 typed conflict 并回滚业务
事务。旧 mutable 行由 generated expression 确定性回填；旧 CDC 行缺失
`partition_key` 无法无损恢复，故 migration 在 `outbox_log` 非空时用静态错误 fail-closed，
不猜测、不留兼容路径。metadata number 冻结为 exact decimal canonical spelling：去符号零、前导零和
coefficient 尾零后编码成 `<integer-coefficient>e<base10-exponent>`（例如 `1e2`/`100.0` → `1e2`、
`1.2300` → `123e-2`、`1e-7` → `1e-7`、`-0` → `0e0`）；Rust 启用 arbitrary-precision JSON
保留输入精度，PostgreSQL 从 exact `jsonb numeric` 做同算法转换，不依赖两端默认格式化。

### 0055 CDC cutover runbook（一次性、无兼容路径）

1. **冻结并存档。** 停止所有 CDC outbox producer；暂停 Kafka Connect connector，确认 task 为
   `PAUSED`。分别保存 `GET /connectors/<name>/config`、`GET /connectors/<name>/status`、
   `GET /connectors/<name>/offsets` 响应并做 SHA-256；用
   `SELECT * FROM pg_publication_tables WHERE pubname='<publication>' ORDER BY 1,2,3` 保存 publication
   membership。执行 `SELECT count(*) FROM outbox_log`，结果必须为 `0`；非零即终止，不 delete、不猜测
   partition、不继续迁移。用 `COPY (SELECT * FROM outbox_log ORDER BY event_id) TO STDOUT (FORMAT binary)`
   生成空表基线 archive 并保存 checksum，作为 cutover 审计证据。
2. **容量/锁预检。** 确认 `pg_total_relation_size('outbox') <= 10 GiB`，maintenance window 至少覆盖
   heap rewrite；确认无长事务持有 `outbox`/`outbox_log` 锁。0055 自身以 `lock_timeout=5s`、
   `statement_timeout=5min` fail-closed，超限或超时只允许扩大已评审的维护窗口后重跑，不启用旧写路径。
3. **迁移。** 保持 connector paused，运行唯一正式 migration runner。验证 `outbox_log.partition_key`、
   两表 stored `fact_fingerprint`、32-byte CHECK 和 canonical helper privilege；运行共享 Rust/SQL golden
   vectors。migration 事务失败时 schema 原子回滚，connector 保持 paused；migration 成功后只允许前向修复。
4. **恢复 publication。** PostgreSQL 18+ 使用
   `CREATE PUBLICATION <publication> FOR TABLE outbox_log WITH (publish_generated_columns = stored)`；若
   publication 已存在，则在同一维护窗口按存档 membership 重建并逐行比对 `pg_publication_tables`。
   低于 PostgreSQL 18 直接终止 cutover，不省略 generated column。
5. **恢复 connector/offset。** connector 必须 stopped 时，以存档 config 原样 `PUT /connectors/<name>/config`，
   再用 `PATCH /connectors/<name>/offsets` 恢复已存档 partition/LSN offset；读取 `/offsets` 做精确比对后才
   resume。禁止 `snapshot.mode=initial`、新 consumer group 或从 earliest 重放来替代 offset restore。
6. **验收与解冻。** 写入一个新 logical fact，确认 connector 只发布一次且消息包含 generated
   fingerprint/header；重试同事实得到 SameFact，异事实得到 typed Conflict。记录 publication、connector
   config/offset、archive checksum 和 golden-vector 结果后，才恢复 producer 流量。archive 按事件数据保留
   策略存入受控对象存储；不得把 payload/metadata 写入工单或日志。

`0056` 为 mutable `outbox` 增加 `published_at` / `dlx_at`。历史 terminal 行以既有 `updated_at`
确定性回填；数据库 CHECK 双向绑定 status 与对应终态时间，使 terminal 缺时间、非 terminal 伪造时间均不可
持久化。publish / mark-DLX 在同一条 CAS UPDATE 中写终态时间，redrive 清空两列后恢复 pending；published
retention 只按 `published_at` 的 partial index 清理，DLX 继续保留供运维巡检。固定 SECURITY DEFINER sweeper
拒绝 `retain_seconds <= 0`，不保留旧 `created_at` predicate 或兼容 fallback。迁移只回填 terminal 行，并以
5 秒 lock timeout、5 分钟 statement timeout 和 10 GiB relation-size 上限 fail-fast；部署前须确认无长事务持有
`outbox` 锁且维护窗口可覆盖 terminal 行回填、CHECK validation 与普通事务型 partial index 重建。超限时停止启动，
扩大经评审的维护窗口后用新的 forward-only migration 调整容量边界，不绕过保护或恢复旧 sweep 路径。

`0057` 将 mutable outbox 从“扫描候选 + 单条 acquire”硬切为 typed atomic `claim_batch`。新函数在一个数据库语句/事务内按 `seq` 确定性选取、`FOR UPDATE SKIP LOCKED`、写入 UUIDv4 token 与显式 `lease_until`、并返回完整 claimed rows。`publishing` 与 token/deadline 由独立 CHECK 双向绑定；published/retry/DLX settle 必须同时匹配 token、精确 deadline 且 deadline 仍新鲜，成功后清除 lease。stale claim、backlog 与 partial index 统一以 `lease_until` 为单源，不再从 `updated_at + 60s` 推断。

### 0057 breaking cutover runbook

1. 先停止全部旧 relay 实例；旧 binary 依赖的 poll/acquire 与 settle overload 会被删除，禁止新旧版本滚动混跑。
2. 确认 `outbox <= 10 GiB`、无长事务持锁，维护窗口可覆盖 publishing deadline 回填、terminal token 清理、CHECK 与 partial index 替换。migration 以 5 秒 lock timeout / 5 分钟 statement timeout fail-fast。
3. 运行唯一正式 migration runner；若发现 `publishing` 行缺 token 则终止，不伪造所有权。失败后只做新的 forward-only 修复，不恢复旧函数。
4. 在 0057 cutover 当时验证 `rss_app` 仅有新 claim/settle/redrive/backlog 函数 EXECUTE，旧 poll/acquire 及旧
   settle 签名不存在；再启动新 binary。升级到 0060 后 redrive 权限按 0060 runbook 从 `rss_app` 撤销。

`0058` / `0059` 将 `secret_refs` 固化为正版本、serving role append-only。SQLx applies pending migrations in
version order，并在某一版本 apply 失败时立即返回；因此异常发生后 0058 remains the first pending migration，
no later forward migration can run first。不可把 forward-only 原则误作失败 migration 的恢复调度机制。

部署含 0058 的 binary 前必须完成以下受审计 preflight；不得等启动 migration 失败后再准备修复：

1. 冻结所有 `secret_refs` writer，记录部署 / change ticket、数据库标识和 preflight 时间窗。
2. 用表 owner 的只读 maintenance session 执行
   `SELECT count(*) FROM secret_refs WHERE version <= 0`。结果为 0 才能继续部署；结果非 0 时终止 rollout，
   把 `(tenant_id, secret_key, version)` inventory 保存到受控审计存储，不写入普通日志或 PR 评论。
3. 由 settings owner 对每条异常历史给出明确的旧版本到新版本映射，再由 DBA review。`version` 是外部可查询的
   历史坐标且参与 `(tenant_id, secret_key, version)` 主键，不能用 `row_number()`、绝对值或统一偏移自动猜测。
4. DBA 在 writer 仍冻结时执行 reviewed out-of-band repair：单事务锁定 `secret_refs`，只应用已批准的逐行映射；
   提交前同时证明 `version > 0`、每个 key 的版本唯一且映射后的历史次序与审批记录一致。保存 repair script
   checksum、审批人、影响行数与事务完成证据。
5. 重新运行同一 preflight，确认异常计数为 0，才可部署 binary 并让 SQLx 执行 0058 / 0059。若 0058 已失败，
   保持 rollout 停止，完成同一个部署前流程后重试；不得创建 0060 期望它越过 0058，也不得临时恢复 serving
   role 的 UPDATE/DELETE 权限。

0058 通过 preflight 后，用短时 `ACCESS EXCLUSIVE` 安装 `CHECK (version > 0) NOT VALID`（新写即时受约束）
并撤销 `rss_app` 的 UPDATE/DELETE。0059 在独立 migration transaction 中 `VALIDATE CONSTRAINT`，避免把安装约束
的强锁持有到历史扫描结束。部署前确认无长事务占用 `secret_refs` DDL 锁；5 秒内无法取得锁会中止启动，移除阻塞
事务后重跑，禁止修改已发布迁移。

ref: Spring Modulith spring-modulith-events/spring-modulith-events-jdbc/src/main/java/org/springframework/modulith/events/jdbc/JdbcEventPublicationRepositoryV2.java@c75f173e5201208d8129b4cd8c112defb1158c67

`0060` 以数据库 singleton `event_delivery_policy` 冻结 `same-id-delivery-v1`：automatic retry 86400s、
same-ID redrive 86400s、safety 86400s、inbox receipt retention 604800s；CHECK 强制 retention 严格大于前三段
之和。runtime/maintenance setup 通过 migrator/maintenance 连接读取唯一行，并要求 revision 与四值和 release
常量完全相等，否则启动 fail-closed；没有正确性环境变量或 caller override。

0060 为 mutable outbox 新增 `same_id_delivery_phase=automatic|redrive`、
`automatic_retry_deadline` 与 `same_id_redrive_deadline`。首次 claim 用 `COALESCE` 冻结 automatic 绝对 deadline；
首次 mark DLX 用 `COALESCE` 冻结 redrive 绝对 deadline；redrive 只切到 `redrive` phase、清 retry/lease/terminal
时间，绝不刷新两个 deadline。publish preflight 在 broker I/O 前检查当前 phase deadline；到期路径不调用 broker，
settle 到 DLX。tenant-scoped `rss_outbox_redrive(text,uuid)` 对已过 deadline 返回 `-1`，不修改行，adapter 映射为
typed `Expired`。

0060 同时删除 `rss_sweep_inbox_receipts(bigint)` 并安装零参数 `rss_sweep_inbox_receipts()`：函数从 policy 读取
7d，只删 done receipt，每次按确定顺序最多 1000 行。旧 retain 参数签名不存在。`rss_app` 继续只可 EXECUTE
claim/publish-preflight/mark-DLX 与零参数 inbox sweep；`rss_outbox_redrive(text,uuid)` 归
`rss_outbox_maintenance` 所有，PUBLIC 与 `rss_app` 均被显式 REVOKE，operator CLI 只能走离线
`PgRuntimeDeps::connect_maintenance` 的 migrator/maintenance 连接。该入口只连接已迁移 schema，绝不隐式
运行 migration；破坏式 migration 仅允许经过 runtime 全部外部 capability preflight 的 bootstrap 执行。

### 0060 breaking cutover runbook（一次性、无兼容路径）

1. **冻结旧执行面。** 停止全部旧 relay；停止并清点仍可执行 `rss dlq redrive-outbox` 的旧 CLI、cron 与 job。
   禁止新旧 binary 滚动混跑，因为 0060 会替换 claim/preflight/mark-DLX 与 inbox sweep 函数签名/语义。
2. **历史 DLX inventory。** 用 DB owner 的只读受控 session 导出历史 outbox DLX 的 tenant、event id、domain、
   contract id、`dlx_at` 与状态计数，保存到受控审计存储并记录 checksum/时间窗；不导出 payload/metadata，
   不写入普通日志、PR 或工单。该 inventory 是 cutover 后人工恢复决策的依据，不是 redrive allowlist。
3. **容量与锁预检。** 在 primary DB host 以 DB owner 运行
   `docs/ops/0060-outbox-capacity-gate.sh`，必须 PASS；它同时检查 10 GiB 表上限、data/WAL/archive 磁盘余量、
   archive 新 segment 和 replica inventory/lag。还须确认无长事务持有 outbox 或 inbox_receipts DDL 锁；维护
   窗口须覆盖全 outbox deadline 回填与约束安装。0060 的 lock timeout 为 5s、statement timeout 为 5min，
   任一失败即保持 rollout 停止，只允许新的 forward-only 修复。
4. **执行 migration。** 运行唯一正式 migration runner。0060 用同一个 materialized cutover timestamp 给每条
   历史 outbox 写两个 deadline；因此历史 pending/publishing/DLX 在切换后立即过期，不获得新的 automatic 或
   redrive 24h 窗口。此 fail-closed 语义防止已可能被清理 receipt 的旧 event id 再次产生 durable effect。
5. **验证 schema/policy/权限。** 确认 policy 恰有一行且 revision/四值精确；outbox phase 无闭集外值、历史
   两 deadline 等于 cutover；`to_regprocedure('rss_sweep_inbox_receipts(bigint)') IS NULL` 且
   `to_regprocedure('rss_sweep_inbox_receipts()') IS NOT NULL`；
   `has_function_privilege('rss_app','rss_outbox_redrive(text,uuid)','EXECUTE') = false`，函数 owner 为
   `rss_outbox_maintenance`，`rss_app` 只保留新 relay 与零参数 inbox sweep 所需 EXECUTE。
6. **启动新版本。** 只有全部验证通过才启动新 binary/relay。历史 DLX 继续保留作审计；对其 same-ID redrive
   返回 typed `Expired` 且不 mutation。不得 reset deadline、恢复旧函数、启动旧 CLI 或新增 bypass 路径。

#### 0060 可执行容量门与中止门

容量、exact WAL archive、replica NULL lag、libpq owner credential、SQLx advisory-lock runner 身份以及
0060/0061 transaction watchdog 的完整执行说明，单一维护在
`docs/ops/202607081909-1440-outbox-inbox-redrive-runbook.md` 的「0060 breaking rollout」章节。执行值只由
`docs/ops/0060-outbox-capacity-gate.sh` 持有；本 migration ledger 不复制阈值、命令或取消查询。

### 0064 breaking relay-budget cutover（一次性、禁止滚动混跑）

`0064` 删除 claim/preflight 旧 overload，并安装显式接收 `lease_ttl_ms` 与
`required_budget_ms` 的新签名。数据库入口每次调用都验证 non-null、正值、统一 `86400000ms`（24h，含边界）
operational ceiling 以及
`required_budget_ms < lease_ttl_ms`；claim 用配置 TTL 铸造 lease，preflight 用数据库时钟要求剩余 lease
严格大于 required budget。该迁移不提供默认别名、兼容 shim 或双路径。

1. 停止全部旧 relay，并确认没有旧 binary、job 或 CLI 仍会调用两项旧签名；禁止新旧版本滚动混跑。
2. 由唯一正式 migration runner 执行 0064。失败时保持 relay 停止，只允许 forward-only 修复，不修改历史迁移。
3. 验证新签名
   `rss_outbox_claim_batch(text,bigint,bigint,bigint)` 与
   `rss_outbox_publish_preflight(text,uuid,bigint,bigint,bigint)` 存在，两个旧 overload 均不存在。
4. 验证两函数 owner 为 NOLOGIN `rss_outbox_maintenance`、`search_path=public, pg_temp`、PUBLIC 无 EXECUTE，
   且 `rss_app` 仅获新签名的精确 EXECUTE。
5. 只有以上验证全部通过，才启动持有同一 typed `RelayBudget` 的新 binary；不得恢复旧函数或在应用侧回退默认值。

### 0065 governed relay-budget cutover（forward-only）

`0065` 把 release relay budget 固化进 maintenance-owned `event_delivery_policy` singleton。Rust
调用者仍传入 typed lease/required 值作为精确握手，但 claim/preflight 只使用 singleton 中的四项值计算
lease 和可发布窗口；任意不一致在锁 outbox 行之前 fail closed。`rss_app` 对 policy 表保持零权限，只能执行
精确的新函数签名。迁移同时移除三个 settle 函数遗留的固定 `lock_timeout`，由每次事务内先于客户端绝对
deadline 设置的 `SET LOCAL statement_timeout/lock_timeout` 统一治理。部署仍遵循 0064 的停旧 relay、迁移、
验证 owner/search path/ACL、再启动新 binary 的非滚动顺序。

### 0066 sealed settlement outcome cutover（一次性、禁止滚动混跑）

`0066` 以同签名破坏式替换 published/retry/DLX 三个 settlement 函数：旧 `bigint`/optional-row
返回语义被 PostgreSQL enum `settled | expired | lost_lease` 完全取代，不提供 overload、别名、shim 或双路径。
旧 binary 会按旧形状解码新返回值，因此绝对禁止新旧 relay 滚动混跑。

1. 停止全部 relay，等待当前 publish/settlement 任务退出，并确认没有旧 binary、job 或 CLI 持续调用三个
   settlement 签名；记录仍为 `publishing` 的行数作为 cutover inventory，不导出 payload、metadata、token
   或 deadline。
2. 由唯一正式 migration runner 执行 0066。5 秒内无法取得 DDL 锁或 5 分钟内无法完成时保持 relay 停止；
   只允许提交新的 forward migration 修复，不修改 0066，也不恢复旧返回语义。
3. 验证 `rss_outbox_settlement_outcome` 的三值精确闭集、owner 为 NOLOGIN
   `rss_outbox_maintenance`、PUBLIC 无 USAGE、`rss_app` 有 USAGE；验证三个函数同 owner、固定
   `search_path=public, pg_temp`、PUBLIC 无 EXECUTE、`rss_app` 有精确 EXECUTE。
4. 在受控事务中用 stale token、当前未过期 token 和已过期当前 token 各探测一次，分别确认
   `lost_lease`、`settled`、`expired`；回滚探测事务并确认 outbox/dead-letter 状态未改变。
5. 只有 catalog、ACL、闭值探测全部通过才启动新 binary。若启动失败，撤销本次启动并保持 relay 停止；
   数据库保持 0066，旧 binary 不得连接已迁移 schema。只允许部署修复后的 0066-compatible binary；
   需要 schema 修正时提交新的 forward migration，不得恢复旧返回语义。

### 0062/0063 dead-letter lifecycle breaking cutover

`0062` 是不可绕过的 fail-closed cutover gate：取得 `dead_letter` 的 ACCESS EXCLUSIVE 锁后，只要存在一行
legacy 数据就中止。inventory digest/row count 不能证明数据可恢复，因此本迁移不创建清理函数、审计删除账本，
也绝不执行 legacy DELETE。非空部署必须先提交一条单独评审的 forward migration：把完整加密行、key refs、
schema/object version 与 checksum 导出到受控存储，并用 restore drill 证明可恢复；该 migration 不属于自动 rollout。

`0063` 将 DLX 切换为强制 `HOT → verified WORM receipt → bounded purge → COLD` 生命周期。核心迁移只接受空
`dead_letter`，否则以静态错误中止；不会读取 v1/v2 ciphertext、猜测 metadata、自动删除 legacy 行、
双写或保留 decoder。空表门通过后直接完成 schema 切换。物理
`tenant_id NOT NULL`、v3 replay capsule、32-byte metadata digest 与独立安全 provenance 列一次完成切换。
`dead_letter_archive_receipts` 使用 FORCE RLS，但回执在 HOT 行 purge 后继续保留；Object Lock 到期只使回执
进入 HEAD reconcile 候选，不会自动删除。回执保存 provider-issued S3 version id；HEAD/get 与 missing proof
必须 version-qualified。claim 在返回最多 100 条前以 CAS 把 `reconcile_after` 推迟 1 天，因此持续 Present 的
第一页不会饿死后续 receipt。只有 verified store 产生的 missing proof 经 tenant/id/object-key/version-id/
checksum CAS 才可删除回执。

三个长期 workload role 必须分别直连、NOBYPASSRLS、非 superuser、NOINHERIT、无角色 membership，且没有
public relation DML 或 schema CREATE。`rss_dlx_archiver` 仅拥有 backlog、原子 claim、transient retry settle 与
invariant quarantine；`rss_dlx_verifier` 仅可用 fresh opaque claim token 写 verified receipt；
`rss_dlx_purger` 仅拥有 verified purge、expired receipt claim 与 missing-proof CAS。archive claim/5 分钟 lease、
失败计数、指数 backoff 与 quarantine 均持久化，坏行只结算自身而不会阻塞整批。函数由独立 NOLOGIN
`rss_dlx_lifecycle_owner` 执行；`rss_app` 不拥有上述任一函数。30 天 HOT predicate 与批量值均冻结在 SQL，
runtime/env 无 retention 或 batch override。published outbox sweep 同迁移改为 `(published_at,event_id)` 稳定
排序、每 tick 最多 1000 行；1001 行必须分两 tick。

### 0062/0063 breaking cutover runbook

1. 停止旧 binary 与所有旧 retention worker，确认 `dead_letter` 为空。若非空，停止 rollout；不得用 inventory
   digest、row count、临时函数或直接 DELETE 继续。先另提 forward migration，完成完整加密行导出与 restore drill。
2. 部署前创建独立 archive bucket、COMPLIANCE Object Lock 与生命周期删除策略，并 provision 独立 S3/Vault
   workload identity 与 archiver/verifier/purger 三个 PG 凭据。不要复用 serving credentials。
3. 运行唯一 migration runner。0062/0063 任一 emptiness gate 失败都保持原数据不变；修复只能走上一步的独立、
   可恢复且经评审的数据迁移，不能修改已提交 migration。
4. 确认旧 sweep regprocedure/maintenance role 均不存在；v3 列、claim/lease/backoff/quarantine、receipt RLS、八个
   固定函数 owner/ACL 与三个 workload role 的精确权限完全匹配。
5. 只有 S3 WORM startup probe、三个 PG exact-role gate 与 v3 hot-key/archive-key provider 均通过才启动新 worker。
   任一能力缺失保持 HOT 行且停止 purge，不恢复旧函数或旧 env。

`0043` 新增 `saga_instances` tenant 表，并前向 tenantize `saga_journal`。`saga_instances` 保存
instance status 与 lease token/holder/epoch/expiry，授予 `rss_app` SELECT/INSERT/UPDATE 且不授 DELETE；
`saga_journal` 主键改为 `(tenant_id, saga_id, seq)`，通过 composite FK 指回 instance，仍是 append-only，
仅授 `rss_app` SELECT/INSERT 并显式 `REVOKE UPDATE, DELETE`。两表均在迁移内落 `FORCE RLS` 与标准 tenant
policy。legacy global `saga_journal` 若非空则 fail-fast，不做隐式 backfill。

### 0070 AuthGrant root 破坏性切换

`0070` 将 pre-GA `sessions` 与独立 refresh family 一次性切换为 `auth_grants` 聚合根。旧行无法证明
`tenant + user UUID + authentication epoch + root status` 的完整绑定，迁移因此在阻断旧 writer 后清空
`refresh_tokens` 并直接删除 `sessions` 表、旧清理函数与旧 maintenance role；不在 `DROP TABLE` 前做冗余的
session 行级 DELETE，也不回填、不保留 nullable 绑定、view、trigger、alias、双读写或旧 binary 兼容。

1. **停止旧 binary 并做迁移前探针。** 停止全部旧 binary，禁止滚动混跑；停止 API、worker 与任何仍写
   `sessions`/`refresh_tokens` 或调用旧 session sweep 的 job。用正式 migrator 凭据确认
   `_sqlx_migrations` 必须为 `69`，并保存 session/refresh 行数与 relation bytes 的受控 inventory；
   inventory 只用于证明切换范围及事务回滚完整性，不用于回填。确认两个旧表没有 serving session、长事务或
   已授予的冲突锁。任一结果不满足即中止。

   同时审查新 binary manifest 中的 `RSS_IDENTITY_AUTH_GRANT_TTL_SECS` 与 `RSS_REFRESH_TTL_SECS`。
   两者默认 30 天、最大 365 天，均须为正整数；AuthGrant TTL 必须大于等于 refresh TTL。旧部署若曾把
   refresh 延长到 60 天，必须成对设置
   `RSS_IDENTITY_AUTH_GRANT_TTL_SECS=5184000`、`RSS_REFRESH_TTL_SECS=5184000`，不得依赖 30 天
   AuthGrant 默认值。将下列配置探针输出保存到 rollout receipt；任一检查失败即在迁移前中止。

   ```sh
   set -eu
   auth_grant_ttl_secs="${RSS_IDENTITY_AUTH_GRANT_TTL_SECS:-2592000}"
   refresh_ttl_secs="${RSS_REFRESH_TTL_SECS:-2592000}"
   case "${auth_grant_ttl_secs}" in
     ''|*[!0-9]*) exit 1 ;;
   esac
   case "${refresh_ttl_secs}" in
     ''|*[!0-9]*) exit 1 ;;
   esac
   test "${auth_grant_ttl_secs}" -gt 0
   test "${refresh_ttl_secs}" -gt 0
   test "${auth_grant_ttl_secs}" -le 31536000
   test "${refresh_ttl_secs}" -le 31536000
   test "${auth_grant_ttl_secs}" -ge "${refresh_ttl_secs}"
   printf 'auth_grant_ttl_secs=%s refresh_ttl_secs=%s\n' \
     "${auth_grant_ttl_secs}" "${refresh_ttl_secs}"
   ```

   ```sql
   SELECT max(version) FROM public._sqlx_migrations;
   SELECT count(*) FROM pg_catalog.pg_stat_activity
    WHERE application_name IN ('rss-postgres-writer', 'rss-postgres-maintenance');
   SELECT count(*) FROM pg_catalog.pg_locks
    WHERE relation IN ('public.sessions'::regclass, 'public.refresh_tokens'::regclass)
      AND granted
      AND mode IN ('RowExclusiveLock', 'ShareUpdateExclusiveLock',
                   'ShareLock', 'ShareRowExclusiveLock',
                   'ExclusiveLock', 'AccessExclusiveLock');
   SELECT count(*) AS session_rows FROM public.sessions;
   SELECT count(*) AS refresh_rows FROM public.refresh_tokens;
   SELECT pg_total_relation_size('public.sessions'::regclass) AS session_bytes,
          pg_total_relation_size('public.refresh_tokens'::regclass) AS refresh_bytes;
   ```

2. **容量、WAL、archive 与 replica fail-closed preflight。** 从同次演练批准的 deployment inventory 显式
   注入 `REFRESH_ROW_BUDGET`、`REFRESH_BYTE_BUDGET`、`WAL_FREE_BUDGET`、
   `ARCHIVE_FREE_BUDGET`、`EXPECTED_REPLICAS` 和 archive mount；不得用默认值或复用旧 rollout 的 PASS。
   在 primary DB host 取步骤 1 的 `refresh_rows`/`refresh_bytes`，用 `df -PB1` 分别读取
   `data_directory/pg_wal` 与 archive mount 的可用字节，逐项确认 rows/bytes 不超过演练上限且 WAL/archive
   可用空间不低于预算。随后保存 archive 基线，执行 `SELECT pg_switch_wal()`，必须观察到新的 archived
   segment 且 `failed_count` 不增加；`pg_stat_replication` 中 streaming replica 数量必须精确等于
   `EXPECTED_REPLICAS`，每个 replica 的 byte/replay lag 都须落在同次演练 envelope 内。

   ```sh
   set -eu
   : "${REFRESH_ROW_BUDGET:?}" "${REFRESH_BYTE_BUDGET:?}"
   : "${WAL_FREE_BUDGET:?}" "${ARCHIVE_FREE_BUDGET:?}" "${EXPECTED_REPLICAS:?}"
   : "${PGDATA:?}" "${WAL_ARCHIVE_DIR:?}"
   refresh_rows="$(psql service=rss-owner -Atqc \
     "SELECT count(*) AS refresh_rows FROM public.refresh_tokens")"
   refresh_bytes="$(psql service=rss-owner -Atqc \
     "SELECT pg_total_relation_size('public.refresh_tokens'::regclass)")"
   wal_free_bytes="$(df -PB1 "${PGDATA}/pg_wal" | awk 'NR == 2 { print $4 }')"
   archive_free_bytes="$(df -PB1 "${WAL_ARCHIVE_DIR}" | awk 'NR == 2 { print $4 }')"
   streaming_replicas="$(psql service=rss-owner -Atqc \
     "SELECT count(*) FROM pg_catalog.pg_stat_replication WHERE state = 'streaming'")"
   test "${refresh_rows}" -le "${REFRESH_ROW_BUDGET}"
   test "${refresh_bytes}" -le "${REFRESH_BYTE_BUDGET}"
   test "${wal_free_bytes}" -ge "${WAL_FREE_BUDGET}"
   test "${archive_free_bytes}" -ge "${ARCHIVE_FREE_BUDGET}"
   test "${streaming_replicas}" -eq "${EXPECTED_REPLICAS}"
   ```

   ```sql
   SELECT archived_count, failed_count, last_archived_wal, last_archived_time
     FROM pg_catalog.pg_stat_archiver;
   SELECT pg_catalog.pg_switch_wal();
   SELECT application_name, state, sync_state,
          pg_catalog.pg_wal_lsn_diff(pg_catalog.pg_current_wal_lsn(), replay_lsn) AS byte_lag,
          replay_lag
     FROM pg_catalog.pg_stat_replication
    ORDER BY application_name;
   ```

   任何变量为空、比较失败、archive 未推进、replica 缺失/NULL lag 或维护窗口不足 5 分钟都 fail closed。
   保存命令、预算、输出与时间戳作为 rollout receipt。
3. **执行唯一迁移。** 只允许正式 `rss-postgres-migrator` 执行 SQLx migration；迁移以 5 秒 lock timeout
   和 5 分钟 statement timeout fail-closed。事务失败时 schema、refresh 删除与 session DROP 原子回滚，
   所有新 binary 保持停止；失败后只允许 forward-only 修复，不修改 0070，也不临时恢复旧写路径。
4. **迁移后精确探针。** 再执行 `SELECT max(version) FROM public._sqlx_migrations`，结果
   `_sqlx_migrations` 必须为 `70`；`to_regclass('public.sessions') IS NULL` 且
   `to_regclass('public.auth_grants') IS NOT NULL`。迁移前 inventory 中的旧 session/refresh 数据必须为 `0`
   条被保留，`retained_refresh_rows` 必须为 0；新 `refresh_tokens` 的 `auth_grant_id`、`user_id`、
   `auth_grant_status` 均为 NOT NULL，`subject`/`kind` 均不存在。精确 ACL 必须证明 `rss_app` 对两表没有
   表级 UPDATE，只有 `auth_grants(status, closed_at, close_reason)` 与 `refresh_tokens(status)` 的列级
   UPDATE；`rss_app_read` 没有任何 UPDATE，两个 serving role 均无 DELETE。

   ```sql
   SELECT max(version) FROM public._sqlx_migrations;
   SELECT to_regclass('public.sessions') IS NULL,
          to_regclass('public.auth_grants') IS NOT NULL;
   SELECT count(*) AS retained_refresh_rows FROM public.refresh_tokens;
   SELECT column_name, is_nullable
     FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'refresh_tokens'
    ORDER BY ordinal_position;
   SELECT has_table_privilege('rss_app', 'public.auth_grants', 'UPDATE') = false,
          has_table_privilege('rss_app', 'public.refresh_tokens', 'UPDATE') = false,
          has_table_privilege('rss_app', 'public.auth_grants', 'DELETE') = false,
          has_table_privilege('rss_app', 'public.refresh_tokens', 'DELETE') = false;
   SELECT grantee, table_name, column_name, privilege_type
     FROM information_schema.column_privileges
    WHERE table_schema = 'public'
      AND table_name IN ('auth_grants', 'refresh_tokens')
      AND grantee IN ('rss_app', 'rss_app_read')
      AND privilege_type = 'UPDATE'
    ORDER BY grantee, table_name, column_name;
   ```
5. **核验根约束。** 从 `pg_catalog.pg_constraint` 保存 AuthGrant 五列复合外键、`ON UPDATE CASCADE` /
   `ON DELETE CASCADE`、状态/原因/时间 CHECK。用受控事务验证 orphan、跨 tenant、跨 user、错误 epoch、
   错误 root status 的 refresh 均无法提交；验证仍有非 revoked refresh 时直接关闭 root 失败，先撤销
   refresh family 再关闭 root 成功；这也验证 FK 的 `ON UPDATE CASCADE` 不要求 `rss_app` 获得
   `refresh_tokens.auth_grant_status` 的直接 UPDATE。`pg_class.relforcerowsecurity` 对 `auth_grants`
   必须为 true；保存 `rss_sweep_expired_auth_grants` 的 owner=`rss_auth_grant_maintenance`、固定 search
   path、PUBLIC 无 EXECUTE、`rss_app` 仅有 EXECUTE，以及单 tick `LIMIT 1000` /
   `FOR UPDATE SKIP LOCKED` 证据。
6. **只启动新世界。** 只有 capacity receipt、ledger、catalog、约束、RLS/ACL 和真实事务探针全部通过才启动
   新 binary。
   启动后 login 必须通过同一事务同时产生 AuthGrant、初始 refresh 与 outbox；任一对象缺失即停止 rollout。
   不得连接旧 binary、重建 `sessions`、恢复旧 sweep 名称或手工补造绑定。
7. **按 ledger 恢复。** 若迁移或 singleton 在提交前失败且 ledger 仍为 `69`，保持新 binary 停止，重复
   步骤 1–2，并确认 session/refresh 行数与 relation inventory 未因失败减少；修复锁、空间、archive 或
   replica 前置条件后重跑唯一迁移。只有 ledger=69、旧 schema 完整且确需恢复服务时才可恢复旧 binary。
   若 ledger 已为 `70`，这是已提交的 forward-only 状态：绝不能启动旧 binary；重复步骤 4–5，修复新
   binary 的启动配置后只启动 0070-compatible 版本。需要 schema 修正时提交新的 forward migration，不修改
   0070，也不从备份恢复 `sessions` 或已失效 refresh。

### 0071 credential-security opaque target mapping（已由 0076 移除）

`0071` 曾新增 `credential_security_target_mappings`。生产审计始终直接消费脱敏 fact，未读取该表；继续写入会
形成无界、无消费者的数据集。`0076` 因而完整删除表、写入路径、resolver port 与公开类型。`0071` 仅作为不可
改写的迁移历史保留，新 binary 不得查询或写入该 relation。

### 0072 persistent certificate revocations

`0072` 纯新增 `certificate_revocations`，精确键为 `(tenant_id, device_id, serial)`；serial 长度、
`revoked_at < not_after`、FORCE RLS 与 canonical tenant policy 在同一 migration 固化。`revoked_at` 只能由
数据库默认值生成。`rss_app` 只有 SELECT 与 tenant/device/serial/not_after 四列 INSERT，
`rss_app_read` 只有 SELECT；两者均无 UPDATE/DELETE。

到期是逻辑判断：`not_after <= authoritative database now` 立即不再命中。物理删除只经零参数
`rss_sweep_expired_certificate_revocations()`；同 transaction 的零参
`rss_certificate_revocation_retention_backlog()` 在 FORCE RLS 后返回全局 eligible depth 与 grace 后 oldest
age。两者由独立 NOLOGIN/BYPASSRLS owner 固定 search path；删除单批最多 1,000 行、`SKIP LOCKED`，并保留
5 分钟 grace。runtime role 对两个固定函数只有 EXECUTE，没有 raw DELETE；backlog sample 失败会回滚同 tick
删除并发出 transient/NaN 证据。

该 migration additive、forward-only，可在新 binary 前应用，但 binary 切换必须是非滚动 hard cutover：

1. **先应用 additive migration，保持撤销入口关闭。** 唯一 migration runner 完成后核验
   `SELECT max(version) FROM public._sqlx_migrations` 为 `72`；此时不得让新 binary 接受撤销流量。
2. **quiesce 撤销入口并停止全部旧 binary。** 禁止旧/新 generation 滚动混跑；先禁用旧 workload/controller/job 的自动重启，
   再从部署平台导出 `OLD_REVOCATION_GENERATION` 的完整进程
   inventory，断言 `EXPECTED_OLD_REPLICAS=0`。该 inventory 必须覆盖常驻 workload、一次性 job 和定时
   controller；任一旧进程仍可重启即停止 rollout。
3. **在任何新 binary 启动前证明全部静态连接 lane 为零。** migration runner 已退出且旧 process
   inventory 为零后，保存下列同一时点的 PostgreSQL 快照；`all_static_lanes_drained` 必须为 `true`：

   ```sql
   SELECT count(*) = 0 AS all_static_lanes_drained
   FROM pg_catalog.pg_stat_activity
   WHERE backend_type = 'client backend'
     AND application_name IN (
       'rss-postgres-writer',
       'rss-postgres-reader',
       'rss-postgres-audit-admin',
       'rss-postgres-maintenance',
       'rss-postgres-migrator'
     );
   ```

   五个名字表达连接职责而非 release generation；本快照与步骤 2 的 process inventory 共同构成时间
   围栏。两份证据缺一、或快照后有旧 workload 恢复能力，均停止 rollout。
4. **只启动新 binary。** 启动必须先通过 table/RLS/ACL/maintenance-role/function capability gate，
   再铸造 receipt、构造 store+sweeper；失败时保持入口关闭。
5. **完成新世界探针。** 保存 ledger=72、表/RLS/ACL/role/function catalog、pool 重建后仍命中，
   以及 `1000 + 1 + 0` retention 证据，并再次证明旧 process inventory 为 `0`。新连接此时会复用上述
   静态 lane 名，故不得再用静态 `application_name` 区分旧/新 generation；启动后的代际证据只来自已
   禁用自动重启的部署 inventory。
6. **最后开放撤销流量。** 只有上述证据完整后才解除 quiesce；开放后持续禁止旧 binary 回池。
7. **执行 rollback fence。** 记录
   `SELECT count(*) AS persisted_revocations FROM public.certificate_revocations`；一旦新 binary 接受首个
   撤销写入（计数或审计证据非零），严禁回退到读取进程内 ledger 的旧 binary。若 capability gate、ACL
   或函数探针失败，保持流量停止并提交新的前向修复 migration；不得修改 `0072`、增加双读/双写或恢复
   SoftCA assembly fallback。

### 0073 audit-chain key pin

`0073` 把 Audit 链唯一支持的 HMAC key generation 固定为 `key_id=1`，并以数据库持久 sentinel tag
拒绝错误 key。该 migration 会删除 `audit_entries.key_id` 的数据库默认值；旧 binary 不显式写入该列，
因此 rollout 必须是 forward-only、non-rolling hard cutover，禁止旧/新 writer 混跑：

1. **迁移前停止全部旧 audit writer。** 先关闭 Primary/Admin 入站并禁用旧 workload、job、controller 的
   自动重启；保存旧 generation inventory 并证明副本数为 0。随后用 migrator 凭据确认 migration
   `ledger=72`，且全部 writer/audit-admin/migrator 静态连接 lane 已退出。
2. **只由唯一 migration runner 应用 0073。** 保留 SQLx advisory lock、checksum 与 transaction；不得手工
   执行部分 DDL、修改已提交 migration 或添加临时默认值。迁移提交后确认 `ledger=73`、
   `audit_entries_key_id_v1`、`audit_chain_key_guard` 与 `rss_verify_audit_chain_key_v1` 的 owner/ACL 均精确。
3. **只启动新 binary，并在开放流量前完成 key probe。** 空 Audit ledger 可首次 pin 当前 key；非空 ledger
   且 guard 缺失必须 fail-closed，交由显式、已验证的前向迁移处理，禁止自动 adoption。相同 key 重启必须
   成功，错误 key 必须在 listener 接流量前失败。
4. **按 ledger 执行失败恢复。** 若 runner 失败且 ledger 仍为 72，确认 transaction 已完整回滚后可修复
   前置条件并重跑；确需恢复服务时只允许恢复旧 generation。若 ledger 已为 73，这是已提交的新世界，
   不得启动旧 binary；保持流量关闭，修复新 binary 的 secret/config 或提交新的前向修复 migration，
   不得写 down migration、兼容默认值、双写或跳过 durable key probe。

## Append-only 表（REVOKE 强制）

append-only 表（如 `projection_events`）在前向迁移内用 `REVOKE UPDATE, DELETE ON <table> FROM <role>` 强制 DB
引擎层不可绕的只追加约束（Hard 主守卫，INVARIANT PROJECTION-APPEND-ONLY-01）。
forward-only 原则同样适用：`REVOKE` 不写 `.down.sql`，逆转须新前向迁移 `GRANT`，不改历史迁移文件。

**Retention / 旧数据清理**：append-only 表（`projection_events` 等）的旧数据删除须经 DBA（表 owner 角色）
或新前向迁移显式 `GRANT DELETE TO <清理角色>`，不可由应用 serving role（已 REVOKE DELETE）直接执行。
forward-only 不写 `.down.sql`；当前 pre-GA 无自动 retention 策略或分区，表膨胀治理待后续规划。

## 新字段

### 0075 session permission 窄化切换

`0075` 在新 binary serving 前，把 `roles.permissions`、`abac_policies.permission` 与
`resource_attributes.permission` 中已删除的 `identity:session:write` 原子替换为
`identity:session:logout-current`。迁移绝不自动授予 `identity:session:logout-all`；role 数组保持首次出现顺序并
去除替换产生的重复项。resource attribute successor 主键若已异常存在，迁移以唯一约束失败并完整回滚，不猜测合并。

这是 non-rolling、forward-only cutover；只由唯一 migration runner 执行，成功后才允许新 binary serving。

### 0076 删除无消费者的 credential-security target mapping

`0076` 删除 `credential_security_target_mappings`。这是 intentional、non-rolling、forward-only cutover：先停止
仍会写入该表的旧 binary，运行唯一 migration runner，再启动只写 projection 与 OutboxFact 的新 binary。表内
数据没有生产消费者，也不是撤销或审计真源，因此不迁移、不归档、不保留兼容 view。回滚只能提交新的 forward
migration；不得修改 `0071` 或 `0076`。

新增列必须有默认值或允许 `NULL`（避免对已有行的 `NOT NULL` 回填失败）。

## 调用时机与行为

- **时机**：先运行 migration phase 的 `rss postgres migrate-all` Job，成功后才允许 serving phase。
- **失败传播**：migration Job 与 serving ledger probe 都 **fail closed**；前者失败不发布，后者发现 stale、超前、失败或 checksum 漂移即拒绝启动。
- **多实例并发**：operator 使用 SQLx advisory lock；重复 Job 只会在同一精确 ledger 上幂等收敛。
- **编译期内嵌**：仅 `postgres-migration` crate 内嵌 SQL；共享 typed inventory carrier 单次生成 version/checksum facts。

## 本地应用 / 测试

集成测试（`integration` feature 门控）对真实 postgres 跑 migration fixtures
并验证幂等。本地用 docker postgres + libpq 标准 env（`PGHOST` / `PGPORT` / `PGDATABASE` / `PGUSER` /
`PGPASSWORD`）：

```bash
PGHOST=127.0.0.1 PGPORT=5432 PGDATABASE=rss PGUSER=rss PGPASSWORD=... \
  cargo nextest run -p postgres --features integration
```

`PGHOST` 未设时集成测试整组跳过（azure 无 CI，不阻塞 `cargo xtask verify`）。
`0077` 以 `SECURITY DEFINER`、`search_path=pg_catalog, pg_temp` 的窄函数向 serving writer 暴露冻结的 delivery policy；`rss_app`
保持对策略表零权限，只能读取启动校验所需的单例字段。

`0078` 以 `search_path=pg_catalog, pg_temp`、撤销 `PUBLIC` 执行权的 `SECURITY DEFINER` 窄函数向 `rss_app`
暴露指定 projection generation 的有序 binding 集合。serving 启动与周期 readiness 对该集合做 exact compare；
`rss_app` 仍不持有 `projection_input_bindings` 的表级权限，missing/less/more 任一漂移均 fail closed。

### 0079 AuthGrant sweeper 锁序对齐

`0079` 直接替换 `rss_sweep_expired_auth_grants()`，不改变签名、owner、`SECURITY DEFINER`、固定
`search_path` 或 ACL。旧函数先锁/删 AuthGrant root，再由 FK cascade 取得 refresh child 锁；这与 refresh
writer 的 `account-security → refresh-family → auth-grant` 顺序相反。新函数先按 `(expires_at, tenant_id,
grant_id)` 选择候选，再按 refresh id 稳定取得 family 锁并显式删除 children，最后重新验证 root 已过期后
删除 root。并发 sweeper 或 writer 已处理目标时收敛为零行，不扩大到其他 family。

这是 forward-only、non-rolling hard cutover。旧 binary 停止且连接排空后由唯一 migration runner 应用；
ledger 到达 `79` 后只启动采用同一锁序的新 binary。若迁移失败且 ledger 未推进，确认事务完整回滚后重试；
若 ledger 已到 `79`，不得回退旧 binary 或修改历史 migration，只能提交新的前向修复。

### 0081 设备证书 desired/reported/condition 权威状态

`0081` 新建 `device_certificate_desired_states`、`device_certificate_reported_states` 与
`device_certificate_conditions` 三张 tenant/device-scoped 表。它们只承载 #1896 的单调
desired generation、reported high-water 和闭值 condition；command、ingress receipt、幂等 operation
与 scheduler wake 由后续 owner 在同一 tenant transaction 中组合，本 migration 不提前建表或
双写。

desired 只持久化 generation 与 canonical policy，不保存 fence epoch；closed key usage 以
`client_auth`/`server_auth` 两个 `NOT NULL` boolean 表达并要求至少一个为真，杜绝开放文本值与排序漂移。
`sans` 必须按 `C` collation 严格排序且唯一，并同时受数量、非空、字符长度、Unicode trim 与控制字符
约束。固定 `search_path=pg_catalog, pg_temp` 的数据库 trigger 按 `clientAuth`、`serverAuth` 顺序以
唯一 framing 计算 `policy_hash`，并由 PostgreSQL server time 生成全部权威时间；serving role 对 hash
与时间列零写权限。

reported 只接受正 fence epoch，并把 `(observed_generation, device_sequence)` 作为同时严格递增的
高水位；观测 generation 不得超前当前 desired，精确重复为零写入且保留 `received_at`。condition
使用 type/status/reason 闭矩阵，拒绝 `Ready=True` 与超前观测，精确重复同样保留 transition time。
初始 reported 状态仍是无行，不持久化 generation zero。

三表同 migration 开启并强制 RLS，使用 canonical `rss.tenant_id` policy。`rss_app_read` 只获
`SELECT`；`rss_app` 只获 `SELECT` 和精确 mutation 列的 `INSERT`/`UPDATE`，没有 table-level
`INSERT`、`UPDATE`、`DELETE`、`TRUNCATE`、`REFERENCES` 或 `TRIGGER`。

这是 additive、forward-only 切换：唯一 migration runner 在 saga definition identity 的 `0080` 后把
ledger 从 `80` 推进到 `81`，通过
schema/RLS/ACL 与真实 PostgreSQL 行为探针后才启动新 binary。失败且 ledger 未推进时修正
前置条件后重跑；ledger 已为 `81` 时不得修改 `0081` 或写 down migration，只能新建前向
修复 migration。

### 0082 durable device command 与 ingress evidence

`0082` 新建 tenant/device-scoped `device_commands` 聚合表和
`device_ingress_receipts` append-only evidence 表。command 保存 generation、fence epoch、intent
digest、deadline、八态 FSM、optimistic version 与 PostgreSQL server timestamps；partial unique
index 强制每个 tenant/device/generation/intent 最多一个 active command，trigger 同时拒绝 identity
漂移、version 跳跃、非法状态边和 terminal 后续写入。Rust FSM 仍是语义 owner，数据库 guard 负责阻止
绕过 adapter 的非法写入。

receipt 以 `(tenant_id, event_id)` 为幂等键，ACK 与 report 使用数据库 CHECK 封闭字段形状；相同事件
精确重放读取原记录，任何变异均冲突且 serving role 没有 UPDATE/DELETE 权限。两表均开启并强制 RLS，
`rss_app_read` 只有 SELECT，`rss_app` 只有精确列级 command INSERT/UPDATE 与 receipt INSERT。

这是 additive、forward-only、non-rolling hard cutover。唯一 migration runner 在 ledger `81` 后应用
`0082`，通过 schema/RLS/ACL、并发唯一性、CAS 与 replay 探针后才启动新 binary。ledger 已为 `82` 时
不得修改历史 migration、增加 down migration、兼容视图、双写或 fallback；修复必须使用新的前向
 migration。

### 0083 Saga protected receipt 与 Completed 原子提交

`0083` 是 pre-GA、non-rolling hard cutover。迁移先确认 `saga_instances`、`saga_journal` 均为空；存在任何
legacy Saga 行即固定错误并完整回滚，不提供 backfill、兼容列、视图或双读。随后新增
`saga_step_receipts`，以 tenant/Saga、完整 worker/definition identity、step、receipt schema 与 forward
effect-key 锁定唯一回执；只持久化随机加密 ciphertext、KMS key reference、format version、successful
attempt 和 versioned HMAC fingerprint，不存在 plaintext 列。

receipt 与 `saga_journal(status='completed')` 由双向 deferred constraint trigger 强制成对；`rss_app` 只能向
精确业务列 INSERT，不能写 `committed_at`，也不能独立 INSERT Completed journal。表启用并强制 canonical
tenant RLS，`rss_app_read` 只有 SELECT。Saga terminal transition 由数据库 trigger 写入不可由 serving caller
伪造的 `terminal_at`。

终态（`succeeded` / `compensated` / `failed`）aggregate 固定以 30 天作为删除 eligibility。
`rss_saga_receipt_maintenance`（NOLOGIN BYPASSRLS、无 role membership）拥有唯一
`rss_sweep_terminal_sagas()` maintenance 函数；函数无 retain 参数，按 `(terminal_at, tenant_id, saga_id)`
稳定选择每批最多 1000 个 root，删除 `saga_instances` 后由 FK cascade 在同一事务清理 journal 与 receipt。
`rss_app` 只有该固定零参数函数的 `EXECUTE` 窄 capability，没有任何 Saga 表 `DELETE` 权限；调用方不能选择
保留期、批量上限或删除目标。#1924 只安装 operator-invoked maintenance capability，不注册周期 worker 或
probe，因而不承诺自动 retention SLA；live scheduling 随 #1925 后的 #1926 production activation 一并闭合。

rollout 顺序固定如下：

1. **停止旧世界并执行 preflight。** 停止旧 Saga writer/worker，禁用旧 workload/job/controller 自动重启；
   migration Job 尚未启动时以 migrator 凭据保存下列同一时点快照。每个结果都必须为 `true`，否则中止。

   ```sql
   SELECT max(version) = 82 AS exact_pre_0083_ledger
     FROM public._sqlx_migrations;

   SELECT
       (SELECT count(*) FROM public.saga_instances) = 0 AS saga_instances_empty,
       (SELECT count(*) FROM public.saga_journal) = 0 AS saga_journal_empty;

   SELECT count(*) = 0 AS all_saga_lanes_drained
     FROM pg_catalog.pg_stat_activity
    WHERE pid <> pg_catalog.pg_backend_pid()
      AND backend_type = 'client backend'
      AND application_name IN (
          'rss-postgres-writer',
          'rss-postgres-reader',
          'rss-postgres-audit-admin',
          'rss-postgres-maintenance',
          'rss-postgres-migrator'
      );
   ```

2. **运行唯一 migration runner。** 只启动一个新镜像的 `rss postgres migrate-all` Job；不得并行启动
   serving binary、第二个 migration Job 或 maintenance CLI。
3. **执行 postflight。** Job 成功退出后仍以 migrator 凭据复制执行下列 catalog probe。ledger、RLS 与 ACL
   查询中的布尔列必须全部为 `true`；trigger 查询必须精确返回两个启用、deferred、initially-deferred 的
   pair trigger；函数查询必须精确返回一行且全部布尔列为 `true`。

   ```sql
   SELECT max(version) = 83 AS exact_post_0083_ledger
     FROM public._sqlx_migrations;

   SELECT relation.relrowsecurity AS rls_enabled,
          relation.relforcerowsecurity AS rls_forced
     FROM pg_catalog.pg_class AS relation
    WHERE relation.oid = 'public.saga_step_receipts'::regclass;

   SELECT
       has_table_privilege('rss_app', 'public.saga_step_receipts', 'SELECT')
           AS rss_app_can_select,
       has_column_privilege('rss_app', 'public.saga_step_receipts', 'tenant_id', 'INSERT')
           AS rss_app_can_insert_business_columns,
       NOT has_column_privilege('rss_app', 'public.saga_step_receipts', 'committed_at', 'INSERT')
           AS rss_app_cannot_insert_committed_at,
       has_table_privilege('rss_app_read', 'public.saga_step_receipts', 'SELECT')
           AS rss_app_read_can_select,
       NOT has_table_privilege('rss_app', 'public.saga_step_receipts', 'DELETE')
           AS rss_app_cannot_delete_receipts,
       NOT has_table_privilege('rss_app', 'public.saga_instances', 'DELETE')
           AS rss_app_cannot_delete_instances,
       NOT has_table_privilege('rss_app', 'public.saga_journal', 'DELETE')
           AS rss_app_cannot_delete_journal;

   SELECT trigger.tgname,
          trigger.tgenabled = 'O' AS enabled,
          trigger.tgdeferrable AS deferred,
          trigger.tginitdeferred AS initially_deferred
     FROM pg_catalog.pg_trigger AS trigger
    WHERE trigger.tgname IN (
        'saga_receipt_requires_completed',
        'saga_completed_requires_receipt'
    )
    ORDER BY trigger.tgname;

   SELECT
       pg_catalog.pg_get_userbyid(proc.proowner) = 'rss_saga_receipt_maintenance'
           AS exact_owner,
       proc.prosecdef AS security_definer,
       proc.proconfig = ARRAY['search_path=pg_catalog, pg_temp']::text[]
           AS exact_search_path,
       has_function_privilege('rss_app', proc.oid, 'EXECUTE')
           AS rss_app_can_execute,
       NOT EXISTS (
           SELECT 1
             FROM pg_catalog.aclexplode(
                 COALESCE(proc.proacl, pg_catalog.acldefault('f', proc.proowner))
             ) AS acl
            WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
       ) AS public_cannot_execute,
       pg_catalog.pg_get_functiondef(proc.oid) LIKE '%interval ''30 days''%'
           AS fixed_30_day_retention
     FROM pg_catalog.pg_proc AS proc
    WHERE proc.oid = 'public.rss_sweep_terminal_sagas()'::regprocedure;
   ```

4. **只启动新世界。** postflight 全部通过后才启动新 binary，并保持 Saga workload disabled；Saga 的
   production activation 必须等待 #1925/#1926。迁移失败且 ledger 仍为 `82` 时保持新 binary 停止，重新
   执行 preflight、修正前置条件后重跑；ledger 已为 `83` 时不得回退旧 binary、修改 `0083` 或写 down
   migration，只能新建前向修复。

### 0084 Durable reconcile wake 与 device policy acceptance

`0084` 在现有 reconcile target 上增加 durable `failure_streak`、闭集 `last_result` 与单调
`wake_version`，attempt 则捕获 claim 时的 streak/version。历史 attempt 只初始化为零，不从旧 ledger
推导 retry 或 result 状态。terminal result transaction 以 captured wake version 防止旧 attempt 覆盖较新的
desired wake；成功/健康 requeue 重置 streak，transient 递增，permanent/invariant 使用闭集 reason quarantine。

同一 migration 新增 append-only `device_certificate_policy_operations`。desired generation CAS、operation
result 与 exact `device-certificate` reconcile target due/wake 在同一个 authenticated tenant transaction 提交；
identical digest replay 与 expected-generation/idempotency/storage conflict 均为零写入。notification 仅是
commit 后的延迟提示，周期 due scan 仍是丢失 notification 的 correctness repair path。

这是 additive、forward-only、non-rolling hard cutover。唯一 migration runner 必须从 ledger `83` 应用
`0084`。部署必须先停止旧 serving/reconcile worker 并禁止自动重启，等待所有
`reconcile_leases.state = 'held'` 归零后，才运行唯一 migration runner；migration 会锁定旧世界写表并在仍有
held lease 时以 `55000` fail closed。完成后须核对 ledger 精确为 `84`、新增表 RLS/FORCE RLS、
`device_certificate_policy_operations` 的 append-only ACL，以及 `reconcile_target_wake_monotonic`
guard trigger；0084 没有 operation append-only trigger。以下 postflight 必须返回一行，且依次为
RLS/FORCE RLS/SELECT 为 `true`，UPDATE/DELETE/TRUNCATE 为 `false`，trigger 为 `O`，`proconfig`
只含 `search_path=pg_catalog, pg_temp`，最后两个 EXECUTE 检查为 `false`：

```sql
SELECT operation.relrowsecurity,
       operation.relforcerowsecurity,
       has_table_privilege('rss_app', operation.oid, 'SELECT'),
       has_table_privilege('rss_app', operation.oid, 'UPDATE'),
       has_table_privilege('rss_app', operation.oid, 'DELETE'),
       has_table_privilege('rss_app', operation.oid, 'TRUNCATE'),
       wake_trigger.tgenabled,
       wake_guard.proconfig,
       has_function_privilege('rss_app', wake_guard.oid, 'EXECUTE'),
       EXISTS (
           SELECT 1
           FROM pg_catalog.aclexplode(
               COALESCE(wake_guard.proacl, pg_catalog.acldefault('f', wake_guard.proowner))
           ) AS acl
           WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
       ) AS public_can_execute
FROM pg_catalog.pg_class AS operation
JOIN pg_catalog.pg_namespace AS operation_ns ON operation_ns.oid = operation.relnamespace
JOIN pg_catalog.pg_trigger AS wake_trigger
  ON wake_trigger.tgrelid = 'public.reconcile_targets'::regclass
 AND wake_trigger.tgname = 'reconcile_target_wake_monotonic'
 AND NOT wake_trigger.tgisinternal
JOIN pg_catalog.pg_proc AS wake_guard ON wake_guard.oid = wake_trigger.tgfoid
WHERE operation_ns.nspname = 'public'
  AND operation.relname = 'device_certificate_policy_operations';
```

以下列级 postflight 必须只返回 migration 列出的六个 INSERT columns，且 `update_columns` 为空：

```sql
SELECT array_agg(attribute.attname ORDER BY attribute.attnum)
           FILTER (WHERE has_column_privilege(
               'rss_app', operation.oid, attribute.attnum, 'INSERT'
           )) AS insert_columns,
       array_agg(attribute.attname ORDER BY attribute.attnum)
           FILTER (WHERE has_column_privilege(
               'rss_app', operation.oid, attribute.attnum, 'UPDATE'
           )) AS update_columns
FROM pg_catalog.pg_class AS operation
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = operation.relnamespace
JOIN pg_catalog.pg_attribute AS attribute ON attribute.attrelid = operation.oid
WHERE namespace.nspname = 'public'
  AND operation.relname = 'device_certificate_policy_operations'
  AND attribute.attnum > 0
  AND NOT attribute.attisdropped
GROUP BY operation.oid;
```

对应 live catalog/行为回归由
`migration_0084_live_guard_freezes_target_identity_and_wake_regression` 与
`device_certificate_schema_rls_and_acl_are_closed` 承载。通过后才启动新 binary。任何 preflight、lock timeout、held-lease
检查失败时必须先核对 commit 边界。若 ledger 仍为 `83` 且确认 `0084` 的 DDL 全部回滚，可临时恢复旧
binary，且仅用于按旧协议 reclaim/release held lease；drain 完成后必须再次停止旧 binary、禁止自动重启并
验证 held lease 为零，再由唯一 runner 重试。若 ledger 已为 `84`，绝不能启动旧 binary，只能保持新 binary
停止并做前向修复；不得修改历史 migration、增加 down migration、兼容视图、双写或 fallback。

### 0085 Projection 凭据边界破坏性切换

`0085` 删除无 scope 的 `rss_read_projection_events(bigint, integer)`、旧五参 registry 函数和
`rss_projection_events_runtime` BYPASSRLS owner，不提供 alias、dual grant、backfill 或旧 binary fallback。
registry identity 原地扩为 generation + projection id + definition version/schema digest + source domain +
contract/version/schema/topic；因此迁移只接受空 `projection_input_bindings`。当前无历史部署、Projection
production activation 关闭，采用 non-rolling fresh cutover。

`0085` 在取 `ACCESS EXCLUSIVE` 前固定 `lock_timeout=5s`、`statement_timeout=5min`。超时会让整个 SQLx
迁移事务回滚，ledger 保持 84；保持旧世界停止，定位并排空下述精确 application name 后可安全重跑，禁止
人工跳过 lock/empty precondition。

权限矩阵是闭合的：`rss_app` 只能 append/probe；`rss_projection_reader` 只能调用 scoped source reader；
`rss_projection_operator` 只能调用 audit/checkpoint/CAS/DLX/token-replay 固定函数。raw relation 权限只授给
四个 NOLOGIN/NOBYPASSRLS function owner。`0085` 同时撤销 `public` schema 全部函数的默认 PUBLIC EXECUTE，
避免新角色从 ambient grant 获得未列入清单的函数；启动门按数据库/Schema/relation/column/sequence/function
完整有效权限指纹核验，而不只检查直接 GRANT。reader 与 operator 是两个独立 LOGIN credential，密码只从各自
绝对只读文件注入，不能放进 serving secret bundle。

1. **停旧世界并执行 preflight。** 缩容全部旧 runtime 和 Projection CLI，用 migrator 凭据确认 ledger
   精确为 `84`、registry 为空、旧 writer/maintenance 会话为零；任一条件不满足均中止。

   ```sql
   SELECT max(version) = 84 AS exact_pre_0085_ledger
     FROM public._sqlx_migrations;
   SELECT count(*) = 0 AS projection_registry_empty
     FROM public.projection_input_bindings;
   SELECT count(*) = 0 AS old_projection_lanes_drained
     FROM pg_catalog.pg_stat_activity
    WHERE pid <> pg_catalog.pg_backend_pid()
      AND backend_type = 'client backend'
      AND application_name IN (
          'rss-postgres-writer',
          'rss-postgres-maintenance',
          'rss-postgres-projection-source-reader',
          'rss-postgres-projection-operator'
      );
   ```

2. **运行唯一 runner，再 provision/rotate 精确 LOGIN 角色。** 只运行一个新镜像的
   `rss postgres migrate-all` Job。fresh cluster 由 `deploy/postgres-init/001-create-app-role.sh` 预置登录凭据；
   retained volume 在 ledger 到 85 后必须运行
   `deploy/postgres-upgrade/provision-projection-roles.sh`。后者从三个绝对 password files 读取 migrator、
   reader、operator secret，在一个事务内把两角色收敛为 LOGIN、NOSUPERUSER、NOBYPASSRLS、NOCREATEDB、
   NOCREATEROLE、NOREPLICATION、NOINHERIT，再用两个新凭据分别直连验证。密码不进入 argv/SQL 文件。

   轮换必须先 stage 两个新 password file，再执行同一脚本；脚本成功后切换 Projection CLI secret mounts，
   等旧 reader/operator pool 排空后销毁旧文件。PostgreSQL 固定角色不支持双密码：若新凭据直连验证失败，
   Projection CLI 保持停止，并立即用上一个版本的两个 password file 重跑脚本恢复登录密码；不得恢复
   migrator 复用、旧函数或宽权限兼容 grant。

3. **执行 postflight。** ledger 与所有布尔列必须为 true；function 查询必须精确返回 8 行（reader 1、
   operator 7，其中包含 token replay），不得手工补 grant。

   ```sql
   SELECT max(version) = 85 AS exact_post_0085_ledger
     FROM public._sqlx_migrations;

   SELECT to_regprocedure('public.rss_read_projection_events(bigint,integer)') IS NULL
              AS legacy_reader_removed,
          to_regprocedure('public.rss_register_projection_input_binding(text,text,text,text,text)')
              IS NULL AS legacy_registry_removed,
          NOT EXISTS (
              SELECT 1 FROM pg_catalog.pg_roles
               WHERE rolname = 'rss_projection_events_runtime'
          ) AS bypass_owner_removed;

   SELECT role.rolname,
          role.rolcanlogin,
          NOT role.rolsuper AND NOT role.rolbypassrls AND NOT role.rolinherit
              AS safe_attributes,
          role.rolconfig
     FROM pg_catalog.pg_roles AS role
    WHERE role.rolname IN ('rss_projection_reader', 'rss_projection_operator')
    ORDER BY role.rolname;

   SELECT NOT has_table_privilege('rss_projection_reader', 'public.projection_events', 'SELECT')
              AS reader_has_no_raw_payload,
          NOT has_table_privilege('rss_projection_operator', 'public.projection_events', 'SELECT')
              AS operator_has_no_raw_payload,
          NOT has_table_privilege('rss_projection_operator', 'public.checkpoint', 'SELECT')
              AS operator_has_no_raw_checkpoint,
          NOT has_table_privilege('rss_projection_operator', 'public.distributed_cas', 'UPDATE')
              AS operator_has_no_raw_cas,
          NOT has_table_privilege('rss_projection_operator', 'public.auth_audit_events', 'INSERT')
              AS operator_has_no_raw_audit,
          NOT has_table_privilege('rss_projection_operator', 'public.dead_letter', 'INSERT')
              AS operator_has_no_raw_dlx;

   SELECT proc.proname,
          proc.prosecdef AS security_definer,
          proc.proconfig = ARRAY['search_path=pg_catalog, pg_temp']::text[]
              AS exact_search_path,
          pg_catalog.pg_get_userbyid(proc.proowner) = CASE
              WHEN proc.proname = 'rss_read_projection_events_scoped'
                  THEN 'rss_projection_source_reader_owner'
              WHEN proc.proname = 'rss_service_token_replay_check_and_record'
                  THEN 'rss_service_token_replay_owner'
              ELSE 'rss_projection_operator_owner'
          END AS exact_owner,
          NOT owner_role.rolcanlogin
              AND NOT owner_role.rolsuper
              AND NOT owner_role.rolbypassrls AS exact_nologin_owner
     FROM pg_catalog.pg_proc AS proc
     JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = proc.proowner
    WHERE proc.oid IN (
        'public.rss_read_projection_events_scoped(uuid,text,text,text,text,bigint,integer)'::regprocedure,
        'public.rss_projection_operator_record_audit(bigint,integer,text,text,text,text,text)'::regprocedure,
        'public.rss_projection_operator_get_checkpoint(uuid,text,text)'::regprocedure,
        'public.rss_projection_operator_save_checkpoint(uuid,text,text,bigint,bigint)'::regprocedure,
        'public.rss_projection_operator_read_active_pointer(uuid,text)'::regprocedure,
        'public.rss_projection_operator_cas_active_pointer(uuid,text,bytea,bytea,bigint)'::regprocedure,
        'public.rss_projection_operator_insert_dead_letter(uuid,text,text,text,text,text,text,jsonb,text,bigint,text,bytea,text,integer,text)'::regprocedure,
        'public.rss_service_token_replay_check_and_record(bytea,timestamptz)'::regprocedure
    )
    ORDER BY proc.proname;
   ```

4. **只启动新世界。** 先验证一个新 CLI 的两个 exact capability gate，再启动新 serving binary。迁移失败且
   ledger 仍为 `84` 时保持新世界停止，修正 empty-registry/会话/role 前置条件后重跑。ledger 已为 `85` 时
   不得启动旧 binary、恢复旧函数/角色或写 down migration；只能修正新配置或新增前向迁移。数据库级回滚
   仅允许恢复迁移前的完整备份，并与旧 artifact 一起整体恢复。

### 0086 Saga durable recovery 单一写入边界

`0086` 是 pre-activation、non-rolling hard cutover。它把 Saga instance、lease、append-only journal、
protected receipt 与 journal cursor 收进同一个 durable recovery model，并破坏式替换旧 status、journal
transition、约束、trigger 与 serving ACL。旧 binary 不理解新增 attempt/effect-key、operator reason 与
compensation cause，也不能满足新的 exact-intent 约束；因此旧/new writer 或 worker 绝不能滚动混跑。

写入权限同时硬切到 NOLOGIN/BYPASSRLS、无 membership 的 `rss_saga_writer`。它只拥有四张 Saga 表的
必要 DML，并且只能通过固定 `search_path=pg_catalog, pg_temp` 的 `SECURITY DEFINER` 函数替 `rss_app`
执行。函数从事务级 `rss.tenant_id` 推导 tenant，并在数据库内校验 exact source status、identity、未过期
lease token 与 epoch；`rss_app` 对四张表只有 SELECT 与函数 EXECUTE，没有任何原始 INSERT/UPDATE/DELETE。
tenant discovery 同步切换为 runnable-only keyset 页：只索引可 claim 的
`ready/running/compensating`，按唯一稳定 `tenant_id` 严格向后读取。`operator_required/degraded` 由独立
`SECURITY DEFINER` observation function 与 partial index 投影，不占 runnable 配额；repair 后 clean tick 可清除
当前 backlog degradation。

迁移拒绝 `saga_instances`、`saga_journal`、`saga_step_receipts` 任一非空状态并返回 SQLSTATE `55000`。
不 backfill、不猜测 intent/attempt/effect key，不保留 view、alias、shim、双写或 fallback。执行顺序固定如下：

1. **停止旧 Saga writer/worker 并封住重启面。** 先停止所有会启动 Saga writer、worker、maintenance CLI
   或 migration 的旧 workload、job 与 controller，禁用自动重启并保存旧 generation process inventory；
   inventory 必须证明旧副本、一次性 Job 与定时任务均为零。新 binary、serving pool 与 migration Job 此时
   同样保持停止。
2. **执行连接、ledger 与空表 preflight。** 用待发布镜像配置的 migrator 凭据取得下列只读快照；每个布尔值
   必须为 `true`。除当前 preflight 会话外，五个静态 PostgreSQL lane 必须全部排空；三张 Saga durable 表
   必须同时为空。任一结果不满足即中止，不得删除业务行、绕过检查或手工执行部分 DDL。

   ```sql
   SELECT max(version) = 85 AS exact_pre_0086_ledger
     FROM public._sqlx_migrations;

   SELECT
       (SELECT count(*) FROM public.saga_instances) = 0 AS saga_instances_empty,
       (SELECT count(*) FROM public.saga_journal) = 0 AS saga_journal_empty,
       (SELECT count(*) FROM public.saga_step_receipts) = 0 AS saga_step_receipts_empty;

   SELECT count(*) = 0 AS all_saga_lanes_drained
     FROM pg_catalog.pg_stat_activity
    WHERE pid <> pg_catalog.pg_backend_pid()
      AND backend_type = 'client backend'
      AND application_name IN (
          'rss-postgres-writer',
          'rss-postgres-reader',
          'rss-postgres-audit-admin',
          'rss-postgres-maintenance',
          'rss-postgres-migrator'
      );

   SELECT count(*) = 0 AS no_conflicting_saga_locks
     FROM pg_catalog.pg_locks
    WHERE granted
      AND relation IN (
          'public.saga_instances'::regclass,
          'public.saga_journal'::regclass,
          'public.saga_step_receipts'::regclass
      )
      AND mode IN (
          'RowExclusiveLock', 'ShareUpdateExclusiveLock', 'ShareLock',
          'ShareRowExclusiveLock', 'ExclusiveLock', 'AccessExclusiveLock'
      );
   ```

3. **运行唯一 migration runner。** 只启动一个待发布镜像的 `rss postgres migrate-all` Job。运行期间不得
   启动 serving binary、第二个 migration Job、Saga worker 或 maintenance CLI；Job 非零退出即进入步骤 5。
4. **执行 ledger、catalog、trigger、ACL 与函数 postflight。** Job 成功后仍以 migrator 凭据执行下列探针；
   所有布尔值必须为 `true`。约束查询必须找到全部 expected 行，trigger 查询必须找到一个普通 terminal
   trigger 与两个启用的 initially-deferred constraint trigger。

   ```sql
   SELECT max(version) = 86 AS exact_post_0086_ledger
     FROM public._sqlx_migrations;

   WITH expected(table_name, column_name, data_type, nullable) AS (
       VALUES
           ('saga_instances', 'operator_reason', 'text', 'YES'),
           ('saga_instances', 'compensation_cause', 'text', 'YES'),
           ('saga_journal', 'attempt', 'integer', 'NO'),
           ('saga_journal', 'effect_key', 'bytea', 'NO'),
           ('saga_journal', 'compensation_cause', 'text', 'YES')
   )
   SELECT count(column.column_name) = count(*)
          AND pg_catalog.bool_and(
              column.data_type = expected.data_type
              AND column.is_nullable = expected.nullable
          ) AS exact_0086_columns
     FROM expected
     LEFT JOIN information_schema.columns AS column
       ON column.table_schema = 'public'
      AND column.table_name = expected.table_name
      AND column.column_name = expected.column_name;

   WITH expected(relation_name, constraint_name) AS (
       VALUES
           ('saga_instances', 'saga_instances_status_valid'),
           ('saga_instances', 'saga_instances_operator_reason_valid'),
           ('saga_instances', 'saga_instances_compensation_cause_valid'),
           ('saga_instances', 'saga_instances_resolution_shape'),
           ('saga_instances', 'saga_instances_terminal_time_consistent'),
           ('saga_journal', 'saga_journal_status_check'),
           ('saga_journal', 'saga_journal_attempt_positive'),
           ('saga_journal', 'saga_journal_effect_key_width'),
           ('saga_journal', 'saga_journal_compensation_cause_valid'),
           ('saga_journal', 'saga_journal_compensation_cause_shape'),
           ('saga_journal', 'saga_journal_error_shape')
   )
   SELECT count(constraint.oid) = count(*) AS all_0086_constraints_present
     FROM expected
     LEFT JOIN pg_catalog.pg_class AS relation
       ON relation.oid = pg_catalog.to_regclass('public.' || expected.relation_name)
     LEFT JOIN pg_catalog.pg_constraint AS constraint
       ON constraint.conrelid = relation.oid
      AND constraint.conname = expected.constraint_name;

   WITH expected(trigger_name, relation_name, deferred, initially_deferred) AS (
       VALUES
           ('saga_instances_terminal_at_guard', 'saga_instances', false, false),
           ('saga_receipt_requires_completed', 'saga_step_receipts', true, true),
           ('saga_completed_requires_receipt', 'saga_journal', true, true)
   )
   SELECT count(trigger.oid) = count(*)
          AND pg_catalog.bool_and(
              trigger.tgenabled = 'O'
              AND trigger.tgdeferrable = expected.deferred
              AND trigger.tginitdeferred = expected.initially_deferred
          ) AS exact_0086_triggers
     FROM expected
     LEFT JOIN pg_catalog.pg_trigger AS trigger
       ON trigger.tgrelid = pg_catalog.to_regclass('public.' || expected.relation_name)
      AND trigger.tgname = expected.trigger_name;

   SELECT relation.relname,
          has_table_privilege('rss_app', relation.oid, 'SELECT') AS rss_app_can_select,
          NOT has_table_privilege('rss_app', relation.oid, 'INSERT')
              AS rss_app_cannot_raw_insert,
          NOT has_table_privilege('rss_app', relation.oid, 'UPDATE')
              AS rss_app_cannot_raw_update,
          NOT has_table_privilege('rss_app', relation.oid, 'DELETE')
              AS rss_app_cannot_raw_delete,
          has_table_privilege('rss_app_read', relation.oid, 'SELECT')
              AS rss_app_read_can_select
     FROM pg_catalog.pg_class AS relation
    WHERE relation.oid IN (
        'public.saga_instances'::regclass,
        'public.saga_journal'::regclass,
        'public.saga_step_receipts'::regclass,
        'public.saga_operator_decisions'::regclass
    )
    ORDER BY relation.relname;

   SELECT pg_catalog.pg_get_userbyid(proc.proowner) = 'rss_saga_writer' AS exact_owner,
          proc.prosecdef AS security_definer,
          proc.proconfig = ARRAY['search_path=pg_catalog, pg_temp']::text[] AS exact_search_path,
          has_function_privilege('rss_app', proc.oid, 'EXECUTE') AS rss_app_can_execute,
          NOT has_function_privilege('PUBLIC', proc.oid, 'EXECUTE') AS public_cannot_execute
     FROM pg_catalog.pg_proc AS proc
     JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = proc.pronamespace
    WHERE namespace.nspname = 'public'
      AND proc.proname IN ('rss_saga_register', 'rss_saga_claim',
          'rss_saga_claim_operator', 'rss_saga_renew_lease', 'rss_saga_release_lease',
          'rss_saga_apply_lifecycle', 'rss_saga_append_journal',
          'rss_saga_record_operator_decision', 'rss_saga_insert_receipt',
          'rss_saga_observe_claim', 'rss_saga_has_exact_prior_intent',
          'rss_saga_intent_attempt_is_next', 'rss_saga_lease_is_held')
    ORDER BY proc.proname;

   SELECT rolcanlogin = false AS no_login,
          rolsuper = false AS not_superuser,
          rolbypassrls AS exact_bypassrls,
          NOT EXISTS (
              SELECT 1 FROM pg_catalog.pg_auth_members AS membership
               WHERE membership.roleid = role.oid OR membership.member = role.oid
          ) AS no_memberships
     FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = 'rss_saga_writer';

   SELECT pg_catalog.pg_get_indexdef(index_relation.oid) LIKE
              '%status IN (''ready'', ''running'', ''compensating'')%'
              AS candidate_index_is_runnable_only
     FROM pg_catalog.pg_class AS index_relation
    WHERE index_relation.oid = 'public.saga_instances_worker_candidate_idx'::regclass;

   SELECT proc.proname,
          pg_catalog.pg_get_userbyid(proc.proowner) = 'rss_saga_maintenance' AS exact_owner,
          proc.prosecdef AS security_definer,
          proc.proconfig = ARRAY['search_path=pg_catalog, pg_temp']::text[] AS exact_search_path,
          proc.proname = 'rss_saga_observe_unresolved'
              OR pg_catalog.pg_get_functiondef(proc.oid) LIKE '%ORDER BY candidate.tenant_id%'
              AS exact_observation_or_keyset_order
     FROM pg_catalog.pg_proc AS proc
    WHERE proc.oid IN (
        'public.rss_saga_candidate_tenants(text,text,uuid,bigint)'::regprocedure,
        'public.rss_saga_observe_unresolved(text,text)'::regprocedure,
        'public.rss_saga_worker_tenant_index_refresh()'::regprocedure
    )
    ORDER BY proc.proname;

   SELECT
       pg_catalog.pg_get_userbyid(proc.proowner) = 'rss_saga_receipt_maintenance'
           AS exact_owner,
       proc.prosecdef AS security_definer,
       proc.proconfig = ARRAY['search_path=pg_catalog, pg_temp']::text[]
           AS exact_search_path,
       has_function_privilege('rss_app', proc.oid, 'EXECUTE')
           AS rss_app_can_execute,
       NOT EXISTS (
           SELECT 1
             FROM pg_catalog.aclexplode(
                 COALESCE(proc.proacl, pg_catalog.acldefault('f', proc.proowner))
             ) AS acl
            WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
       ) AS public_cannot_execute,
       pg_catalog.pg_get_functiondef(proc.oid) LIKE '%interval ''30 days''%'
           AS fixed_30_day_retention,
       pg_catalog.pg_get_functiondef(proc.oid) LIKE '%LIMIT 1000%'
           AS fixed_1000_batch
     FROM pg_catalog.pg_proc AS proc
    WHERE proc.oid = 'public.rss_sweep_terminal_sagas()'::regprocedure;
   ```

5. **按 ledger fail closed。** migration 失败且 ledger 仍为 `85` 时，保持所有 binary/worker 停止，证明
   `operator_reason` 与 journal `attempt` 列仍不存在、旧 trigger/constraint 仍完整，确认事务没有部分 DDL，
   然后重新执行步骤 1–3；非空表只能由产生数据的 owner 显式处置，不得由 rollout 自动删除。ledger 已为
   `86` 时视为 Saga 新世界已经提交：禁止启动旧 binary、修改 `0086`、写 down migration 或恢复旧
   status/ACL；postflight、启动配置或 schema 缺陷只能由 0086-compatible 新 binary 或新的 forward-only
   migration 修正。

   ```sql
   SELECT max(version) = 85 AS failed_0086_ledger_unchanged
     FROM public._sqlx_migrations;

   SELECT NOT EXISTS (
       SELECT 1
         FROM information_schema.columns
        WHERE table_schema = 'public'
          AND (
              (table_name = 'saga_instances'
                  AND column_name IN ('operator_reason', 'compensation_cause'))
              OR (table_name = 'saga_journal'
                  AND column_name IN ('attempt', 'effect_key', 'compensation_cause'))
          )
   ) AS failed_0086_has_no_partial_columns;

   SELECT
       pg_catalog.pg_get_constraintdef(instance_status.oid) LIKE '%failed%'
           AND pg_catalog.pg_get_constraintdef(instance_status.oid) NOT LIKE '%operator_required%'
           AS old_instance_status_constraint_intact,
       pg_catalog.pg_get_constraintdef(journal_status.oid) LIKE '%completed%'
           AND pg_catalog.pg_get_constraintdef(journal_status.oid) NOT LIKE '%forward_completed%'
           AS old_journal_status_constraint_intact
     FROM pg_catalog.pg_constraint AS instance_status
     CROSS JOIN pg_catalog.pg_constraint AS journal_status
    WHERE instance_status.conrelid = 'public.saga_instances'::regclass
      AND instance_status.conname = 'saga_instances_status_valid'
      AND journal_status.conrelid = 'public.saga_journal'::regclass
      AND journal_status.conname = 'saga_journal_status_check';
   ```

6. **只启动新 binary。** 只有部署 inventory、ledger=86、全部 postflight 与新 binary 的 startup capability
   gate 同时通过，才允许启动 Saga worker 并开放 workload。后续任何失败保持旧 binary 永久隔离，不恢复
   legacy writer、runtime lock、独立 checkpoint 或拆分 store。

### 0087 Device command generation/epoch fencing 破坏性切换

`0087` 是 non-rolling、forward-only hard cutover。它删除 intent-local active uniqueness，改由
`(tenant, device, generation, lease epoch)` fence、每设备唯一非终态命令和同 generation 唯一 intent
语义共同保护。迁移不猜测或回填旧 command/report；任一 held lease、重复坐标、同 generation 多 digest，
或不能由当前 desired/lease authority 安全支配的 durable 坐标都会让整个事务失败。
迁移同时撤销 `rss_app` 对 command 与 reported state 的直接 INSERT/UPDATE：command 安装与 ACK
状态推进只能调用 `rss_install_fenced_device_command` / `rss_apply_device_command_ack`，reported
state 只能调用 `rss_upsert_device_certificate_report`。三个固定 `SECURITY DEFINER` funnel 由
`rss_device_command_funnel_owner`（NOLOGIN、NOBYPASSRLS）持有，均先按
target → lease → desired 加锁，再触碰 command row；`rss_app_read` 不具备 EXECUTE。

1. **Drain 旧世界。** 停止 serving、reconcile worker、device ingress 与 maintenance CLI，禁止自动重启；
   等待所有 reconcile lease 正常 release。不得通过删 command、report、receipt 或强行清 lease 绕过 drain。
2. **Preflight。** 用 migrator 凭据确认 ledger 精确为 `86`、旧 writer/maintenance session 为零、held lease
   为零，并运行与迁移相同的 command/report authority 查询。以下计数必须全部为零；digest 查询覆盖 terminal
   历史，因为 takeover 必须保持 generation intent。

   ```sql
   SELECT max(version) = 86 AS exact_pre_0087_ledger FROM public._sqlx_migrations;
   SELECT count(*) FROM pg_catalog.pg_stat_activity
    WHERE application_name IN ('rss-postgres-writer', 'rss-postgres-maintenance');
   SELECT count(*) FROM public.reconcile_leases WHERE state = 'held';
   SELECT count(*) FROM (
       SELECT tenant_id, device_id, generation
         FROM public.device_commands
        GROUP BY tenant_id, device_id, generation
       HAVING count(DISTINCT intent_digest) > 1
   ) AS ambiguous_generation;
   SELECT count(*) FROM public.device_commands AS command
    LEFT JOIN public.device_certificate_desired_states AS desired
      ON (desired.tenant_id, desired.device_id) = (command.tenant_id, command.device_id)
    LEFT JOIN public.reconcile_targets AS target
      ON target.tenant_id = command.tenant_id
     AND target.reconciler_id = 'identity.device-certificate'
     AND target.resource_kind = 'device-certificate'
     AND target.resource_id = command.device_id::text
    LEFT JOIN public.reconcile_leases AS lease
      ON (lease.tenant_id, lease.target_id) = (target.tenant_id, target.target_id)
   WHERE command.state IN ('queued', 'published', 'received')
     AND ((desired.generation = command.generation AND lease.epoch = command.fence_epoch)
       OR (desired.generation >= command.generation AND lease.epoch > command.fence_epoch))
       IS NOT TRUE;
   SELECT count(*) FROM public.device_certificate_reported_states AS reported
    LEFT JOIN public.device_certificate_desired_states AS desired
      ON (desired.tenant_id, desired.device_id) = (reported.tenant_id, reported.device_id)
    LEFT JOIN public.reconcile_targets AS target
      ON target.tenant_id = reported.tenant_id
     AND target.reconciler_id = 'identity.device-certificate'
     AND target.resource_kind = 'device-certificate'
     AND target.resource_id = reported.device_id::text
    LEFT JOIN public.reconcile_leases AS lease
      ON (lease.tenant_id, lease.target_id) = (target.tenant_id, target.target_id)
   WHERE (desired.generation >= reported.observed_generation
          AND lease.epoch >= reported.fence_epoch) IS NOT TRUE;
   ```

3. **唯一 runner。** 只启动一个待发布镜像的 `rss postgres migrate-all` Job；不得并行运行第二个 migrator、
   旧 binary、ingress 或 maintenance CLI。非零退出立即保持 drain，不得扩容。
4. **Postflight。** 确认 ledger 精确为 `87`，两个新 unique index 均 valid，command/reported trigger 指向
   新函数，receipt disposition constraint 含 `device_rejected`（设备明确拒绝）以及
   `rejected`（服务端 authority 拒绝）、`stale_generation/stale_fence/stale_sequence`，且 trigger
   function 对 PUBLIC、`rss_app`、`rss_app_read` 均无 EXECUTE。

   ```sql
   SELECT max(version) = 87 AS exact_post_0087_ledger FROM public._sqlx_migrations;
   SELECT indexrelid::regclass::text, indisvalid
     FROM pg_catalog.pg_index
    WHERE indexrelid IN (
      'public.device_commands_fence_coordinate_unique'::regclass,
      'public.device_commands_one_nonterminal_per_device'::regclass
    ) ORDER BY 1;
   SELECT tgname, pg_catalog.pg_get_triggerdef(oid)
     FROM pg_catalog.pg_trigger
    WHERE tgrelid IN ('public.device_commands'::regclass,
                      'public.device_certificate_reported_states'::regclass)
      AND NOT tgisinternal ORDER BY tgname;
   ```

5. **失败与重试。** ledger 仍为 `86` 时，确认新 index/trigger 没有部分落地，修复 preflight 所揭示的 owner
   数据或完成正常 drain，再从步骤 2 重试。ledger 已为 `87` 即视为新世界提交：严禁 down migration、修改
   `0087` checksum、恢复旧 binary 或旧 wire；缺陷只能由 0087-compatible binary 或新的 forward-only migration
    修正。全部 postflight 和新 binary startup gate 通过后，才逐步恢复 serving/reconcile/ingress。


### 0088 Projection full-scope high-water 固定成本切换

`0088` 是 forward-only、non-rolling、无兼容路径的 Projection reader/control cutover。它安装固定
`SECURITY DEFINER` issuer、共享 scope validator、scoped event read 与七参数
`public.rss_projection_source_high_water_scoped(uuid,uuid,uuid,text,text,text,text)`，并新增只保存 SHA-256 digest 的
single-use `projection_source_capabilities` catalog。operator 为 sealed tenant/scope 签发两个 UUID half，reader 只能
把 opaque capability 交给 read/high-water 函数原子消费；reader 无 catalog/issuer 权限，operator 无 payload reader
权限。token 固定 30 秒过期，operator-only 零参数 sweeper 每次最多回收 1000 个签发后未消费的 orphan；TTL、batch
与删除目标均不可由调用方配置。旧 reader/control
binary 的 capability fingerprint 与新数据库不再兼容。不得保留旧分页求尾逻辑、函数 alias、双 grant、
版本特判或 global-high-water fallback。

issuer 只接受 sealed assembly target 已固定的 tenant、projection id、definition version、definition schema
digest 与 generated input generation；read/high-water 还必须提交 issuer 返回的一次性 capability。共享校验器统一
执行 lowercase grammar、generation receipt、完整 binding 和 token/scope digest 校验。完整 scope 未命中
`projection_input_bindings` 或 token 被复用/跨 scope 使用必须 fail-closed，不能伪装成
空 source；它以 SQLSTATE `22023` 表示 permanent/invariant identity drift，不可自动重试。scope 有效但尚无已提交
event 时返回 `NULL`（typed `None`）。一个函数调用只对该 scope 的每个静态 binding 执行一次 indexed tail seek，
再合并 committed LSN；相同静态 binding 集的 SQL 次数不随 `projection_events` 历史长度增长。真实 PostgreSQL
conformance 以 100,000 行无关历史、非空 relation block 前置条件与 shared-buffer 上限锁定该 T2 seam，不能外推为
T3 production acceptance。

`0088` 不替换 `rss_append_projection_event` 的全局
`pg_advisory_xact_lock(hashtextextended('rss.projection_events.append', 0))`。该 transaction advisory lock 仍在
projection LSN 分配前串行化 commit order；普通 sequence 不能替代它，当前能力仍只承诺 at-least-once。#1917
持 checkpoint/target correctness，#1921 持 high-water 读取与 pointer CAS 之间的 promote TOCTOU，#1922 持 lock
wait、tenant fairness、throughput、业务事务延迟与 X01 替换阈值。

1. **冻结 0087 世界并缩容到零。** 这是 `0087 → 0088` non-rolling cutover；先冻结所有 Projection append，
   再把 projection append writer、source reader、operator/CLI、worker 与相关一次性 Job 全部缩容到 0 并禁用
   自动重启。新 binary 与 migration Job 同样保持停止。用 migrator 的同一个只读 preflight session 确认 ledger
   精确为 `86`、三个 lane 的 active session 为零，且 `projection_events` 上会与 `CREATE INDEX` 冲突的已授予或
   等待锁均为零；任一布尔值不是 true 都中止，不得仅凭 deployment desired replicas 推断已经 drain。

   ```sql
   SELECT max(version) = 87 AS exact_pre_0088_ledger
     FROM public._sqlx_migrations;

   SELECT count(*) FILTER (
              WHERE application_name = 'rss-postgres-writer'
          ) = 0 AS projection_append_writer_sessions_drained,
          count(*) FILTER (
              WHERE application_name = 'rss-postgres-projection-source-reader'
          ) = 0 AS projection_source_reader_sessions_drained,
          count(*) FILTER (
              WHERE application_name = 'rss-postgres-projection-operator'
          ) = 0 AS projection_operator_sessions_drained
     FROM pg_catalog.pg_stat_activity
    WHERE pid <> pg_catalog.pg_backend_pid()
      AND backend_type = 'client backend'
      AND application_name IN (
          'rss-postgres-writer',
          'rss-postgres-projection-source-reader',
          'rss-postgres-projection-operator'
      );

   SELECT count(*) = 0 AS projection_events_conflicting_locks_drained
     FROM pg_catalog.pg_locks
    WHERE relation = 'public.projection_events'::regclass
      AND mode IN (
          'RowExclusiveLock', 'ShareUpdateExclusiveLock',
          'ShareRowExclusiveLock', 'ExclusiveLock', 'AccessExclusiveLock'
      );
   ```

2. **在同次只读 preflight 固定容量 receipt。** 保持上述 lane 为零；不得复用旧查询或旧 rollout 的 PASS。
   先运行下列固定 SQL，记录 journal rows/heap/total bytes 和 index planning estimate，再记录 archive/replica lag
   与剩余 maintenance window。index estimate 只用于与同次演练批准的安全余量比较，不是新的通用容量阈值；
   容量 envelope、lock wait/fairness/throughput 与业务延迟仍由 #1922 持有。

   ```sql
   WITH journal AS (
       SELECT relation.reltuples,
              pg_catalog.pg_relation_size(relation.oid) AS heap_bytes,
              pg_catalog.pg_total_relation_size(relation.oid) AS total_bytes
         FROM pg_catalog.pg_class AS relation
        WHERE relation.oid = 'public.projection_events'::regclass
   ), indexed_width AS (
       SELECT 36 + 8 + COALESCE(sum(stat.avg_width), 0) AS bytes_per_entry
         FROM pg_catalog.pg_stats AS stat
        WHERE stat.schemaname = 'public'
          AND stat.tablename = 'projection_events'
          AND stat.attname IN (
              'domain', 'contract_id', 'contract_version', 'schema_hash', 'event_type'
          )
   )
   SELECT (SELECT count(*) FROM public.projection_events) AS journal_rows,
          journal.heap_bytes AS journal_heap_bytes,
          journal.total_bytes AS journal_total_bytes,
          ceil(
              greatest(journal.reltuples, 0) * (indexed_width.bytes_per_entry + 24) / 0.90
          )::bigint AS estimated_index_bytes
     FROM journal CROSS JOIN indexed_width;

   SELECT archived_count, failed_count, last_archived_wal, last_archived_time,
          pg_catalog.clock_timestamp() - last_archived_time AS archive_time_lag,
          last_failed_wal, last_failed_time
     FROM pg_catalog.pg_stat_archiver;

   SELECT application_name, state, sync_state,
          pg_catalog.pg_wal_lsn_diff(
              pg_catalog.pg_current_wal_lsn(), replay_lsn
          ) AS byte_lag,
          write_lag, flush_lag, replay_lag
     FROM pg_catalog.pg_stat_replication
    ORDER BY application_name;

   -- 用 psql -v rollout_deadline_utc='<批准的 UTC deadline>' 注入本次窗口终点。
   SELECT extract(epoch FROM (
              :'rollout_deadline_utc'::timestamptz - pg_catalog.clock_timestamp()
          ))::bigint AS remaining_maintenance_window_seconds;
   ```

   再在 primary DB host 以只读命令记录 data 与 `pg_wal` 的可用字节；目录必须来自同一 primary 的
   `SHOW data_directory`，不得手填其他 host 路径。

   ```sh
   RSS_0088_DATA_DIRECTORY="$(psql service=rss-owner -Atqc 'SHOW data_directory')"
   test -n "${RSS_0088_DATA_DIRECTORY}"
   df -PB1 "${RSS_0088_DATA_DIRECTORY}" "${RSS_0088_DATA_DIRECTORY}/pg_wal"
   ```

   将 rows/bytes/index estimate、data/`pg_wal` 余量、archive counters/time lag、部署 inventory 中预期的
   streaming replica 数量及各 replica byte/time lag、剩余窗口逐项与同次批准的 rehearsal envelope 比较。
   任一值为空、replica 数量/状态不符、lag 或 estimate 越界、空间不足，或剩余窗口不足以覆盖演练最大 migration
   时长加 postflight/abort 预算，都保持全体缩容并中止。不得新增脚本、把该 receipt 写成 T3 carrier，或以扩大
   `lock_timeout`/`statement_timeout` 代替重新批准窗口。
3. **运行唯一 migration runner。** 只启动一个待发布镜像的 `rss postgres migrate-all` Job；运行前再次执行步骤
   1 的 session/lock 查询，结果仍须全 true。失败时不得手工执行部分 index/function/grant，也不得修改 0088、
   写 down migration 或启动任何 frozen lane。
4. **执行 ledger、index、函数与权限 postflight。** ledger 必须精确为 `87`；index 查询必须恰好返回一行且
   `exact_definition`、`indisvalid`、`indisready` 全为 true。启动新 binary 的 exact catalog verifier 必须确认
   capability table 的列/约束/expiry index/owner/ACL、五个函数（含 bounded sweeper）的
   identity/owner/volatility/`SECURITY DEFINER`/配置/ACL 与登记
   fingerprint 全部精确；reader 仍无 raw journal、binding 或 capability catalog 权限，且不能调用 issuer/helper。

   ```sql
   SELECT max(version) = 88 AS exact_post_0088_ledger
     FROM public._sqlx_migrations;

   SELECT pg_catalog.pg_get_indexdef(index_rel.oid, 0, false) =
              'CREATE INDEX idx_projection_events_scoped_tail ON public.projection_events USING btree (domain, contract_id, contract_version, schema_hash, event_type, ((metadata ->> ''tenantId''::text)), id DESC)'
              AS exact_definition,
          index_status.indisvalid,
          index_status.indisready
     FROM pg_catalog.pg_class AS index_rel
     JOIN pg_catalog.pg_namespace AS namespace
       ON namespace.oid = index_rel.relnamespace
     JOIN pg_catalog.pg_index AS index_status
       ON index_status.indexrelid = index_rel.oid
    WHERE namespace.nspname = 'public'
      AND index_rel.relname = 'idx_projection_events_scoped_tail';

   SELECT to_regprocedure(
              'public.rss_read_projection_events_scoped(uuid,uuid,uuid,text,text,text,text,bigint,integer)'
          ) IS NOT NULL AS exact_scoped_reader,
          to_regprocedure(
              'public.rss_projection_source_high_water_scoped(uuid,uuid,uuid,text,text,text,text)'
          ) IS NOT NULL AS exact_scoped_high_water,
          to_regprocedure(
              'public.rss_projection_operator_issue_source_capability(uuid,text,text,text,text)'
          ) IS NOT NULL AS exact_operator_issuer,
          to_regprocedure(
              'public.rss_projection_operator_sweep_source_capabilities()'
          ) IS NOT NULL AS exact_operator_sweeper,
          to_regprocedure(
              'public.rss_assert_projection_source_scope(boolean,uuid,uuid,uuid,text,text,text,text)'
          ) IS NOT NULL AS exact_shared_validator,
          to_regprocedure(
              'public.rss_read_projection_events_scoped(uuid,text,text,text,text,bigint,integer)'
          ) IS NULL AS legacy_reader_absent,
          NOT has_table_privilege(
              'rss_projection_reader', 'public.projection_events', 'SELECT'
          ) AS reader_has_no_raw_payload,
          NOT has_table_privilege(
              'rss_projection_reader', 'public.projection_input_bindings', 'SELECT'
          ) AS reader_has_no_raw_bindings,
          NOT has_table_privilege(
              'rss_projection_reader', 'public.projection_source_capabilities', 'SELECT'
          ) AS reader_has_no_capability_catalog,
          NOT has_function_privilege(
              'rss_projection_reader',
              'public.rss_projection_operator_issue_source_capability(uuid,text,text,text,text)',
              'EXECUTE'
          ) AS reader_cannot_issue_capabilities;
   ```

5. **按 ledger fail closed。** migration 失败且 ledger 仍为 `87` 时，保持新旧 Projection reader/control
   全部停止，确认函数、index 与 grant 没有部分提交后修正阻塞并由唯一 runner 重试。ledger 已为 `88` 时禁止
   启动旧 binary、恢复分页求尾、增加兼容函数或回改 0088；只允许修正新配置、新 binary，或增加新的
   forward-only migration。
6. **只启动 0088-compatible binary。** startup exact capability、full-scope negative、valid-empty `NULL`、
   concurrent commit-order 与 100,000-row buffer regression 全部通过后，才允许恢复 Projection CLI/worker。
   这些是 #1916 的 T2 receipts，不关闭 #1917/#1921/#1922，也不产生 T3 或 exactly-once 声明。

### 0089 Saga lifecycle/operator hard cutover

`0089` 在已完成 `0088` 的数据库上安装 Saga start authorization、unresolved observation 与
retry-compensation/terminate CAS transition ledger。迁移是 forward-only、non-rolling；执行前必须停止 serving、
Saga worker、operator CLI 与其他 migrator，并确认 `saga_instances`、`saga_operator_decisions` 为空。只允许一个新
artifact migrator 执行。失败且 ledger 仍为 `88` 时保持 drain 后重试；ledger 已为 `89` 时不得恢复旧 binary 或修改
迁移 checksum。

Postflight 必须确认 ledger=89、`saga_operator_transitions` 及其 RLS/index 存在，retry/terminate 函数由
`rss_saga_writer` 持有、固定 `search_path=pg_catalog, pg_temp`、PUBLIC 无 EXECUTE，且 `rss_app` 不能直接写 transition
table。

### 0090 Saga operator credential cutover

`0090` 创建永久 NOLOGIN 的 `rss_saga_operator_owner` 与 function-only `rss_saga_operator` credential。部署须通过
`deploy/postgres-upgrade/provision-saga-operator-role.sh` 注入 file-only secret；禁止 argv/环境明文密码、role
membership 或 owned object。启用 operator 前必须确认 ledger=90、credential 仅有 `_sqlx_migrations` SELECT，且
四个函数权限精确如下：

```sql
SELECT has_function_privilege('rss_app',
         'public.rss_saga_retry_compensation(uuid,text,text,bigint,text,integer,bytea,text,text,text,text)',
         'EXECUTE') AS app_can_retry,
       has_function_privilege('rss_app',
         'public.rss_saga_terminate(uuid,text,text,text,text,text,text)',
         'EXECUTE') AS app_can_terminate,
       has_function_privilege('rss_saga_operator',
         'public.rss_saga_retry_compensation(uuid,text,text,bigint,text,integer,bytea,text,text,text,text)',
         'EXECUTE') AS operator_can_retry,
       has_function_privilege('rss_saga_operator',
         'public.rss_saga_terminate(uuid,text,text,text,text,text,text)',
         'EXECUTE') AS operator_can_terminate;
```

期望 `app_can_retry=false`、`app_can_terminate=false`、`operator_can_retry=true`、
`operator_can_terminate=true`；另外两个允许函数仅为 service-token replay 与 correlated audit。任何额外 relation、
sequence 或 routine 权限都必须 fail closed。

### 0091 Settings metadata Projection 持久模型

`0091` 新建 `settings_projection_generations`、`settings_config_projection_rows` 与
`settings_projection_dedupe_receipts`。三表只保存 tenant、definition/generation、config key/version、change kind、
source event/LSN、digest 与 timestamps；没有 config value、secret、token、raw payload、JSON 或 sourceVersion。

迁移为 additive、forward-only 且无 backfill；#1919 注册 typed target 前三表保持 dormant。三表均启用
ENABLE+FORCE RLS，reader 只有 SELECT，writer 只有当前行 apply 所需的列级 INSERT/UPDATE，receipt append-only，
所有应用角色均无 DELETE/TRUNCATE。`mutation + receipt + high-water` 由 adapter 在一个 tenant-scoped 本地事务中提交；
失败时不得留下部分状态。ledger 已为 91 时不得恢复不理解该 schema 的旧 writer，也不增加旧表、alias、dual-write
或兼容 migration。

### 0092 Device certificate artifact evidence and deletion finalizer

`0092` 是 non-rolling、forward-only hard cut：开放 `Ready=True`，为 desired authority 增加
`deletion_requested_at` / `finalizer_present` 的闭合状态组合，并创建按
`(tenant_id, device_id, generation)` 唯一的 immutable authorized-artifact receipt。receipt 表启用
`FORCE RLS`；serving writer 只有列级 INSERT 和 SELECT，没有 UPDATE/DELETE/TRUNCATE/TRIGGER 权限。

部署前须停止 certificate reconciler 并等待所有该 reconciler lease 释放。ledger=92 后只允许 0092-compatible
binary；删除完成必须在同一 tenant transaction 内重查 retained receipt：每个 receipt 仅当
`clock_timestamp() >= not_after`，或现有 `certificate_revocations` 中存在相同
tenant/device/serial/not_after 记录时才是 terminal evidence。完成事务同时写
`Deleting=True/DeletionComplete`、释放 certificate finalizer、禁用 target、写 settled attempt result并释放
lease；证据不足或 attempt/lease/epoch/wake fence 失效必须零写。

### 0093 Settings Projection apply function hard cutover

`0093` 破坏性撤销 `rss_app` 对三张 Settings Projection 表的原始 INSERT/UPDATE 权限，并安装唯一的
`public.rss_settings_projection_apply(...)`。函数只接受 validated metadata，不接受 config value、secret、token、
raw payload 或 JSON；serving writer 与 `rss_projection_operator` 仅有 EXECUTE，reader 与 PUBLIC 无 EXECUTE。

函数由永久 NOLOGIN、NOSUPERUSER、NOBYPASSRLS 的 `rss_projection_operator_owner` 持有，固定
`search_path=pg_catalog, pg_temp`，只接受调用方已经设置且与参数精确一致的 transaction-local
`rss.tenant_id`；unset/empty/mismatch 一律以 `P1902` fail closed。receipt duplicate/conflict、
persistent LSN order、current row、receipt 与 high-water 在同一 statement transaction 内完成。ledger=93 后禁止启动
仍执行 0091 原始表 SQL 的旧 binary，也不得增加兼容函数、raw-write grant、dual-write 或 fallback。

这是 non-rolling hard cut，部署顺序固定如下：

1. **Quiesce / drain**：停止所有旧 serving writer、Projection replay/operator 和 Settings maintenance，确认
   `pg_stat_activity` 不再有旧 `rss-postgres-writer` / `rss-postgres-projection-operator` 会话；ledger 必须精确为 92。
2. **唯一 migrator**：只运行一个待发布镜像的 `rss postgres migrate-all` Job。迁移失败或超时即停止，禁止启动
   serving/operator，也禁止手工补 grant 或直接执行函数 DDL。
3. **Postflight**：确认 ledger=93；函数 owner 属性与 `search_path` 精确；app/operator 只有函数 EXECUTE、三张表
   无 raw write；reader/PUBLIC 无 EXECUTE。分别以 app/operator 在回滚事务中验证 unset/mismatch 均 `P1902`、match
   可 `applied`。同时验证 scoped source 对同 tenant、known binding 的 version/schema drift 返回 metadata-only poison
   （payload 长度为 0），而非静默过滤或释放 raw payload。
4. **恢复边界**：若 ledger 仍为 92 且 catalog 确认 0093 全部回滚，才可恢复旧 binary；若 ledger 已为 93，严禁
   恢复旧 binary，只能修正新镜像/凭据并重做 postflight 后逐步启动同一新版本。正式 shadow worker 激活仍由 #1920
   负责，serving promotion 仍由 #1921 负责。

### 0094 Durable device ingress UoW hard cut

`0094` 删除 `rss_apply_device_command_ack` 与 `rss_upsert_device_certificate_report`，不保留旧签名或
overload。ACK 与 report 分别只能调用
`rss_commit_device_command_ack_ingress` / `rss_commit_device_certificate_report_ingress`；两个
`SECURITY DEFINER` funnel 在 tenant scope 下按 event ID 串行化，重查完整 immutable evidence，锁定
target → lease → desired → command authority，并在同一事务内写 command/reported/conditions/wake 与
internal ingress receipt。serving role 对 receipt、command、reported 和 condition 表的直接 mutation 权限
全部撤销，函数由固定 NOLOGIN/NOBYPASSRLS owner 持有。

两个 funnel 同时接收 transport 已认证的 `credential_generation`，并只在锁定 canonical desired
generation 后比较；NULL scope proof 或 credential generation 失配统一落 `scope_mismatch`，不得进入业务
mutation，也不向调用方暴露 stale credential oracle。receipt ledger 的 high-water 查询使用
`device_ingress_receipts_high_water_idx` partial composite index，只纳入 `advanced` / `device_rejected` 的
authoritative sequence，拒绝高序 receipt 不得污染后续有效低序输入。

应用层在同一 tenant transaction 内从函数返回的 DB transaction-time receipt 生成冻结的
`identity.device-ingress-receipted` FACT 并追加 Outbox；metadata 只由 persisted `committedAt` 和生成契约
构造，不掺入 ambient trace/correlation，保证 exact replay fingerprint 稳定。commit acknowledgement 丢失时，
只有 internal receipt 的完整 evidence 与确定性 Outbox `fact_fingerprint` 同时匹配才恢复为 committed；任一
缺失或冲突都保持 delivery unsettled。

identity 只负责 decode 与 receipt evidence 校验，不铸造 transport settlement authority。PostgreSQL 仅在真实
commit 或 exact readback 后私有铸造 move-only `PgDeviceIngressCommitProof`；组合根的具体 PG runner 消费该 proof
后才可进入 settlement。普通 repository receipt、identity domain outcome 与 MQTT broker-only fixture 都不能触发
PUBACK；该 production seam 的 assembly 激活由 #1904 完成。

部署是 non-rolling hard cut：先停止旧 device-ingress writer，确认 ledger=93 后迁移，再只启动 0094-compatible
binary。postflight 必须确认旧函数 `to_regprocedure(...) IS NULL`、两个新函数仅 `rss_app` 可 EXECUTE、
`rss_app` 不具备上述四表的 INSERT/UPDATE/DELETE 权限，并保留各表 FORCE RLS。

执行协议（所有探针使用 migration owner 连接；`rss_app` smoke test 单独注明）：

1. drain 所有旧 binary，按部署约定的 `application_name` 查询 `pg_stat_activity`，直到旧 writer session 为零；
   在迁移窗口保持旧 deployment scale=0，禁止滚动混跑。
2. 只允许一个 migration Job 取得部署锁；执行前确认
   `SELECT max(version) FROM _sqlx_migrations WHERE success` 为 `93`，否则停止。
3. 运行 0094。提交前失败可终止 Job、恢复旧 deployment 并重试；一旦 0094 提交，严禁恢复旧 binary，
   只能修复并启动兼容 0094 的 binary。
4. postflight 查询 `pg_proc`/`pg_roles` 验证两个新函数 owner 为
   `rss_device_command_funnel_owner`（NOLOGIN、NOBYPASSRLS），旧函数的 `to_regprocedure` 为 NULL；用
   `has_function_privilege` 验证仅 `rss_app` 有 EXECUTE。逐列查询 `has_column_privilege`，确认 `rss_app`
   对 receipt/command/reported/condition 无 INSERT/UPDATE，并确认四表 `relrowsecurity` 与
   `relforcerowsecurity` 均为 true。
5. 以 `rss_app` 开启事务、绑定测试 tenant，分别调用两个新 funnel 的无资源/拒绝路径并检查返回 closed
   receipt；在同一事务核对 receipt 与 Outbox 后执行 `ROLLBACK`。任一 catalog 或 smoke probe 失败均保持
   新 binary 停止，修复 0094-compatible 路径后重试，不允许回退旧 writer。
