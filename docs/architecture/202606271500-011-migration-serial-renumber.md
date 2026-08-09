# ADR-011：postgres 迁移序号重编（去重）+ 序号唯一性治理门

- **状态**：Accepted（#1998 修订：连续性 / 固定四位假门退役；唯一性上移 inventory Hard SoT；`MIGRATION-SERIAL-UNIQUE-01` Medium 门删除）
- **日期**：2026-06-27
- **关联**：issue #1134 [infra-deploy]（容器化交付时 E2E 首次对真实 PG 跑 `run_migrations` 暴露本 bug）；issue #1457 / #1458（未部署 audit schema 真源硬化）；issue #1998（假连续性门清理 + Migrator 同源 inventory）；issue #2060（未部署 migration 中 Projection source SQL 归位）
- **归属**：framework（持久化基座 / 迁移治理，provider-agnostic）
- **AI-robust 评级**：序号唯一性 + version/checksum 同源 = **Hard**（`postgres-migration-inventory` build.rs 调用 `sqlx_core::migrate::resolve_blocking`，INVARIANT `POSTGRES-MIGRATION-INVENTORY-01`）

---

## 1. 背景与问题

`adapters/postgres/migrations/` 由 `PgStore::run_migrations` 经 `sqlx::migrate!("./migrations")` 应用。sqlx 以
解析自文件名前缀的整数 `version` 为**主键**记账 `_sqlx_migrations`（version → checksum）。

develop 历史上有 **4 对重复序号**：`0002`（inbox_dedup + outbox）、`0008`（roles + secret_refs）、
`0009`（add_sessions_revoked + enable_tenant_rls）、`0013`（add_seq_and_partition_to_outbox + refresh_tokens）。
其中 `0013` 是两个独立 PR（#1211 PR287、#1325 PR284）各自加同号迁移、合入时未被任何门拦截而成。

重号在任意 fresh DB 上**直接破坏迁移**：sqlx 对同 `version` 的第二个文件触发 `VersionMismatch`（checksum 与已记账
不符）或 `_sqlx_migrations` 主键冲突 ⇒ `run_migrations` fail-fast、server 永远起不来、`/readyz` 到不了 200。
因 azure 集成 CI 未激活（`AZURE_HAS_CI=false`，integration lane 仅手动），此前无任何自动路径对真实 PG 跑全量迁移，
缺陷潜伏至 #1134 容器化首次 E2E 才暴露。**即：server 从未成功对一个 fresh PG 完成迁移。**

## 2. 决策

### 2.1 一次性重编为唯一连续序号（pre-GA append-only carve-out）

把 18 个迁移整体重编为唯一连续 `0001`–`0018`，**保持原有应用顺序**（重号对内按依赖安全的字母序定序：
outbox 在其 ALTER 之前、被建表在 `enable_tenant_rls` 之前等），仅破开重号、不改任一迁移的 SQL 语义。

这是 `rust-standards.md` / 迁移 README「已提交 migration 只增不改」的**显式例外**，依据：

- **pre-GA、无外部消费方、无已部署 DB** ⇒ 不存在持有旧 checksum 的 `_sqlx_migrations`，重编无破坏对象。
- 「只增不改」保护的是**可独立演进的已部署 schema 历史**；重号迁移在任何 DB 上本就无法应用，重编是
  **bug 修复**而非演进破坏——保护对象不存在，仪式无意义（同 `api-versioning.md` pre-GA wire 窗口的推理）。
- 不考虑向后兼容（`CLAUDE.md`：当前只有 rss 自身）。

窗口边界：GA 或出现已部署 DB 后，本例外即失效，迁移恢复严格 append-only。

### 2.2 #1255 扩展：修复 PR329 后残留的 `0020` 重号

PR329 合并后的 `develop` 再次出现两个 `0020`：
`0020_add_inbox_dedup_sweep_index.sql` 与 `0020_harden_dead_letter_rls.sql`。该状态同样会让
fresh DB 上的 `run_migrations` 在版本记账处 fail-fast。

#1255 只做必要重编号：保留 `0020_add_inbox_dedup_sweep_index.sql`，将 dead-letter RLS 迁移与 sweep 索引顺延为
`0021`/`0022`，新增 distributed CAS 为 `0023`，RLS 空 GUC policy 修复为新的前向迁移 `0024`。重编号文件不改 SQL
语义；任何 policy 语义修正均用新迁移表达，避免把内容 rewrite 混入序号修复。

依据仍是本 ADR 的 pre-GA carve-out：重复序号本身已破坏 fresh DB 迁移；在 GA 或已有部署 DB 后不得再扩展本例外。

### 2.3 序号唯一性治理门（堵住根因）

重编只修存量；根因是**无机器门挡住两 PR 加同号**。#1134 曾新增 `cargo xtask migrations`
（Medium，`MIGRATION-SERIAL-UNIQUE-01`）扫描文件名唯一性与连续性。

### 2.4 #1998 修订：删除假连续性门 + Hard SoT

SQLx 真正关心 version 唯一、排序、checksum 与成功/失败状态，**不要求**无空洞的 `0001..=N` 或固定四位。
把命名偏好写成正确性门会误杀合法缺号，并与独立 filename parser 形成第二套事实源。

#1998 决策：

1. 删除连续性 / 从 `0001` / 固定四位作为 correctness gate。
2. `postgres-migration-inventory` build.rs 改用 `sqlx_core::migrate::resolve_blocking`（与 `sqlx::migrate!` 同源）派生 `(version, checksum)`；Hard 查重 + 目录内每个 `.sql` 必须被 resolve。
3. 删除 Medium `migrations-serial` / `MIGRATION-SERIAL-UNIQUE-01` 整扇门（含 `cargo xtask migrations`），避免双 parser。
4. 保留 serving SQL-text-free（sqlx-core 仅 build-dep）与 ledger dirty/failed/checksum 匹配。
5. **不重编号**任何已存在 migration 文件。

### 2.5 #2060 窄例外：未部署 Projection source SQL 归位

用户已确认项目仍为 pre-GA 且从未部署，不存在持有旧 `0088`/`0093` checksum 的数据库。`0093` 曾在 Settings
Projection apply funnel 之外后置覆盖 `0088` 的 scoped read 与 high-water，其中 high-water 放宽 binding identity
并退化为 ledger 宽扫描。#2060 原地整理这段尚未部署的 migration history：metadata-only poison read 归还 `0088`，
`0093` 只保留 Settings apply funnel，错误 high-water 定义直接删除。

该决定不建立历史 migration 内容可任意改写的通用许可，只覆盖这次 owner 归位与错误覆盖删除；一旦出现部署 DB、
旧 checksum 或 GA 发布，本例外立即失效，后续修正必须恢复严格 forward-only。

### 2.6 #1457 / #1458 窄例外：未部署 audit session resource 真源硬化

用户确认项目没有历史部署、`_sqlx_migrations` ledger 或历史数据。#1457 / #1458 因而直接修正尚未部署的
`0018_create_audit_entries.sql`：`identity:login/session` 的 `resource_id` 只接受由独立 EventId 派生的
`event:<canonical UUID v4>`，数据库拒绝 bearer SessionId、非 RFC variant、非 v4 与非 canonical 形态。

该例外只覆盖本次 fresh-install audit schema 真源修正，不授权改写其他 migration，也不引入 backfill、兼容
reader、双写或后置 migration。一旦出现任何部署、migration checksum ledger、历史行或 GA 发布，窗口立即
失效；后续 SQL 语义修正必须恢复严格 forward-only。

## 3. 备选与否决

- **把第二个重号迁移挪到序列末尾**（最小改动）：否决——`0016_add_seq_and_partition_to_outbox` ALTER outbox，
  若把 `outbox` 建表挪到其后则依赖倒置；保持顺序的唯一办法是整体重编尾部。
- **仅修存量、不加门**：否决——根因（无唯一性门）会让同类重号复发，违反 AI-robust「错误尽量不可表达 / 至少机器可判定」。
- **运行期靠 sqlx `VersionMismatch` 兜底**：否决——那是**部署期**才暴露的 fail-fast，远晚于 PR 评审；
  Hard inventory 在**编译期**拦截，上移到尽量早。
- **保留 Medium xtask 瘦身唯一性门**：否决（#1998）——与 inventory Hard 双 parser，违反优雅简洁 / 不双路径。

## 4. AI-robust / 威胁

- 载体档位：version/checksum SoT 与 `migrate!` 同函数（Hard build 派生）；唯一性与「无可解析 `.sql` 遗漏」为 Hard assert。
- 原 Medium 文件名扫描门（含连续性假不变量）已退役。
- 残余风险：门不校验迁移**SQL 语义**正确性（后者由集成测试 + sqlx 运行期 checksum / ledger 守）。
