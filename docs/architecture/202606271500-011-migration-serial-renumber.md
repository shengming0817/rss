# ADR-011：postgres 迁移序号重编（去重）+ 序号唯一性治理门

- **状态**：Accepted
- **日期**：2026-06-27
- **关联**：issue #1134 [infra-deploy]（容器化交付时 E2E 首次对真实 PG 跑 `run_migrations` 暴露本 bug）
- **归属**：framework（持久化基座 / 迁移治理，provider-agnostic）
- **AI-robust 评级**：序号唯一性 = **Medium**（`cargo xtask migrations` 文件名扫描，接入 verify/ci，INVARIANT `MIGRATION-SERIAL-UNIQUE-01`）

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

### 2.3 新增序号唯一性治理门（堵住根因）

重编只修存量；根因是**无机器门挡住两 PR 加同号**。新增 `cargo xtask migrations`（接入 `cargo xtask verify`
/ `ci`，Medium，INVARIANT `MIGRATION-SERIAL-UNIQUE-01`）：扫描 `migrations/*.sql` 文件名，序号重复或非连续即
门红，列出冲突号与文件名。带 synthetic red case（重号 / 缺号）+ anti-vacuity。

## 3. 备选与否决

- **把第二个重号迁移挪到序列末尾**（最小改动）：否决——`0016_add_seq_and_partition_to_outbox` ALTER outbox，
  若把 `outbox` 建表挪到其后则依赖倒置；保持顺序的唯一办法是整体重编尾部。
- **仅修存量、不加门**：否决——根因（无唯一性门）会让同类重号复发，违反 AI-robust「错误尽量不可表达 / 至少机器可判定」。
- **运行期靠 sqlx `VersionMismatch` 兜底**：否决——那是**部署期**才暴露的 fail-fast，远晚于 PR 评审；
  本门在**静态/CI 期**拦截，上移到尽量早。

## 4. AI-robust / 威胁

- 载体档位：文件名扫描属第 5 档（metadata 内容扫描）；序号是文件系统事实，无法上移到类型系统/crate 图，
  Medium 是该约束可达的最高档（符合 ai-robust「最低门槛 Medium」）。
- 守卫自身 anti-vacuity：红例（重号、缺号）确保门非恒真。
- 残余风险：门只校验**文件名序号**，不校验迁移**内容**正确性（后者由集成测试 + sqlx 运行期 checksum 守）。
