# ADR-011：持久化模式 tenant 作用域合约 — RLS 解锁器（PERSIST-016）

- **状态**：Accepted（#1437 落地；为 #1405 / #1426 / #1436 提供稳定底座）
- **日期**：2026-06-27
- **关联**：issue #1437 [PERSIST-016] · Parent Feature #1418 [PERSIST-EPIC] · 同批 #1405（outbox tenant 注入）· #1426（repo conformance testkit）· #1436（PG tx funnel / raw-pool guard）
- **依赖 ADR**：**ADR-002**（tenant 只来自已认证通道，`TenantId` 在 base 层 `vocab`）· **ADR-005**（域形 repo port 归属，`cotx` funnel 是 adapter 层实现）· **ADR-010**（`PgRuntimeDeps::setup` 能力门控是持久化能力分层的自底向上第一步）
- **归属**：framework（tenant 隔离接缝是 provider-agnostic 持久化治理，非单一域逻辑）
- **AI-robust 评级**：见 §6

---

## 1. 背景

PERSIST epic #1418 自底向上长出 durable 持久化能力，ADR-010 已定 `PgRuntimeDeps` /
`PgDomainDeps` 分层语义与 `DomainModuleResult` 聚合约定。在该框架之上，同批 issue 均要求
postgres adapter 中 **tenant scope 的注入方式**已经统一且机器可验证：

- **#1405**（outbox tenant 注入）：outbox 目前是无 `tenant_id` 列的全局表，加列 + RLS 前需确保
  现有 tenant 表路径已通过受控 funnel 注入；否则全局表 RLS 加入后改一半、另一半仍裸注入，
  无法判断覆盖面。
- **#1426**（repo conformance testkit）：testkit 要断言「缺 tenant → 0 行 / 写拒」，需已有可靠的
  fail-closed 语义作为被测目标，而不是先在 testkit 内定义它。
- **#1436**（PG tx funnel / raw-pool guard）：raw-pool bypass 保护依赖 `cotx` funnel 已是单一
  入口；多入口时 bypass 保护只能是 Soft。

当前状态：`cotx.rs` 的 helper 参数是裸 `&str`，可传任意字符串作为 tenant_id；xtask 也没有
扫描 `set_config('rss.tenant_id'` 调用分布的守卫；startup 没有在迁移后动态验证 RLS 确实在
force 中。**三个兄弟 issue 均被这三处缺口阻塞**，故 #1437 先行落地，仅做最小 RLS 解锁，
不触碰 outbox / inbox 结构。

### 关于全局基础设施表的边界判断

`outbox` / `inbox_dedup` / `saga_journal` / `projection_events` **无 `tenant_id` 列**，不在
本 ADR 范围。其中 `inbox_dedup.event_id` 是全局唯一（UUID），跨租户无碰撞风险；
`IdempotencyStore` 是 L0 引擎 trait，不引用任何域实体，使其携带 tenant 维度会把基础设施语义与
租户业务语义混入同一个 L0 层，违反分层约束。因此这些表的 tenant 硬化推迟到各自对应的
domain-enroll issue（`outbox` → #1405），不属于本解锁器。

---

## 2. 决策

> **以四个正交载体落地持久化模式 tenant 作用域合约，为 #1405 / #1426 / #1436 解锁，不修改
> outbox / inbox 结构，不引入新 crate / 新分层。**

### 2.1 类型化 cotx funnel（Hard）

`adapters/postgres/src/cotx.rs` 的三个 helper 参数从裸 `tenant_uuid: &str` 改为
`tenant: TenantId`（`vocab`）：

```rust
// 之前（可传任意字符串）
pub async fn set_local_tenant(conn: &mut PgConn, tenant_uuid: &str) -> Result<(), PgError>

// 之后（类型层封闭）
pub async fn set_local_tenant(conn: &mut PgConn, tenant: TenantId) -> Result<(), PgError>
```

三个 helper：`set_local_tenant` / `tenant_scoped_read` / `co_tx_with_outbox`。非
`TenantId` 类型无法编译进入 funnel（Hard，type system）。`TenantId::parse` 已 fail-closed
拒空值 / nil UUID / 非 canonical（ADR-002 §D3 落地 #1032）。

### 2.2 setlocal-funnel 守卫（Medium）

新增 `cargo xtask setlocal-funnel`（接入 `cargo xtask verify` / `ci`），INVARIANT
`TENANCY-SETLOCAL-FUNNEL-01`：扫 `adapters/postgres/src/` 下所有生产源文件（独立测试文件
`integration_tests.rs` / `*_test(s).rs` / `tests/` 豁免），断言 tenant-scope GUC 写入仅出现在
`cotx.rs`。检测经**归一化**（去空白 + 小写）匹配特征串：`set_config('rss.tenant_id'`（容忍
`set_config ( '…` 空白变体）+ 裸 `SET LOCAL rss.tenant_id =/to` 赋值式（不止裸字面量，#310 review F4）；
放行做**路径精确**匹配（相对 src 根 `cotx.rs`，嵌套同名 `sub/cotx.rs` 不放行）。anti-vacuity green +
synthetic red（嵌套路径 / 空白变体 / 裸 SET LOCAL / 散文不误报）防守卫恒真。

守卫盲区（中档，可接受）：① 独立测试文件按文件名/目录豁免，生产文件内 `#[cfg(test)]` 内联块不豁免
（含特征即报）；② SET-LOCAL 特征锚定赋值号 `=`/`to` 避散文误报，故无赋值号的等价写入（如经变量拼 SQL）
仍可绕过——文本扫描固有局限，AST/token 级守卫为 refactor 档 follow-up。生产路径的类型封闭（2.1 Hard）
+ 启动能力门（2.3）+ schema-rls 静态门纵深互补。

### 2.3 启动期 RLS 能力门控（Medium）

`PgRuntimeDeps::setup`（ADR-010 §2.3 的 runtime bundle 初始化序列）在迁移完成后调用
`PgStore::verify_rls_capability()`（四段，任一不过 fail-fast）：

0. **连接角色不绕过 RLS**（#310 review F2，最先）：`SELECT rolsuper OR rolbypassrls FROM pg_roles
   WHERE rolname = current_user`——superuser / `BYPASSRLS` 角色永远绕过含 FORCE 的 RLS，使后续 schema
   校验形同虚设；命中即 `Err(RlsBypassRole)`。这是 tenancy.md「生产 owner 须为非 superuser」的运行期强制
   （serving 连接须直连 `rss_app` 且该角色为非 superuser、NOBYPASSRLS）。
1. **动态派生 tenant 表集合**：用 `pg_catalog`（`pg_class` + `pg_attribute`，**非** `information_schema`——
   后者按当前角色权限过滤，非 superuser serving 角色会漏看未授权 tenant 表致门控盲区）得含 `tenant_id` 列的表。
2. **RLS + policy 断言**：每表 `relrowsecurity AND relforcerowsecurity`（ENABLE+FORCE）；且 `pg_policies`
   ≥1 条 policy 的 `qual` 形如规范谓词 `tenant_id … current_setting … rss.tenant_id`
   （`LIKE '%tenant_id%current_setting%rss.tenant_id%'`，非仅 "提到 GUC"）；且**无** allow-all 的 PERMISSIVE
   policy（`qual` normalize ∈ {`true`,`(true)`}——PostgreSQL permissive policy OR 合并，额外 allow-all 会
   放宽 SELECT，#310 review F3）。形同 `USING (true)` / OR-widening 不达标、被拒。
3. **GUC round-trip 断言**：事务内经 funnel `set_local_tenant` 注入探测租户，读回
   `current_setting('rss.tenant_id', true)` 断言等值，事务 rollback 还原。

任一断言失败 → `PgRuntimeDeps::setup` 返回 `Err`，durable 模式启动 fail-fast。RLS 状态是数据库运行期状态，
不可在编译期校验，故载体为 Medium 运行期门（ADR-010 §2.6 自底向上顺序第一步）。**runtime-vs-static 分工**：
本门守"实际 DB 有规范 tenant policy + 无 widening + 非绕过角色 + GUC 可用"；policy DDL 全文规范性（含
`WITH CHECK` 写侧）由静态 `cargo xtask schema-rls`（TENANCY-RLS-FORCE-01）守，纵深互补（不重复全量
normalizer——抽共享 predicate normalizer 是 refactor 档 follow-up）。

与既有 `cargo xtask schema-rls`（INVARIANT `TENANCY-RLS-FORCE-01`）的分工：xtask 守迁移文件
的 DDL 完整性（静态文本扫描），`verify_rls_capability` 守实际数据库运行状态（动态断言）。
两者纵深互补，不重叠。

### 2.4 readyz RLS backstop probe（Medium）

`RlsReadyProbe` 订阅 `PgRuntimeDeps::setup` 的验证结果：

- 验证通过 → probe 返回 `Healthy`（→ readyz 200）。
- 验证未通过或未运行 → probe 返回 `Unhealthy`（→ readyz 503）。

probe 接入 `httpserve::HealthListener`，遵循 `docs/rules/observability.md` §readyz probe
约定。其语义是对 2.3 启动期断言的 **backstop**（避免启动期 setup 因某路径被跳过而静默
通过），不是首次验证路径。

### 2.5 最小 tenant scope conformance harness（crates/testkit seed，Medium）

在 `crates/testkit`（`containers` feature）落地 `assert_tenant_isolation` harness（#1426 完整
conformance testkit 的 seed），经调用方传入的「按租户写 / 按租户读存在性」异步闭包驱动真实
RLS-scoped repo，断言三件事：

- **tenant-A round-trip**：租户 A 写入 → 以 A 读回，断言可见。
- **cross-tenant invisible**：以租户 B 读 A 写入的行，断言不可见。
- **cross-tenant non-interference**：租户 B 在自身 scope 写后，A 仍读到自己的行（B 的写不抹除
  A 的可见性）。

「missing-tenant fail-closed」**不经 repo API harness 表达**：repo 方法签名 `tenant: TenantId`
必填，省略即编译错误（Hard 类型层，无法在运行期「忘记传 tenant」）；DB 层缺 SET LOCAL →
`current_setting` NULL → 0 行的 fail-closed 由 adapter raw-SQL 集成测试直证。harness 首个 enroll
消费方 = `adapters/postgres` 的 `tc9b_config_repo_tenant_isolation_conformance`（真实 `PgConfigRepo`
驱动）+ harness 自带 in-mem fake（泄漏 repo → `CrossTenantVisible` 的 anti-vacuity）。

---

## 3. 范式（Pattern）

```rust
// cotx.rs — 类型化 funnel（Hard 载体）
pub async fn set_local_tenant(
    conn: &mut PgConn,
    tenant: TenantId,          // ← 非 TenantId 无法编译
) -> Result<(), PgError> {
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant.as_uuid().to_string())
        .execute(conn)
        .await?;
    Ok(())
}

// PgRuntimeDeps::setup — 启动期能力门控（Medium 载体）
pub async fn setup(&self) -> Result<(), PgStoreError> {
    self.run_migrations().await?;
    self.store.verify_rls_capability().await?;   // fail-fast on any assertion failure
    Ok(())
}

// RlsReadyProbe — readyz backstop
impl Probe for RlsReadyProbe {
    async fn check(&self) -> ProbeResult {
        if self.verified.load(Ordering::Acquire) {
            ProbeResult::Healthy
        } else {
            ProbeResult::Unhealthy("rls_capability_not_verified")
        }
    }
}
```

---

## 4. 后果

**正向**：

- `TenantId` 类型封闭（Hard）+ xtask setlocal-funnel 守卫（Medium）+ startup 能力门控（Medium）
  三层纵深，不存在 "编译通过但 tenant scope 错误" 的无声注入路径。
- fail-closed 语义（无 SET LOCAL → 0 行 / 写拒）成为机器验证的合约，而非约定——#1426
  conformance testkit 有稳定被测目标。
- #1405 / #1436 不再因 cotx 入口多元而被阻塞，可独立推进。
- 零新增 crate / 零新增 workspace 层（`cotx.rs` 仍在 `adapters/postgres/`，`testkit` seed
  扩写已有 crate）。

**负向 / 代价**：

- `verify_rls_capability` 在每次 durable 启动时对数据库执行查询；在迁移后立即运行，
  单次执行开销通常可接受，但依赖数据库连通性，网络分区时 startup 会阻塞直至超时。
  这是数据库级安全门的必要代价，不是可优化掉的 noop。
- setlocal-funnel 守卫（Medium）的盲区：`#[cfg(test)]` 豁免允许测试代码内绕过扫描。
  生产路径由 Hard 类型封闭覆盖，可接受。
- readyz probe 不能替代 startup fail-fast（2.3 是首要门，probe 是 backstop）；若 setup
  路径被绕过（如在测试中跳过 `PgRuntimeDeps::setup`），probe 不会自行发现。

**威胁模型注**：

| 威胁 | 后果 | 缓解 | 档位 |
|------|------|------|------|
| 直接构造 `&str` 绕过 funnel 注入 `rss.tenant_id` | 跨租户读写 | `set_local_tenant` 参数改为 `TenantId`，非法类型无法编译 | **Hard** |
| 非法 tenant UUID（空 / nil / 非 canonical）进入 SET LOCAL | 范围外 tenant scope | `TenantId::parse` fail-closed 拒绝（ADR-002 #1032 落地） | **Hard** |
| 表新增但忘加 RLS DDL | RLS 缺失静默泄漏 | `schema-rls` xtask（TENANCY-RLS-FORCE-01）+ `verify_rls_capability` startup 双重断言 | **Medium × 2（纵深）** |
| serving 连接以 superuser/`BYPASSRLS` 角色运行 | FORCE RLS / policy 全失效、能力门形同虚设 | `verify_rls_capability` step 0 查 `rolsuper/rolbypassrls` fail-fast（`RlsBypassRole`，#310 F2） | **Medium** |
| tenant 表有规范 policy 但另叠 allow-all PERMISSIVE policy | OR 合并放宽 SELECT、跨租可读 | 能力门拒 allow-all permissive（`qual` normalize ∈ {true,(true)}，#310 F3）+ schema-rls 静态门 | **Medium × 2（纵深）** |
| 生产源中 `set_config` / 裸 `SET LOCAL` 直写逃逸 funnel | funnel 被绕过 | setlocal-funnel xtask 归一化扫描 + 路径精确放行（TENANCY-SETLOCAL-FUNNEL-01，#310 F4） | **Medium** |
| setlocal-funnel 守卫被测试代码中的 `set_config` 「accidentally」位于生产文件 | 扫描误报 / 漏报 | 豁免仅针对 `#[cfg(test)]` 内容；生产路径由 Hard 类型覆盖 | **Medium（可接受盲区）** |
| startup 跳过 `PgRuntimeDeps::setup` 导致 probe 未更新 | RLS 未验证但 readyz 无感知 | probe 默认 Unhealthy（未验证即 503，fail-closed 语义） | **Medium** |

---

## 5. 与 ADR-002 / 005 / 010 的关系（叠加，无 amendment）

- **ADR-002**：本 ADR 复用其「tenant 只来自已认证通道」约定，不新增 tenant source 规则。
  `TenantId` 归 `vocab::tenant`（ADR-002 §D3），cotx funnel 消费它，依赖方向不变（adapter
  依赖 `vocab`，Hard）。ADR-002 威胁矩阵无变化。
- **ADR-005**：`cotx.rs` 是 adapter 层实现（`adapters/postgres/`），依赖 `vocab` 但不被域
  crate 依赖（`域→adapter` 禁，ADR-005 §2.4）；`verify_rls_capability` 属 infra setup，不引
  域实体，不触发 DI port 归属二分。ADR-005 威胁矩阵无变化。
- **ADR-010**：本 ADR 是 ADR-010 §2.6「自底向上能力」序列的第 0 步补全——`PgRuntimeDeps::setup`
  按 ADR-010 §2.3 已是 runtime bundle 初始化入口，本 ADR 在其中追加 `verify_rls_capability`
  调用，语义与分层均在 ADR-010 框架内，无 amendment。ADR-010 §6 AI-robust 分级无变化。

---

## 6. AI-robust 分级（本 ADR 引入 / 锚定的 enforcement）

| 约束 | 评级 | 载体 |
|------|------|------|
| `set_local_tenant` / `tenant_scoped_read` / `co_tx_with_outbox` 参数类型为 `TenantId`（非 `&str`） | **Hard（类型系统）** | 参数类型，非 `TenantId` 无法编译；`TenantId::parse` fail-closed 拒非法值（ADR-002 #1032） |
| `set_config('rss.tenant_id'` 字面量只允许出现在 `cotx.rs`（生产源） | **Medium（xtask 内容扫描）** | `cargo xtask setlocal-funnel`（TENANCY-SETLOCAL-FUNNEL-01）；synthetic red + anti-vacuity green，`xtask/src/setlocal_funnel.rs`；盲区 = `#[cfg(test)]` 豁免，由 Hard 载体覆盖 |
| durable 模式启动断言 tenant 表 RLS 三件套已在 force 中 | **Medium（运行期门）** | `PgStore::verify_rls_capability` 在 `PgRuntimeDeps::setup` 中 fail-fast；DB 状态不可编译期校验 |
| readyz probe 反映 startup RLS 验证状态（未验证 → 503） | **Medium（运行期 backstop）** | `RlsReadyProbe`，默认 Unhealthy，fail-closed；接入 `httpserve::HealthListener` |
| tenant 作用域 conformance（round-trip / fail-closed / cross-tenant）机器验证 | **Medium（testkit seed）** | `crates/testkit` 三断言 harness；#1426 扩展为完整 conformance testkit |

无 Soft 新增 enforcement。Hard 化路径：setlocal-funnel Medium 守卫理论上可通过 proc-macro 强制
"只有 `cotx.rs` 内的 macro 展开才能调用 `set_config`"，但收益有限（Hard 类型封闭已覆盖生产路径），
暂不立项。

---

## 7. 备选（为何不取）

- **保留 `&str` 参数 + 仅靠命名约定**：Soft，不可机器验证，被 ai-robust 章程拒绝（新增机制最低
  Medium 门，见 `.claude/rules/rss/ai-robust.md`）。
- **同时为 `outbox` / `inbox_dedup` 加 `tenant_id` 列（在本 PR 一起落）**：范围蔓延——`outbox`
  加列需 L2 原子性测试、consumer 幂等验证、partition_key 语义变更，单独 #1405 更干净；
  `IdempotencyStore` 加 tenant 维度会把 L0 引擎语义与业务租户混入基础设施层（分层违规）。
- **仅靠 `schema-rls` xtask 静态扫描，不做 startup 动态验证**：缺失运行期确认——迁移可能
  未被应用、GUC 可能未正确配置，静态扫描无法感知。两者纵深互补，均保留。
- **用 `BYPASSRLS` 临时角色做开发便利**：与 `rss_app NOBYPASSRLS` 约定直接冲突（`tenancy.md`
  §RLS 与 PG scope），被架构约束拒绝。

---

## 8. Closeout 状态（落地同步点）

- dual-pool bootstrap 已接线：durable serving pool 使用非 superuser、`NOBYPASSRLS` 的 `rss_app`
  角色，启动期 `verify_rls_capability()` 会拒绝 owner/superuser、`BYPASSRLS` 角色和非 `rss_app`
  serving role。最终规则见 `docs/rules/tenancy.md` §RLS 与 PG scope。
- outbox tenant scope 已落地：`outbox.tenant_id` + RLS 三件套 + 固定 `SECURITY DEFINER`
  维护函数已成为最终边界；ordered delivery head-of-partition gating 按
  `(tenant_id, domain, partition_key)` 判队头。`inbox_dedup` 仍保持既有去重维度，不属于本
  ADR 的 closeout 变更面。
- PG tx funnel / raw-pool guard 已落地：`PgTenantPool` 是 tenant 表生产路径的 typed funnel，
  `cargo xtask setlocal-funnel` 与 `cargo xtask pg-tenant-tx-guard` 接入 verify/ci，防
  `TxManager` / raw-pool bypass。
- repo tenant isolation conformance 已纳入真实 postgres repos（config seed + role / audit /
  dead_letter 等），完整 CAS / rollback / co-tx 扩展按后续 conformance 范围推进，不改变本 ADR 的
  tenant-scope 合约。
- setlocal-funnel 守卫 Hard 化（proc-macro 限定 call-site）：未立项，Medium 当前足够，登记为技术债
  候选，待 Hard 化收益明显时再评估。
