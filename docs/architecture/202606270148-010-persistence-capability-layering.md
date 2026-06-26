# ADR-010：持久化能力分层 — module result / capability bundle / adapter bundle 单源

- **状态**：Accepted（**设计单源**；执行体随 #1419 runtime base / #1421 settings closure / W 阶段各域逐个落地，本 ADR **不实现** funnel 执行体，只定语义与归属）
- **日期**：2026-06-27
- **关联**：issue #1425 [PERSIST-004] · Parent Feature #1419 [PERSIST-FEA-A] · Parent Epic #1418 [PERSIST-EPIC] · 同批 #1432（defer gate 落地）
- **依赖 ADR**：**ADR-003**（DI dynosaur 派发）· **ADR-005**（域形 repo/UoW port 归属 + category line，本 ADR 复用其归属判据不重证）· **ADR-009**（typed route funnel）
- **归属**：framework（分层 / DI 接缝 / 组合根装配约定，provider-agnostic 基础设施治理）
- **AI-robust 评级**：见 §6（defer gate Medium；module-result / bundle funnel 落地时 Hard via 构造器必填参数）

---

## 1. 背景

PERSIST epic #1418 把「GoCell 级数据持久化底座」引入 RSS。前身系统 GoCell 通过 `SharedDeps` / `CellModule`·`ModuleResult` /
`PGSet.ForCell` / `WithPGBundle` 把横切接线复杂度压成少数原子 funnel。RSS 现状——ADR-005 已定域形 repo/UoW port 归属、
postgres adapter 已有 `PgConfigRepo`/`PgSecretRepo`/`ConfigUnitOfWork`、`assemblies/runtime` 已有 `wire_settings` 雏形——下，
每新增一项 durable 能力仍需**手工跨 ports / adapter / assembly / journey / governance 多处接线**：`assemblies/runtime/src/lib.rs`
手工 `compose` + `PgStore::connect` + migrations + `wire_settings` + health listener，且 settings service 构造后直接 drop、
业务路由尚未接线。缺统一规则时，后续能力容易继续散装接线、用无追踪 defer 补洞。

本 ADR 把**持久化能力分层**定为架构单源：哪些是 provider-agnostic infra port、哪些是域形 port、域如何经标准 module result
暴露能力、postgres 如何按 capability bundle 打包、组合根如何聚合、defer 如何受 gate 约束、能力按什么顺序自底向上长出。

## 2. 决策（持久化能力分层单源）

### 2.1 两类 DI port 归属（**引用 ADR-005，不重证**）

- **provider-agnostic infra port**（签名只引基础 / 引擎 / `generated` wire / port 自定义类型，如 `Clock`/`Signer`/`Publisher`/
  `Subscriber`/`AuditSink`/`ManagedResource`）→ `diport`（ADR-003）。
- **域形 repo / service / UoW port**（签名引域内实体，如 `SessionLifecycle`/`ConfigRepo`）→ 所属域 crate `pub mod ports`
  （ADR-005 §2.1 category line；`adapter→域` DIP 内向边 impl）。

归属反向测试（「此 port 能否在 `diport` 内编译而不让 `diport` 新增域依赖」）见 ADR-005 §2.1，本 ADR 不重述。

### 2.2 DomainModuleResult — 域能力的标准装配出口

现状 `bootstrap::DomainModule` 仅承载 `{ name, domain: Box<dyn Domain> }`（`crates/bootstrap/src/module.rs`），组合根经
`module()` 收集后驱动 init + shutdown。PERSIST 要求域不止暴露「一个 init 入口」，而是一组装配产物：**services / routes /
probes / resources（`ManagedResource`）/ workers**。`DomainModuleResult` 是 `module()` 的**演进结果型**：域构造期把这组产物
聚合为单一结果，组合根**只聚合各域 result**（不再逐项手工接线）。

- 形态：`DomainModuleResult { name, domain, routes / probes / resources / workers 聚合 }`（具体字段随 #1419 落地——本 ADR 定语义、不冻字段）。
- 强制：必填依赖（pool / clock / publisher …）经**构造器必填位置参**注入（ADR-005 C5），`module()` 内完成 DI、返回 ready 结果——缺失即编译错误（Hard）。
- 对标：omicron 组合根（`bins`/`nexus`）手工注入具体 impl + 聚合（见 §对标证据）。

### 2.3 Pg capability bundle — postgres 能力按运行时 / 域打包

postgres adapter 把「连接池 + 一组域形 repo/UoW provider impl」打包为 **capability bundle**，而非组合根逐 port `new`。两档：

- **`PgRuntimeDeps`**（运行时级）：拥有 `Arc<Pool>` + migrations + 健康 / `ManagedResource` 接线，单次 `PgStore::connect` 产出。
- **`PgDomainDeps`**（域级）：从 `PgRuntimeDeps` 按域投影出该域所需的 repo/UoW 句柄集（如 settings 的 `ConfigRepo` + `SecretRepo`
  + `ConfigUnitOfWork`），交该域 `module()` 构造器。

对标 GoCell `PGSet.ForCell`（per-cell 投影）/ `WithPGBundle`，及 omicron `DataStore`（一个 struct 持 `Arc<Pool>`、子模块聚合
per-resource 方法、单 `new(log, pool, ..)` 构造——见 §对标证据）。**RSS 偏离**：omicron `DataStore` 是单体全聚合，RSS 按域形
port（ADR-005）切分 provider impl，bundle 是「pool + 多个 dynosaur `DynX` 句柄」的**组合根装配单元**，不把全部 query 聚到一个
god-struct（保域封装）。

### 2.4 adapter bundle — 一般化

adapter bundle 是 §2.3 的一般化：任一 adapter（不止 postgres）经组合根以 **typed bundle** 暴露其 capabilities（provider impl
句柄集 + `ManagedResource`），消除散装 per-port `new` + 散装 shutdown 登记。bundle 在**组合根装配**、注入域 / 服务；adapter 仍
不被域依赖（`域→adapter` 禁，DIP 方向不变，ADR-005 §2.4）。

### 2.5 defer gate — 散装 defer 受机器门约束

为防「自底向上长能力」退化回无追踪 defer 补洞，本批新增 defer gate（#1432）：**governed 高风险路径**（`docs/rules` +
`docs/architecture` + `.claude/rules` + 根 config）内，**结构化 defer 标签必须四字段齐全**。canonical 格式（示例）：

```text
// DEFER(#<issue>): <描述>; owner=<name>; blocked-by=<#NNNN | trigger:...>; closes-when=<关闭条件>
```

载体 = `cargo xtask defer-gate`（接 verify / ci no-compile meta 步），评级 **Medium**，INVARIANT `DEFER-GATE-01`，实现 / 盲区
单源见 `xtask/src/defergate.rs` + `docs/rules/architecture.md` §二档。v1 锁**结构化标签完整性 + 经典注解**（`TODO`/`FIXME`/`XXX`/`HACK`
注解位）；自由词散文（`defer`/`follow-up`/`后续`，governed docs 中绝大多数是描述性散文）+ 代码注释扩域 + 历史约 6700 baseline
冻结轨道 = ratchet follow-up（§8）。

### 2.6 实施顺序（自底向上）

能力**自底向上**长出，按序（每步标已落 / 待落）：

1. provider-agnostic infra port + 域形 port 归属 — **已落**（ADR-003 / ADR-005）。
2. `DomainModuleResult` + `SharedRuntimeDeps` 聚合 — **待落**（#1419）。
3. Pg capability bundle（`PgRuntimeDeps` / `PgDomainDeps`）+ adapter bundle — **待落**（#1419）。
4. L1/L2 repo/UoW conformance（CAS / rollback / tenant / co-tx both-or-neither）— session 维度**已落**（ADR-005 §9/§10），其余 W 阶段。
5. 第一条 durable 闭环：settings module + routes / probes / resources / journey — **待落**（#1421）。
6. defer gate — **本批落**（#1432）。

后续域能力照此自底向上长，不每次散装补洞。

## 3. 范式（设计意图，执行体随 #1419 / #1421）

```rust
// 域 module() 返回 DomainModuleResult（设计意图，字段随 #1419 落地；构造器必填依赖注入 = Hard）
pub fn module(deps: SettingsDomainDeps) -> DomainModuleResult {
    // 构造期完成 DI，聚合 services / routes / probes / resources / workers；组合根只聚合 result。
}

// postgres capability bundle（设计意图）
pub struct PgRuntimeDeps { /* pool: Arc<PgPool> + migrations + ManagedResource */ }
impl PgRuntimeDeps {
    pub fn for_settings(&self) -> SettingsDomainDeps { /* 投影 ConfigRepo / SecretRepo / ConfigUnitOfWork 句柄 */ }
}
```

## 4. 后果

- **正**：横切接线压成少数 funnel；新增能力自底向上、组合根只聚合 result；散装 defer 受门约束；**零新增 crate / 零新增分层**
  （沿用 ADR-005 域形 port + diport，bundle / module-result 是组合根装配层概念，非新层）。
- **负 / 代价**：① `DomainModuleResult` / bundle 字段需随首条闭环（#1419 / #1421）定形并冻结（届时 codegen / golden 视需要）；
  ② defer gate v1 标记集窄（精度取舍——自由词散文不触发，见 §6 + `xtask/src/defergate.rs` rustdoc 盲区）。
- **下游**：各域 W 阶段照 §2.6 顺序 + ADR-005 §8.1 同步点清单落 repo/UoW port + adapter bundle。

## 5. 对 ADR-003 / 005 / 009 的关系（叠加，无 amendment）

本 ADR **不修改** ADR-003 / 005 / 009 的决策或威胁矩阵——它在其上**叠加**「能力如何被组合根聚合 + defer 受门」的装配层
约定。ADR-005 的 `adapter→域` DIP 内向边、dynosaur 白名单、co-tx UoW（OUTBOX-COTX-SESSION-01）不变；ADR-009 typed route
funnel 不变（`DomainModuleResult` 的 routes 仍经 `bootstrap::finalize_routes` → `httpserve::finalize_auth` funnel，
ROUTE-AUTH-FUNNEL-01）。故**无威胁矩阵重评**（ai-robust「ADR amendment 同步重评」不触发——本 ADR 非 amendment）。

## 6. AI-robust 分级（本 ADR 引入 / 锚定的 enforcement）

| 约束 | 评级 | 载体 |
|------|------|------|
| defer / follow-up 结构化完整性（governed scope） | **Medium（xtask + CI 门）** | `cargo xtask defer-gate`（DEFER-GATE-01）；synthetic red + anti-vacuity green，`xtask/src/defergate.rs` |
| `DomainModuleResult` 必填依赖注入（落地时） | **Hard（构造器必填参数）** | `module()` 构造器必填位置参，缺失即编译错误（继承 ADR-005 C5） |
| 域形 vs infra port 归属（已立 ADR-005） | **Hard（crate 图 + 编译器）** | `allows(DiPort,Domain)=false` + cargo 未声明 import 不到 |

无 Soft 新增 enforcement。

## 7. 备选（为何不取）

- **散装在组合根逐 port `new`（现状）**：被 PERSIST epic 否决——横切复杂度随域数线性膨胀、易漏 `ManagedResource` / probe 接线、
  defer 无追踪。
- **单体 `DataStore` god-struct（omicron 式全聚合）**：与 ADR-005 域形 port「按域切分 provider」冲突，god-struct 把全部域 query
  聚一处破坏域封装。RSS 取 bundle = pool + per-域 dynosaur 句柄装配单元（§2.3 偏离）。

## 8. Follow-up（落地同步点 + 后续 issue）

- `DomainModuleResult` / `PgRuntimeDeps` / `PgDomainDeps` 执行体 + 字段冻结：**#1419**。
- settings durable 第一条闭环（routes / probes / resources / journey）：**#1421**。
- defer gate ratchet 扩域（自由词散文 + 代码注释 `crates/*`、`xtask/*` + 历史约 6700 baseline 冻结轨道）：登记为 #1447（不阻塞本 PR）。
- 各域 repo/UoW conformance（CAS / rollback / tenant / co-tx）：W 阶段逐域。

## 对标证据（ref）

- `ref: oxidecomputer/omicron nexus/db-queries/src/db/datastore/mod.rs@main` — `DataStore` 持 `Arc<Pool>`、子模块（`mod disk; mod
  instance; mod project; …`）聚合 per-resource 持久化方法、单 `new(log, pool, config, identity_check)` 构造的「能力聚合 + 单池」
  范本，对应 §2.3 Pg capability bundle（RSS 偏离：按 ADR-005 域形 port 切分 provider，不聚 god-struct）。
- `ref: oxidecomputer/omicron` — 组合根（`bins` / `nexus`）手工注入具体 impl 的 Rust 范本（`docs/references/framework-comparison.md`
  §域 crate 运行时 / 依赖注入），对应 §2.2 `DomainModuleResult` 组合根聚合。
- `ref: Cockburn Hexagonal Ports&Adapters` / `ref: Evans DDD「Repository」` — port 属域、adapter 经 DIP 内向实现（ADR-005 承接）。
- `ref: uber-go/fx app.go@master` — 消费侧声明接口、组合根注册具体实现的依赖反转（概念对标，framework-comparison §依赖注入）。
- GoCell 映射：`docs/prd/rust-mapping.md`（`SharedDeps` / `CellModule`·`ModuleResult` / `PGSet.ForCell` / `WithPGBundle` 概念出处，历史快照）。
