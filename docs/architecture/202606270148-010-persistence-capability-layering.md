# ADR-010：持久化能力分层 — domain binding / module result / capability bundle 单源

- **状态**：Accepted，2026-07-20 经 #1792 amendment（ProviderPlan 构造与 output bijection 已闭合）
- **日期**：2026-06-27
- **关联**：issue #1425 [PERSIST-004] · Parent Feature #1419 [PERSIST-FEA-A] · Parent Epic #1418 [PERSIST-EPIC] · 同批 #1432（defer gate 落地）
- **依赖 ADR**：**ADR-003**（DI dynosaur 派发）· **ADR-005**（域形 repo/UoW port 归属 + category line，本 ADR 复用其归属判据不重证）· **ADR-009**（typed route funnel）
- **归属**：framework（分层 / DI 接缝 / 组合根装配约定，provider-agnostic 基础设施治理）
- **AI-robust 评级**：见 §6（binding 所有权与构造器注入 Hard；result 聚合顺序由类型 + 测试承载）

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

### 2.2 DomainBinding + DomainModuleResult — 单一所有权装配出口

Phase 4 的 settings/identity/audit `module()` 已返回 `DomainBinding::new(name, Box<dyn Domain>, DomainModuleResult)`；
统一 module funnel 已由 #1672 接入 live runtime。`DomainBinding` 把已构造的域实例与其生命周期输出绑定在同一 owner 下且字段私有；
组合根把 bindings 交给 `compose_bindings`，它先按顺序临时借出 `Vec<&dyn Domain>` 执行 fail-fast compose，只有成功后
才排空 bindings 并返回聚合 output。compose 失败时 bindings 与 outputs 原样保留。

`DomainModuleResult` 只承载 **probes / resources（`ManagedResource`）/ workers** 三条生命周期出口：

- `merge` 与 `Extend<DomainModuleResult>` 逐字段直接 `Vec::extend`，严格保留 binding 输入顺序与域内顺序；空输出为 identity，重复项原样保留。
- `name` / `domain` 只属于 `DomainBinding` 且不提供 output getter；domain service / routes 不进入 result 或其它 generic service bag。service 留在 typed domain 内，由 `Domain::init` 捕获并注册 typed route。
- 必填依赖（pool / clock / publisher …）由具体 domain 的 **typed 构造器必填位置参**注入（ADR-005 C5），缺失即编译错误（Hard）；settings/identity/audit 的 `module() -> DomainBinding` 经 generated list 进入 live runtime，跨阶段句柄只经 typed Registry funnel 交接。
- `Domain: Send + Sync`；binding 与 output 可跨线程转移（`Send`），但包含单 owner resource / `FnOnce` worker 的完整 output 不承诺 `Sync`、`Clone` 或重复消费。
- 对标：omicron 组合根（`bins`/`nexus`）手工注入具体 impl + 聚合（见 §对标证据）。

### 2.3 Pg capability bundle — postgres 能力按运行时 / 域打包

postgres adapter 把「连接池 + 一组域形 repo/UoW provider impl」打包为 **capability bundle**，而非组合根逐 port `new`。
#1677 把同一份 PG 状态的两个真实角色显式分开；这不是多源，而是 owner 直接包住唯一 handle：

- **`PgRuntimeDeps`**（运行时级生命周期 owner）：不实现 `Clone`，生产 `setup*()` 构造家族产出；内部只持一份
  `PgRuntimeHandle`，不再同时保存第二份 store/readiness 状态。`handle(&self)` 只克隆该 handle 内的 `Arc`，不会形成第二个
  生命周期 owner。
- **`PgRuntimeHandle`**（可克隆能力句柄）：只提供 `for_domain`、`infra`、`readiness_handle`、`rls_ready_handle` 投影；不暴露
  pool guard、sampler factory 或 lifecycle output API。`SharedRuntimeDeps` 与无 launch assembly 只保存此 handle。
- **`PgDomainDeps<D>`**（域级能力句柄）：由 `PgRuntimeHandle::for_domain` 按域投影所需 repo/UoW（如 settings 的
  `ConfigRepo` + `SecretRepo` + `ConfigUnitOfWork`），交该域 `module()` 构造器。
- 生命周期交接只能由 `PgRuntimeDeps::into_runtime_parts(self, period)` 按值完成：返回顺序固定为 primary → optional
  audit-admin 的 pool guards，以及 non-`Clone` `PgReadinessSamplerFactory`；factory 的 `spawn(self, token)` 再按值消费，单个
  owner/factory 均不能生成第二套关闭或 sampler 路径。

对标 GoCell `PGSet.ForCell`（per-cell 投影）/ `WithPGBundle`，及 omicron `DataStore`（一个 struct 持 `Arc<Pool>`、子模块聚合
per-resource 方法、单 `new(log, pool, ..)` 构造——见 §对标证据）。**RSS 偏离**：omicron `DataStore` 是单体全聚合，RSS 按域形
port（ADR-005）切分 provider impl，bundle 是「pool + 多个 dynosaur `DynX` 句柄」的**组合根装配单元**，不把全部 query 聚到一个
god-struct（保域封装）。

### 2.4 adapter bundle — 一般化

adapter bundle 是 §2.3 的一般化：任一 adapter（不止 postgres）经组合根以 **typed bundle** 暴露其 capabilities（provider impl
句柄集 + `ManagedResource`），消除散装 per-port `new` + 散装 shutdown 登记。bundle 在**组合根装配**、注入域 / 服务；adapter 仍
不被域依赖（`域→adapter` 禁，DIP 方向不变，ADR-005 §2.4）。

**落地（#1498，RW-W-hardening）**：§2.3 的 pg 范式（#1422/#1423）已一般化到 redis / amqp / vault——`RedisRuntimeDeps`（funnel +
`RedisInfraDeps::inbox`，REDIS-BUNDLE-FUNNEL-01/POOL-02）、`AmqpRuntimeDeps`（per-vhost = per-connection，`AmqpInfraDeps`
派发 publisher/subscriber，AMQP-BUNDLE-CONN-01）、`VaultRuntimeDeps`（sealed `caps::Settings` + `VaultDomainDeps<Settings>::secret_resolver`，
VAULT-BUNDLE-DOMAIN-01/RESOLVER-02）。各 provider 能力按真实能力面落 InfraDeps（provider-agnostic：redis inbox claimer / amqp
transport / vault signer）或 per-domain DomainDeps（域消费：vault resolver→settings）；不造空壳层。

**provider output 层序修正（Redis/S3/Vault 不依赖 bootstrap）**：`DomainModuleResult` 在服务层 `bootstrap`；通用
`Adapter → Service` 依赖仍按分层矩阵合法（包括 postgres → bootstrap），但 Redis/S3/Vault 三个 provider adapter 被精确禁止
依赖 bootstrap，不能取得该 runtime 聚合类型。
故 bundle 的 managed-resource/rollback 单源**不**返回 `DomainModuleResult`，而经 `runtime_resources(&self) -> Vec<Box<DynManagedResource>>`
（仅 `diport` 类型）派生。#1792 删除旧的 generic trait、静态 output binding 与
`DomainModuleResultExt::merge_provider` 自证明路径。`assemblies/runtime` 由唯一
`ProviderBuild::from_plan` exact-join `RuntimePlan::provider_plans()` 与生成的 14 项
`PROVIDER_CATALOG`，再经封闭的 `ProviderFactoryDispatch` 为每项工厂铸造一张 private one-shot permit。
每个真实构造只能把 permit 与实际 lifecycle channels 一起封装成 owned `ProviderOutput`；零输出 rate
limiter 同样必须回执。`finish(self)` 才能生成 `CompletedProviderBuild`，缺声明、少输出、多输出或重复消费
均在 ready/bind 前失败。

PG readiness 仍由唯一 `build_pg_runtime_module(owner, period)` 按值消费 owner，但 output 在
`BuildInfra` 立即进入同一 provider transaction，不再以独立 phase field 走到 Launch。Event transport
继续 crate-private 返回 `DomainModuleResult`，随后必须同时消费 publisher/subscriber receipts。
任一后续 phase 失败都由 transaction 对已构造 resources 做 async LIFO rollback，且不启动 worker
closure；只有 completed owner 能把统一 provider module 交给 Launch。

### 2.5 defer gate — 散装 defer 受机器门约束

为防「自底向上长能力」退化回无追踪 defer 补洞，本批新增 defer gate（#1432）：仅在机器拥有的根 config
（`deny.toml` / `clippy.toml`）内，**结构化 defer 标签必须四字段齐全**。canonical 格式（示例）：

```text
// DEFER(#<issue>): <描述>; owner=<name>; blocked-by=<#NNNN | trigger:...>; closes-when=<关闭条件>
```

载体 = `cargo xtask defer-gate`（接 verify / ci no-compile meta 步），评级 **Medium**，INVARIANT `DEFER-GATE-01`，实现 / 盲区
单源见 `xtask/src/defergate.rs` + `docs/rules/architecture.md` §二档。该门只锁 config 中的**结构化标签完整性 + 经典注解**
（`TODO`/`FIXME`/`XXX`/`HACK` 注解位）；Markdown、`CLAUDE.md` 与自由词散文不进入阻塞门，只由周期、非阻塞 advisory grep 提示。

### 2.6 实施顺序（自底向上）

能力**自底向上**长出，按序（每步标已落 / 待落）：

1. provider-agnostic infra port + 域形 port 归属 — **已落**（ADR-003 / ADR-005）。
2. `DomainModuleResult` + `SharedRuntimeDeps` 聚合 — **已落**（#1422）；`DomainBinding` 单一所有权形状 + result `Extend` — **已落**（#1669）。
3. Pg capability bundle（`PgRuntimeDeps` / `PgRuntimeHandle` / `PgDomainDeps`）— **已落**（#1423 / #1677）；adapter bundle 泛化到 redis/amqp/vault — **已落**（#1498，见 §2.4）；14 项 active provider 的 plan/catalog/output transaction bijection — **已落**（#1792）。
4. L1/L2 repo/UoW conformance（CAS / rollback / tenant / co-tx both-or-neither）— session 维度**已落**（ADR-005 §9/§10），其余 W 阶段。
5. 第一条 durable 闭环：settings module + routes / probes / resources / journey — **待落**（#1421）。
6. defer gate — **本批落**（#1432）。

后续域能力照此自底向上长，不每次散装补洞。

## 3. 范式（设计意图，执行体随 #1419 / #1421）

```rust
// 域 module() 返回单一所有权 binding；构造器必填依赖注入 = Hard。
pub fn module(deps: SettingsDomainDeps) -> DomainBinding {
    DomainBinding::new(
        "settings",
        Box::new(SettingsDomain::new(/* typed services */)),
        DomainModuleResult { /* probes / resources / workers */ },
    )
}

// postgres capability bundle（#1677 已落：一个数据源、两个权限角色）
pub struct PgRuntimeDeps { handle: PgRuntimeHandle } // non-Clone lifecycle owner
#[derive(Clone)]
pub struct PgRuntimeHandle { /* shared store/readiness capability state */ }
impl PgRuntimeDeps {
    pub fn handle(&self) -> PgRuntimeHandle { /* Arc clone only */ }
    pub fn into_runtime_parts(self, period: Duration) -> (Vec<Box<DynManagedResource>>, PgReadinessSamplerFactory) { /* single-use */ }
}
impl PgRuntimeHandle {
    pub fn for_domain<D: PgDomain>(&self) -> PgDomainDeps<D> { /* typed capability projection */ }
}
```

## 4. 后果

- **正**：横切接线压成少数 funnel；`DomainBinding` 私有字段 + `compose_bindings` 唯一 output 出口在类型/API 边界
  强制 compose 成功后才 drain，并守住 single owner、禁止重复消费；三出口保序由 bootstrap 测试锁定，runtime baseline
  检查三字段 merge 完整性；Redis / S3 / Vault 经 crate-private provider adapter 进入同一个 result merge，不引入 service locator，
  PG 则由 non-`Clone` owner 直接生成既有 `DomainModuleResult` batch，并经公共注册 helper 保持 sampler/pool 依赖顺序；owner
  只包 handle，能力投影与生命周期权限分离但数据源及 output 类型仍唯一。**零新增 crate / 零新增分层**（沿用 ADR-005 域形 port + diport）。
- **负 / 代价**：① binding/output 含单 owner worker/resource，不提供 `Clone` 或完整 `Sync`；确需并发共享时必须拆出窄只读视图；
  ② defer gate v1 标记集窄（精度取舍——自由词散文不触发，见 §6 + `xtask/src/defergate.rs` rustdoc 盲区）。
- **下游**：各域 W 阶段照 §2.6 顺序 + ADR-005 §8.1 同步点清单落 repo/UoW port + adapter bundle。

## 5. #1669 / #1677 amendment 的安全 / 威胁重评

#1669 把原先拟议的扁平 result 修正为私有字段 `DomainBinding` + 受控 `compose_bindings`，因此本节完成 amendment 重评：

- ADR-005 的 `adapter→域` DIP 内向边、dynosaur 白名单与跨域仅经 contract 的隔离边界不变；bootstrap 仍不依赖 adapter。
- ADR-009 typed route/auth funnel 不变：route 由 binding 内的 typed domain 在 `Domain::init` 注册，仍经
  `bootstrap::Registry::finalize_routes` → `httpserve::finalize_auth`，不通过 `DomainModuleResult` 绕过 funnel。
- `DomainModuleResult` 固定为生命周期三出口，不接受 domain service、route、`Any` 或无类型 bag；新形状减少了跨域 service
  泄漏与 service-locator 扩张面。
- 所有权威胁收敛：外部调用方无法直接取得 domain/output；`compose_bindings` 在 compose 成功前不 drain，失败时 bindings
  与 outputs 原样保留；成功后 `FnOnce` worker 与 managed resource 只转移一次，避免提前启动、clone 后重复启动或重复关闭。
- PG 生命周期复制威胁收敛：`PgRuntimeDeps` 与 `PgReadinessSamplerFactory` 均 non-`Clone` 且按值消费；cloneable
  `PgRuntimeHandle` 没有生命周期 API，因此能力消费者无法取得 pool guard 或重复启动 sampler。owner 只能转换为既有
  `DomainModuleResult`，不存在第二套 lifecycle output seam。
- Provider 关闭顺序漂移收敛：PG owner 交出的 guards 固定 primary → optional audit-admin，所有 provider
  resources/workers 合并为 completed provider module；Launch 在 domain module 前注册它，LIFO 使
  event/domain/listener 先排空。部分构造失败时 transaction 只注册已存在 resources 并逆序关闭，不启动 worker。
  类型系统 Hard 锁定 role-specific permit/owner 的单次消费；14 项 exact set、8 个 sealed output batches、唯一 finish/async rollback/handoff
  由 synthetic-red/anti-vacuity Medium runtime baseline 补齐。
- Event output 分叉威胁收敛：`wire_event_transport` 的 crate-private owned 返回类型使旧 `.module/.infra_guards`
  投影不可编译（`EVENT-TRANSPORT-OUTPUT-TYPE-01`，Hard）；跨文件唯一 resource 派生、run merge 与 launch
  注册顺序由 `EVENT-TRANSPORT-OUTPUT-FUNNEL-01` 的 synthetic-red/anti-vacuity AST 门补齐（Medium）。

结论：既有 adapter/domain、typed route/auth 与跨域隔离安全边界均不降级；binding/output 分离进一步强化这些边界。

## 6. AI-robust 分级（本 ADR 引入 / 锚定的 enforcement）

| 约束 | 评级 | 载体 |
|------|------|------|
| defer / follow-up 结构化完整性（根 config） | **Medium（xtask + CI 门）** | `cargo xtask defer-gate` 仅扫描 `deny.toml` / `clippy.toml`（DEFER-GATE-01）；Markdown 只做周期非阻塞 advisory；synthetic red + anti-vacuity green，`xtask/src/defergate.rs` |
| `DomainBinding` 形状 / domain ownership | **Hard（类型 + 所有权）** | 私有字段 + `DomainBinding::new` 必填位置参 + `Box<dyn Domain>` + owned `DomainModuleResult`；`Domain: Send + Sync + 'static` supertrait；错误 domain 类型或重复 move 均编译失败 |
| compose-before-drain 生命周期顺序 | **Hard（封闭 API）** | 私有 `domain/output` + 唯一公开 `compose_bindings` output 出口；成功后才 drain，失败在 drain 前返回；compile-fail rustdoc 锁定外部直接取 output 不可编译 |
| 具体域依赖完整性 | **Hard（已有 typed 构造器处）** | settings/identity/audit 已有统一 async `module(&impl XModuleSource)` 参数 funnel；source trait 按域 sealed、生产实现仅 `SharedRuntimeDeps`，具体依赖完整性仍由各 domain typed 构造器的必填位置参承载，`DomainBinding` 本身不内省或验证这些依赖 |
| result 三出口完整聚合与保序 | **Medium（测试 + baseline gate）** | bootstrap 单测锁定 `merge`/`Extend`；`cargo xtask runtime-baseline verify` 检查三字段与 merge 全字段覆盖 |
| provider 输出形状与 live 集合 | **Hard（类型 + 所有权）/ Medium（exact-set baseline）** | private raw permit + 14 种不可互换的 role-specific consuming permit + non-Clone `ProviderBuild`/`CompletedProviderBuild`；`ProviderOutput` 只能经 8 个 sealed constructors 携带 owned `DomainModuleResult` 与对应 receipts，并从实际 module 推导 channel union；runtime baseline 锁 14 项生成 catalog、每项唯一消费、8 个 output batches、唯一 finish/async rollback/handoff，并以 synthetic red + real-workspace anti-vacuity 防空门 |
| PG owner / handle 权限分离 | **Hard（类型 + 可见性）** | `PgRuntimeDeps` non-`Clone` 且只包 `PgRuntimeHandle`；handle `Clone` 但只暴露能力投影，生命周期字段/API 不可见；compile-fail/pass UI tests 锁 owner 不可克隆、handle 无 lifecycle API、能力投影可用 |
| PG 生命周期单次消费 | **Hard（所有权 + `FnOnce`）/ Medium（runtime baseline）** | `into_runtime_parts(self)` 与 factory `spawn(self, token)` 按值消费；唯一 `build_pg_runtime_module` 在 BuildInfra 生成 `DomainModuleResult` 并立即进入 `ProviderBuild`，不跨 phase 暴露 PG batch；`RUNTIME-PROVIDER-BIJECTION-LIVE-01` 锁唯一生产调用与 provider-before-domain 注册 |
| Event transport 单一 output | **Hard（类型 + 可见性）/ Medium（runtime baseline）** | `EVENT-TRANSPORT-OUTPUT-TYPE-01` 以 crate-private `wire_event_transport -> DomainModuleResult` 禁止旧字段投影；`EVENT-TRANSPORT-OUTPUT-FUNNEL-01` 以 synthetic-red/anti-vacuity AST 门锁 AMQP resources 唯一派生、run 唯一 merge、launch 公共 helper 注册（AcceptedMedium） |
| 域形 vs infra port 归属（已立 ADR-005） | **Hard（crate 图 + 编译器）** | `allows(DiPort,Domain)=false` + cargo 未声明 import 不到 |

无 Soft 新增 enforcement。

## 7. 备选（为何不取）

- **把 `PgRuntimeDeps` / `PgRuntimeHandle` 合成一个类型**：若统一类型可 `Clone`，任何能力消费者也会复制 lifecycle 权限，无法阻止
  重复 guards/sampler；若统一类型不可 `Clone`，则 session/event/domain/probe 等并行消费者无法持有共享能力，且无 launch assembly
  被迫保留不属于自己的生命周期 owner。两类型只分离权限角色，owner 直接包 handle，故没有引入第二数据源。
- **散装在组合根逐 port `new`（现状）**：被 PERSIST epic 否决——横切复杂度随域数线性膨胀、易漏 `ManagedResource` / probe 接线、
  defer 无追踪。
- **单体 `DataStore` god-struct（omicron 式全聚合）**：与 ADR-005 域形 port「按域切分 provider」冲突，god-struct 把全部域 query
  聚一处破坏域封装。RSS 取 bundle = pool + per-域 dynosaur 句柄装配单元（§2.3 偏离）。

## 8. Follow-up（落地同步点 + 后续 issue）

- `DomainModuleResult` / `PgRuntimeDeps` / `PgRuntimeHandle` / `PgDomainDeps` 执行体：**已落**（#1422 / #1423 / #1677）；私有字段 `DomainBinding`、受控 `compose_bindings` 与 result `Extend`：**已落**（#1669）；泛化到 redis/amqp/vault bundle：**已落**（#1498，§2.4）；settings/identity/audit `module()`：**已落**（#1670）；live bindings、typed-handle funnel 与生成列表：**已落**（#1672）；PG owner/factory/output 单次消费与独立 launch slot：**已落**（#1677）。
- settings durable 第一条闭环（routes / probes / resources / journey）：**#1421**。
- defer gate ratchet 扩域（自由词散文 + 代码注释 `crates/*`、`xtask/*` + 历史约 6700 baseline 冻结轨道）：登记为 #1447（不阻塞本 PR）。
- 各域 repo/UoW conformance（CAS / rollback / tenant / co-tx）：W 阶段逐域。

## 对标证据（ref）

- `ref: oxidecomputer/omicron nexus/db-queries/src/db/datastore/mod.rs@main` — `DataStore` 持 `Arc<Pool>`、子模块（`mod disk; mod
  instance; mod project; …`）聚合 per-resource 持久化方法、单 `new(log, pool, config, identity_check)` 构造的「能力聚合 + 单池」
  范本，对应 §2.3 Pg capability bundle（RSS 偏离：按 ADR-005 域形 port 切分 provider，不聚 god-struct）。
- `ref: oxidecomputer/omicron` — 组合根（`bins` / `nexus`）手工注入具体 impl 的 Rust 范本（`docs/references/framework-comparison.md`
  §域 crate 运行时 / 依赖注入），对应 §2.2 `DomainModuleResult` 组合根聚合。
- `ref: oxidecomputer/omicron nexus/src/context.rs@3298185e6cb3f6934a581122101e52988dc81895` — 组合根持有共享 datastore
  capability context 的对标；RSS 进一步把 cloneable capability handle 与 non-`Clone` lifecycle owner 分权，并保留 PG 独立 output 槽位。
- `ref: Cockburn Hexagonal Ports&Adapters` / `ref: Evans DDD「Repository」` — port 属域、adapter 经 DIP 内向实现（ADR-005 承接）。
- `ref: uber-go/fx app.go@master` — 消费侧声明接口、组合根注册具体实现的依赖反转（概念对标，framework-comparison §依赖注入）。
- GoCell 映射：`docs/prd/rust-mapping.md`（`SharedDeps` / `CellModule`·`ModuleResult` / `PGSet.ForCell` / `WithPGBundle` 概念出处，历史快照）。
