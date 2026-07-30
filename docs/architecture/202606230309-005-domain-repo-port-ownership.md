# ADR-005：域 repo / 领域服务 DI port 归属（Option 2：域内 port + DIP 内向实现）

- **状态**：Accepted（消解 layer-diport.md ↔ data-model.md 待决项#1 矛盾；amend ADR-003 §6/§7 + ADR-004 C1/C7）；**§9 amended by #1192**（co-tx Unit-of-Work seam 交付 #1083 session 接缝，威胁矩阵重评见 §9.3）；**§10 amended by #1278**（`SessionUnitOfWork` + `SessionRepo` 合并为单一 `SessionLifecycle`，威胁矩阵重评见 §10.3）；**§11 amended by #1168**（DLX provider-neutral port 归位 + associated proof binding）
- **日期**：2026-06-23（§9 amendment：2026-06-25；§10 amendment：2026-06-26）
- **关联**：issue #1083 [RW-G0.2] · #1192（§9 co-tx UoW amendment）· #1278（§10 SessionLifecycle 合并 amendment）· epic #991 · spike 来源 PR #1051(PR-4) / #1049(PR-diport) · 解锁 W 阶段（#1000–#1016）repo 接缝单元
- **依赖 ADR**：**ADR-003**（DI async+dyn 派发 = dynosaur，本 ADR 复用其派发范式不变）· **ADR-004**（签名约定单源）
- **归属**：framework（分层 / DI 接缝归属约定，provider-agnostic 基础设施治理）
- **AI-robust 评级**：见 §6（逐条 Hard/Medium，Soft 禁止立项）

---

## 1. 背景

ADR-003 把可替换 provider 的 DI port trait 收敛进 DI-infra 层 crate `diport`。RW-G0.2 签名冻结期，**域 repo / 领域服务 DI port trait**（`SessionRepo`/`ConfigRepo`/`AuditRepo`/`ContractRepo`/各域仓储口）的归属浮现一处**两份 spec 互相矛盾**的待决：

- `docs/spec/001-crate-signature-freeze/contracts/layer-diport.md`（冻结接缝表「域」行）：域 repo port **收敛进 `diport`**（dynosaur，`pub`）。
- `docs/spec/001-crate-signature-freeze/data-model.md` 待决项#1：`diport` 是 DI-infra 层 crate，按分层规则 **MUST NOT 依赖域 crate**（`deny.toml` + `xtask layer-deps` 编译期/CI 强制，`allows(DiPort, Domain) = false`），故其 port 签名只能引用基础（`ids`/`vocab`）/`generated`（wire）类型，**不得**引用域内实体。

**矛盾本质**：`SessionRepo::find(..) -> Option<Session>` 必然引用域内实体 `Session`（域 crate `pub(crate)` 类型）。放 `diport` 即要求 `diport → 域` 反向依赖、层序倒置、deny 红；而 `domain-patterns.md` 又把「DI port 一律收敛 diport」写成例外、**禁止**域 crate 自定义 DI port。结果：域 repo port **既不能放 diport、也不能放域 crate**。PR-diport(#1049) 因此未交付任何 repo port，PR-4(#1051) 据此只冻 Scope A（域内值对象 + 非 DI 纯域逻辑）。W 阶段行为 PR 需要 repo port 接线持久化，本待决是其前置。

根因：ADR-003 的「**所有** DI port 收敛 diport」对 provider-agnostic 基建 port 成立、但对**域形 port over-reach**。`diport` 现有 7 个 port（`Clock`/`Signer`/`Publisher`/`Subscriber`/`AuditSink`/`ManagedResource`/`SubscribeInitializer`）**全部只引用基础/wire/自定义类型**——`AuditSink::record(AuditEvent)` 中 `AuditEvent` 是 diport 自定义的扁平类型（`principal_id: String`），刻意不引域内 `audit::AuditEntry` 聚合。这条「不引域实体」的线已隐式存在，只是没被显式表述为归属判据。

---

## 2. 决策（Option 2：两类 port，两处归属）

> **provider-agnostic infra port → `diport`；域形 repo/service port → 所属域 crate `pub mod ports`。**

派发范式**继承 ADR-003 不变**（native AFIT + `#[trait_variant::make(X: Send)]` Send 变体 + `#[dynosaur(pub DynX = dyn(box) X, bridge(dyn))]`，构造器注入 `Box<DynX>`）；本 ADR 只改 port 的**定义点归属**，不改派发机制。

备选 Option 1（域实体上移基础层/`generated`）/ Option 3（per-域 `{domain}-model` crate）见 §7，未取。

### 2.1 归属判据（category line，machine-reviewable）

> 一个 DI port 归 `diport` **当且仅当**其整个 trait 签名（每个方法的入参/返回/关联类型/错误类型）只引用基础层（`vocab`/`ids`/`secure`/`support`/`runctx`）、引擎（`consistency`/`primitives`）、`generated` wire 类型或 port 自身定义的类型；**若任一方法签名引用域内实体**（域 crate `domain` 模块定义的类型）→ 该 port 归该域 crate `ports` 模块。
>
> 反向测试：「此 port 签名能否在 `diport` 内编译而不让 `diport` 新增对域 crate 的依赖？」能 → `diport`；不能 → 域 crate。

此判据在**反证侧 Hard 成立**：`diport` 一旦想放域形 port，必须新增对域 crate 的依赖，被 `allows(DiPort, Domain) = false`（`xtask layer-deps`）+ cargo 编译期拒绝（diport 的 `Cargo.toml` 未声明该域依赖即 import 不到实体）。完整 AST 级「无域实体出现在 diport port 签名」未机器强制（盲区），由判据 + 反证侧 Hard 兜底，proactive AST lint 列 §8 follow-up（不阻塞本 PR）。

### 2.2 定义位置与可见性

- 域形 port 放域 crate 新建 `pub mod ports`（**非** `internal/ports`——`internal` 语义是 `pub(crate)` 域内封闭，而 repo port 须被独立 adapter crate 跨 crate impl，必须 `pub`）。
- repo port trait（Send 变体 `RoleRepo` + dyn wrapper `DynRoleRepo`）`pub`；非 Send 基 trait `RoleRepoLocal` 不在 crate 根 re-export（同 diport `XLocal` 约定）。
- port 签名引用的**最小实体集**（如 `Role`/`RoleId` + repo error）由 `pub(crate)` 升 `pub`（**仅类型名**，使其能出现在跨 crate 的 `pub` trait 签名里），经 `ports` 模块 `pub use` façade 暴露；**字段保持私有 + 构造器保持 `pub(crate)` funnel**——外部 crate 可在签名中**命名**实体、按值收发，但**不可伪造其不变式**（fail-closed，类型名可见 ≠ 不变式可破）。
  - 注：**类型名 `pub` ≠ accessor `pub`**。实体的读取 accessor（`RoleId::as_str` / `Role::id|name`）默认仍 `pub(crate)`——签名冻结/编译证明阶段 adapter body=`todo!()` 不读实体，故不需升。**W 阶段** adapter 真实 impl 需读取时，按需把所读 accessor 升 `pub`（最小集，逐 port 按真实读取面）。其余域类型保持 `pub(crate)`。实体定义仍留 `domain/` 路径段，继续受 `dylint rss_domain_no_serialize`（SERDE-DOMAIN-FREEZE-01）扫描。

### 2.3 派发 = 动态（dynosaur），非静态泛型

域 repo port 是「provider prod/test 可换 + 组合根跨 crate 注入 + L1+ I/O」的典型动态接缝（ADR-003 §4.5 判定表落动态侧），与现有全部 DI port 统一经 `Box<DynX>` 位置参注入（ADR-004 C5）。**不选**静态泛型（`Svc<R: RoleRepo>`）：类型参数会漏到组合根，正是 ADR-003 §5 否决的「纯静态泛型铺满」，且破坏「全部注入 = `Box<Dyn>`」统一性。

### 2.4 adapter → 域 = DIP 内向边

adapter（如 `postgres`）依赖所属域 crate、以 native AFIT impl 其域形 port（命名域的 `pub` 实体）。这是依赖反转（DIP）的标准内向箭头：**域定义接口、adapter 依赖内向实现**。

- `allows(Adapter, Domain) = true`（`xtask/src/layers.rs`，本 ADR 新增；反向 `域 → adapter` 仍 `false`，依赖反转方向保持）。
- `deny.toml`：实现某域 repo port 的 adapter 加入该域 ban 的 wrappers（如 `identity` wrappers 加 `postgres`），经 LAYER-DEPS-06 反向②（`allows(Adapter,Domain)=true`）放行。
- 「adapters 不被域依赖（域 → adapter 禁）」不变量**仍成立**；仅新增 `adapter → 域` 编译期 impl 边，运行期仍由组合根注入。

### 2.5 dynosaur 宏收敛放宽（DIPORT-MACRO-CONFINE-01 → -01′）

域 crate 现需依赖 `dynosaur`/`trait-variant`（为域形 port 生成 dyn wrapper）。原 `DIPORT-MACRO-CONFINE-01`（dynosaur/trait-variant 只准 `diport` 依赖，`deny.toml` wrapper + `xtask`，Medium）放宽为 **-01′**：白名单 = `diport`（DiPort 层）+ **定义自身 repo/service port 的域 crate**（Domain 层）。`xtask` 的 `EXTERNAL_CONFINEMENT_WRAPPERS` 由单 wrapper 改 allowlist，校验「白名单条目属 DiPort/Domain 层 + deny.toml wrappers 集合相等」（红/绿 case 见 `xtask/src/layerdeps.rs`）。

---

## 3. 范式（落地代码）

```rust
// crates/identity/src/ports.rs — 域形 repo port（Option 2）
use dynosaur::dynosaur;
pub use crate::domain::{IdentityError, Role, RoleId};   // 实体 façade（types pub，构造器 pub(crate) funnel）
pub use vocab::TenantId;                                // typed tenant scope

#[trait_variant::make(RoleRepo: Send)]
#[dynosaur(pub DynRoleRepo = dyn(box) RoleRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait RoleRepoLocal {
    async fn find(&self, tenant: TenantId, id: RoleId) -> Result<Option<Role>, IdentityError>;  // body: todo!()
    async fn save(&self, tenant: TenantId, role: Role) -> Result<(), IdentityError>;
}

// adapters/postgres/src/lib.rs — adapter→域 DIP 内向边（native AFIT，不 invoke dynosaur 宏）
use identity::ports::{IdentityError, Role, RoleId, RoleRepo, TenantId};
impl RoleRepo for PgStore {                                // postgres 依赖 identity（DIP 内向）
    async fn find(&self, _tenant: TenantId, _id: RoleId) -> Result<Option<Role>, IdentityError> { todo!() }
    async fn save(&self, _tenant: TenantId, _role: Role) -> Result<(), IdentityError> { todo!() }
}
```

本 PR 落 1 个代表性 port（identity `RoleRepo` + postgres impl，body=todo!()）作**编译证明**——验证放宽的 `adapter→域` 边 + 域内 dynosaur + `pub` 实体真实编译、typed tenant scope 由 repo 签名承载、mockall mock 经 `new_box` 装入 `DynRoleRepo`（PORT-SHAPE-01/02）。其余域的 repo port（Session/Config/Audit/Contract）随 W 阶段行为单元逐域补（机械复制本范式）。

---

## 4. 后果

- **正**：域形 port 归域核心（标准 hexagonal/DDD：repository 接口属域、adapter 经 DIP 实现），聚合不外泄、`pub(crate)` funnel 不变式保持；**零新增 crate、零新增分层**；最可逆（实体在 `domain/`、port 在 `ports/` 已隔离）。消解两份 spec 矛盾、解锁 W 阶段 repo 接缝。
- **负 / 代价**：① 新增 `adapter → 域` 编译期边（3 处守卫放宽：`layers.rs allows` / `layerdeps confinement` / `deny.toml` wrappers）；② 域 repo 签名实体由 `pub(crate)` 升 `pub`（封装面扩大，经私有字段 + funnel 缓解，仅升最小集）；③ `DIPORT-MACRO-CONFINE-01` 由单 crate 锁放宽为白名单（其「单一 dyn-dispatch 依赖点」语义随域形 port 多点定义而失去，见 §5 威胁重评）。
- **下游**：W 阶段每个域行为单元在 `pub mod ports` 补本域 repo/service port + adapter impl（按需把该 adapter 加入该域 deny.toml wrapper + dynosaur 白名单——若该域首次定义 repo port）。

### 4.1 升级触发（Option 2 → Option 3，登记备查）

Option 2 不 foreclose Option 3（per-域 `{domain}-model` crate）。任一条成立即重评升级：

1. 单域某 repo port 出现**第 2 个并存生产 adapter**（如同时 postgres + redis），二者需共享 trait + entity → thin `{domain}-model` crate 让多 adapter 只链薄模型而非整个域 crate，收益 > 成本。
2. `adapter ↔ 域` **编译耦合成为实测构建/爆炸半径问题**（adapter 链入域 crate 全 service/logic 依赖树）。
3. `DIPORT-MACRO-CONFINE-01′` 白名单膨胀到治理异味。
4. 趋近 GA / 出现外部消费方，稳定域模型需与高频变动的应用逻辑独立 SemVer。

迁移成本低（这是 Option 2 现在就选的关键理由）：实体在 `domain/`、port 在 `ports/` 已模块隔离，抽到 `{domain}-model` crate 是机械搬迁，非重设计。

---

## 5. 对 ADR-003 / ADR-004 的 amendment + 威胁重评（ai-robust「ADR amendment 同步重评」）

### 5.1 Amend ADR-003

- **§6 偏离 2**（「domain-patterns『port trait 属域 crate internal/ports』→ DI port trait 集中到 diport」）：**部分化**——provider-agnostic infra port 收敛 `diport`；**域形 repo/service port 不收敛，归所属域 crate `ports`**（§2.1 category line）。dynosaur 派发范式不变，仅扩定义点集合。
- **§7 威胁矩阵第 1 行（DIPORT-MACRO-CONFINE-01）→ -01′ 重评**：原威胁前提「单一 dyn-dispatch 依赖点」随 Option 2（repo port 必然多点定义于各域 crate）**已失效**——「单一」不再可达也不再必要。残余威胁（dynosaur 宏被非 port-定义 crate 滥用）由白名单 + 「白名单条目须属 DiPort/Domain 层」守（Medium，红 case anti-vacuity）。unsafe 维度威胁更早已被 ADR-003 落地结论 1（def-site hygiene，dynosaur unsafe 不逃逸 consumer forbid）中和，故白名单放宽**零安全代价**——确认安全模型不退化。
- **§4.2 跨 crate sealing**：域形 port 同样无法对独立 adapter crate sealing（与 diport 同），impl-allowlist 仍待 #1060；本 ADR 不改变该缺口。

### 5.2 Amend ADR-004

- **C1（async/dyn 二分）**：DI port → dynosaur 不变；补充**定义位置二分**——provider-agnostic infra port 定义于 `diport`，域形 repo/service port 定义于所属域 crate `ports`（§2.1）。
- **C5（必填依赖/Clock）**：不变——域 repo port 同样经 `Box<DynX>` 构造器必填位置参注入（统一性保持）。
- **C7（sealed/newtype）**：DI port 不跨 crate sealed 不变；补充 `adapter → 域` DIP 内向边（adapter 依赖域 crate impl 其域形 port，经 deny.toml 域 wrapper 放行）。
- **§5 AI-robust 表**：C7 行的 deny.toml wrapper 范围由「仅 diport」扩为「diport + port-定义域 crate」（DIPORT-MACRO-CONFINE-01′），评级仍 Medium。

---

## 6. AI-robust 分级（本 ADR 引入/修改的 enforcement）

| 约束 | 评级 | 载体 |
|------|------|------|
| 域形 port 归域 crate、不可放 diport（category line 反证侧） | **Hard（crate 图 + 编译器）** | diport 放域形 port 须新增域依赖 → `allows(DiPort,Domain)=false`（`xtask layer-deps`）+ cargo 未声明 import 不到。完整 AST 级判据为盲区，proactive lint 待 §8 follow-up |
| `adapter → 域` 内向边放行（反向 `域→adapter` 仍禁） | **Hard（source-centric lint）** | `xtask/src/layers.rs allows(Adapter,Domain)=true`；矩阵红/绿 case anti-vacuity |
| 域 repo 签名实体 `pub` 但不可伪造 | **Hard（可见性 + 类型）** | 类型 `pub`、字段私有、构造器 `pub(crate)` funnel——外部无构造路径 |
| dynosaur/trait-variant 收敛白名单（DIPORT-MACRO-CONFINE-01′） | **Medium（cargo-deny + xtask）** | `deny.toml` wrappers + `xtask EXTERNAL_CONFINEMENT_WRAPPERS`（白名单越层 + 正向覆盖 + 集合相等，红 case anti-vacuity） |
| 域形 port dyn-compatible + 必填注入 | **Hard（编译器/类型）** | 非 dyn-safe → `Box<DynX>` 编不过；构造器必填位置参（继承 ADR-003 C1/C5，PORT-SHAPE smoke 机器锁） |
| co-tx UoW：业务写 + outbox append 同一事务、不可拆解（OUTBOX-COTX-SESSION-01，§9 amendment #1192） | **Hard（类型层）+ Medium（adapter same-tx anti-vacuity）** | combined 方法 `persist_session_and_emit`——域无 tx 句柄、无半提交 API（Hard：split-tx 不可表达）；adapter 单事务接线（closed exact-lane façade `TenantDb<ServingWriteLane>::producer_tx` 仅私有铸造 `TenantTx<ServingWriteLane>`，并在同一事务内执行业务写 + canonical append）由集成测试 t11(commit 两行皆在)↔t12(rollback 两行皆无) anti-vacuity 守（Medium） |

无 Soft 新增 enforcement。

---

## 7. 备选（为何不取 Option 1 / Option 3）

- **Option 1（域实体上移基础层 / `generated`）**：repo port 签名实体（`Session`/`ConfigEntry`）定义于 `ids`/`vocab`/`generated`，diport 即可承载 repo port。**否决**：① 破坏「域内类型 `pub(crate)` 封装」+ 把域类型塞进 domain-agnostic 基础层（语义倒置）；② `generated` 是 codegen-only wire 类型（`DO NOT EDIT` + derive Serialize），手写域记录污染「generated = 契约派生 wire 单源」不变式；③ 其「持久化 DTO/record」变体最干净也需另起一个 records crate（= Option 3 的 crate 成本），且把 repository 降级为 DAO——读侧返回 record 而非聚合，对 `AuditEntry`（哈希链聚合）尤其危险（重建链不重验 `prev_hash`）。仅对 `Session`/`ConfigEntry` 等扁平实体勉强成立，对 `AuditRepo`/`ContractRepo` 退化——「只对半数实例正确」不成立为统一设计。
- **Option 3（per-域 `{domain}-model` crate）**：每域拆 `{domain}-model`（实体 + port）+ `{domain}`（逻辑）。架构最「正确」（聚合完整、port 归域、无层序弯折），但 **+4~5 crate + 新 `Layer` 变体 + 各自 deny.toml/layering 机器 + 仍稀释 dynosaur 收敛**；当前多为单 adapter/域、签名冻结期，属过度设计。其收益（多 adapter 共享薄模型 / 独立 SemVer / 编译隔离）成立时由 §4.1 升级触发引入——Option 2 的可逆性保证这是低成本机械搬迁。

---

## 8. Follow-up（W 阶段同步点 + 后续 issue）

### 8.1 新增一个域 repo port 的同步点清单（W 阶段开发者照此操作）

某域**首次**定义 repo/service port 时，须同步下列各处（漏任一由对应 lint fail-closed 抓住，但提前列清单降踩坑）：

1. 域 crate `src/ports.rs`（新建 `pub mod ports`）：定义 port trait（`#[trait_variant::make]` + `#[dynosaur(...)]`）。
2. 域 crate `Cargo.toml [dependencies]`：加 `dynosaur` + `trait-variant`（dev-dep 加 `mockall`/`tokio` 供 smoke）。
3. 域 crate `domain/mod.rs`：把 port 签名引用的最小实体集（+ adapter 真实 impl 所读 accessor）由 `pub(crate)` 升 `pub`（字段私有 + 构造器 `pub(crate)` funnel 不变）。
4. `deny.toml`：`dynosaur` / `trait-variant` 两条 ban 的 `wrappers` 各加该域 crate（DIPORT-MACRO-CONFINE-01′ 白名单）。
5. `xtask/src/layerdeps.rs` `EXTERNAL_CONFINEMENT_WRAPPERS`：两个 entry 的 allowlist 各加该域 crate（**须与第 4 步 deny.toml 集合相等**，否则 `check_external_confinement` 红——错误消息会提示多列/欠列 + 权威来源）。
6. 实现该 port 的 adapter：`Cargo.toml` 加该域 crate 依赖；`deny.toml` 该域 crate 的分层 ban `wrappers` 加该 adapter（`allows(Adapter,Domain)=true` 经 LAYER-DEPS-06 反向② 放行）。

> 第 4/5 步是同一约束的两侧（deny.toml 实配 ⟷ xtask 权威白名单），`check_external_confinement` 守其集合相等。

### 8.2 后续 issue

- **proactive AST lint（§2.1 盲区 Hard 化）**：完整「无域实体出现在 diport port 签名」未机器强制（现由 category line + 反证侧 Hard 兜底）。`dylint` 自写 lint 可把它升为主动 Medium——登记 GitHub issue 跟踪（不阻塞本 PR）。
- **代表性 RoleRepo 的真实 repo 接缝**：可读 accessor / 查询方法随 W 阶段行为单元补（tenant scope 已由 `TenantId` 签名参数承载；见 `ports.rs` RoleRepo 注释 + §8.1）——RoleRepo 自身的 roles 表 + RBAC 持久化与 #1083 session 接缝**解耦**（#1083 session 维度已由 §9 交付），登记 backlog issue 跟踪。

---

## 9. Amendment（#1192）：L2 OutboxFact co-tx Unit-of-Work seam（#1083 session 接缝交付）

> **后续合并（#1278，见 §10）**：本 §9 描述的独立 `SessionUnitOfWork`（postgres `PgSessionUnitOfWork`）已与 `SessionRepo` 合并为单一 `SessionLifecycle`（postgres `PgSessionLifecycle`）。下文为 #1192 当时的历史记录，symbol 名以 §10 为准。

**触发**：#1192（PR #219 codex F2 defer）落地 identity session 持久化（#1083 核心）+ OutboxFact L2 完整 co-tx 接缝。`SessionUnitOfWork`（`identity::ports`）是 Option 2 范式下**第一个真实写实**（非 `todo!()` 冻结）的域形 port——postgres `PgSessionUnitOfWork` 把 session 行与 `identity.session-created` outbox 行**同一本地事务**原子写入。

### 9.1 是同一 Option 2 范式的细化，非新架构轴

`SessionUnitOfWork` 与 `RoleRepo`（§3）同构：域形 port 定义于 `identity::ports`、`adapter→域` DIP 内向边、dynosaur Send 变体、`Box<DynX>` 必填注入。**唯一新增维度**是 port 形态——`RoleRepo` 是 `find/save` 普通仓储，`SessionUnitOfWork` 是 **combined-method Unit-of-Work**：单方法 `persist_session_and_emit(session, entry, envelope)` 把业务实体持久化 + outbox append 收进 adapter 独占的单事务。这是 §3 范式内的细化，不引入新归属轴。

> 为何 combined 方法而非「`SessionRepo::save` + `OutboxEmitter::emit` 两调用」或 closure-UoW：拆两个 provider-agnostic 端口，域无法把二者绑同一事务（端口签名不容 `TenantTx<ServingWriteLane>` 这类 adapter-owned exact-lane capability，否则 `ports`→adapter 反向耦合）；closure-UoW 把事务句柄回传给域，重开 split-tx 洞且泄漏 provider 类型。combined 方法把事务边界完全收进 adapter。

### 9.2 §8.1 同步点清单的实际执行（identity 非「首次」）

identity 在 RoleRepo 落地时已完成 §8.1 步骤 2/4/5（dynosaur/trait-variant 白名单 + xtask confinement 已含 `identity`），故 `SessionUnitOfWork` **新增零** deny.toml/xtask confinement 改动。实际触动：步骤 3（`Session`/`SessionId` 升 `pub` + accessor 真升 `pub` 供 adapter 跨 crate 读，**首次真实行使**——RoleRepo accessor 仍 `pub(crate)` 因其 body 仍 `todo!()`）；步骤 6（postgres 已 dep identity；**新增 demo provider** `memory` → `identity` 边，`deny.toml` identity wrapper 加 `memory`）。

### 9.3 威胁矩阵重评（ai-robust「ADR amendment 同步重评」强制）

| 新威胁 | 缓解 / 评级 | 安全模型是否退化 |
|--------|------------|------------------|
| UoW impl 把业务写与 outbox append 拆进**不同事务**（两次 closed exact-lane transaction façade / 各自 `begin`），defeat co-tx 原子性 | **INVARIANT OUTBOX-COTX-SESSION-01**：①域侧 **Hard**——combined 方法是唯一 session-写 API（无 `persist`/`emit` 分调），返回 `Result<(),E>` 不漏 tx 句柄，域无半开事务可拆；②adapter 侧 **Medium**——`TenantDb<ServingWriteLane>::producer_tx` 独占 begin/tenant setup/commit/rollback，仅在 closed concern façade 内私有铸造 `TenantTx<ServingWriteLane>`，业务写与 canonical outbox append 共用该 exact-lane transaction（复用 OUTBOX-ATOMIC-IDEM-01），并由集成测试 t11(commit 两行皆在)↔t12(rollback 两行皆无) anti-vacuity 守 | **否（不退化）**：§2.4 `adapter→域` 边 + §2.5 dynosaur 白名单对 `identity` 已覆盖；新增第二域形 port 不加新 crate-graph 风险，`memory`→`identity` 边经既有 LAYER-DEPS-06 反向②（真实 source edge）守。仅**扩展**威胁矩阵，不冲突既有结论 |

`OUTBOX-COTX-SESSION-01` 是 `OUTBOX-ATOMIC-IDEM-01`（守裸 `append_outbox` 在事务内）的 **sibling**（守 session 行 + outbox 行 both-or-neither），非其重载；emit-only `PgEmitter` 与 co-tx `PgSessionLifecycle` 复用同一 `append_outbox` 接缝，两路并存（前者用于无 co-located 业务写的 OutboxFact 事件）。

## 10. Amendment（#1278）：`SessionUnitOfWork` + `SessionRepo` 合并为单一 `SessionLifecycle` 域形 port

**触发**：PR #255 finding F3——会话「创建（co-tx，L2）」与「查询 / 软撤销（L1）」分属**两个未绑定**的域形 port（§9 的 `SessionUnitOfWork` + `SessionRepo`）。组合根可注入分属不同底座的实例——`with_seed_credential` 实建一个**新的空** `InMemSessionRepo`、与注入的 UoW **异 store**，导致 login 写入的会话无法被同一 service 的 logout 撤销，且类型系统无法阻止该 bug；且无 login→logout 全链回归。合并为单一 `SessionLifecycle`（`persist_session_and_emit` + `find` + `revoke` 同一 trait），使「两个未绑定 store」从类型层不可表达。

### 10.1 合并仍是同一 Option 2 范式的细化，非新归属轴

`SessionLifecycle` 仍：域形 port 定义于 `identity::ports`、`adapter→域` DIP 内向边、dynosaur Send 变体、`Box<DynX>` 必填注入——把 §9 的 combined-method UoW 与 `find`/`revoke` 读路径收敛进**单一** trait，不引入新归属轴。**零新增** deny.toml / xtask confinement（identity wrapper 已含 postgres/memory；dynosaur/trait-variant 白名单已含 identity）。工业 Rust 一致采用单一会话存储接口、「创建写」与「查询/撤销」不拆端口（`ref: maxcountryman/tower-sessions tower-sessions-core/src/session_store.rs@main` `SessionStore` create+save+load+delete 同 trait；`ref: oxidecomputer/omicron nexus/db-queries/src/db/datastore/console_session.rs@main` session_create/lookup/hard_delete 同 impl）；RSS 偏离仅在 combined `persist_session_and_emit` 内嵌 outbox（L2 OutboxFact 契约要求），故保留该 combined 方法（拆 `save`+`emit` 重开 split-tx 洞）。

### 10.2 co-tx 原子性 OUTBOX-COTX-SESSION-01 不退化

`OUTBOX-COTX-SESSION-01`（§9.3）的 Hard 强制力来自 `persist_session_and_emit` 的**方法签名形状**（combined 单方法、域无半开事务句柄），**非** `SessionUnitOfWork` 与 `SessionRepo` 是否分立 trait。合并后该方法与 `find` / `revoke` 并列于同一 trait 仍是唯一 session-写 API（无 `save` / `emit` 分调）；postgres `PgSessionLifecycle` 的事务边界（begin → SET LOCAL → INSERT session → append_outbox → 单 commit）不变，t11/t12/t14 anti-vacuity 照旧守。

### 10.3 威胁矩阵重评（ai-robust「ADR amendment 同步重评」强制）

| 新威胁 | 缓解 / 评级 | 安全模型是否退化 |
|--------|------------|------------------|
| 两个未绑定 session port 来自**不同底层 store**（persist 写 store A、find/revoke 查 store B），login 后 logout 失效（接缝悬空，PR #255 F3） | **Hard（类型系统）**：合并为单一 `SessionLifecycle` 域形 port——`LoginService::new` 由 5 必填位置参减为 4（`sessions` + `session_uow` 两独立必填参 → 单一 `lifecycle`），「两 store 选型空间」经**构造器必填参数 + typed function choice** 消除（违反不可表达）。anti-vacuity：service 级 `login_then_logout_revokes_via_shared_lifecycle`（login 写入 → 同 lifecycle find=Some → logout → find=None）守「create/find/revoke 同源」非恒真 | **否（安全模型加强）**：tenant 隔离仍由 `find` / `revoke` 签名的 `TenantId` 位置参承载（跨租 fail-closed）；OUTBOX-COTX-SESSION-01 combined 方法不变；audit actor = canonical user_id（#1277 F1）不受影响。零新增 crate-graph 风险（`adapter→域` 边、dynosaur 白名单对 `identity` 已覆盖） |

durable `find` / `revoke` 由 postgres `PgSessionLifecycle` 实写（tenant-scope SELECT/UPDATE + `0011_add_sessions_revoked.sql` 引入 `revoked` 列；集成测试 t20–t22 覆盖 persist→find / revoke→find None / 跨租隔离）——**补齐原 #1116 的 session durable 闭合**。合并 trait 的必然要求：单一 `SessionLifecycle` 强制 provider 交付完整生命周期，故 postgres **不留 `todo!()` 半实现**（否则 `LoginService::logout` 经 `revoke` 落到 runtime panic——把合并前「无 `PgSessionRepo` ⇒ 编译期挡住」的保护退化成运行期 panic，PR #273 codex F1）。`SessionLifecycle` 的「单一完整 provider」类型约束与生产行为至此闭合一致。

## 11. Amendment（#1168）：DLX provider-neutral port 与 sealed proof associated binding

`DlxLifecycleRepository` 与 `DlxArchiveStore` 的方法语义是 PostgreSQL/S3 可替换的基础设施能力，不是
eventexec 域形实体仓储；其签名可只引用 port-owned observation DTO 与 associated types。因此按 §2.1 category
line 归 `diport`。`DlxArchiveCipher` 不构成独立 provider 能力：它只是既有 `KeyProvider` 上的 DLX-specific AAD
编排，已删除并收回 eventexec 私有具体 service。

repository 仍需传递 eventexec 独占构造的 candidate/receipt/proof。为避免 `diport → eventexec` back-path，port
声明四个 associated types；eventexec 消费侧以 equality bound 精确绑定到自身 sealed 类型。associated type 声明
本身不命名服务类型，binding 发生在 `eventexec → diport` 的合法下行依赖侧，因此 category line 与 crate DAG
同时成立。archive store 同理只声明 `ObjectKey`，eventexec 将其绑定到只能由 typed `DeadLetterId` 派生的
`DlxArchiveObjectKey`，不开放 raw-string 构造。

### 11.1 派发与威胁重评

- 两个 port 由组合根静态选择、被 worker 多次调用，采用 ADR-003 #1095 已批准的 Send+Sync 静态泛型，不新增
  dyn wrapper；provider prod/test 可换性仍由 trait bound 保持。
- proof 类型错误绑定、raw object key provider 无法满足 `DlxLifecycle` equality bound（Hard）；proof 私有构造器
  不变。
- `diport` 不依赖 eventexec，由 layer-deps/cargo DAG 守（Hard）；adapter impl 站点由既有
  `rss_diport_impl_allowlist` 守（Medium）。旧 eventexec port/cipher 由 DLX funnel recursive scan 拒绝（Medium）。
- 无新增 Soft enforcement，安全模型不退化。

## 对标证据（ref）

- `ref: oxidecomputer/omicron Cargo.toml@main` — 域 trait 定义 + 组合根（`bins`）手工注入具体 impl 的 Rust 范本（`docs/references/framework-comparison.md` §域 crate 运行时 / 依赖注入），对应「域定义 port、组合根注入 adapter impl」。
- `ref: Cockburn Hexagonal Ports&Adapters` — port 接口属应用/域核心、adapter 依赖内向实现（DIP）的原始范式。
- `ref: Evans DDD「Repository」` — repository 接口是域层的一部分、实现属基础设施。
- `ref: uber-go/fx app.go@master` — 消费侧声明接口、`fx.Provide` 注册具体实现的依赖反转（概念对标，framework-comparison §域运行时）。
