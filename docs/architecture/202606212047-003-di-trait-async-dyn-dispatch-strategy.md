# ADR-003：DI trait 的 async + dyn 派发策略与 Arc 样板范式

- **状态**：Accepted + **Landed**（PR-diport #1049，2026-06-22）。派发策略（dynosaur）已落地；§8 三项开放风险已实测，结论见下「落地结论」——**dynosaur 可行，且比本 ADR 原设更简**（无 unsafe 例外）。
- **日期**：2026-06-21（落地回写：2026-06-22）
- **关联**：issue #995 [RW-G0.5] · epic #991 · 落地单元 #1049 · `docs/migration-from-gocell/gocell-rust-crate-mapping.md`
- **归属**：framework（DI 接缝是 provider-agnostic 基础设施，不绑单一域）
- **AI-robust 评级**：见 §7（本 ADR 引入的 enforcement 逐条 Hard/Medium）

---

## 落地结论（PR-diport #1049，覆盖 §3/§4/§7/§8）

dynosaur 0.3 落地 spike 实测，三项开放风险结论 + 对原 ADR 的修订（**冲突段落以本节为准**）：

1. **§8 风险 1（unsafe carve-out）→ 不存在**：实测 dynosaur 0.3 宏生成的 `unsafe transmute` 经 **def-site
   hygiene** 不触发 consumer crate 的 `unsafe_code` lint——`diport` 即便 `#![forbid(unsafe_code)]` 也编译通过
   （anti-vacuity 已验证 forbid 对 `diport` 手写 unsafe 仍生效）。故 **§3 的「必须把 forbid 降为 deny」例外
   不需要**：`diport` 与其它 crate 一致 `[lints] workspace = true`（继承 forbid），无 forbid→deny 例外、
   无 `#[allow(unsafe_code)]`、无 error-handling §Carve-out 登记项。**威胁重评**：原 §3「unsafe 注入消费 crate」
   的威胁前提在 0.3 不成立；`diport` 的存在理由降为纯架构（DI port 集中 + 单一 dyn-dispatch 依赖点），
   unsafe 收敛不再是动机。dynosaur exact-pin `=0.3.0`，升级须复测本不变式（`diport` rustdoc DIPORT-UNSAFE-HYGIENE-01）。
2. **§8 风险 2（跨 crate sealing）→ 方案 ②**：DI port trait 不带 sealed supertrait；「谁可 impl」由 `deny.toml`
   wrapper 限定可依赖 `dynosaur`/`trait-variant`/`diport` 的 crate 集（cargo-deny Medium，INVARIANT
   DIPORT-MACRO-CONFINE-01，`layer-deps` 守 wrapper⟷源一致）。cargo-deny 限「依赖」非「impl」的残余缺口
   （域 crate 也依赖 diport 来消费端口）+ 本轮无 adapter 实 impl → implementer-allowlist 待 PR-5（OOS）。
3. **§8 风险 3（v0.3 API）→ 修订**：真实构造 API = `DynX::new_box` / `new_arc` / `from_box` / `from_mut`
   （§4 示例 `new_box`/`new_arc` 正确；README 的 `boxed` 形态为旧版）。**新增**：`dyn(box)` 默认 boxed future
   **非 Send**；DI port 须在多线程 runtime 跨 spawn → 用 `#[trait_variant::make(X: Send)]` 生成 Send 变体 +
   `#[dynosaur(DynX = dyn(box) X, bridge(dyn))]` 据此生成 Send 的 `DynX`（需 `trait-variant` crate，同 exact-pin）。
   公开 Send 变体 `X` + `DynX`；非 Send 基 trait `XLocal` 不在 crate 根 re-export（避免方法解析歧义）。
4. **§4.3 Clock 修订**：`Clock` 是 **sync** trait（`fn now(&self) -> SystemTime`），天然 dyn-compatible →
   经 `Box<dyn Clock>` 注入，**不需** dynosaur / 无 `DynClock`（dynosaur 仅为 async fn in trait 的 dyn 派发）。
5. **ManagedResource（§7 末条 + 跨 ADR-001 冲突）→ 已收敛**：迁入 `diport` 改 dynosaur Send 变体；`bootstrap`
   `ShutdownStack` 以 `Box<DynManagedResource<'static>>` 持有并 `tokio::spawn` 隔离 panic——`Box` 仅需 `Send`
   （免 `Arc` 的 `Send+Sync`），并去掉原 `Arc::clone`。ADR-001 威胁矩阵同步重评（见 ADR-001 落地回写）。

---

## 1. 背景

GoCell→Rust 迁移的 G0「接缝冻结」阶段需要先定下一个贯穿所有后续单元的基础决策：**依赖注入（DI）
trait 的 async 方法如何做动态派发**。

根因（`gocell-rust-crate-mapping.md` §三）：组合根（`bins/`、assembly）重度持有
`Arc<dyn Authorizer / Signer / Store / Publisher / ...>` 这类可替换 provider 接缝。而 Rust 的
**async fn in trait（AFIT，1.75 起稳定）静态分发 OK、`dyn` 不行**——`async fn` 脱糖成 RPITIT，返回
每个 impl 各异的 opaque type，尺寸不定，无法进 vtable，trait 因此非 dyn-compatible（object-unsafe）。
直接写 `Arc<dyn Store>` 会得到 `error[E0038]: the trait cannot be made into an object`。

当前 workspace 为骨架：`crates/` 全部仅 `lib.rs`、无任何 trait 定义——本 ADR（**编号 003**）属 G0「接缝冻结」批次，是 greenfield 决策，不存在向后兼容包袱。

本 ADR 产出：① 派发策略决策；② 可被下游直接套用的「Arc 样板范式」；③ 与 RSS 既有 Hard/Medium 治理
规则的契合 / 偏离登记；④ 落地前须验证的开放风险与 follow-up。

---

## 2. 决策

按接缝性质分两档，**单一策略、不留双路径 / 兼容 shim**：

| 接缝 | 策略 | 形态 |
|------|------|------|
| **可替换 provider 的 DI port trait**（`Store` / `Signer` / `Publisher` / `Authorizer` / `Clock`，含 I/O、L1–L4） | **dynosaur**（native AFIT trait + 宏生成 dyn-compatible wrapper） | `#[dynosaur::dynosaur(DynXxx = dyn(box) Xxx)]`，组合根经 `Box<DynXxx>` / `Arc<DynXxx>` 注入 |
| **L0 域内纯计算 / 单实现**（`consistency` / `primitives` / `vocab` 内部，无运行时替换需求） | **native AFIT + 泛型静态分发** | `fn f<S: Xxx>(s: &S)` / `impl Xxx`；零开销、`pub(crate)` 封住类型签名扩散 |

**为何选 dynosaur 而非 async-trait**：dynosaur 是 rust-lang 生态（Santiago Pastorino）官方推进、瞄准取代
async-trait 的新派范式——**静态分发路径零开销、仅 dyn 路径才 box**；而 `#[async_trait]` 无条件把每个
方法体 `Box::pin`，即便静态调用也付一次堆分配。选 dynosaur 即选「静态零成本、动态才付费」的成本模型，
代价是接受其 `unsafe` 偏离（§3、§6、§8）。

**明确拒绝**（备选矩阵见 §5）：

- **async-trait**：每调用 box（含静态路径），与上面成本模型相悖。其**零 unsafe** 仅作为 dynosaur 在
  发 1.0 前若实测不达标时的**复评对照**，**不是**当前并行维护的退路。
- **native AFIT + `dyn`**：Rust **1.96 仍非 stable**（RTN / async-fn-in-dyn 实验性；RTN 稳定化
  PR #138424 因新 trait solver 顾虑被 blocked）。不可用。
- **trait-variant**：`#[trait_variant::make(T: Send)]` 只生成 Send-bounded 变体解 Send bound 问题，
  **不解 dyn**（返回仍是 opaque type）。不满足需求。
- **纯静态泛型铺满**：组合根「满天飞 `Arc<dyn>`」场景会造成单态膨胀 + bin crate 编译时间爆炸 +
  类型参数漏到组合根难写。仅用于 L0。

---

## 3. unsafe 收敛：专用 `diport` crate（边界决策）

> ⚠ **本节原设前提已被落地实测推翻——以顶部「落地结论」为准**：dynosaur 0.3 的 unsafe 经 def-site
> hygiene **不触发** consumer forbid，故 `diport` **无需** forbid→deny 例外、无 `#[allow]` carve-out。
> 下文「必须把 forbid 降为 deny」「目标 `#[allow]`」仅存原始推理记录，不代表落地形态。

dynosaur 宏展开会把 `unsafe { core::mem::transmute(...) }`（把 trait object 的局部 lifetime 擦除到
`'static`，layout 不变、仅编译期成立）注入到调用宏的消费 crate。原设：RSS 默认
`#![forbid(unsafe_code)]`（rust-standards §工程护栏，**Hard**），且 `forbid` 无法被内层 `#[allow]`
覆盖——故曾推断承载 dynosaur trait 的 crate 须把 `forbid` 降为 `deny`（**实测不需要**，见落地结论 1）。

**决策**：DI port trait 定义 + 其 dynosaur `Dyn*` wrapper **集中到一个专用服务层 crate `diport`**
（命名待评审）。**只有 `diport`** 在自己的 `Cargo.toml [lints]` 中把 `unsafe_code` 设为 `deny`（覆盖
workspace 默认的 `forbid`）并对 dynosaur 生成点做目标 `#[allow(unsafe_code)]`；其余所有 crate 继续
`[lints] workspace = true` 继承 `forbid`。

**收敛的真正守卫是 crate 依赖图 + cargo-deny（Medium），不是 per-crate forbid（后者可被覆盖）。**
准确说：① 要 invoke `#[dynosaur::dynosaur(...)]` 宏，crate 必须**声明对 `dynosaur` 的依赖**；
② `deny.toml` wrappers 把「可依赖 `dynosaur`」限定到 `diport` 一个 crate（cargo-deny，**Medium**，CI 门）——
没有依赖就 import 不到宏、也就展开不出 unsafe。per-crate `#![forbid(unsafe_code)]` 只是**可被成员
`[lints]` 覆盖的纵深防御默认**（workspace lints 是 opt-in 继承、非硬上限，见 Cargo workspace 文档），
**不**单独构成编译期 Hard——故本约束按 **Medium** 登记（§7），不夸大为 Hard。

> 收敛的代价是偏离「port trait 属域 crate `internal/ports`」（§6 偏离 2）。DI infra port 不是跨域 wire——
> 跨域通信仍只经 contract，本偏离不触碰「契约是跨域通信单源」。

---

## 4. Arc 样板范式

### 4.1 port trait 定义（在 `diport`）

> ⚠ **本节示例代码已被落地实测替换——落地形态以顶部「落地结论」+ `crates/diport/src/signer.rs` 为准**：
> ① `diport` **用** `[lints] workspace = true`（无 forbid→deny 例外、无 `#![deny(unsafe_code)]` 覆盖、无目标
> `#[allow]`，见落地结论 1）；② 单 `#[dynosaur(...)]` 生成的 boxed future **非 Send**，DI port 须改
> `#[trait_variant::make(X: Send)]` + `#[dynosaur(pub DynX = dyn(box) X, bridge(dyn))]`（落地结论 3），下方
> `pub trait UserStore: Send + Sync` 单宏模板会产出非 Send `DynX`、在 `tokio::spawn` 处编不过。下文仅存原始推理。

`diport` 的 `Cargo.toml`（**原设**，已废）**不**写 `[lints] workspace = true`，而是显式
`[lints.rust] unsafe_code = "deny"`（覆盖 workspace 默认 `forbid`，使 crate 根 / 生成点的目标 `#[allow]`
能生效——`forbid` 下 `#[allow]` 无效，`deny` 下有效）：

```rust
// crates/diport/src/lib.rs
#![deny(unsafe_code)] // crate 根：deny（非 forbid），仅本 crate；其余 crate 继承 workspace forbid

// crates/diport/src/store.rs
use std::sync::Arc;

/// dynosaur 生成 dyn-compatible 的 `DynUserStore` wrapper；static 路径零开销，dyn 路径才 box。
/// 实现方限制：本模板按方案 ②（adapter 独立 crate 实现）——port trait **不带** sealed supertrait，
/// 「谁可 impl」由 `deny.toml` wrappers 限定（cargo-deny Medium，见 §4.2 / §8 风险 2）。
/// 仅当改选方案 ①（adapter impl 收回 `diport`）才加 `mod private { pub trait Sealed {} }` + `private::Sealed` supertrait。
#[dynosaur::dynosaur(DynUserStore = dyn(box) UserStore)]
pub trait UserStore: Send + Sync {
    async fn find_by_id(&self, id: UserId) -> Result<User, StoreError>;
    async fn save(&self, user: &User) -> Result<(), StoreError>;

    // 无 async Drop（Rust Drop 只能同步）：infra 资源（PgPool flush 等）显式异步关闭。
    // reason: no async Drop in Rust; infra teardown is async — see §4.4
    async fn shutdown(&self) -> Result<(), StoreError>;
}
```

### 4.2 adapter 实现（在 adapter crate）

raw adapter client 先 newtype 包成 `pub(crate)`，再实现 port trait——adapter crate
**保持 `#![forbid(unsafe_code)]`**（只 import `diport` 的 trait + `Dyn*`，自己不 invoke dynosaur 宏）：

```rust
// adapters/postgres/src/user_store.rs  （forbid(unsafe_code) 不变）
use diport::UserStore;

pub(crate) struct PgUserStore(sqlx::PgPool); // raw client 保持 pub(crate)

impl UserStore for PgUserStore {            // native AFIT impl，无 #[async_trait]
    async fn find_by_id(&self, id: UserId) -> Result<User, StoreError> { /* sqlx ... */ }
    async fn save(&self, user: &User) -> Result<(), StoreError> { /* ... */ }
    // reason: sqlx::PgPool::close() 返回 ()，无错误路径——其它有错误路径的 port（Signer/Publisher）须用 `?`
    async fn shutdown(&self) -> Result<(), StoreError> { self.0.close().await; Ok(()) }
}
```

> **sealing 的根本张力（§8 风险 2）**：sealed-trait（`private::Sealed` supertrait）只能在**定义 crate（`diport`）
> 内**封闭；而 adapter 是**独立 crate**——sealed-trait 无法「只放行某个外部 crate impl」。故集中到 `diport`
> 后，DI port trait **无法**对其 adapter 实现方 sealing。落地二选一（本 ADR 倾向 ②，保持 adapter crate 独立）：
> **①** port impl 收回 `diport` 内（sealing 成立，但 adapter 逻辑入 diport）；**②** 放弃跨 crate sealing，改由
> `deny.toml` wrappers 限定「可依赖 `diport` 并 impl port trait」的 crate 集（cargo-deny，**Medium**）。
> §4.1 trait 模板 + 上方 adapter 骨架**统一按 ② 写**（trait 无 sealed supertrait、adapter 不 `impl Sealed`），
> 可直接复制编译，**单一可执行路径**；若改选 ①，§4.1 加回 `private::Sealed` supertrait + `mod private` 且 adapter impl 收回 `diport`。

### 4.3 构造器必填注入（Clock 同范式）

DI 依赖是**非 `Option` 构造器位置参**，缺失即编译错误（ai-robust Hard 范本）。`Clock` 走同一
`Box<DynClock>` 范式，**不**经 builder option / Config 字段：

```rust
// crates/identity/src/application/session_service.rs  （forbid(unsafe_code) 不变）
pub(crate) struct SessionService {
    store: Box<DynUserStore>,        // 非 Option，缺失即编不过（Hard）
    clock: Box<DynClock>,            // Clock 同范式：构造器位置参，不走 Config
    publisher: Box<DynEventPublisher>,
}

impl SessionService {
    pub(crate) fn new(
        store: Box<DynUserStore>,
        clock: Box<DynClock>,
        publisher: Box<DynEventPublisher>,
    ) -> Self {
        Self { store, clock, publisher }
    }
}
```

> `Box<Dyn*>` 还是 `Arc<Dyn*>`？单一所有者 → `Box`；需要跨 `tokio::spawn` / 多 service 共享同一 provider
> → `Arc`（`Box` 不能 clone 共享）。两者都满足 `Send + Sync + 'static`（trait 定义处已声明 `Send + Sync`）。
> 共享场景示例：
>
> ```rust
> let publisher: Arc<DynEventPublisher> = Arc::new(DynEventPublisher::new_box(AmqpPublisher::..));
> let p = Arc::clone(&publisher);
> tokio::spawn(async move { p.publish(evt).await }); // Arc 可 move 进 'static task；Box 不行
> ```

### 4.4 组合根装配 + 逆序关闭（无 async Drop）

```rust
// bins/server/src/main.rs  （forbid(unsafe_code) 不变）
// CAUTION: new_box / from_box 是 dynosaur pre-1.0（=0.3.x）API，升级前先查 changelog（§8 风险 3）
let store = DynUserStore::new_box(PgUserStore(pool));        // dynosaur v0.3 API：new_box
let clock = DynClock::new_box(SystemClock);                  // prod clock 只在组合根构造
let publisher = DynEventPublisher::new_box(AmqpPublisher::connect(...).await?);

let svc = SessionService::new(store, clock, publisher);
// ... bootstrap / serve ...

// 显式逆序关闭（构造顺序的反向）——由 bootstrap shutdown 框架统一编排（§7 Medium），
// 不靠组合根手记顺序。
```

### 4.5 静态 ↔ 动态判定准则

| 选 `Box<Dyn*>` / `Arc<Dyn*>`（动态） | 选 `impl Trait` / `<S: Trait>`（静态） |
|---|---|
| provider 在 prod/test/staging 会换（PgStore vs InMem vs Mock） | 总是同一实现，无运行时替换 |
| 在组合根跨 crate 注入的依赖 | 同 crate 内调用、无跨界 |
| 一致性等级 L1–L4（I/O / 事务 / 远程） | L0 纯计算、域内、无副作用 |
| 传给 `tokio::spawn` 的依赖需 `'static` | crate 内直接持有泛型参 |
| 用 `mockall` mock 注入测试 | 测试直接 monomorphize |

具体：`UserStore`/`SessionStore`/`CertSigner`/`EventPublisher`/`Pdp`/`Clock` → 动态；`vocab` 错误格式化、
`ids` 校验、`consistency` 状态机转移、`tower::Layer` 中间件 → 静态。

> 表中「用 `mockall` mock 注入测试」**只适用于已经走 `Box<Dyn*>`/`Arc<Dyn*>` 的动态依赖**——可 mock
> 不是选动态的理由。L0 静态依赖的单测用 `#[cfg(test)]` 模块内的直接 impl 替身，不引入 dynosaur wrapper、
> 不破坏「L0 保持 forbid 干净」。

### 4.6 dyn 对象安全 dos / don'ts（port trait 写法约束）

**禁**（破坏 dyn-compatible）：泛型方法 `fn f<T>(..)`、返回 `Self`、返回 `impl Trait`、`where Self: Sized`、
`Clone` supertrait（`dyn` 不能 Clone）、未在 `dyn` 处指定的关联类型。
**须**：每方法 `&self`/`&mut self`、参数 / 返回为具体类型或 `Box<dyn _>`、supertrait 仅
`Send + Sync`（方案 ② 默认；实现方 crate 集由 `deny.toml` wrappers 限定，见 §4.2——选方案 ① 时再加 `private::Sealed`）、带 `async fn shutdown`。

---

## 5. 备选权衡矩阵

| 方案 | dyn 兼容 | 堆分配/调用 | Send+Sync | MSRV | unsafe | 编译开销 | 成熟度(2026) | 裁决 |
|------|---------|-----------|-----------|------|--------|---------|------------|------|
| **dynosaur 0.3** | ◎ 经 `Dyn*` wrapper | dyn 时 box / 静态 0 | ◎ wrapper 处理 | 1.75+ | **有**（生成 transmute） | proc-macro 中 | △ pre-1.0 | **选** |
| async-trait 0.1 | ◎ 天然 | **每调用 box**（含静态） | ◎ 默认 +Send | 全版 | 无 | proc-macro 中 | ◎ 生态标准 | 拒（成本模型）/复评对照 |
| native AFIT + dyn | ✗ stable 不可 | — | △ RTN 未稳 | — | — | 最小 | 1.96 ✗ | 拒 |
| trait-variant 0.1 | ✗ 不解 dyn | 0（静态） | ◎ 生成变体 | 1.75+ | 无 | proc-macro 小 | △ helper | 拒（不解 dyn） |
| 纯静态泛型 | 不适用 | 0 | ◎ where 显式 | 全版 | 无 | **单态膨胀大** | ◎ 语言特性 | 仅 L0 |

---

## 6. 与 RSS 既有规则的契合 / 偏离

**契合**（范式不破坏既有 Hard）：构造器必填参（ai-robust Hard）；raw client `pub(crate)` 封装
（`PgUserStore(PgPool)`）；Clock 构造器位置参（rust-standards）；Init fail-fast（`Arc/Box<Dyn*>` 由组合根
构造后注入，`init()` 不做 I/O / 不构造连接）；跨域只经 contract（DI port ≠ 跨域 wire，不触碰）。

**偏离 1**：`#![forbid(unsafe_code)]` 全局默认 → **`diport` 例外**（`deny` + 目标 `allow`）。理由：dynosaur
生成点的 transmute 无法在 `forbid` 下编译；收敛到单一 crate 使其余全仓保持 `forbid`（§3）。

**偏离 2**：domain-patterns「port trait 属域 crate `internal/ports`」→ **DI port trait 集中到 `diport`**。
理由：unsafe 收敛要求宏调用集中（§3）。澄清：DI infra port 是 provider-agnostic 基础设施 trait，**不是**
跨域 wire 类型；跨域通信单源仍是 contract，本偏离不削弱该不变式。

**偏离 3（部分）**：domain-patterns「port trait 用 sealed-trait 封闭」在**同 crate**内仍成立，但 DI port
trait 集中到 `diport` 后**无法对独立 adapter crate sealing**（§4.2）——本 ADR 倾向放弃跨 crate sealing、
改 cargo-deny wrappers（Medium）限定实现方 crate 集。即「外部无法 impl」从类型系统 Hard 降为 cargo-deny
Medium。

> 三条偏离须在 `diport` crate 实落时**同步回写** `docs/rules/architecture.md`（§扁平 workspace 结构树 + §分层，
> **架构单一事实源**，登记 `diport` 服务层 crate）、`rust-standards.md §工程护栏` 与 `domain-patterns.md`
> （见 §8 follow-up）——本 doc-only PR 不改规则文件（规则提前引用尚不存在的 crate 反而制造漂移）。

---

## 7. AI-robust 分级（本 ADR 引入的 enforcement 逐条评级，Soft 禁止立项）

| 约束 | 评级 | 载体 |
|------|------|------|
| **dynosaur / trait-variant 只能被 `diport` 依赖**（原「unsafe 只能出现在 `diport`」） | **Medium（cargo-deny）** | `deny.toml` wrapper 把「可依赖 `dynosaur`/`trait-variant`」限定到 `diport`（INVARIANT DIPORT-MACRO-CONFINE-01，`layer-deps` 守 wrapper⟷源）。**落地修订（结论 1）**：dynosaur 0.3 的 unsafe 不触发 consumer forbid，故本约束的动机是 **DI port 集中 + 单一 dyn-dispatch 依赖点**（架构），**非** unsafe 收敛；`diport` 无 forbid 例外。 |
| **DI port trait 必须 dyn-compatible** | **Hard（编译器）** | 写出非 dyn-safe trait，`Box<Dyn*>`/`Arc<Dyn*>` 直接编不过。`trybuild` compile-fail 用例仅作 **Medium 回归锁**（锁错误形态），列 §8 follow-up。 |
| **必填 DI 依赖非 Option** | **Hard（类型系统）** | 构造器必填位置参 `Box<Dyn*>`，缺失即编译错误（ai-robust 范本）。 |
| **dynosaur 版本 pin** | **Medium（cargo-deny）** | `deny.toml` 注释 ID：dynosaur `=0.3.x`。列 §8 follow-up（`diport` 落地时加）。 |
| **shutdown 逆序关闭** | **Soft（当前）→ Medium（`bootstrap` 框架落地后）** | 逆序类型系统管不到（无 async Drop）。`bootstrap` shutdown 框架（§8 follow-up，**尚未落地**）按注册逆序统一执行 `shutdown()` 后升 Medium；在此之前为 Soft，故该框架是 `diport` 实落的**前置项**而非可选 follow-up——**禁止**长期停留在「组合根手记顺序」的 Soft 纪律。 |

---

## 8. 落地前须验证的开放风险 + follow-up

**开放风险（`diport` crate 实落前必须验证，dynosaur pre-1.0 的不确定面）**：

1. **目标 `#[allow]` 可达性 + carve-out 登记**：dynosaur 是否自带 `#[allow(unsafe_code)]` 于生成点？若否，
   需 item-level 包裹机制把 allow 局限到生成项——**不得**用 module/crate-level carve-out（与 error-handling.md
   §Carve-out「carve-out 只能 item-level」冲突）。须实测 `cargo expand` 确认。**无论自带或手写**，只要 unsafe
   出现在 `diport`，即构成一次 carve-out 事件——须按 error-handling.md §Carve-out 同步更新 ADR registry +
   lint 配置映射，并在展开点提供 `// SAFETY:`（或 `diport` rustdoc INVARIANT 集中登记）阐明 transmute 的
   lifetime-擦除安全假设（rust-standards §工程护栏「unsafe 必须带 `// SAFETY:`」）。
2. **跨 crate sealing 不可行（见 §4.2）**：sealed-trait 只能在定义 crate `diport` 内封闭，adapter 是独立
   crate → DI port trait 无法对其 adapter 实现方 sealing。落地须在 §4.2 ①（impl 收回 diport）/ ②（放弃跨
   crate sealing，cargo-deny wrappers 限定实现方 crate 集）间定夺；本 ADR 倾向 ②。须 `diport` 落地确认。
3. **dynosaur v0.3 API 稳定性**：`new_box` / `from_box` / bridge impl 仍在破坏式演进；pin `=0.3.x` 并在
   升级时审 changelog。供应链 advisory 由 `deny.toml [advisories]`（全量 advisory 扫描 + `yanked = "deny"`）
   自动覆盖，无需显式 ignore。

**follow-up（本 doc-only PR 不做；归属下游 `diport` 落地单元——epic #991 的 G1/W/Join 子项跟踪，不在此重复建 issue）**：

- **结构单源回写（`diport` 落地同 PR，三处一并改防漂移）**：`docs/rules/architecture.md` §扁平 workspace 结构树
  + §分层（登记 `diport` 服务层 crate）、`Cargo.toml [workspace] members`（加 `crates/diport`）、`deny.toml` wrappers。
- `deny.toml` wrappers（Medium）：「可依赖 `dynosaur`」限定到 `diport`、「可依赖 `diport` 并 impl port trait」
  限定到允许的 adapter crate 集；clippy / cargo-deny 守 unsafe 仅准 `diport`。
- 首个 port trait 落地：加 `trybuild` dyn-compatible compile-pass / compile-fail 用例（Medium 回归锁）。
- `bootstrap` shutdown 框架：按注册逆序执行 `shutdown()`（把 §7 末条从 Soft 升 Medium）——**前置项**，先于
  port trait 大规模落地。
- 回写 `rust-standards.md §工程护栏`（`diport` forbid 例外）+ `domain-patterns.md`（DI port 集中例外 + port trait sealing 由 sealed-trait 改 cargo-deny wrappers）。
- **复评触发**：dynosaur 发 1.0 时复评（破坏式 API / unsafe 收口 / forbid 兼容）；若 1.0 前实测三项开放
  风险任一不可接受，按 §5 以 async-trait 为对照重评。

---

## 对标证据（ref）

- `ref: spastorino/dynosaur releases/v0.3.0` — 选定方案：`dyn(box)` 生成、`new_box`/`from_box` API、pre-1.0。
- `ref: tower tower-service/src/lib.rs@master` — `poll_ready + type Future` 规避 async-fn-in-trait 的 pre-AFIT 范式。
- `ref: kube-rs kube-runtime/src/watcher.rs@main` — 内部 trait 用 native AFIT + 泛型静态分发（L0 档对标）。
- `ref: linkerd2-proxy linkerd/stack/src/arc_new_service.rs@main` — `Arc<dyn NewService>` 同步工厂 + 异步 call 的 DI 接缝。
- `ref: sqlx sqlx-core/src/executor.rs@main` — 手工 `BoxFuture` + 泛型 `impl Executor` 的库级取舍。
- `ref: dtolnay/async-trait README@master` — 被拒方案：每调用 `Box::pin` 的成本模型。
