# ADR-001：DI trait 的 async + dyn 派发策略与 Arc 样板范式

- **状态**：Accepted（spike RW-G0.5 决策；下游 G1/W/Join 单元据此实落）
- **日期**：2026-06-21
- **关联**：issue #995 [RW-G0.5] · epic #991 · `docs/migration-from-gocell/gocell-rust-crate-mapping.md`
- **归属**：framework（DI 接缝是 provider-agnostic 基础设施，不绑单一域）
- **AI-robust 评级**：见 §7（本 ADR 引入的 enforcement 逐条 Hard/Medium）

---

## 1. 背景

GoCell→Rust 迁移的 G0「接缝冻结」阶段需要先定下一个贯穿所有后续单元的基础决策：**依赖注入（DI）
trait 的 async 方法如何做动态派发**。

根因（`gocell-rust-crate-mapping.md` §三）：组合根（`bins/`、assembly）重度持有
`Arc<dyn Authorizer / Signer / Store / Publisher / ...>` 这类可替换 provider 接缝。而 Rust 的
**async fn in trait（AFIT，1.75 起稳定）静态分发 OK、`dyn` 不行**——`async fn` 脱糖成 RPITIT，返回
每个 impl 各异的 opaque type，尺寸不定，无法进 vtable，trait 因此非 dyn-compatible（object-unsafe）。
直接写 `Arc<dyn Store>` 会得到 `error[E0038]: the trait cannot be made into an object`。

当前 workspace 为骨架：`crates/` 全部仅 `lib.rs`、无任何 trait 定义，`docs/architecture/` 仅
`.gitkeep`——这是**首个 ADR（编号 001）**，是 greenfield 决策，不存在向后兼容包袱。

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

dynosaur 宏展开会把 `unsafe { core::mem::transmute(...) }`（把 trait object 的局部 lifetime 擦除到
`'static`，layout 不变、仅编译期成立）**注入到调用宏的消费 crate**。而 RSS 默认
`#![forbid(unsafe_code)]`（rust-standards §工程护栏，**Hard**），且 **`forbid` 无法被内层 `#[allow]`
覆盖**——所以承载 dynosaur trait 的 crate 必须真正把 `forbid` 降为 `deny`。

**决策**：DI port trait 定义 + 其 dynosaur `Dyn*` wrapper **集中到一个专用服务层 crate `diport`**
（命名待评审）。**只有 `diport`** 把 crate 根降为 `#![deny(unsafe_code)]` 并对 dynosaur 生成点做目标
`#[allow(unsafe_code)]`；**其余所有 crate（基础 / 引擎 / 服务 / 域 / adapters / bins）保持
`#![forbid(unsafe_code)]` 不变**。

收敛的强度来自一个免费的编译期事实：**非-`diport` crate 既然仍 `forbid`，任何在 `diport` 之外
invoke dynosaur 宏 → 展开出 unsafe → 当场编译失败**。「dynosaur 只能在 `diport` 用」因此是 crate
属性强制的 **Hard** 约束，不靠口头纪律（§7）。

> 收敛的代价是偏离「port trait 属域 crate `internal/ports`」（§6 偏离 2）。DI infra port 不是跨域 wire——
> 跨域通信仍只经 contract，本偏离不触碰「契约是跨域通信单源」。

---

## 4. Arc 样板范式

### 4.1 port trait 定义（在 `diport`）

```rust
// crates/diport/src/store.rs
#![deny(unsafe_code)] // crate 根用 deny（非 forbid），使 dynosaur 生成点的 #[allow] 能生效

use std::sync::Arc;

mod private {
    pub trait Sealed {}
}

/// INVARIANT: DIPORT-SEALED-01 — 外部 crate 无法实现（private::Sealed 不可见）。
/// dynosaur 生成 dyn-compatible 的 `DynUserStore` wrapper；static 路径零开销，dyn 路径才 box。
#[dynosaur::dynosaur(DynUserStore = dyn(box) UserStore)]
pub trait UserStore: private::Sealed + Send + Sync {
    async fn find_by_id(&self, id: UserId) -> Result<User, StoreError>;
    async fn save(&self, user: &User) -> Result<(), StoreError>;

    // 无 async Drop（Rust Drop 只能同步）：infra 资源（PgPool flush 等）显式异步关闭。
    // reason: no async Drop in Rust; infra teardown is async — see §4.4
    async fn shutdown(&self) -> Result<(), StoreError>;
}
```

### 4.2 sealed marker wrapper + 实现（在域 crate / adapter）

raw adapter client 先 newtype 包成 `pub(crate)` sealed marker，再实现 port trait——域 / adapter crate
**保持 `#![forbid(unsafe_code)]`**（只 import `diport` 的 trait + `Dyn*`，自己不 invoke dynosaur 宏）：

```rust
// adapters/postgres/src/user_store.rs  （forbid(unsafe_code) 不变）
use diport::{UserStore, store::private::Sealed};

pub(crate) struct PgUserStore(sqlx::PgPool); // raw client 保持 pub(crate)

impl Sealed for PgUserStore {}

impl UserStore for PgUserStore {            // native AFIT impl，无 #[async_trait]
    async fn find_by_id(&self, id: UserId) -> Result<User, StoreError> { /* sqlx ... */ }
    async fn save(&self, user: &User) -> Result<(), StoreError> { /* ... */ }
    async fn shutdown(&self) -> Result<(), StoreError> { self.0.close().await; Ok(()) }
}
```

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

> `Box<Dyn*>` 还是 `Arc<Dyn*>`？需要跨 `tokio::spawn` 多处共享同一 provider → `Arc`；单一所有者 →
> `Box`。两者都满足 `Send + Sync + 'static`（trait 定义处已声明 `Send + Sync`）。

### 4.4 组合根装配 + 逆序关闭（无 async Drop）

```rust
// bins/server/src/main.rs  （forbid(unsafe_code) 不变）
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

### 4.6 dyn 对象安全 dos / don'ts（port trait 写法约束）

**禁**（破坏 dyn-compatible）：泛型方法 `fn f<T>(..)`、返回 `Self`、返回 `impl Trait`、`where Self: Sized`、
`Clone` supertrait（`dyn` 不能 Clone）、未在 `dyn` 处指定的关联类型。
**须**：每方法 `&self`/`&mut self`、参数 / 返回为具体类型或 `Box<dyn _>`、supertrait 仅
`private::Sealed + Send + Sync`、带 `async fn shutdown`。

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

**契合**（范式不破坏既有 Hard）：构造器必填参（ai-robust Hard）；sealed-trait + `pub(crate)` 封装；
Adapter sealed marker（`PgUserStore(PgPool)` 保持 `pub(crate)`）；Clock 构造器位置参（rust-standards）；
Init fail-fast（`Arc/Box<Dyn*>` 由组合根构造后注入，`init()` 不做 I/O / 不构造连接）；跨域只经 contract
（DI port ≠ 跨域 wire，不触碰）。

**偏离 1**：`#![forbid(unsafe_code)]` 全局默认 → **`diport` 例外**（`deny` + 目标 `allow`）。理由：dynosaur
生成点的 transmute 无法在 `forbid` 下编译；收敛到单一 crate 使其余全仓保持 `forbid`（§3）。

**偏离 2**：domain-patterns「port trait 属域 crate `internal/ports`」→ **DI port trait 集中到 `diport`**。
理由：unsafe 收敛要求宏调用集中（§3）。澄清：DI infra port 是 provider-agnostic 基础设施 trait，**不是**
跨域 wire 类型；跨域通信单源仍是 contract，本偏离不削弱该不变式。

> 这两条偏离须在 `diport` crate 实落时**同步回写** `rust-standards.md §工程护栏` 与 `domain-patterns.md`
> （见 §8 follow-up）——本 doc-only PR 不改规则文件（规则提前引用尚不存在的 crate 反而制造漂移）。

---

## 7. AI-robust 分级（本 ADR 引入的 enforcement 逐条评级，Soft 禁止立项）

| 约束 | 评级 | 载体 |
|------|------|------|
| **unsafe 只能出现在 `diport`** | **Hard（编译期，免费）** | **保留**非-`diport` crate 的 `#![forbid(unsafe_code)]`——在别处用 dynosaur 即展开 unsafe → 当场编不过。不靠纪律。 |
| **DI port trait 必须 dyn-compatible** | **Hard（编译器）** | 写出非 dyn-safe trait，`Box<Dyn*>`/`Arc<Dyn*>` 直接编不过。`trybuild` compile-fail 用例仅作 **Medium 回归锁**（锁错误形态），列 §8 follow-up。 |
| **必填 DI 依赖非 Option** | **Hard（类型系统）** | 构造器必填位置参 `Box<Dyn*>`，缺失即编译错误（ai-robust 范本）。 |
| **dynosaur 版本 pin + `diport` unsafe allowlist** | **Medium（cargo-deny）** | `deny.toml` 注释 ID：unsafe 仅准 `diport`、dynosaur `=0.3.x`。列 §8 follow-up（`diport` 落地时加）。 |
| **shutdown 逆序关闭** | **Medium（bootstrap 框架）** | 逆序类型系统管不到（无 async Drop）；由 `bootstrap` 按注册逆序统一执行 `shutdown()`，把它从 Soft 升 Medium——**禁止**退化成「组合根手记顺序」的 Soft 纪律。 |

---

## 8. 落地前须验证的开放风险 + follow-up

**开放风险（`diport` crate 实落前必须验证，dynosaur pre-1.0 的不确定面）**：

1. **目标 `#[allow]` 可达性**：dynosaur 是否自带 `#[allow(unsafe_code)]` 于生成点？若否，需 item-level
   包裹机制把 allow 局限到生成项——**不得**用 module/crate-level carve-out（与 error-handling.md §Carve-out
   「carve-out 只能 item-level」冲突）。须实测 `cargo expand` 确认。
2. **sealed + dynosaur 共存**：dynosaur 生成的 `DynUserStore` wrapper 能否 impl `private::Sealed`
   supertrait（其生成代码 module path 与 `Sealed` 定义处一致）？若不能，须在 `diport` 内为每个 `Dyn*` 显式
   补 `impl Sealed`，或放宽 sealing。须实测。
3. **dynosaur v0.3 API 稳定性**：`new_box` / `from_box` / bridge impl 仍在破坏式演进；pin `=0.3.x` 并在
   升级时审 changelog。

**follow-up（登记，本 doc-only PR 不做）**：

- `diport` crate 落地（service 层）+ pin dynosaur `=0.3.x`。
- `deny.toml` / clippy Medium 守卫：unsafe 仅准 `diport`、dynosaur 仅准 `diport` 依赖。
- 首个 port trait 落地：加 `trybuild` dyn-compatible compile-pass / compile-fail 用例（Medium 回归锁）。
- `bootstrap` shutdown 框架：按注册逆序执行 `shutdown()`（把 §7 末条落到 Medium）。
- 回写 `rust-standards.md §工程护栏`（`diport` forbid 例外）+ `domain-patterns.md`（DI port 集中例外）。
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
