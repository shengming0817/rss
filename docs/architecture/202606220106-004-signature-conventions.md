# ADR-004：签名编写 Conventions（全 crate 签名冻结的统一约定单源）

- **状态**：Accepted（约定单源）；DI 派发取 dynosaur 方向**继承 ADR-003**，其可行性待 `diport` 落地 spike 验证（ADR-003 §8）
- **日期**：2026-06-22
- **关联**：issue #997 [RW-G0.2 签名冻结] · 子 PR #1046(PR-0)/#1047/#1048/#1049(diport)/#1050/#1051/#1052 · epic #991
- **依赖 ADR**：**ADR-001**（关闭逆序）· **ADR-002**（context 传播）· **ADR-003**（DI async+dyn 派发 = dynosaur）
- **后续修订**：**ADR-005**（#1083）补 DI port 定义位置二分（infra→diport / 域形 repo port→域 crate）+ `adapter→域` DIP 边——C1/C7/§5 已就地补注。
- **归属**：framework（签名约定是 provider-agnostic 基础设施，贯穿全部 crate）
- **AI-robust 评级**：见 §5（逐条 Hard/Medium，Soft 禁止立项）

---

## 1. 背景

#997 要把 RSS 全部库 crate（19 `crates/` + diport + 12 `adapters/`）的公开 trait/type **签名冻结**
（body=`todo!()` + stub + mockall），按分层拆 PR 并行放行 W 扇出。冻结的价值在「晚改接缝最贵」——
若 30+ crate 各写各的 async/dyn/mock/ctx 风格，W 阶段任一签名漂移都引发跨单元返工，且 review 无机判基准。

本 ADR 是**签名编写约定的唯一持久单源**：把 ADR-001/002/003 的决策落到「下游实现者照着写」的逐条范式，
被全部签名 PR 引用（`docs/spec/001-crate-signature-freeze/contracts/conventions.md` 薄引用本 ADR）。
本 ADR **不复述** ADR-001/002/003 的论证，只引用其结论。

---

## 2. 约定（C1–C12）

### C1. async / dyn 二分（← ADR-003）

按接缝性质二分，**单一策略、不留双路径 / 兼容 shim**：

```rust
// 可替换 provider 的 DI port trait（Store/Signer/Publisher/Authorizer/Clock，含 I/O、L1–L4）
// → dynosaur：native AFIT trait + 宏生成 dyn-compatible wrapper。定义于 diport crate。
#[dynosaur::dynosaur(DynUserStore = dyn(box) UserStore)]
pub trait UserStore: Send + Sync {
    async fn find_by_id(&self, id: UserId) -> Result<User, StoreError>;  // body: todo!()
}
// 组合根经 Box<DynUserStore> / Arc<DynUserStore> 注入。

// L0 域内纯计算 / 单实现（consistency/primitives/vocab 内部，无运行时替换需求）
// → native AFIT + 泛型静态分发（零开销）
pub trait IdemCheck {
    async fn seen(&self, key: &IdemKey) -> Result<bool, EngineError>;  // body: todo!()
}
fn run<S: IdemCheck>(s: &S) { /* 单态、零 box */ }
```

判据（ADR-003 §4.5）：provider 在 prod/test 会换 + 组合根跨 crate 注入 + L1–L4 → 动态（dynosaur）；
总是同一实现 + 同 crate 内调用 + L0 纯计算 → 静态泛型。**dyn 对象安全 do/don't 见 ADR-003 §4.6**（禁泛型方法/返回 Self/`impl Trait`/`Clone` supertrait）。

> **ADR-005 补充（#1083）——DI port 定义位置二分**：provider-agnostic infra port（签名只引基础/wire/自定义
> 类型）定义于 `diport`；**域形 repo/service port**（签名引用域内实体，如 `RoleRepo::find(..)->Option<Role>`）
> 定义于**所属域 crate `pub mod ports`**（同款 dynosaur Send 变体范式，但归域 crate）。归属判据见 ADR-005 §2.1。

### C2. mock

- mock 在**同 crate `#[cfg(test)]`** 生成消费，**禁跨 crate 共享**（合 rust-standards「域 crate 单测不依赖 adapter crate」）；外部 trait 用 `mockall::mock!`。
- **✅ 已验证（PR-diport #164，data-model 待决项#6）**：dynosaur Send 变体 + native AFIT 下 mockall **可用**——用 `mockall::mock!` 对 Send 变体 trait（如 `Signer`）写 mock（**非** `#[async_trait]`，方法 `async fn` 直接声明），生成的 `MockX` 经 `DynX::new_box(mock)` 装入 dyn wrapper 且 future `Send`（跨 `tokio::spawn` 通过）。即 **mock 是 native trait impl，经 `new_box` 进 `DynX`**（不是 mock `DynX` 本身）。机器锁：`crates/diport/src/signer.rs` `#[cfg(test)] mockall_mock_loads_into_dyn_signer`（`cargo test -p diport` 跑）。

### C3. ctx 传播（← ADR-002 D2）

- tenant/principal 经 `runctx::RequestCtx<T, P>`——**显式、不可变、sealed struct + `tokio::task_local!` 传播**。
- 需把 ctx 喂 PDP / repo 处**显式传 `&RequestCtx`**（类型安全），不靠到处隐式读。
- `RequestCtx` **私有字段 + 不 derive `Deserialize`**（body 构造不可表达，Hard）；只能从已认证通道构造。
- **fail-closed（ADR-002 D6）**：ctx 访问器返回 `Result<_, MissingCtx>`，缺失即 **deny**（返回 `Err` / 401 / 403）；**禁** `.unwrap()` / `unwrap_or_default()` / 伪造 ctx——ctx 缺失被当 anonymous/default-tenant 放行即 fail-open 越权。
- 可观测 ID（trace/correlation）一律走 `tracing` span，**不入 trait 签名**。
- `tokio::spawn`/`spawn_blocking`/`std::thread` **不继承** task_local，必须重新 `scope`（ADR-002 §3）。

### C4. 关闭逆序（← ADR-001）

- 关闭由 `bootstrap` 持注册栈**两阶段 LIFO 逆序**驱动（cancel 广播 + 逆序 `await` `shutdown()`），无 async Drop。
- `ShutdownStack::shutdown(self)` **消费 self**（双关闭 / 关闭后注册编译期不可表达，Hard）。
- `ManagedResource`：`async fn shutdown(&self)` + `name()` + `shutdown_timeout()`，typed `ShutdownError`（非 `anyhow`，公共 port 不泄漏 adapter 信息）。
- **⚠️ inter-ADR 冲突（data-model 待决项#4）**：ADR-001 把 `ManagedResource` 定为 `#[async_trait]` + `Arc<dyn>`；C1 通则（ADR-003）是 DI 注入→dynosaur。**`ManagedResource` 暂遵 ADR-001（async_trait）**，随 bootstrap shutdown 框架落地时由 PR-diport 统一为 dynosaur 并**同步重评 ADR-001 威胁矩阵**（ai-robust「ADR amendment 同步」）。

### C5. 必填依赖 / Clock（← ADR-003 §4.3 + Amendment #1095）

- 必填 DI 依赖 = 构造器**必填位置参**（非 `Option`），缺失即编译错误：`fn new(store: Box<DynUserStore>, clock: Box<DynClock>) -> Self`。
- `Clock` 走同一 `Box<DynClock>` 范式；**禁** builder option / Config 字段传 clock，**禁**默认系统时钟（prod clock 仅在组合根构造）。
- **async DI port 注入形态三分**（单源 = [ADR-003 Amendment #1095 / #1828 / #1331](202606212047-003-di-trait-async-dyn-dispatch-strategy.md)）：默认 `make(X: Send)` 的 `DynX` 是 Send 非 Sync，故 `Box<DynX>` 单 owner；多次调用 + 跨 Send future 用泛型静态分发 `<S: X + Send + Sync + 'static>` + `Arc<S>`；`Arc<DynX>` 仅限不跨 Send future。共享 Sync 例外是 ADR-003 `classify_ports!` `async_sync` 闭集四端口（`KeyProvider` / `Pdp` / `SecretResolver` / `ServiceTokenReplayStore`），base trait 显式 `Send + Sync`，可共享 `Arc<DynX>`；PDP 由 #1828 compile-pass / compile-fail 门锁定。（sync port `Clock` 天然 `Send + Sync`。）
- **server policy capability 同样必填**：HTTP adapter 只能消费 `RateLimitedRoutes::into_server_service(ServerRequestBudget)`
  或 `HealthRoutes::into_server_service(ServerRequestBudget)` 返回的字段私有 `ServerService`；裸
  `AuthenticatedRoutes` 没有 public bind 出口。`ServerService` 不实现 axum make-service，实际 bind 只能由 `httpd` 私有 wrapper
  完成。budget 是非零 newtype，runtime 配置缺失/为零在 bind 前失败。禁止用
  `Option`、默认无界值或 plaintext/mTLS 双签名绕开完整请求预算。

### C6. serde 边界

domain 类型**不** derive `Serialize`/`Deserialize`；仅 contract/DTO（`generated`）可序列化到 wire（类型层杜绝实体直接上 wire）。

### C7. sealed / newtype（← ADR-003 §4.2）

- **DI port trait 不跨 crate sealed**：集中到 `diport` 后，sealed-trait 无法「只放行某外部 adapter crate impl」→ 采**方案②**：放弃跨 crate sealing。`deny.toml` wrapper 收敛 **dynosaur/trait-variant 宏依赖**（保证 port 只在 DI port 定义点 crate 定义）——但 cargo-deny **限依赖非 impl**，故「谁可 impl」**当前未机器强制**（落地实测，见 ADR-003 落地结论 2）；implementer-allowlist 仍待 **#1060**（PR-5 已落 12 个 adapter 真实 impl，但 cargo-deny 无法限 impl 站点）。
- **ADR-005 补充（#1083）——`adapter → 域` DIP 内向边**：实现**域形** repo port（如 `identity::ports::RoleRepo`）的 adapter 须依赖该域 crate（命名其 `pub` 实体），经 `deny.toml` 该域 ban 的 wrappers（加该 adapter）+ `allows(Adapter,Domain)=true` 放行；反向「域 → adapter」仍禁，「adapter 不被域依赖」不变量保持（仅新增 impl 边，运行期仍组合根注入）。dynosaur 宏依赖白名单同步扩到该域 crate（DIPORT-MACRO-CONFINE-01′）。
- adapter（PR-5 落地口径）：签名冻结期为 **unit sealed-marker**（`pub struct PgStore;`，无 raw client 字段），以 **native AFIT** impl **已冻** DI port trait——diport 基建 port（`ManagedResource` 普适 + `Signer`/`Publisher` 按职责）+ 域形 repo port（`identity::ports::RoleRepo`，ADR-005）body=`todo!()`；raw client 字段（如 `sqlx::PgPool`，保持 `pub(crate)` 不泄漏）延迟到 W 阶段接后端时填入。adapter crate 保持 `#![forbid(unsafe_code)]`（不 invoke dynosaur 宏）。

### C8. 覆盖率豁免

签名 PR body=`todo!()` 不可达 → PR body **必须**声明「覆盖率延迟到对应行为 PR（W 阶段）兑现」，避免 80%/90% 门触发 CI 红。

### C9. 每 PR 对标

PR body 标 `ref: {framework} {path}@{ref}`（见 research.md），或「无需对标：<理由>」。

### C10. 错误

`vocab` + `thiserror` 枚举；message 为 `&'static str` const literal，**禁** `format!` 拼 runtime 数据（runtime 数据走 `with_details`/`with_internal` typed 通道）。domain 层不返回 HTTP 状态码。

### C11. DI port 宏依赖收敛（← ADR-003 §3 落地结论 1 + ADR-005）

- 默认全仓 `#![forbid(unsafe_code)]`，**无 crate 例外、无 unsafe carve-out**：ADR-003 落地结论 1 实测 dynosaur 0.3 生成的 unsafe 经 def-site hygiene **不触发** consumer `forbid`（无 `[lints.rust] unsafe_code="deny"` 覆盖、无生成点 `#[allow(unsafe_code)]`、无 ADR registry / lint carve-out 登记）。
- 收敛守卫 = `deny.toml` wrappers + `xtask layer-deps`（Medium）把「可依赖 `dynosaur`/`trait-variant`」限定到 **DI port 定义点白名单** = `diport`（provider-agnostic infra port）+ **定义自身域形 repo/service port 的域 crate**（ADR-005 Option 2，DIPORT-MACRO-CONFINE-01′）——无依赖即 import 不到宏。本约束是「DI port 定义点集中」架构守卫，**非** unsafe 收敛。

### C12. dynosaur 版本 pin（← ADR-003 §7/§8）

`dynosaur` pin `=0.3.x`；升级审 changelog（`new_box`/`from_box`/bridge impl pre-1.0 破坏式演进）。供应链 advisory 由 `deny.toml [advisories]` 覆盖。

---

## 3. 适用与门

- 本约定被全部签名 PR（PR-1..PR-5 + PR-diport）引用；review 以 C1–C12 为机判基准。
- **DI port trait 的 C1/C2/C7/C11/C12 实质落地门于 PR-diport**——dynosaur 可行性（ADR-003 §8 三开放风险）未验证前，DI port 签名不大规模铺开；若不可接受按 ADR-003 §5 回退 async-trait，本 ADR C1/C2/C7/C11 须随之修订（amendment 同步重评）。
- C3（ADR-002）/ C4（ADR-001）/ C5/C6/C8/C9/C10 不受 dynosaur 可行性影响，即刻生效。

---

## 4. 后果

- **正**：30+ crate 签名风格统一、review 机判化；DI 派发零静态开销（dynosaur）；unsafe 收敛单 crate；ctx/关闭/serde/错误边界全部以类型或 const 表达（多为 Hard）。
- **负 / 风险**：依赖 dynosaur pre-1.0（C12 pin + ADR-003 §8 风险）；`ManagedResource` 暂存 inter-ADR 不一致（C4，PR-diport 收口）；mockall×dynosaur 形态待实测（C2）。
- **下游**：本 ADR 是 conventions 单源；PR-diport 落地时回填 C2（mock 形态）、统一 C4（ManagedResource），并在 architecture.md/rust-standards/domain-patterns 回写 diport 例外（ADR-003 §8 follow-up）。

---

## 5. AI-robust 分级（本 ADR 引入 / 重申的 enforcement）

| 约定 | 评级 | 载体 |
|------|------|------|
| C1 DI port dyn-compatible（dynosaur） | **Hard（编译器）** | 非 dyn-safe trait → `Box/Arc<DynX>` 直接编不过；`trybuild` compile-fail 作 Medium 回归锁（PR-diport TD04） |
| C5 必填 DI 依赖非 Option | **Hard（类型系统）** | 构造器必填位置参 `Box<DynX>`，缺失即编译错误 |
| C3 RequestCtx 不可伪造 | **Hard（类型 + 可见性）** | 私有字段 + 不 derive Deserialize（body 构造不可表达，ADR-002） |
| C4 单次关闭 | **Hard（move 语义）** | `shutdown(self)` 消费 self（ADR-001）；LIFO 顺序为 Medium（测试断言） |
| C6 serde 边界 | **Hard（serde derive 冻结）** | domain 不 derive；golden 锁 wire 字段 |
| C7 DI port 实现方限定 | **Medium（cargo-deny）** | deny.toml wrappers（方案②，跨 crate sealing 不可行的降级）；dynosaur 宏依赖白名单 = diport + 定义 repo port 的域 crate（DIPORT-MACRO-CONFINE-01′，ADR-005）；`adapter→域` impl 边经域 ban wrapper 放行 |
| C11 DI port 宏依赖收敛白名单 | **Medium（cargo-deny + xtask）** | deny.toml + layer-deps 把 dynosaur/trait-variant 依赖限定到白名单 = diport + 定义域形 port 的域 crate（DIPORT-MACRO-CONFINE-01′，ADR-005）；无 unsafe carve-out（def-site hygiene，ADR-003 结论 1） |
| C12 dynosaur pin | **Medium（cargo-deny）** | deny.toml 注释 ID `=0.3.x` |
| C8 覆盖率豁免 | **Medium（governance 测试）** | 签名 PR 声明 + CI 门豁免 todo!() 不可达 |
| C10 错误 message const | **Hard/Medium** | `&'static str` 类型约束（Hard）+ clippy（Medium） |
| C3 ctx fail-closed | **Hard + Medium** | 私有字段 + 无 Deserialize（Hard）；ctx 缺失 deny 的行为测试（Medium，ADR-002） |
| C2 mock 形态 | **Medium（PR-diport #164 落地）** | dynosaur Send 变体 + native-AFIT 下 mockall `mock!` 形态已实测可用，由 `crates/diport/src/signer.rs` `mockall_mock_loads_into_dyn_signer` 机器锁（`cargo test -p diport`，接入 verify nextest）守（data-model 待决项#6 闭合） |

> 无 Soft **新增 enforcement 机制**；C2 的 Soft 是「评级待定」的临时状态（PR-diport 收口），非以 Soft 立项的约束。

---

## 6. 备选（为何不另起炉灶）

- **不重定义 async/dyn 派发**：直接继承 ADR-003（dynosaur），本 ADR 只做「下游可照抄」的范式落地，避免第二事实源。
- **不把 conventions 写成代码框架**：约定是一份 ADR 文档（最小必要抽象），非运行时抽象层——签名冻结只冻接缝、不引入新机制（plan.md Complexity Tracking）。

## 对标证据（ref）

- `ref: spastorino/dynosaur releases/v0.3.0` — DI 派发范式（`dyn(box)` 生成、`new_box`/`from_box`），继承 ADR-003。
- `ref: uber-go/fx lifecycle.go@master` — 关闭逆序 Hook 语义（C4，经 ADR-001）。
- `ref: tokio tokio/src/task/task_local.rs` — `LocalKey::scope`/`try_with`（C3 ctx 传播，经 ADR-002）。
- `ref: dtolnay/async-trait README@master` — 被拒对照（C1，每调用 box 成本模型）。
