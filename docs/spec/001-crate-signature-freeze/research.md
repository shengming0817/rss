# Phase 0 Research — 签名冻结的对标与范式决策

> 来源：ship 探索阶段两路 explorer 实拉 raw 源码 + RSS 规则单源。所有 `ref:` 为真实路径。
> **派发范式以已落地的 ADR-003（dynosaur）为单源**；本节决策已对齐 ADR-001/002/003，不复述其正文。

## D1. async + dyn 派发范式（gate: #995 / **ADR-003**）

- **Decision**：按接缝性质二分（ADR-003 §2）。
  - **可替换 provider 的 DI port trait**（Store/Signer/Publisher/Authorizer/Clock，含 I/O、L1–L4）→ **dynosaur**：native AFIT trait + `#[dynosaur::dynosaur(DynX = dyn(box) X)]` 宏生成 dyn-compatible wrapper，组合根经 `Box<DynX>`/`Arc<DynX>` 注入。收敛进专用 `diport` crate。
  - **L0 域内纯计算 / 单实现**（consistency/primitives/vocab 内部）→ **native AFIT + 泛型静态分发**（`fn f<S: Xxx>(s:&S)`），零开销、`pub(crate)` 封住类型扩散。
- **Rationale**：dynosaur「静态零成本、动态才付费」的成本模型优于 async-trait「每调用无条件 box」。native AFIT 在 1.96 仍不 object-safe（RTN/async-fn-in-dyn 实验性、RTN 稳定化 PR 被 blocked），故 dyn 路径必须经 wrapper。
- **明确拒绝**（ADR-003 §5）：
  - **async-trait**：每调用 box（含静态路径），与成本模型相悖；仅作 dynosaur pre-1.0 实测不达标时的**复评对照**，**非**并行退路。
  - **native AFIT + dyn**：1.96 非 stable，不可用。
  - **trait-variant**：只解 Send-bound、不解 dyn，拒。
  - **纯静态泛型铺满**：组合根 `Arc<dyn>` 场景单态膨胀 + 编译爆炸，仅用于 L0。
- **代价**：接受 dynosaur 的 `unsafe`（生成点 transmute）+ pre-1.0 API 风险——收敛到 `diport` 单 crate（forbid→deny 例外）+ §8 三开放风险待 diport 落地验证。
- **ref**: `spastorino/dynosaur releases/v0.3.0`（`dyn(box)` 生成、`new_box`/`from_box`）；`dtolnay/async-trait README@master`（被拒：每调用 Box::pin 成本模型）；`tower tower-service/src/lib.rs@master`（pre-AFIT `poll_ready + type Future` 范式）；`kube-rs kube-runtime/src/watcher.rs@main`（内部 native AFIT + 泛型，L0 对标）。

## D2. mock 范式 + 签名冻结期测试策略

- **Decision**：
  - mock 在**同 crate `#[cfg(test)]`** 生成消费，不跨 crate 共享（合 `rust-standards.md`）。外部 trait 用 `mock!`。
  - **dynosaur/native-AFIT 下 mockall 的具体形态（automock 是否直接支持 native `async fn` in trait、mock 是装入 native trait 还是 `DynX` wrapper）ADR-003 未覆盖 → 列为 diport 落地 spike 待验证项（data-model 待决项#6）**。L0 静态依赖单测用 `#[cfg(test)]` 内直接 impl 替身，不引入 dynosaur wrapper。
  - 签名冻结期三件测试：**PORT-SHAPE-01**（`Box/Arc<DynX>` 装得下 mock = dyn-compatible）、**PORT-SHAPE-02**（mock 可作构造器必填位置参注入）、**PORT-SHAPE-03**（async mock `.await` 且 Future `Send`）。
  - 基础/引擎 crate 额外产 `cargo public-api` baseline。
- **Rationale**：body=`todo!()` 无行为可测；测试唯一目标是证明**签名编译 + mock 可构造 + DI 接线成立 + dyn-compatible**。覆盖率门对 todo!() 不可达不适用 → 显式豁免到行为 PR。
- **Alternatives considered**：跨 crate `test-utils` 共享 mock（破坏域单测隔离，拒）；签名 PR 写真实现凑覆盖率（破坏并行冻结价值，拒）。
- **ref**: `mockall` docs.rs；`rust-standards.md` §命名/覆盖率。

## D3. bootstrap 生命周期 / init / 关闭逆序接缝（gate: #996 / **ADR-001**）

- **Decision**：
  - `Domain::init(&self, reg: &mut Registry) -> Result<(), KernelError>`（同步，init 内不 I/O、不 spawn）；失败返回 `Err` 不 panic。
  - 关闭：bootstrap 持注册栈两阶段 **LIFO 逆序** 驱动（cancel 广播 + 逆序 await），`shutdown(self)` 消费 self（双关闭编译期不可表达，ADR-001 §2.2）。Rust 无 async Drop。
  - **`ManagedResource` 派发形态存在 inter-ADR 冲突**：ADR-001 定为 `#[async_trait]` + `Arc<dyn ManagedResource>`；ADR-003 通则是 DI 注入→dynosaur。**暂遵 ADR-001（async_trait）**，随 bootstrap shutdown 框架落地时由 PR-diport 统一 + 同步重评 ADR-001（data-model 待决项#4）。
  - 域 crate 暴露 `pub fn module() -> DomainModule`；DI 用显式构造器注入，不用反射。
- **Rationale**：对标 fx `Hook{OnStart,OnStop}` + 逆序 Stop；对标 kube-rs Controller 注册 + `graceful_shutdown_on`（映射 `CancellationToken`）。RSS 用类型系统替 fx 反射 DI。
- **ref**: `kube-rs kube-runtime/src/controller/mod.rs@main`；`uber-go/fx lifecycle.go@master` / `module.go@master` / `app.go@master`。

## D4. httpserve 中间件 / route 接缝

- **Decision**：不自造中间件 trait，直接用 `tower::Layer<S>`（同步 `layer(&self, inner)->Service`）；route 注册经 `RouteGroup{ listener, prefix, register: Fn(Router)->Result<Router> }` + `Route{ method, path, contract_id, public }`；state 经 axum `Router::with_state(Arc<AppState>)`；`ListenerKind` 穷尽 enum（Primary/Internal/Health/Admin，值集 Hard 冻结）。这些是**非 DI 接缝**，留 httpserve（不进 diport）。
- **Rationale**：tower/axum 既定生态，复用免自造；`register` 同步闭包返回 `Result` 冒泡到 bootstrap。
- **ref**: `tower-rs/tower tower-layer/src/lib.rs@master`；`tower-service/src/lib.rs@master`；`tokio-rs/axum axum/src/routing/mod.rs@main`。

## D5. eventexec 事件总线接缝

- **Decision**：`Publisher`/`Subscriber` 拆两个 trait——作为 DI port，**经 dynosaur 收敛进 diport**（`#[dynosaur::dynosaur(DynPublisher = dyn(box) Publisher)]`）；`Subscriber::subscribe` 返回 `impl Stream<Item=Result<Message,_>> + Send`。eventexec 自身留**非 DI 接缝**：`HandlerFn = Arc<dyn Fn(Message)->BoxFuture<...> + Send + Sync>` 函数类型、`Disposition` enum（`Ack|Nack|Requeue{delay}` 穷尽 match）、`SubscribeInitializer`。
- **Rationale**：对标 watermill Pub/Sub 分离 + HandlerFunc 类型别名；Rust 侧用返回值 Disposition + `impl Stream` 取代 Go channel/方法确认。
- **ref**: `ThreeDotsLabs/watermill message/pubsub.go@master`、`message/router.go@master`、`pubsub/gochannel/pubsub.go@master`。

## D6. PR 拆分边界与顺序（重排：新增 diport 单元）

- **Decision**：PR 边界=架构分层；跨层严格串行，同层 crate 互不依赖→可并行。先 PR-0 conventions 地基。**ADR-003 把 DI port trait 收敛进 `diport` → 新增 PR-diport 单元**（PR-2 后、PR-3/4/5 前）；PR-3/PR-4 只冻非 DI 接缝。
- **Rationale**：分层依赖图由 cargo + deny.toml 编译期强制，是天然无环的 PR 序；conventions 先行避免 31+ crate 风格漂移；diport 单独成 PR 因其携带 unsafe 收敛 + dynosaur 可行性验证（ADR-003 §8）。
- **Alternatives considered**：「一 crate 一 PR」（31 PR，review 负担大，拒）；单巨 PR（不可并行，拒）。
- **门**：ADR-002+ADR-003 横切硬门（已落地）；ADR-001 局部（lifecycle/bootstrap）；diport 落地门 gate PR-3/4/5；#998 软门（域层 wire）。#993 已 close。

## 未决项

- 规划层无遗留 [NEEDS CLARIFICATION]。**diport 落地待决项（6 条，含实体引用层序 / Clock 归属 / ManagedResource inter-ADR 冲突 / mockall×dynosaur 兼容性 / dynosaur 可行性回退）见 data-model.md「diport 落地待决项」**——属**实施**前置（PR-diport 拍板），非规划阻塞：spec 只声明「以 ADR-003 dynosaur 为方向 + 待验证回退路径」的依赖门，不预判 dynosaur 实测结果。
