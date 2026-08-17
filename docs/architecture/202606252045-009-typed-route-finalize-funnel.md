# ADR-009：typed route finalize funnel + per-listener typed route-group — 受控 `bootstrap → httpserve` 编译期路由类型边

- **状态**：Accepted（裁决 #1113 auth-finalize-before-bind + #1103 typed per-listener route-group 的类型层落地形态；2026-06-25）
- **日期**：2026-06-25
- **关联**：issue **#1113**（finalize_routes 裸 Router 可绕 auth bind）· **#1103**（route-group listener 隔离 Medium→Hard）· epic #991 · 两 issue body 均注「应合并设计」
- **依赖 / 修订 ADR / 规则**：修订 **PR #137 review F1**（bootstrap「不依赖兄弟服务」）为带受控例外；对齐 **ADR-005 §2.4** sanctioned `adapter → 域` DIP 内向边范式；修订 `docs/spec/001-crate-signature-freeze/contracts/layer-services.md` 的 httpserve `finalize_auth`/`RouteGroup`/`Route` 冻结签名；`ai-robust.md` §载体选择（上移编译期）
- **归属**：framework（路由生命周期类型词汇，provider-agnostic）
- **AI-robust 评级**：见 §6

---

## 1. 背景

`bootstrap::Registry::finalize_routes` 旧形态返回 `Vec<(ListenerKind, axum::Router)>`——**可直接 bind 的裸 Router**。两条类型层缺口骑在这同一接缝上：

- **#1113（pri-p1 安全）**：「组合根须先跑 `httpserve::finalize_auth` 再 bind」仅靠 rustdoc 约束。调用方可 `axum::serve(listener, router)` 绕过 auth 装配 → 未认证服务暴露。
- **#1103（pri-p2）**：`finalize_routes` 按**运行期** `ListenerKind` 值分组折叠；`route_group(listener: ListenerKind, ..)` 接受任意值，域 crate 误声明（把 Internal 路由标 Primary）类型层不可阻断。SEGREGATION-01 仅 runtime 反例测试守（Medium）。

二者的「彻底」解都要求 typed route 词汇，且 #1103「重构」明文「需 ADR + 协同 httpserve mount 改造」。**约束**：`bootstrap` 与 `httpserve` 是同层兄弟服务，按 PR #137 F1（bootstrap「不依赖兄弟服务」）+ `httpserve/src/lib.rs` `RouteGroupError` 注释「分层禁依赖 bootstrap」——**互不依赖**，仅共享 `primitives`（`primitives` 不引 axum）。

真正的类型层 Hard funnel 要求「produce（bootstrap finalize）+ seal + transform（httpserve finalize_auth）」**co-locate 在同一 crate**（私有构造 / `pub(crate)` 跨 crate 不可达；sealed-trait 仅定义 crate 内封闭）。给定调用链 `bootstrap(produce) → httpserve(transform) → Root(bind)`，无任一 wrapper 归属点能在**不引一条 bootstrap↔httpserve 边**的前提下达成 Hard——把 wrapper 放 `primitives`（泛型 + sealed state）会因 transform 必在 httpserve、而 httpserve 无法构造 primitives 的 sealed 态而退化成 public 构造孔（Medium，需 dylint 兜）。

## 2. 决策

**采纳 P1（类型系统 Hard）：sanction 一条受控的 `bootstrap → httpserve` 编译期路由类型边，typed 词汇归 httpserve。**

### 2.1 httpserve 路由类型词汇（`crates/httpserve/src/routes.rs`）

- **listener 类型 marker**（sealed）：`Listener: sealed::Sealed { const KIND: ListenerKind }`，markers `Primary`/`Internal`/`Admin`/`Health`；`NonPrimaryListener: Listener`（Internal/Admin）。外部 crate 无法命名 `sealed::Sealed` ⇒ 无法新增 listener marker。
- **listener-typed builder** `ListenerRouter<L>`：`mount(GeneratedEndpoint)` 仅 `L: NonPrimaryListener`、
  `mount(GeneratedPrimaryEndpoint)` 仅 `L = Primary`。endpoint 构造只接受 codegen 的
  `HttpRouteBinding<RouteMarker>`，handler 首 extractor 必须是同一 `ContractMarker<RouteMarker>`；随后 endpoint
  同时携擦除 marker 的 `HttpRouteEvidence` 与 handler。故不同契约的 evidence/handler 交换在类型层不可表达，
  path/method/auth/resource scope 不可分别传入。构造 `new` / 拆 `into_inner` 均 `pub(crate)`——域 crate
  只在 register 闭包里收到 builder、无 raw-bypass；Health 只能经 crate 内固定 builder 挂载。
- **funnel 闭值状态机**：`UnfinalizedRoutes`（未认证态，兼 per-listener 累加器，`empty()` + `nest_group::<L>()`；**无 public service 出口**）→ auth finalizer 产 `AuthenticatedRoutes`（构造私有、仍**无 public transport 出口**）。业务 listener 必须再经 `with_client_rate_limit` 换得 `RateLimitedRoutes`；Health 必须经独立 `finalize_health` 直接换得 `HealthRoutes`。只有后两种闭值能力可消费必填 `ServerRequestBudget` 产 `ServerService`。该 core 只实现 per-request `Service`、不能直接交给 `axum::serve`；`httpd` 的私有 make-service 才能在真实 bind 分支完成 lowering。
- **不变量**：任何 public（非 `#[doc(hidden)]` test）API **都不**返回裸 `axum::Router`——裸 Router 全程不出 httpserve。

### 2.2 受控 `bootstrap → httpserve` 边

- `bootstrap` 在 `[dependencies]` 连 `httpserve`；`Registry::route_group::<L: Listener>(prefix, register)`（listener 由类型参数携带，`L::KIND` 给折叠键）；process root 必须按值调用 `Registry::admit_writes(WriteAdmission)` 进入 `WriteAdmittedRegistry`，且只有该状态暴露 `finalize_routes` 并返回 `Vec<(ListenerKind, httpserve::UnfinalizedRoutes)>`。bootstrap 只碰 sealed `UnfinalizedRoutes`，不碰裸 Router。
- 该边经 `xtask` `layers::route_funnel_allows("bootstrap","httpserve")` 放行（INVARIANT **LAYER-DEPS-ROUTE-FUNNEL-01**），`check_layers` 在 `!allows(Service,Service)` 时叠加。fail-closed：**只**放行这一对有向边；反向 `httpserve → bootstrap` 及其它任意 `Service → Service` 仍禁（rstest + 端到端 `check_layers` 正反例守）。

### 2.3 INVARIANT 落点

- **ROUTE-LISTENER-TYPED-01**（#1103 Medium→Hard）：generated endpoint 经 `ListenerRouter<L>` 挂载、随组 fold 进 `L::KIND` listener；Internal/Admin endpoint 类型层不可能进 Primary Router，Health 固定 builder 不接受业务 endpoint。
- **ROUTE-ENDPOINT-ATOMIC-01 / ROUTE-MOUNT-NOBYPASS-01**（#1690 Hard）：production public API 不接受 raw
  `MethodRouter` 或 route 字段；endpoint 是 handler 与完整 evidence 的唯一注册单元。
- **ROUTE-AUTH-FUNNEL-01**（#1113 Hard）：`UnfinalizedRoutes` 无 public bindable 出口。
- **ROUTE-AUTH-FUNNEL-02**（#1113 Hard）：auth finalizer 是 `AuthenticatedRoutes` 唯一生产者，但该中间态不可 bind；业务只能由 `RateLimitedRoutes`、Health 只能由 `HealthRoutes` 进入唯一 transport core funnel。
- **ROUTE-WRITE-ADMISSION-01**（#2134 Hard）：裸 `Registry` 不存在 `finalize_routes`；`admit_writes` 是该 registry 进入 `WriteAdmittedRegistry` 的唯一按值转换，后者私有持有传入 gate，并把同一 gate 克隆到本次 finalization 的所有 listener accumulator。漏装 gate 在编译期失败，无 optional field、install API 或 production fallback。该 Hard 结论不扩张为 workspace 全局 authority 不可铸造或 OS process singleton；独立 process/test root 可以各自准备 admission controls，canonical serving runtime 的单 coordinator 归 assembly owner。

## 3. 修订既有决策（ai-robust §审查要求：ADR amendment 须同步重评威胁矩阵）

- **PR #137 review F1**（`crates/bootstrap/Cargo.toml` 注释「不依赖兄弟服务」）：**收窄为带受控例外**。F1 的实质论据是「kernel 不向兄弟服务横向索取 **runtime provider**（resolver / transport 等由组合根 DI 注入）」——本例外**不**触动该论据：bootstrap→httpserve 边只取**编译期路由类型词汇**（`ListenerRouter<L>` / `UnfinalizedRoutes`），**零 runtime provider** 跨边。
- **`httpserve/src/lib.rs` `RouteGroupError` 注释「分层禁依赖 bootstrap」**：**仍成立**——本 ADR 只开 `bootstrap → httpserve`（单向），`httpserve → bootstrap` 反向仍禁（layers 反例守）。注释更新为「httpserve 不依赖 bootstrap（反向边仍禁）；正向 bootstrap→httpserve 受控边见 ADR-009」。
- **signature-freeze（`docs/spec/001-.../layer-services.md`）**：httpserve `finalize_auth` 签名由 `(axum::Router, AuthPlan) -> Result<axum::Router>` 改为 `(UnfinalizedRoutes, AuthPlan) -> Result<AuthenticatedRoutes>`；#1690 再删除字段级 `Route`/`PrimaryRoute` 与 raw mount，替换为 generated endpoint mount。pre-GA 无外部消费方，原地破坏式更新。

### 威胁矩阵重评（受控边）

| 维度 | 评估 |
|---|---|
| 成环 | `httpserve` 依赖集（vocab/primitives/axum/tower/…）无一可达 bootstrap ⇒ `bootstrap → httpserve` 无环（cargo 亦拒环）。 |
| F1 原威胁（kernel 横向取 runtime provider、生命周期耦合兄弟服务运行期） | **不变**——本边零 runtime provider，仅编译期类型；bootstrap 生命周期不耦合 httpserve 运行期。 |
| 新增面 | bootstrap 现编译期依赖 httpserve 路由类型；二者均 framework-internal 服务层，无外部消费方，可接受。 |
| 收口 | `route_funnel_allows` 精确白名单单条有向边（非放宽 `Service→Service`）；兄弟服务互不依赖通则不破。 |

## 4. 备选（已否决）

- **P2（保持分层）**：泛型 `Routes<L,S>` 放 `primitives`（不引 axum，泛型 over router）+ 自写 dylint `rss_*_callsite` 守「只有 finalize_auth 能产 Authenticated」。**Medium**（不变式由 lint 而非类型承载），且污染 `primitives` public-api golden（轴 A SemVer）+ 把 funnel 逻辑覆盖率门抬到 90%（primitives ∈ STRICT）+ 多一个 dylint crate。ai-robust §审查要求「能上移编译期就必须上移，不接受『已有运行期/lint 等价物』停留」⇒ 否决（P1 是该上移路径，且无环、结构成本低）。
- **P3（bootstrap-only newtype）**：`finalize_routes` 返回 bootstrap 本地 `UnfinalizedRoutes` newtype + 单一 accessor。accessor 仍可被组合根直接调拿 Router → 非真强制（issue 自评「弱，不推荐单独落地」）。否决。

## 5. 后果

- #1113 + #1103 双不变式均 **Hard**（类型系统）：未认证 router 无法 bind、跨 listener 路由泄漏不可表达。
- 一条新 sanctioned `Service → Service` 边（受 layers 白名单 + rstest 守）。
- **无 public-api golden 漂移**：httpserve/bootstrap 属 Service 层、不在 `cargo public-api` baseline（仅 basis+engine）——P1 相对 P2 的额外收益。
- **测试专用让步**（非生产，**feature-gated Medium**）：`UnfinalizedRoutes::into_router_for_test` /
  `AuthenticatedRoutes::into_plaintext_router_for_test` /
  `routes::unfinalized_for_test` 由 `#[cfg(any(test, feature = "test-util"))]`
  门控——**生产构建（无 `test-util` feature）里编译期不存在**，故生产代码无法取裸 Router 绕过 funnel（内置 review #7
  采纳：由 doc-hidden+命名的 Soft 升为 cfg 门控的 Medium）。跨 crate 测试消费方（bootstrap/audit/bins，及 httpserve
  自身集成测试经 self dev-dep）经 dev-dependency 显式启用该 feature；workspace 测试构建经 dev-dep 启用，生产/`cargo build` 不启用。
- **assemblies/runtime launch 是下游（downstream）非前置（blocked-by）**：本 PR 交出 per-listener `AuthenticatedRoutes`；assemblies/runtime launch 将
  `into_server_service` 产物交给 `httpd`，由 adapter-private make-service 完成 socket bind/serve——funnel 的安全收益「未认证不可 bind」
  已由类型系统兑现。
- **旧 `RouteGroup` struct 退役**：接受裸 `axum::Router` 的旧 `httpserve::RouteGroup`（pre-funnel 公开面）已删除——
  与 §2.1「无 public API 交出裸 `axum::Router`」一致；其错误通道 `RouteGroupError` 保留（`finalize_auth` 返回型）。

## 6. AI-robust 评级

| 不变式 | 载体 | 档 |
|---|---|---|
| ROUTE-AUTH-FUNNEL-01/02（auth-before-bind） | 类型系统（`pub(crate)` 构造 + 无 bindable 出口 + sealed 生产者 co-located） | **Hard** |
| ROUTE-WRITE-ADMISSION-01（write gate before finalize） | typestate（消费式 `Registry → WriteAdmittedRegistry`；裸 Registry 无 finalize 方法；同次 finalization 传播同一 gate） | **Hard** |
| ROUTE-LISTENER-TYPED-01（listener 隔离） | 类型系统（typed marker + `NonPrimaryListener` 门 + typed-fold） | **Hard** |
| LAYER-DEPS-ROUTE-FUNNEL-01（受控边收口） | `xtask` layers 白名单（rstest + 端到端 check_layers 正反例 anti-vacuity） | **Medium** |

### 2026-07-11 amendment：consistency typestate（#1693）

本 ADR 在 2026-06-25 记录的单参数 `HttpRouteBinding<RouteMarker>` 保留为历史语义；现行接口已破坏式
收窄为 `HttpRouteBinding<RouteMarker, ConsistencyMarker>`。`ConsistencyMarker` 由 codegen 从 contract manifest
`consistencyLevel` 单源生成，是 sealed marker，不允许域代码替换。非 L0 endpoint 使用 `.with_state`；
L0 (`LocalOnly`) endpoint 不提供该方法，只能 stateless 或使用 `.with_classified_state` 绑定
`ReadEffect`/`AuthEffect` + `LocalPrivilege` state。这一修订不改变本 ADR 的 listener 隔离与
auth-before-bind 结论，只在同一 generated endpoint funnel 上新增 consistency/effect typestate。

## 7. 实施

见 #1113/#1103 落地 PR。改动矩阵：`crates/httpserve/src/{routes.rs(新),lib.rs}`（含**删除旧 `RouteGroup` struct** +
`test-util` feature 门控测试辅助）、`crates/httpserve/Cargo.toml`（`[features] test-util` + self dev-dep）、
`crates/bootstrap/src/registry.rs` + `Cargo.toml`（httpserve 边 + test-util dev-dep）、域 callers（identity/settings/audit
+ 各 test-util dev-dep）、`bins/{rss,server}/src/{lib.rs,auth_bridge.rs}` + `tests/auth_e2e.rs` + `Cargo.toml`（字节级同步 +
test-util dev-dep）、`xtask/src/{layers.rs,layerdeps.rs}`、`crates/httpserve/tests/{runtime.rs,funnel_trybuild.rs,ui/*}`（compile-fail
负向证据）、本 ADR + signature-freeze spec + `runtime-api.md` §RouteGroup + 上述注释修订。
