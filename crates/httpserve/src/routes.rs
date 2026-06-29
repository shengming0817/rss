//! routes — typed route lifecycle: listener-typed registration (#1103) + auth-finalize-before-bind funnel (#1113).
//!
//! 两条正交的类型层不变式收口在本模块（对标 axum `Router<S>` 用状态类型表达「缺状态不可 serve」的阶段约束。
//! ref: tokio-rs/axum axum/src/routing/mod.rs@main）：
//!
//! - **#1103 listener segregation（Medium→Hard）**：路由经 listener-typed [`ListenerRouter<L>`] 挂载，
//!   register 闭包绑定到具体 [`Listener`] marker；`mount`（无 opt-out）仅 [`NonPrimaryListener`] 可用，
//!   `mount_primary`（唯一 opt-out 入口）仅 `ListenerRouter<Primary>` 可用 ⇒ Internal/Admin/Health 路由
//!   类型层不可能落进 Primary（对外）Router，跨 listener 泄漏不可表达（typed function choice，Hard）。
//! - **#1113 auth-finalize-before-bind funnel（Hard）**：[`finalize_auth`] 是 [`AuthenticatedRoutes`] 的
//!   **唯一**生产者（构造 `pub(crate)`），[`AuthenticatedRoutes::into_make_service`] 是**唯一** bindable
//!   出口；[`UnfinalizedRoutes`] 无 public bindable 出口 ⇒ 未跑 auth 装配的 router 无法 bind。
//!
//! 与兄弟 crate `bootstrap` 的协同：`bootstrap::Registry::finalize_routes` 经受控 `bootstrap → httpserve`
//! 编译期路由类型边（ADR-009）构造 [`UnfinalizedRoutes`]，再由组合根跑 [`finalize_auth`] 产 [`AuthenticatedRoutes`]。

use crate::auth::{AuditSinkHandle, AuthAudit, enforce_layer};
use crate::{PrimaryRoute, Route, RouteGroupError};
use core::marker::PhantomData;
use primitives::{AuthPlan, ListenerKind};
use std::sync::Arc;

/// 封闭 [`Listener`] / [`NonPrimaryListener`] 实现面：外部 crate 无法命名 [`sealed::Sealed`] ⇒ 无法新增
/// listener marker（type-layer Hard seal，对齐 `vocab::contract::owner` 私有内层封闭先例）。
mod sealed {
    pub trait Sealed {}
}

/// listener 类型层 marker（sealed）。`KIND` 把 marker 落到运行期 [`ListenerKind`] 值（fold 分组键）。
pub trait Listener: sealed::Sealed {
    /// 本 marker 对应的运行期 listener 值。
    const KIND: ListenerKind;
}

/// 非-`Primary` listener marker（sealed）：`ListenerRouter::mount`（无 opt-out 路由）仅这些 listener 可用。
pub trait NonPrimaryListener: Listener {}

/// 对外业务 listener marker。
pub struct Primary;
/// 服务间控制面 listener marker。
pub struct Internal;
/// operator / 管理面 listener marker。
pub struct Admin;
/// health / ready / metrics listener marker。
pub struct Health;

impl sealed::Sealed for Primary {}
impl sealed::Sealed for Internal {}
impl sealed::Sealed for Admin {}
impl sealed::Sealed for Health {}

impl Listener for Primary {
    const KIND: ListenerKind = ListenerKind::Primary;
}
impl Listener for Internal {
    const KIND: ListenerKind = ListenerKind::Internal;
}
impl Listener for Admin {
    const KIND: ListenerKind = ListenerKind::Admin;
}
impl Listener for Health {
    const KIND: ListenerKind = ListenerKind::Health;
}

impl NonPrimaryListener for Internal {}
impl NonPrimaryListener for Admin {}
impl NonPrimaryListener for Health {}

/// register 闭包内构建本组路由的 listener-typed builder（`route_group::<L>` 注入）。
///
/// INVARIANT: ROUTE-LISTENER-TYPED-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— 路由经本 builder 挂载、随组 fold 进 `L::KIND` listener 的
/// Router；Internal/Admin/Health 路由类型层不可能进 Primary Router（取代 SEGREGATION-01 Medium runtime
/// 守，#1103 Medium→Hard）。`mount_primary`（opt-out）仅 `L = Primary`、`mount`（无 opt-out）仅
/// `L: NonPrimaryListener` —— 与 AUTH-OPTOUT-PRIMARYONLY-01 在 listener 维度对齐。
#[must_use = "ListenerRouter 须返回给 route_group register 闭包（否则路由未挂载）"]
pub struct ListenerRouter<L: Listener> {
    inner: axum::Router,
    _l: PhantomData<fn() -> L>,
}

impl<L: Listener> ListenerRouter<L> {
    /// 在 fresh `axum::Router` 上起一个 listener-typed builder。**`pub(crate)`**：外部 crate 无法构造——
    /// 域 crate 只在 `route_group` register 闭包里**收到** builder，仅能 `mount`/`mount_primary`（无
    /// raw-bypass）。构造与裸 Router erase 只发生在 httpserve 内（[`UnfinalizedRoutes::nest_group`]），
    /// 故无任何 public API 交出可 bind 的裸 `axum::Router`（#1103/#1113 Hard 闭环）。
    pub(crate) fn new(router: axum::Router) -> Self {
        Self {
            inner: router,
            _l: PhantomData,
        }
    }

    /// 交还累积的裸 `axum::Router`（仅 httpserve 内 erase 边界用，`pub(crate)`）。
    pub(crate) fn into_inner(self) -> axum::Router {
        self.inner
    }
}

impl<L: NonPrimaryListener> ListenerRouter<L> {
    /// 挂载非-`Primary` [`Route`]（无 opt-out；`resolve_requirement` 恒收 `None`）。对标 axum `Router::route`。
    pub fn mount(self, route: Route, handler: axum::routing::MethodRouter) -> Self {
        Self {
            inner: self.inner.route(
                route.path,
                handler.layer(enforce_layer(None, route.method, route.contract_id)),
            ),
            _l: PhantomData,
        }
    }
}

impl ListenerRouter<Primary> {
    /// 挂载 `Primary` [`PrimaryRoute`]——**唯一**接受 auth opt-out 的入口（AUTH-OPTOUT-PRIMARYONLY-01）。
    pub fn mount_primary(self, route: PrimaryRoute, handler: axum::routing::MethodRouter) -> Self {
        Self {
            inner: self.inner.route(
                route.path,
                handler.layer(enforce_layer(
                    route.opt_out,
                    route.method,
                    route.contract_id,
                )),
            ),
            _l: PhantomData,
        }
    }
}

/// 单 listener 的 per-listener Router，**未** auth-finalize（#1113 funnel 入态），兼作 finalize 折叠的
/// per-listener **累加器**。
///
/// INVARIANT: ROUTE-AUTH-FUNNEL-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }—— 无 public bindable 出口（无 `into_make_service`）；唯一前进路径是
/// [`finalize_auth`]（同 crate 读私有字段）换 [`AuthenticatedRoutes`] ⇒ 未跑 auth 装配的 router 无法 bind。
/// 经 [`empty`](Self::empty) + [`nest_group`](Self::nest_group) 累加（裸 `axum::Router` 不出 httpserve），
/// 由 `bootstrap::finalize_routes` 经受控 `bootstrap → httpserve` 边驱动（ADR-009）。
#[must_use = "UnfinalizedRoutes 须经 finalize_auth 换 AuthenticatedRoutes 才能 bind"]
pub struct UnfinalizedRoutes {
    router: axum::Router,
}

impl UnfinalizedRoutes {
    /// 起一个空的 per-listener 累加器（bootstrap finalize 每 listener 一个）。
    pub fn empty() -> Self {
        Self {
            router: axum::Router::new(),
        }
    }

    /// 跑 register 闭包构建本组路由（listener-typed [`ListenerRouter<L>`]），nest 到本累加器的 `prefix` 下。
    ///
    /// 裸 `axum::Router` 全程不出 httpserve（`ListenerRouter::{new, into_inner}` 均 `pub(crate)`）——域 crate
    /// 只能经收到的 builder 的 typed `mount`/`mount_primary`，无法 raw-bypass（#1103 Medium→Hard）；产物仍是
    /// `UnfinalizedRoutes`（无 bindable 出口，#1113）。register 闭包 `Err` 原样冒泡（保留 bootstrap `KernelError` 变体）。
    pub fn nest_group<L, E>(
        self,
        prefix: &str,
        register: impl FnOnce(ListenerRouter<L>) -> Result<ListenerRouter<L>, E>,
    ) -> Result<Self, E>
    where
        L: Listener,
    {
        let group = register(ListenerRouter::<L>::new(axum::Router::new()))?.into_inner();
        Ok(Self {
            router: self.router.nest(prefix, group),
        })
    }

    /// 测试专用：取回裸 Router 做 `tower::ServiceExt::oneshot` listener 隔离断言。
    ///
    /// **`cfg(any(test, feature = "test-util"))` 门控（Medium）**：生产构建（无 `test-util` feature）里本入口
    /// **编译期不存在**——故不削弱 ROUTE-AUTH-FUNNEL-01（生产无 public bindable 出口）。跨 crate 测试消费方
    /// （bootstrap/audit/bins/httpserve 自身集成测试）经 dev-dependency 显式启用 `httpserve` 的 `test-util` feature。
    #[cfg(any(test, feature = "test-util"))]
    pub fn into_router_for_test(self) -> axum::Router {
        self.router
    }
}

/// auth-finalize 后的 per-listener Router（#1113 funnel 出态，可 bind）。
///
/// INVARIANT: ROUTE-AUTH-FUNNEL-02 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }—— 唯一生产者 = [`finalize_auth`]（构造 `pub(crate)`，外部 crate 无法
/// mint）；[`into_make_service`](Self::into_make_service) 是唯一 bindable 出口。验签桥（#1109）经
/// [`layer`](Self::layer) 叠在外层、保持封印（产物仍是 `AuthenticatedRoutes`，只能加层不能替换）。
///
/// INVARIANT: BODYLIMIT-BEFORE-AUTH-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— body-limit **层**（CL 闸 + Limited wrap）叠在
/// [`sealed_router`](Self::sealed_router) 唯一 funnel ⇒ 每个 bindable router 必带且必 outer 于 auth：
/// CL-declared 超限 → before-auth clean 413；无声明/chunked → Limited read-time 字节硬顶（内存有界，
/// 未认证请求经 enforce 401 时 body 从不被读，无 pre-auth buffer）。详见 middleware.rs body_limit 注释。
#[must_use = "AuthenticatedRoutes 须经 into_make_service bind（否则 router 未 serve）"]
pub struct AuthenticatedRoutes {
    router: axum::Router,
    hardening: crate::protect::EdgeHardening,
}

impl AuthenticatedRoutes {
    /// 唯一生产入口（`pub(crate)`）——仅 [`finalize_auth`] 可构造，外部 crate 无法 mint（ROUTE-AUTH-FUNNEL-02）。
    pub(crate) fn new(router: axum::Router) -> Self {
        Self {
            router,
            hardening: crate::protect::EdgeHardening::default(),
        }
    }

    /// 覆盖边缘防护配置（body-limit + security-headers）。
    ///
    /// 组合根在 `finalize_auth` 产物上调用，覆盖默认的 [`crate::protect::EdgeHardening`] 值
    /// （如调整 body 上限或关闭 HSTS）。`sealed_router` 将使用更新后的配置叠层。
    pub fn with_edge_hardening(mut self, hardening: crate::protect::EdgeHardening) -> Self {
        self.hardening = hardening;
        self
    }

    /// 在已认证 router **外层**叠中间件（验签桥 #1109 的请求方向先于 `EnforceService`）。
    ///
    /// 镜像 axum `Router::layer` 的约束——只能**加层**、不能替换 router，故 funnel 封印不破（产物仍 `AuthenticatedRoutes`）。
    pub fn layer<L>(self, layer: L) -> Self
    where
        L: tower::Layer<axum::routing::Route> + Clone + Send + Sync + 'static,
        L::Service: tower::Service<axum::extract::Request> + Clone + Send + Sync + 'static,
        <L::Service as tower::Service<axum::extract::Request>>::Response:
            axum::response::IntoResponse + 'static,
        <L::Service as tower::Service<axum::extract::Request>>::Error:
            Into<core::convert::Infallible> + 'static,
        <L::Service as tower::Service<axum::extract::Request>>::Future: Send + 'static,
    {
        Self {
            router: self.router.layer(layer),
            hardening: self.hardening,
        }
    }

    /// 在唯一 bindable 出口封全局防护中间件链（请求 ID + correlation + security-headers + body-limit）。
    ///
    /// INVARIANT: ROUTE-REQUESTID-OUTERMOST-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— `request_id` **不**在 [`finalize_auth`] 内挂（那会被组合根
    /// 后叠的验签桥包到内层 ⇒ 桥运行时读不到 `RequestId`，#1109 NOTE / #1320）；改由本出口统一注入 ⇒ 每个被
    /// bind 的 router 都带 request_id 且**不可遗漏**（can't-forget funnel）。
    ///
    /// INVARIANT: ROUTE-CORRELATION-INNER-REQUESTID-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— `correlation` 封在 `request_id` 内侧、验签桥外侧：
    ///   · `request_id` 先行（外层）确保 `RequestId` extension 在场，`correlation` 可读回作回退值；
    ///   · `diagctx::scope` 包住验签桥 + handler + application + adapter emit ⇒ outbox emit 可经
    ///     [`diagctx::correlation`] 读回 correlation id（ADR-002 §D1-bis）。
    ///
    /// INVARIANT: BODYLIMIT-BEFORE-AUTH-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— body-limit **层**（CL 闸 + Limited wrap）outer 于 auth 验签桥：
    ///   · **CL-declared 超限 → before-auth clean 413（`ERR_CORE_PAYLOAD_TOO_LARGE`）**：层1 CL fast-reject
    ///     在验签桥前拒，无 auth 开销；
    ///   · **无声明/chunked → `http_body_util::Limited` 字节硬顶（read-time，内存有界）**：未认证请求经
    ///     enforce 401 时 body 从不被读 ⇒ 无 pre-auth buffer（DoS 优姿态；见 middleware.rs body_limit reason）。
    ///   CL 路径的**拒绝决策** before-auth；无 CL 路径的 cap 由 Limited read-time 实施，非 before-auth 413。
    /// 结构性 Hard：唯一 bindable 出口经本 funnel 封层，不可遗漏。security-headers outer 于 body-limit（所有响应
    /// 含 413 均追加安全头）。
    ///
    /// 层序（外→内）：`request_id` → `correlation` → security-headers → body-limit → 验签桥
    /// → listener trace policy（Health 无 `trace`）→ `panic_recovery` → `Extension(plan)` → enforce → handler。
    ///
    /// 生产出口 [`into_make_service`](Self::into_make_service) 与 test 出口
    /// [`into_router_for_test`](Self::into_router_for_test) 共用本 fn ⇒ 层序一致（test 不漂移）。
    fn sealed_router(self) -> axum::Router {
        // `.layer` 调用顺序 = 内→外；最后 `.layer(request_id)` 使其成为绝对最外层。

        // 1. body-limit（最内层新防护，outer 于验签桥）。
        let mut router = self.router.layer(axum::middleware::from_fn_with_state(
            self.hardening.body_limit,
            crate::middleware::body_limit,
        ));

        // 2. security-headers（outer 于 body-limit；所有响应包含安全头）。
        for hl in self.hardening.headers.response_layers() {
            router = router.layer(hl);
        }

        // 3. correlation + request_id（绝对最外两层）。
        router
            .layer(axum::middleware::from_fn(crate::middleware::correlation))
            .layer(axum::middleware::from_fn(crate::middleware::request_id))
    }

    /// **唯一** bindable 出口：封防护层（[`sealed_router`](Self::sealed_router)）后转 axum
    /// `IntoMakeServiceWithConnectInfo`（bind 时注入 `ConnectInfo<SocketAddr>`，供 rate_limit
    /// 中间件读 peer IP；天生只能消费已认证 router，ROUTE-AUTH-FUNNEL-02）。
    pub fn into_make_service(
        self,
    ) -> axum::extract::connect_info::IntoMakeServiceWithConnectInfo<
        axum::Router,
        std::net::SocketAddr,
    > {
        self.sealed_router()
            .into_make_service_with_connect_info::<std::net::SocketAddr>()
    }

    /// 测试专用：取回裸 Router 做 `oneshot` e2e 断言（经 [`sealed_router`](Self::sealed_router) ⇒ 与生产
    /// `into_make_service` 同层序，含 request_id 最外层）。**`cfg(any(test, feature = "test-util"))` 门控（Medium）**——
    /// 生产构建里编译期不存在，不削弱 ROUTE-AUTH-FUNNEL-02（生产唯一 bindable 出口仍是 `into_make_service`）。
    #[cfg(any(test, feature = "test-util"))]
    pub fn into_router_for_test(self) -> axum::Router {
        self.sealed_router()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TracePolicy {
    Enabled,
    Disabled,
}

impl TracePolicy {
    /// 从 listener auth plan 派生 trace 策略。Health listener 是高频 probe/scrape 面，禁用
    /// `http.request` span；未知未来 listener fail-closed 为 Enabled，避免静默丢可观测性。
    fn from_plan(plan: AuthPlan) -> Self {
        match plan.listener() {
            ListenerKind::Health => Self::Disabled,
            ListenerKind::Primary | ListenerKind::Internal | ListenerKind::Admin => Self::Enabled,
            _ => Self::Enabled,
        }
    }
}

/// 所有 route 注册完成后装配 auth enforcement（plan 由组合根注入，本函数不构造 `AuthPlan`）。
///
/// #1113 funnel transform：消费 [`UnfinalizedRoutes`] 产 [`AuthenticatedRoutes`]——本 fn 是后者**唯一**
/// 生产者（ROUTE-AUTH-FUNNEL-02）。业务不得绕过最终 matcher（runtime-api.md）。
///
/// 层序（`.layer` 调用顺序 = 内→外）：`Extension(plan)`（最内，EnforceService 读 plan）→ `panic_recovery`
/// （request-aware panic → 500 envelope）→ listener 派生 `trace`（Health listener 禁用；其余 listener 启用）。
/// `request_id` / `correlation` **不**在此挂——二者均由唯一 bindable 出口
/// [`AuthenticatedRoutes::sealed_router`] 封为最外两层（ROUTE-REQUESTID-OUTERMOST-01 /
/// ROUTE-CORRELATION-INNER-REQUESTID-01 / #1320）。完整请求流（外→内）：`request_id` → `correlation` →
/// 验签桥 → listener trace（Health 无）→ `panic_recovery` → `Extension(plan)` → 路由匹配 → `EnforceService`
/// → handler。
///
/// 验签桥（#1109）经 [`AuthenticatedRoutes::layer`] 叠在 `finalize_auth` 产物的**外层**（请求方向先于
/// `EnforceService`），其注入的 [`Authenticated`](crate::Authenticated) 证据在 enforce 读取前就位；request_id
/// 再外封一层（见上）。当前恒 `Ok`——`RouteGroupError` 变体留给扩展点（签名冻结保留）。
pub fn finalize_auth(
    routes: UnfinalizedRoutes,
    plan: AuthPlan,
) -> Result<AuthenticatedRoutes, RouteGroupError> {
    finalize_auth_inner(routes, plan, None)
}

/// #1113 funnel transform with auth decision audit sink.
///
/// The sink records final enforce decisions. Missing authenticated evidence is not audited because no trusted tenant can
/// be derived without the verify bridge.
pub fn finalize_auth_with_audit(
    routes: UnfinalizedRoutes,
    plan: AuthPlan,
    audit_sink: AuditSinkHandle,
    clock: Arc<dyn diport::Clock>,
) -> Result<AuthenticatedRoutes, RouteGroupError> {
    finalize_auth_inner(routes, plan, Some(AuthAudit::new(audit_sink, clock)))
}

fn finalize_auth_inner(
    routes: UnfinalizedRoutes,
    plan: AuthPlan,
    audit: Option<AuthAudit>,
) -> Result<AuthenticatedRoutes, RouteGroupError> {
    let trace_policy = TracePolicy::from_plan(plan);
    let mut router = routes.router.layer(axum::Extension(plan));
    if let Some(audit) = audit {
        router = router.layer(axum::Extension(audit));
    }
    let router = router.layer(axum::middleware::from_fn(crate::middleware::panic_recovery));
    let router = match trace_policy {
        TracePolicy::Enabled => router.layer(axum::middleware::from_fn(crate::middleware::trace)),
        TracePolicy::Disabled => router,
    };
    Ok(AuthenticatedRoutes::new(router))
}

/// 测试专用：跑一个 listener-typed register 闭包，产出单组 [`UnfinalizedRoutes`]（直接挂载，**不** nest
/// prefix——测试路径即完整路径）。供 httpserve **外**的 funnel e2e 测试（bins `auth_e2e`）构造 funnel 输入——
/// 它们无法直接构造 `pub(crate)` 的 [`ListenerRouter`]。生产路径经 `bootstrap::Registry::route_group` +
/// `finalize_routes` 构造。
///
/// **`cfg(any(test, feature = "test-util"))` 门控（Medium）**：生产构建里编译期不存在，不削弱封印——产物是
/// [`UnfinalizedRoutes`]（无 bindable 出口，ROUTE-AUTH-FUNNEL-01），且 routes 仍经 typed `ListenerRouter<L>`
/// 挂载（ROUTE-LISTENER-TYPED-01）。
#[cfg(any(test, feature = "test-util"))]
pub fn unfinalized_for_test<L: Listener>(
    build: impl FnOnce(ListenerRouter<L>) -> ListenerRouter<L>,
) -> UnfinalizedRoutes {
    UnfinalizedRoutes {
        router: build(ListenerRouter::<L>::new(axum::Router::new())).into_inner(),
    }
}

#[cfg(test)]
mod tests {
    //! routes funnel 行为单测：typed listener marker（KIND 落值）+ funnel 三态（empty/nest_group →
    //! UnfinalizedRoutes → finalize_auth → AuthenticatedRoutes）round-trip serve + `layer` 保封印 +
    //! `into_make_service` bindable 出口存在。compile-fail 负向证据（不可绕过）见 `tests/ui/`。
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::routing::get;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt as _;

    // 测试断言用 expect/unwrap：item-level carve-out（error-handling.md §Carve-out）。
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    async fn oneshot_status(router: axum::Router, uri: &str) -> StatusCode {
        let req = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request");
        router.oneshot(req).await.expect("oneshot").status()
    }

    fn admin_route() -> Route {
        Route {
            method: Method::GET,
            path: "/list",
            contract_id: "test.admin.list",
        }
    }

    #[derive(Clone, Debug)]
    struct CapturedSpan {
        name: &'static str,
        fields: HashMap<String, String>,
    }

    #[derive(Default)]
    struct CapturedSpans {
        spans: Mutex<Vec<CapturedSpan>>,
    }

    impl CapturedSpans {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        #[allow(clippy::expect_used)]
        fn snapshot(&self) -> Vec<CapturedSpan> {
            self.spans.lock().expect("capture lock").clone()
        }
    }

    struct SpanVisit {
        fields: HashMap<String, String>,
    }

    impl tracing::field::Visit for SpanVisit {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.fields
                .insert(field.name().to_string(), format!("{value:?}"));
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }
    }

    struct SpanCapture {
        captured: Arc<CapturedSpans>,
    }

    impl tracing::Subscriber for SpanCapture {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        #[allow(clippy::expect_used)]
        fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::Id {
            let mut visitor = SpanVisit {
                fields: HashMap::new(),
            };
            attrs.record(&mut visitor);
            let mut spans = self.captured.spans.lock().expect("capture lock");
            let id = u64::try_from(spans.len() + 1).unwrap_or(u64::MAX);
            spans.push(CapturedSpan {
                name: attrs.metadata().name(),
                fields: visitor.fields,
            });
            tracing::Id::from_u64(id)
        }

        #[allow(clippy::expect_used)]
        fn record(&self, span: &tracing::Id, values: &tracing::span::Record<'_>) {
            let mut visitor = SpanVisit {
                fields: HashMap::new(),
            };
            values.record(&mut visitor);
            let idx = usize::try_from(span.into_u64())
                .expect("span id fits usize")
                .saturating_sub(1);
            let mut spans = self.captured.spans.lock().expect("capture lock");
            if let Some(existing) = spans.get_mut(idx) {
                existing.fields.extend(visitor.fields);
            }
        }

        fn record_follows_from(&self, _span: &tracing::Id, _follows: &tracing::Id) {}
        fn enter(&self, _span: &tracing::Id) {}
        fn exit(&self, _span: &tracing::Id) {}
        fn event(&self, _event: &tracing::Event<'_>) {}
    }

    #[allow(clippy::expect_used)]
    fn run_with_span_capture<R>(f: impl FnOnce() -> R) -> (R, Vec<CapturedSpan>) {
        let captured = CapturedSpans::new();
        let subscriber = SpanCapture {
            captured: Arc::clone(&captured),
        };
        let dispatch = tracing::Dispatch::new(subscriber);
        let result = tracing::dispatcher::with_default(&dispatch, f);
        (result, captured.snapshot())
    }

    #[test]
    fn listener_kind_maps_marker_to_value() {
        assert_eq!(Primary::KIND, ListenerKind::Primary);
        assert_eq!(Internal::KIND, ListenerKind::Internal);
        assert_eq!(Admin::KIND, ListenerKind::Admin);
        assert_eq!(Health::KIND, ListenerKind::Health);
    }

    #[test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    fn primary_listener_emits_http_request_span_fields() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let (_, spans) = run_with_span_capture(|| {
            rt.block_on(async {
                let routes = UnfinalizedRoutes::empty()
                    .nest_group::<Primary, core::convert::Infallible>("/api/v1", |rb| {
                        Ok(rb.mount_primary(
                            PrimaryRoute {
                                method: Method::GET,
                                path: "/x",
                                contract_id: "test.primary.x",
                                opt_out: Some(primitives::RouteAuthOptOut::Public),
                            },
                            get(|| async { "ok" }),
                        ))
                    })
                    .expect("nest ok");
                let plan =
                    primitives::AuthPlan::new(ListenerKind::Primary, primitives::AuthScheme::Jwt)
                        .expect("plan");
                let router = finalize_auth(routes, plan)
                    .expect("finalize_auth")
                    .into_router_for_test();
                let req = Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/x")
                    .header("x-request-id", "rid-span-1")
                    .header("x-correlation-id", "corr-span-1")
                    .body(Body::empty())
                    .expect("request");
                let resp = router.oneshot(req).await.expect("oneshot");
                assert_eq!(resp.status(), StatusCode::OK);
            });
        });
        let http_spans: Vec<_> = spans
            .iter()
            .filter(|span| span.name == "http.request")
            .collect();
        assert_eq!(http_spans.len(), 1, "Primary request emits one span");
        let fields = &http_spans[0].fields;
        assert_eq!(fields.get("method").map(String::as_str), Some("GET"));
        assert_eq!(fields.get("path").map(String::as_str), Some("/api/v1/x"));
        assert_eq!(
            fields.get("request_id").map(String::as_str),
            Some("rid-span-1")
        );
        assert_eq!(
            fields.get("correlation").map(String::as_str),
            Some("corr-span-1")
        );
        assert_eq!(fields.get("status").map(String::as_str), Some("200"));
    }

    #[test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    fn health_listener_serves_probe_routes_without_http_request_spans() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let (_, spans) = run_with_span_capture(|| {
            rt.block_on(async {
                let routes = UnfinalizedRoutes::empty()
                    .nest_group::<Health, core::convert::Infallible>("/health/v1", |rb| {
                        Ok(rb
                            .mount(
                                Route {
                                    method: Method::GET,
                                    path: "/healthz",
                                    contract_id: "framework.healthz",
                                },
                                crate::health::healthz(),
                            )
                            .mount(
                                Route {
                                    method: Method::GET,
                                    path: "/readyz",
                                    contract_id: "framework.readyz",
                                },
                                crate::health::readyz(|| {
                                    primitives::HealthReport::aggregate(vec![
                                        primitives::HealthCheck::new(
                                            primitives::ProbeName::parse("db").expect("probe"),
                                            primitives::HealthStatus::Healthy,
                                            "ok",
                                        ),
                                    ])
                                }),
                            )
                            .mount(
                                Route {
                                    method: Method::GET,
                                    path: "/metrics",
                                    contract_id: "framework.metrics",
                                },
                                crate::health::metrics(|| String::from("# HELP test_metric\n")),
                            ))
                    })
                    .expect("nest ok");
                let plan =
                    primitives::AuthPlan::new(ListenerKind::Health, primitives::AuthScheme::NoAuth)
                        .expect("plan");
                let router = finalize_auth(routes, plan)
                    .expect("finalize_auth")
                    .into_router_for_test();
                for path in [
                    "/health/v1/healthz",
                    "/health/v1/readyz",
                    "/health/v1/metrics",
                ] {
                    let resp = router
                        .clone()
                        .oneshot(
                            Request::builder()
                                .method(Method::GET)
                                .uri(path)
                                .header("x-request-id", "rid-health")
                                .body(Body::empty())
                                .expect("request"),
                        )
                        .await
                        .expect("oneshot");
                    assert_eq!(resp.status(), StatusCode::OK, "{path}");
                }
            });
        });
        assert!(
            spans.iter().all(|span| span.name != "http.request"),
            "Health listener should not emit http.request spans: {spans:?}"
        );
    }

    /// funnel round-trip：`unfinalized_for_test` → `finalize_auth` → `AuthenticatedRoutes` → 取回裸 Router
    /// oneshot。挂载路径 matched（enforce 无证据 fail-closed 403，非 404）；未挂载路径 404。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn finalize_auth_round_trip_serves_mounted_route() {
        let routes =
            unfinalized_for_test::<Admin>(|rb| rb.mount(admin_route(), get(|| async { "ok" })));
        let plan = primitives::AuthPlan::new(ListenerKind::Admin, primitives::AuthScheme::Jwt)
            .expect("plan");
        let authed = finalize_auth(routes, plan).expect("finalize_auth");
        let router = authed.into_router_for_test();

        // 强断言精确 fail-closed 码（非弱 `assert_ne!(404)`）：matched + finalize_auth 注入 Jwt plan →
        // Require(Jwt) + 无 Authenticated 证据 → 401（AUTH-EVIDENCE-REQUIRE-01）。若 enforce 失效（误放行 200）
        // 或路由未挂（404）测试即红——锁住 funnel 产出的 router 确实经 enforce。
        assert_eq!(
            oneshot_status(router.clone(), "/list").await,
            StatusCode::UNAUTHORIZED,
            "挂载路径 matched + Require(Jwt) 无证据 → fail-closed 401"
        );
        assert_eq!(
            oneshot_status(router, "/absent").await,
            StatusCode::NOT_FOUND,
            "未挂载路径 404"
        );
    }

    /// `nest_group` 把组路由挂到声明 prefix 下（empty 累加器 → 完整路径命中、裸相对路径 404）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn nest_group_mounts_under_prefix() {
        let routes = UnfinalizedRoutes::empty()
            .nest_group::<Admin, core::convert::Infallible>("/api/v1/audit", |rb| {
                Ok(rb.mount(admin_route(), get(|| async { "ok" })))
            })
            .expect("nest ok");
        let plan = primitives::AuthPlan::new(ListenerKind::Admin, primitives::AuthScheme::Jwt)
            .expect("plan");
        let router = finalize_auth(routes, plan)
            .expect("finalize_auth")
            .into_router_for_test();

        assert_eq!(
            oneshot_status(router.clone(), "/api/v1/audit/list").await,
            StatusCode::UNAUTHORIZED,
            "完整 prefix 路径 matched + Require(Jwt) 无证据 → 401"
        );
        assert_eq!(
            oneshot_status(router, "/list").await,
            StatusCode::NOT_FOUND,
            "裸相对路径 404（prefix 参与挂载）"
        );
    }

    /// `AuthenticatedRoutes::layer` 保封印：叠一层透传中间件后产物仍是 `AuthenticatedRoutes` 且仍可 serve。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn layer_preserves_authenticated_and_serves() {
        let routes =
            unfinalized_for_test::<Admin>(|rb| rb.mount(admin_route(), get(|| async { "ok" })));
        let plan = primitives::AuthPlan::new(ListenerKind::Admin, primitives::AuthScheme::Jwt)
            .expect("plan");
        let authed: AuthenticatedRoutes = finalize_auth(routes, plan)
            .expect("finalize_auth")
            .layer(axum::middleware::from_fn(
                |req: axum::extract::Request, next: axum::middleware::Next| async move {
                    next.run(req).await
                },
            ));
        // 仍是 AuthenticatedRoutes（类型已断言），且 into_make_service bindable 出口可构造 + 仍 serve。
        {
            let r = authed.into_router_for_test();
            assert_eq!(
                oneshot_status(r, "/list").await,
                StatusCode::UNAUTHORIZED,
                "叠透传层后仍 matched + Require(Jwt) 无证据 → 401（层不注证据）"
            );
        }
    }

    /// `into_make_service` 是 bindable 出口（仅 `AuthenticatedRoutes` 有，#1017 bind 点消费）——可构造即证存在。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn authenticated_routes_into_make_service_available() {
        let routes = unfinalized_for_test::<Health>(|rb| rb.mount(admin_route(), get(|| async {})));
        let plan = primitives::AuthPlan::new(ListenerKind::Health, primitives::AuthScheme::NoAuth)
            .expect("plan");
        let authed = finalize_auth(routes, plan).expect("finalize_auth");
        let _make_service = authed.into_make_service();
    }

    /// 取回完整 Response（不仅 status）做 header 断言（request_id 封口验证）。
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    async fn oneshot_response(router: axum::Router, uri: &str) -> axum::response::Response {
        let req = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request");
        router.oneshot(req).await.expect("oneshot")
    }

    /// ROUTE-REQUESTID-OUTERMOST-01：`request_id` 不在 `finalize_auth` 内挂，但 bindable 出口
    /// （`sealed_router`，test 经 `into_router_for_test` 同路径）仍封它 ⇒ 响应带 `x-request-id`。
    /// NoAuth listener 取 200 路径（避免 enforce 401 干扰，纯验出口封口）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn request_id_sealed_at_bindable_exit() {
        let routes =
            unfinalized_for_test::<Health>(|rb| rb.mount(admin_route(), get(|| async { "ok" })));
        let plan = primitives::AuthPlan::new(ListenerKind::Health, primitives::AuthScheme::NoAuth)
            .expect("plan");
        let router = finalize_auth(routes, plan)
            .expect("finalize_auth")
            .into_router_for_test();
        let resp = oneshot_response(router, "/list").await;
        assert_eq!(resp.status(), StatusCode::OK, "NoAuth matched → 200");
        let rid = resp
            .headers()
            .get("x-request-id")
            .expect("出口 sealed_router 须封 request_id（即便 finalize_auth 未挂）");
        assert!(!rid.is_empty(), "x-request-id 非空");
    }

    /// ROUTE-REQUESTID-OUTERMOST-01：request_id 在组合根后叠的**外层**（验签桥位）**之前**运行 ⇒ 该外层
    /// 中间件运行时已能读到 `RequestId` extension（落实「桥可读 requestId」）。用一个验签桥位的探针层断言
    /// extension 在场，命中即回写 `x-saw-rid: 1`。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn request_id_visible_to_outer_bridge_layer() {
        let routes =
            unfinalized_for_test::<Health>(|rb| rb.mount(admin_route(), get(|| async { "ok" })));
        let plan = primitives::AuthPlan::new(ListenerKind::Health, primitives::AuthScheme::NoAuth)
            .expect("plan");
        // 探针层模拟验签桥（经 AuthenticatedRoutes::layer 叠在 finalize_auth 外、request_id 内）：
        // 读 RequestId extension，在场则回写 marker header。
        let probed =
            finalize_auth(routes, plan)
                .expect("finalize_auth")
                .layer(axum::middleware::from_fn(
                    |req: axum::extract::Request, next: axum::middleware::Next| async move {
                        let saw = req
                            .extensions()
                            .get::<crate::middleware::RequestId>()
                            .is_some();
                        let mut resp = next.run(req).await;
                        if saw {
                            resp.headers_mut()
                                .insert("x-saw-rid", axum::http::HeaderValue::from_static("1"));
                        }
                        resp
                    },
                ));
        let resp = oneshot_response(probed.into_router_for_test(), "/list").await;
        assert_eq!(
            resp.headers().get("x-saw-rid").map(|v| v.as_bytes()),
            Some(&b"1"[..]),
            "外层（验签桥位）中间件运行时 RequestId 须在场（request_id 已外封先行运行）"
        );
    }

    /// `request_id_str` accessor：从 extension 读 request id（在场 → `Some`，不在场 → `None`），
    /// 不暴露 `RequestId` newtype（供验签桥等组合根外层中间件读关联 id）。
    #[test]
    fn request_id_str_reads_from_extensions() {
        let mut ext = axum::http::Extensions::new();
        assert_eq!(crate::request_id_str(&ext), None, "无 RequestId → None");
        ext.insert(crate::middleware::RequestId("test-rid".to_owned()));
        assert_eq!(
            crate::request_id_str(&ext),
            Some("test-rid"),
            "在场 → Some(借出字符串)"
        );
    }

    // ── edge hardening 集成测试（经 sealed_router / into_router_for_test funnel）─────────────────

    /// security-headers 通过 sealed_router funnel 叠在所有响应上（200 路径）。
    /// 验证 `x-content-type-options: nosniff` 等默认安全头存在且值正确。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn security_headers_present_in_successful_response() {
        let routes =
            unfinalized_for_test::<Health>(|rb| rb.mount(admin_route(), get(|| async { "ok" })));
        let plan = primitives::AuthPlan::new(ListenerKind::Health, primitives::AuthScheme::NoAuth)
            .expect("plan");
        let router = finalize_auth(routes, plan)
            .expect("finalize_auth")
            .into_router_for_test();

        let resp = oneshot_response(router, "/list").await;
        assert_eq!(resp.status(), StatusCode::OK, "NoAuth → 200");

        // 各安全头存在且值正确。
        let headers = resp.headers();
        assert_eq!(
            headers
                .get("x-content-type-options")
                .expect("x-content-type-options")
                .as_bytes(),
            b"nosniff"
        );
        assert_eq!(
            headers
                .get("x-frame-options")
                .expect("x-frame-options")
                .as_bytes(),
            b"DENY"
        );
        assert_eq!(
            headers
                .get("referrer-policy")
                .expect("referrer-policy")
                .as_bytes(),
            b"no-referrer"
        );
        assert_eq!(
            headers
                .get("cross-origin-resource-policy")
                .expect("corp")
                .as_bytes(),
            b"same-origin"
        );
        assert!(
            headers.get("strict-transport-security").is_some(),
            "HSTS 默认开启"
        );
        assert!(
            headers.get("cache-control").is_some(),
            "cache-control 默认注入"
        );
    }

    /// body-limit 超出 Content-Length 门限时返回 413，经 sealed_router funnel 有效（#1106）。
    /// 使用 with_edge_hardening 设小上限（10 bytes）验证 funnel 叠层生效。
    #[tokio::test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    // reason: test helper — NonZeroUsize::new(10) is known non-zero, unwrap is infallible.
    async fn body_limit_via_sealed_router_returns_413_on_oversized_cl() {
        let routes =
            unfinalized_for_test::<Health>(|rb| rb.mount(admin_route(), get(|| async { "ok" })));
        let plan = primitives::AuthPlan::new(ListenerKind::Health, primitives::AuthScheme::NoAuth)
            .expect("plan");
        let router = finalize_auth(routes, plan)
            .expect("finalize_auth")
            .with_edge_hardening(crate::protect::EdgeHardening {
                body_limit: crate::protect::BodyLimit::new(
                    std::num::NonZeroUsize::new(10).unwrap(),
                ),
                headers: crate::protect::SecurityHeaders::default(),
            })
            .into_router_for_test();

        // Content-Length: 11 > 10 → 413
        let req = Request::builder()
            .uri("/list")
            .header("content-length", "11")
            .body(Body::empty())
            .expect("request");
        let resp = router.clone().oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE, "CL>cap → 413");

        // Content-Length: 10 ≤ 10 → 200（NoAuth）
        let req_ok = Request::builder()
            .uri("/list")
            .header("content-length", "10")
            .body(Body::empty())
            .expect("request");
        let resp_ok = router.oneshot(req_ok).await.expect("oneshot");
        assert_eq!(resp_ok.status(), StatusCode::OK, "CL==cap → 200");
    }

    /// FIX-5：security-headers 叠在 body-limit 外侧 → 413 错误响应也包含安全头。
    ///
    /// 证 security-headers outer 于 body-limit（layer 叠加顺序：security-headers 在 body-limit 外层），
    /// 所有响应（含 413 拒绝路径）均追加安全头。复用 body-limit 413 setup + 追加安全头断言。
    #[tokio::test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    // reason: test helper — NonZeroUsize::new(10) is known non-zero, unwrap is infallible.
    async fn security_headers_present_in_413_error_response() {
        let routes =
            unfinalized_for_test::<Health>(|rb| rb.mount(admin_route(), get(|| async { "ok" })));
        let plan = primitives::AuthPlan::new(ListenerKind::Health, primitives::AuthScheme::NoAuth)
            .expect("plan");
        let router = finalize_auth(routes, plan)
            .expect("finalize_auth")
            .with_edge_hardening(crate::protect::EdgeHardening {
                body_limit: crate::protect::BodyLimit::new(
                    std::num::NonZeroUsize::new(10).unwrap(),
                ),
                headers: crate::protect::SecurityHeaders::default(),
            })
            .into_router_for_test();

        // Content-Length: 11 > 10 → 413（CL fast-reject）。
        let req = Request::builder()
            .uri("/list")
            .header("content-length", "11")
            .body(Body::empty())
            .expect("request");
        let resp = router.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE, "CL>cap → 413");

        // 413 响应也必须有安全头（security-headers outer 于 body-limit）。
        let headers = resp.headers();
        assert_eq!(
            headers
                .get("x-content-type-options")
                .expect("413 须有 x-content-type-options")
                .as_bytes(),
            b"nosniff",
            "security-headers 应在 413 错误响应上存在（outer 于 body-limit）"
        );
        assert_eq!(
            headers
                .get("x-frame-options")
                .expect("413 须有 x-frame-options")
                .as_bytes(),
            b"DENY"
        );
        assert_eq!(
            headers
                .get("referrer-policy")
                .expect("413 须有 referrer-policy")
                .as_bytes(),
            b"no-referrer"
        );
    }

    /// request_id 头仍在（回归：加入 edge hardening 层后 request_id 封口不受影响）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn request_id_still_present_after_edge_hardening_layers() {
        let routes =
            unfinalized_for_test::<Health>(|rb| rb.mount(admin_route(), get(|| async { "ok" })));
        let plan = primitives::AuthPlan::new(ListenerKind::Health, primitives::AuthScheme::NoAuth)
            .expect("plan");
        let router = finalize_auth(routes, plan)
            .expect("finalize_auth")
            .into_router_for_test();

        let resp = oneshot_response(router, "/list").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers().get("x-request-id").is_some(),
            "x-request-id 在 edge hardening 层后仍存在"
        );
    }

    // ── correlation sealed_router 不变式测试 ──────────────────────────────────────────────────

    /// ROUTE-CORRELATION-INNER-REQUESTID-01：`sealed_router` 封了 `correlation` ⇒ 响应带
    /// `x-correlation-id`。NoAuth listener 取 200 路径（避免 enforce 401 干扰，纯验封口）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn correlation_sealed_at_bindable_exit() {
        let routes =
            unfinalized_for_test::<Health>(|rb| rb.mount(admin_route(), get(|| async { "ok" })));
        let plan = primitives::AuthPlan::new(ListenerKind::Health, primitives::AuthScheme::NoAuth)
            .expect("plan");
        let router = finalize_auth(routes, plan)
            .expect("finalize_auth")
            .into_router_for_test();

        let resp = oneshot_response(router, "/list").await;
        assert_eq!(resp.status(), StatusCode::OK, "NoAuth matched → 200");
        let cid = resp
            .headers()
            .get("x-correlation-id")
            .expect("sealed_router 须封 correlation middleware ⇒ 响应须有 x-correlation-id");
        assert!(!cid.is_empty(), "x-correlation-id 非空");
    }

    /// ROUTE-CORRELATION-INNER-REQUESTID-01：验签桥位（`AuthenticatedRoutes::layer`）运行时
    /// `diagctx::correlation()` 须在场——`correlation` 在 `request_id` 内侧、验签桥外侧，
    /// `diagctx::scope` 包住桥 + handler 全链。
    ///
    /// 用探针层模拟验签桥（经 `AuthenticatedRoutes::layer` 叠在 `finalize_auth` 外）：
    /// 读 `diagctx::correlation()`，在场则回写 `x-saw-correlation: 1`。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn correlation_visible_to_outer_bridge_layer() {
        let routes =
            unfinalized_for_test::<Health>(|rb| rb.mount(admin_route(), get(|| async { "ok" })));
        let plan = primitives::AuthPlan::new(ListenerKind::Health, primitives::AuthScheme::NoAuth)
            .expect("plan");
        // 探针层叠在验签桥位（correlation 内侧，sealed_router 封 correlation + request_id 后成为外侧）。
        let probed =
            finalize_auth(routes, plan)
                .expect("finalize_auth")
                .layer(axum::middleware::from_fn(
                    |req: axum::extract::Request, next: axum::middleware::Next| async move {
                        let saw = diagctx::correlation().is_some();
                        let mut resp = next.run(req).await;
                        if saw {
                            resp.headers_mut().insert(
                                "x-saw-correlation",
                                axum::http::HeaderValue::from_static("1"),
                            );
                        }
                        resp
                    },
                ));
        let resp = oneshot_response(probed.into_router_for_test(), "/list").await;
        assert_eq!(
            resp.headers()
                .get("x-saw-correlation")
                .map(|v| v.as_bytes()),
            Some(&b"1"[..]),
            "外层（验签桥位）中间件运行时 diagctx::correlation() 须在场（correlation sealed_router 先行运行）"
        );
    }
}
