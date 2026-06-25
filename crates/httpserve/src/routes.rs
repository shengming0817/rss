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

use crate::auth::enforce_layer;
use crate::{PrimaryRoute, Route, RouteGroupError};
use core::marker::PhantomData;
use primitives::{AuthPlan, ListenerKind};

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
/// INVARIANT: ROUTE-LISTENER-TYPED-01 —— 路由经本 builder 挂载、随组 fold 进 `L::KIND` listener 的
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
/// INVARIANT: ROUTE-AUTH-FUNNEL-01 —— 无 public bindable 出口（无 `into_make_service`）；唯一前进路径是
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
/// INVARIANT: ROUTE-AUTH-FUNNEL-02 —— 唯一生产者 = [`finalize_auth`]（构造 `pub(crate)`，外部 crate 无法
/// mint）；[`into_make_service`](Self::into_make_service) 是唯一 bindable 出口。验签桥（#1109）经
/// [`layer`](Self::layer) 叠在外层、保持封印（产物仍是 `AuthenticatedRoutes`，只能加层不能替换）。
#[must_use = "AuthenticatedRoutes 须经 into_make_service bind（否则 router 未 serve）"]
pub struct AuthenticatedRoutes {
    router: axum::Router,
}

impl AuthenticatedRoutes {
    /// 唯一生产入口（`pub(crate)`）——仅 [`finalize_auth`] 可构造，外部 crate 无法 mint（ROUTE-AUTH-FUNNEL-02）。
    pub(crate) fn new(router: axum::Router) -> Self {
        Self { router }
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
        }
    }

    /// **唯一** bindable 出口：转 axum make-service 交 `axum::serve`（#1017 bind 点天生只能消费已认证 router）。
    pub fn into_make_service(self) -> axum::routing::IntoMakeService<axum::Router> {
        self.router.into_make_service()
    }

    /// 测试专用：取回裸 Router 做 `oneshot` e2e 断言。**`cfg(any(test, feature = "test-util"))` 门控（Medium）**——
    /// 生产构建里编译期不存在，不削弱 ROUTE-AUTH-FUNNEL-02（生产唯一 bindable 出口仍是 `into_make_service`）。
    #[cfg(any(test, feature = "test-util"))]
    pub fn into_router_for_test(self) -> axum::Router {
        self.router
    }
}

/// 所有 route 注册完成后装配 auth enforcement（plan 由组合根注入，本函数不构造 `AuthPlan`）。
///
/// #1113 funnel transform：消费 [`UnfinalizedRoutes`] 产 [`AuthenticatedRoutes`]——本 fn 是后者**唯一**
/// 生产者（ROUTE-AUTH-FUNNEL-02）。业务不得绕过最终 matcher（runtime-api.md）。
///
/// 层序（`.layer` 调用顺序 = 内→外）：`Extension(plan)`（最内，EnforceService 读 plan）→ `panic_recovery`
/// （request-aware panic → 500 envelope）→ `trace` → `request_id`（最外）。请求流（外→内）：request_id →
/// trace → panic_recovery → Extension(plan) → 路由匹配 → EnforceService → handler。
///
/// 验签桥（#1109）经 [`AuthenticatedRoutes::layer`] 叠在**外层**（请求方向先于 `EnforceService`），其注入的
/// [`Authenticated`](crate::Authenticated) 证据在 enforce 读取前就位。当前恒 `Ok`——`RouteGroupError` 变体
/// 留给扩展点（签名冻结保留）。
pub fn finalize_auth(
    routes: UnfinalizedRoutes,
    plan: AuthPlan,
) -> Result<AuthenticatedRoutes, RouteGroupError> {
    let router = routes
        .router
        .layer(axum::Extension(plan))
        .layer(axum::middleware::from_fn(crate::middleware::panic_recovery))
        .layer(axum::middleware::from_fn(crate::middleware::trace))
        .layer(axum::middleware::from_fn(crate::middleware::request_id));
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

    #[test]
    fn listener_kind_maps_marker_to_value() {
        assert_eq!(Primary::KIND, ListenerKind::Primary);
        assert_eq!(Internal::KIND, ListenerKind::Internal);
        assert_eq!(Admin::KIND, ListenerKind::Admin);
        assert_eq!(Health::KIND, ListenerKind::Health);
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
}
