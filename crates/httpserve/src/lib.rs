//! httpserve — RSS HTTP 服务基础设施（listener / route 声明、auth 装配接缝）。
//!
//! 提供 `mount` / `mount_primary` / `finalize_auth` 三个冻结公共函数，以及
//! `health` 模块（`healthz` / `readyz` builders）。
//!
//! ref: tokio-rs/axum axum/src/middleware/from_fn.rs@main（Layer::from_fn 同步语义）

mod auth;
pub mod error;
pub mod health;
mod middleware;

pub use auth::RouteMeta;

use primitives::{ListenerKind, RouteAuthOptOut};

/// 非-`Primary` listener 路由声明性元数据：**类型层无 auth opt-out 字段**。
///
/// `Internal` / `Admin` / `Health` listener 上的 route 用此类型——opt-out 在类型层不可表达
/// （input-struct-field-exclusion，Hard）：没有字段可设，故 `resolve_requirement` 对经 [`mount`]
/// 挂载的 route 恒收 `None`。对外 `Primary` listener 的 opt-out 走兄弟类型 [`PrimaryRoute`]。
#[derive(Debug, Clone)]
pub struct Route {
    pub method: axum::http::Method,
    pub path: &'static str,
    pub contract_id: &'static str,
}

/// `Primary` listener 路由声明性元数据：**唯一**可携带 auth opt-out 的 route 类型。
///
/// INVARIANT: AUTH-OPTOUT-PRIMARYONLY-01 —— auth opt-out（[`RouteAuthOptOut`]）仅 `PrimaryRoute`
/// 可携带；plain [`Route`] 类型层无此字段（input-struct-field-exclusion，Hard，取代旧裸 `bool` 字段）。
/// 非-Primary route 经 [`mount`] 挂载、永远拿不到 opt-out 值；`Primary` route 经 [`mount_primary`]
/// 挂载并透传 `opt_out`。运行期 fail-closed 由 `primitives::resolve_requirement`（INVARIANT
/// AUTH-FAILCLOSED-01）作 listener-mismatch 残留 seam 的 backstop（defense-in-depth：类型层删常见
/// 误用类，运行期兜异常接线）。
#[derive(Debug, Clone)]
pub struct PrimaryRoute {
    pub method: axum::http::Method,
    pub path: &'static str,
    pub contract_id: &'static str,
    /// `Some(..)` = 显式 opt-out 降级（`Public` / `PasswordResetExempt`，runtime-api.md §Auth plan 优先级 1）；
    /// `None` = 正常认证。`mount_primary` body 落地时透传给 `resolve_requirement(plan, opt_out)`。
    pub opt_out: Option<RouteAuthOptOut>,
}

/// 域 crate 在 `Domain::init` 中声明的路由组。
///
/// `register` 为一次性消费闭包（`FnOnce`）：路由注册是单次操作——bootstrap
/// 启动时每个 `RouteGroup` 的 `register` 只被调用一次，与 `bootstrap::Registry::route_group`
/// 的 `FnOnce` 语义对齐（对标 tower `Layer::layer` 同步语义；因需在 bootstrap
/// 异构收集多域实例而装箱，是对 tower 泛型静态分发的合理偏离）。
///
/// 使用 `FnOnce` 而非 `Fn`：路由注册语义上是单次消耗；bootstrap 收集时包装为
/// `KernelError`，经 `From<RouteGroupError>` 桥接转换。
/// 去掉 `Sync`：`FnOnce` 不要求 `Sync`（与 `Fn + Sync` 语义不同，不可多次调用）。
pub struct RouteGroup {
    pub listener: ListenerKind,
    pub prefix: &'static str,
    pub register:
        Box<dyn FnOnce(axum::Router) -> Result<axum::Router, RouteGroupError> + Send + 'static>,
}

/// httpserve 本地错误（分层禁依赖 bootstrap，故不用 KernelError；bootstrap 收集时再包装）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RouteGroupError {
    #[error("duplicate route registration")]
    DuplicateRoute,
    #[error("listener mismatch")]
    ListenerMismatch,
    #[error("route registration failed")]
    RegistrationFailed,
}

/// 非-`Primary` listener 的声明性 [`Route`] 挂载到 axum Router（无 opt-out；`resolve_requirement` 恒收 `None`）。
///
/// 对标 axum `Router::route` 逐条注册，携带 `contract_id` 和 `method` 元数据进运行时 extension
/// （供下游审计/可观测消费及 drift 检测）。
pub fn mount(
    router: axum::Router,
    route: Route,
    handler: axum::routing::MethodRouter,
) -> axum::Router {
    router.route(
        route.path,
        handler.layer(auth::enforce_layer(None, route.method, route.contract_id)),
    )
}

/// `Primary` listener 的声明性 [`PrimaryRoute`] 挂载到 axum Router；唯一接受 auth opt-out 的入口
/// （`PrimaryRoute.opt_out` 透传至 `resolve_requirement`，AUTH-OPTOUT-PRIMARYONLY-01）。
pub fn mount_primary(
    router: axum::Router,
    route: PrimaryRoute,
    handler: axum::routing::MethodRouter,
) -> axum::Router {
    router.route(
        route.path,
        handler.layer(auth::enforce_layer(
            route.opt_out,
            route.method,
            route.contract_id,
        )),
    )
}

/// 所有 RouteGroup 注册完成后装配 auth enforcement（plan 由组合根注入，本函数不构造 AuthPlan）。
///
/// `finalize_auth` 在所有 route 注册完成后运行；业务不得绕过最终 matcher（runtime-api.md）。
///
/// 层序（`.layer` 调用顺序 = 内→外）：
/// - `Extension(plan)`：最内（路由前设 plan ext），EnforceService 在 MethodRouter 层读取 plan。
/// - `panic_recovery`：request-aware panic → 500 envelope（带 requestId；须在 trace 内侧让 trace 看到 500）。
/// - `trace`：tracing span，可看到 panic_recovery 合成的 500。
/// - `request_id`：最外，设 id + 回填 header（panic 路径也能补 header）。
///
/// 请求流（外→内）：request_id → trace → panic_recovery → Extension(plan) → 路由匹配 →
/// EnforceService（读 plan，决策 requirement）→ handler。
///
/// 当前恒 `Ok`（无失败分支）——`RouteGroupError` 变体留给 bootstrap-driver 路径（签名冻结保留扩展点）。
pub fn finalize_auth(
    router: axum::Router,
    plan: primitives::AuthPlan,
) -> Result<axum::Router, RouteGroupError> {
    let router = router
        .layer(axum::Extension(plan))
        .layer(axum::middleware::from_fn(middleware::panic_recovery))
        .layer(axum::middleware::from_fn(middleware::trace))
        .layer(axum::middleware::from_fn(middleware::request_id));
    Ok(router)
}
