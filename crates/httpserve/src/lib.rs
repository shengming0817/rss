//! httpserve — RSS HTTP 服务基础设施（listener / route 声明、auth 装配接缝）。
//!
//! 路由生命周期的类型层不变式收口在 [`routes`]：listener-typed 注册（[`ListenerRouter<L>`]，#1103
//! segregation Medium→Hard）+ auth-finalize-before-bind funnel（[`UnfinalizedRoutes`] → [`finalize_auth`]
//! → [`AuthenticatedRoutes`]，#1113 Hard）。另有 `health` 模块（`healthz` / `readyz` builders）。
//!
//! ref: tokio-rs/axum axum/src/middleware/from_fn.rs@main（Layer::from_fn 同步语义）；
//! ref: tokio-rs/axum axum/src/routing/mod.rs@main（`Router<S>` 状态类型表达「缺状态不可 serve」）

mod auth;
pub mod error;
pub mod health;
mod middleware;
pub mod protect;
pub mod routes;

pub use auth::{
    AuditSinkHandle, Authenticated, PendingScopeCtx, RouteMeta, ServiceTokenTenantBindingError,
    service_token_tenant_binding,
};
pub use middleware::rate_limit;
pub use protect::{BodyLimit, EdgeHardening, SecurityHeaders};
pub use routes::{
    Admin, AuthenticatedRoutes, Health, Internal, Listener, ListenerRouter, NonPrimaryListener,
    Primary, UnfinalizedRoutes, finalize_auth, finalize_auth_with_audit,
};

/// 读框架注入的 request id（`request_id` 中间件在唯一 bindable 出口
/// [`AuthenticatedRoutes::into_make_service`] 封为**最外层**，ROUTE-REQUESTID-OUTERMOST-01）。
///
/// 供组合根叠在 `finalize_auth` 产物**外层**（但 request_id 内层）的中间件——如 #1109 验签桥——读
/// request 关联 id 入自身 span / 日志（桥运行时 request_id 已就位，落实 #1320「桥可读 requestId」）。
/// 内层 enforce / handler 仍经请求 extension 直读 [`RouteMeta`] 等；本 accessor 仅为外层中间件提供
/// 不暴露 `RequestId` newtype 的只读窗口。
pub fn request_id_str(extensions: &axum::http::Extensions) -> Option<&str> {
    extensions
        .get::<middleware::RequestId>()
        .map(middleware::RequestId::as_str)
}

use primitives::RouteAuthOptOut;

/// 非-`Primary` listener 路由声明性元数据：**类型层无 auth opt-out 字段**。
///
/// `Internal` / `Admin` / `Health` listener 上的 route 用此类型——opt-out 在类型层不可表达
/// （input-struct-field-exclusion，Hard）：没有字段可设，故 `resolve_requirement` 对经
/// [`ListenerRouter::mount`](routes::ListenerRouter::mount) 挂载的 route 恒收 `None`。对外 `Primary`
/// listener 的 opt-out 走兄弟类型 [`PrimaryRoute`]。
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
/// 非-Primary route 经 [`ListenerRouter::mount`](routes::ListenerRouter::mount) 挂载、永远拿不到 opt-out
/// 值；`Primary` route 经 [`ListenerRouter::mount_primary`](routes::ListenerRouter::mount_primary)
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

// 旧 `RouteGroup` struct（接受裸 `axum::Router` 的 register 闭包）已随 ADR-009 typed funnel 退役——
// 路由组声明面收敛到 `bootstrap::Registry::route_group::<L>`（listener 由类型参数携带）+ 域 crate 经
// `routes::ListenerRouter<L>` typed mount；裸 `axum::Router` 不再出现在任何 public 路由声明 API（ADR-009 §2.1）。

/// httpserve 本地错误（httpserve **不**依赖 bootstrap，故不用 KernelError；bootstrap 收集时再包装）。
/// 注：ADR-009 只开**正向** `bootstrap → httpserve` 受控路由类型边；**反向** `httpserve → bootstrap` 仍禁
/// （layers `route_funnel_allows` 单向放行 + 反例守），故本错误类型保留。
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

// 路由挂载（`ListenerRouter::{mount, mount_primary}`）与 auth-finalize funnel（`finalize_auth` /
// `UnfinalizedRoutes` / `AuthenticatedRoutes`）见 `routes` 模块——typed listener marker + funnel 状态类型。
