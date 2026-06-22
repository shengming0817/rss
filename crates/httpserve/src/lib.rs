//! httpserve — RSS HTTP 服务基础设施（listener / route 声明、auth 装配接缝）。
//!
//! 只含签名冻结（ADR-004 C8 覆盖率豁免）；所有函数体为 `todo!()`，逻辑待后续 PR 实现。
//!
//! ref: tower tower-layer/src/lib.rs@master（Layer::layer 同步语义）
//! ref: axum axum/src/routing/mod.rs@main（Router::route/nest/layer）

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
/// 对标 axum `Router::route` 逐条注册，携带 `contract_id` 元数据用于治理扫描。
pub fn mount(
    _router: axum::Router,
    _route: Route,
    _handler: axum::routing::MethodRouter,
) -> axum::Router {
    todo!()
}

/// `Primary` listener 的声明性 [`PrimaryRoute`] 挂载到 axum Router；唯一接受 auth opt-out 的入口
/// （`PrimaryRoute.opt_out` 透传至 `resolve_requirement`，AUTH-OPTOUT-PRIMARYONLY-01）。
///
/// 调用方责任：仅在 `Primary` listener 的 `RouteGroup::register` 闭包内调用——类型层只保证「opt-out 字段
/// 仅 `PrimaryRoute` 有」，不绑定 `Router` 与 listener 种类（须 phantom type，未立项）。`PrimaryRoute` 误挂
/// 到非 Primary listener 的残留 seam 由 `finalize_auth` / `resolve_requirement` 运行期 fail-closed 兜底
/// （AUTH-FAILCLOSED-01）。
pub fn mount_primary(
    _router: axum::Router,
    _route: PrimaryRoute,
    _handler: axum::routing::MethodRouter,
) -> axum::Router {
    todo!()
}

/// 所有 RouteGroup 注册完成后装配 auth enforcement（plan 由组合根注入，本函数不构造 AuthPlan）。
///
/// `finalize_auth` 在所有 route 注册完成后运行；业务不得绕过最终 matcher（runtime-api.md）。
pub fn finalize_auth(
    _router: axum::Router,
    _plan: primitives::AuthPlan,
) -> Result<axum::Router, RouteGroupError> {
    todo!()
}

#[cfg(test)]
mod smoke {
    use super::*;

    // FnOnce 不要求 Sync，只检查 Send（RouteGroup 需跨线程传递至 bootstrap）
    fn _assert_send<T: Send>() {}

    #[test]
    fn signatures_consumable() {
        // 非-Primary route：**无 opt-out 字段**——opt-out 在类型层不可表达（field exclusion，Hard）。
        let _r = Route {
            method: axum::http::Method::GET,
            path: "/internal/v1/x",
            contract_id: "x",
        };
        // Primary route：唯一携 opt-out 的类型；Some(..) 表降级，None 表正常认证。
        let _pr = PrimaryRoute {
            method: axum::http::Method::GET,
            path: "/api/v1/x",
            contract_id: "x",
            opt_out: Some(RouteAuthOptOut::Public),
        };
        let _pr_none = PrimaryRoute {
            method: axum::http::Method::POST,
            path: "/api/v1/y",
            contract_id: "y",
            opt_out: None,
        };
        // register 用 Ok 构造器（恒等成功）证明字段类型，FnOnce 满足，合法
        let _g = RouteGroup {
            listener: ListenerKind::Primary,
            prefix: "/api/v1/x",
            register: Box::new(Ok),
        };
        // 绑定函数指针，不调用（不触发 todo!()）
        let _m: fn(axum::Router, Route, axum::routing::MethodRouter) -> axum::Router = mount;
        let _mp: fn(axum::Router, PrimaryRoute, axum::routing::MethodRouter) -> axum::Router =
            mount_primary;
        let _f: fn(axum::Router, primitives::AuthPlan) -> Result<axum::Router, RouteGroupError> =
            finalize_auth;
        _assert_send::<RouteGroup>();
    }
}
