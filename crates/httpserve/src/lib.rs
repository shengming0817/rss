//! httpserve — RSS HTTP 服务基础设施（listener / route 声明、auth 装配接缝）。
//!
//! 只含签名冻结（ADR-004 C8 覆盖率豁免）；所有函数体为 `todo!()`，逻辑待后续 PR 实现。
//!
//! ref: tower tower-layer/src/lib.rs@master（Layer::layer 同步语义）
//! ref: axum axum/src/routing/mod.rs@main（Router::route/nest/layer）

use primitives::ListenerKind;

/// 单条路由声明性元数据（区别于 axum 内部 service-newtype Route）。
///
/// `public` / `password_reset_exempt` 对应 `primitives::RouteAuthOptOut`；
/// 仅 `Primary` listener 上的 route 允许 opt-out 降级（runtime-api.md §Auth plan 优先级）。
#[derive(Debug, Clone)]
pub struct Route {
    pub method: axum::http::Method,
    pub path: &'static str,
    pub contract_id: &'static str,
    /// 对应 `RouteAuthOptOut::Public`（仅 Primary listener 生效）。
    ///
    /// opt-out 仅对 `PrimaryListener` 合法。`InternalListener` / `AdminListener` 上的 route
    /// 由 `primitives::resolve_requirement`（INVARIANT AUTH-FAILCLOSED-01，随 authn W 行为 PR
    /// 落地的 governance test）fail-closed 拒绝；类型层强制（PrimaryRoute 拆分）已 defer 跟踪
    /// （见 PR #168 defer issue）。
    pub public: bool,
    /// 对应 `RouteAuthOptOut::PasswordResetExempt`（仅 Primary listener 生效）。
    ///
    /// opt-out 仅对 `PrimaryListener` 合法。`InternalListener` / `AdminListener` 上的 route
    /// 由 `primitives::resolve_requirement`（INVARIANT AUTH-FAILCLOSED-01，随 authn W 行为 PR
    /// 落地的 governance test）fail-closed 拒绝；类型层强制（PrimaryRoute 拆分）已 defer 跟踪
    /// （见 PR #168 defer issue）。
    pub password_reset_exempt: bool,
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

/// 单条声明性 Route 挂载到 axum Router（携带 contract_id 元数据登记 + 路由注册）。
///
/// 对标 axum `Router::route` 逐条注册，携带 `contract_id` 元数据用于治理扫描。
pub fn mount(
    _router: axum::Router,
    _route: Route,
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
        let _r = Route {
            method: axum::http::Method::GET,
            path: "/api/v1/x",
            contract_id: "x",
            public: false,
            password_reset_exempt: false,
        };
        // register 用 Ok 构造器（恒等成功）证明字段类型，FnOnce 满足，合法
        let _g = RouteGroup {
            listener: ListenerKind::Primary,
            prefix: "/api/v1/x",
            register: Box::new(Ok),
        };
        // 绑定函数指针，不调用（不触发 todo!()）
        let _m: fn(axum::Router, Route, axum::routing::MethodRouter) -> axum::Router = mount;
        let _f: fn(axum::Router, primitives::AuthPlan) -> Result<axum::Router, RouteGroupError> =
            finalize_auth;
        _assert_send::<RouteGroup>();
    }
}
