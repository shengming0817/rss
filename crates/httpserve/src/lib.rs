//! httpserve — RSS HTTP 服务基础设施（listener / route 声明、auth 装配接缝）。
//!
//! 路由生命周期的类型层不变式收口在 [`routes`]：listener-typed 注册（[`ListenerRouter<L>`]，#1103
//! segregation Medium→Hard）+ auth-finalize-before-bind funnel（[`UnfinalizedRoutes`] → [`finalize_auth`]
//! → [`AuthenticatedRoutes`]，#1113 Hard）。另有 `health` 模块（`healthz` / `readyz` builders）。
//!
//! ref: tokio-rs/axum axum/src/middleware/from_fn.rs@main（Layer::from_fn 同步语义）；
//! ref: tokio-rs/axum axum/src/routing/mod.rs@main（`Router<S>` 状态类型表达「缺状态不可 serve」）

mod auth;
mod budget;
pub mod error;
pub mod health;
mod middleware;
pub mod protect;
pub mod routes;

pub use auth::{
    AuditSinkHandle, Authenticated, AuthenticatedAuditEvent, AuthorizedSubject,
    BearerCredentialError, ExtractedBearerCredential, FieldMask, PendingScopeCtx,
    ResourceProjection, RouteAuthorizationDecision, RouteAuthorizationRequest, RouteAuthorizer,
    RouteMeta, RouteResource, ServiceTokenTenantBindingError, TenantHeaderError,
    authorize_subject_for_permission, exact_tenant_header, extract_bearer_credential,
    service_token_tenant_binding,
};
pub use budget::ServerRequestBudget;
pub use middleware::rate_limit;
pub use protect::{BodyLimit, EdgeHardening, SecurityHeaders};
pub use routes::{
    Admin, AuthenticatedRoutes, ClassifiedRouteState, ContractMarker, GeneratedEndpoint,
    GeneratedPrimaryEndpoint, Health, Internal, Listener, ListenerRouter, LocalOnlyAllowedEffect,
    NonPrimaryListener, Primary, ProducerAssuranceReceipt, ProducerAuthorization, ProducerMarker,
    ServerMakeService, UnfinalizedRoutes, finalize_auth, finalize_auth_with_audit,
    finalize_auth_with_audit_and_authorizer, finalize_primary_auth,
    finalize_primary_auth_with_audit,
};
#[cfg(any(test, feature = "test-util"))]
pub use routes::{
    LocalOnlyMountedRouteProof, LocalOnlyRouteNotMounted, StatelessLocalOnlyMountedRouteProof,
    prove_local_only_mounted_route_state, prove_stateless_local_only_mounted_route,
    with_producer_witness_for_test,
};
#[cfg(any(test, feature = "test-util"))]
pub use routes::{TestPrimaryRoute, TestRoute, TestRoutePermission, TestRouteResourceScope};

/// 读框架注入的 request id（`request_id` 中间件在唯一 bindable 出口
/// [`AuthenticatedRoutes::into_make_service`] 封为**最外层 request-context middleware**（仅机械
/// security response-header layers 在其外），ROUTE-REQUESTID-OUTERMOST-01）。
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RoutePermission {
    pub(crate) permission: vocab::RoutePermissionId,
    pub(crate) scope: RouteResourceScope,
    pub(crate) tenant_binding: RouteTenantBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteTenantBinding {
    Unrestricted,
    Ambient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteResourceScope {
    None,
    PathParam(&'static str),
    SelfSubject,
}

#[derive(Debug, Clone)]
pub(crate) enum PrimaryRouteAuthz {
    Permission(RoutePermission),
    OptOut(primitives::RouteAuthOptOut),
    ServiceCaller(ServiceCallerPolicy),
}

/// Exact caller policy for one Internal service-token route.
///
/// The caller is a closed typed domain, so a policy is intrinsically non-empty. The contract id
/// is checked against generated route evidence at mount time and again at authorization time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceCallerPolicy {
    contract_id: &'static str,
    caller: vocab::ServiceCallerDomain,
}

impl ServiceCallerPolicy {
    pub const fn exact(contract_id: &'static str, caller: vocab::ServiceCallerDomain) -> Self {
        Self {
            contract_id,
            caller,
        }
    }

    pub(crate) fn matches_contract(&self, contract_id: &str) -> bool {
        self.contract_id == contract_id
    }

    pub(crate) fn allows(&self, caller: vocab::ServiceCallerDomain) -> bool {
        self.caller == caller
    }
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
    #[error(
        "listener mismatch: registered={registered:?}, conflicting={conflicting:?}, finalized={finalized:?}"
    )]
    ListenerMismatch {
        /// First listener registered in the accumulator, if any.
        registered: Option<primitives::ListenerKind>,
        /// A second, incompatible listener observed during group folding, if any.
        conflicting: Option<primitives::ListenerKind>,
        /// Listener selected by the auth plan at finalization.
        finalized: primitives::ListenerKind,
    },
    /// The selected listener exposes fixed framework routes that do not support this scheme.
    #[error("auth scheme {scheme:?} is unsupported for listener {listener:?}")]
    UnsupportedAuthPlan {
        /// Listener selected by the auth plan.
        listener: primitives::ListenerKind,
        /// Authentication scheme rejected for that listener.
        scheme: primitives::AuthScheme,
    },
    #[error("route registration failed")]
    RegistrationFailed,
    #[error(
        "generated route method is invalid or unsupported: contract={contract_id}, method={method}, path={path}"
    )]
    InvalidMethod {
        contract_id: &'static str,
        method: String,
        path: &'static str,
    },
    #[error(
        "generated route path is outside its route group: contract={contract_id}, method={method}, path={path}, prefix={prefix}, listener={listener:?}"
    )]
    PathOutsideGroup {
        contract_id: &'static str,
        method: &'static str,
        path: &'static str,
        prefix: &'static str,
        listener: primitives::ListenerKind,
    },
    #[error(
        "generated route auth is incompatible with its listener: contract={contract_id}, method={method}, path={path}, listener={listener:?}, auth={auth:?}"
    )]
    InvalidAuth {
        contract_id: &'static str,
        method: &'static str,
        path: &'static str,
        listener: primitives::ListenerKind,
        auth: vocab::HttpRouteAuth,
    },
    #[error("service caller policy does not match its route contract")]
    InvalidServiceCallerPolicy,
}

// generated endpoint 挂载（`ListenerRouter::mount`）与 auth-finalize funnel（`finalize_auth` /
// `UnfinalizedRoutes` / `AuthenticatedRoutes`）见 `routes` 模块——typed listener marker + funnel 状态类型。
