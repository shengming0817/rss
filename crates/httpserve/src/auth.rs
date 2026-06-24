//! 每路由鉴权闸：`resolve_requirement` 纯决策 → HTTP 落地。
//!
//! 偏离说明（相对于任务文档 `from_fn` 方案）：axum 0.8 `from_fn` 生成的 `FromFnLayer`
//! 不满足 `MethodRouter::layer` 的 trait bound（`Next: FromRequest` 不成立）；
//! 改用手写 `EnforceLayer`（`impl tower::Layer`）+ `EnforceService`（`impl tower::Service`），
//! 通过 `tower = { workspace = true }` 引入 Layer/Service trait。
//! opt_out 存于 `EnforceLayer`（Copy 字段），不经 extension 传递——这样 enforce 在
//! MethodRouter 层执行时可直接读捕获的 opt_out 和外层注入的 AuthPlan extension。
//!
//! INVARIANT: AUTH-FAILCLOSED-01 —— 缺 AuthPlan（finalize_auth 未跑） → fail-closed Deny → 403；
//! 控制面 listener opt-out → Deny → 403（不 Allow，永不降级）。
//!
//! INVARIANT: AUTH-EVIDENCE-REQUIRE-01 —— `Require(required)` 路由仅在请求携 [`Authenticated`] 证据、其
//! `principal_kind` 非 `Anonymous`、**且 `scheme()` exact-match `required`** 时放行；缺证据 / `Anonymous` 证据 /
//! 方案不匹配（如 Jwt 证据撞 `Require(Mtls)`）→ fail-closed 401（`Anonymous` = 「已知未认证」；匿名可达路由走
//! `PrimaryRoute.opt_out(Public)`，非 Require）。证据由组合根验签桥（外层 `.layer()`）在凭据校验通过后注入，
//! httpserve 自身不构造、不验签（finalize_auth 签名冻结，无 verifier 参）；本 crate 单独 merge 无注入方 →
//! 所有 Require 路由仍 401，零端点放开（Medium，单测 + tests/runtime.rs 集成测试守）。
//!
//! INVARIANT: AUTH-EVIDENCE-MINT-01 —— [`Authenticated`] 私有字段（外部无法 struct-literal 伪造）+
//! `Authenticated::new` 仅组合根可调（`rss_authenticated_callsite` callsite dylint，Medium，与 `AuthPlan` 同治理
//! 姿态），杜绝域 crate `.layer(Extension(Authenticated::new(..)))` 伪造证据绕过 enforce。
//!
//! tower readiness 契约：call 使用的 inner 实例必须是 poll_ready 的实例。
//! 采用 clone-replace 模式：call 入口 clone 一份新实例用于放行分支，原 self.inner
//! 保留 poll_ready 状态（见 `EnforceService::call` 注释）。
//!
//! ref: tokio-rs/axum axum/src/middleware/from_fn.rs@main

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::extract::Request;
use axum::response::Response;
use primitives::{AuthRequirement, RequiredScheme, RouteAuthOptOut, resolve_requirement};
use tower::Layer;
use tower::Service;
use vocab::PrincipalKind;

use crate::middleware::RequestId;

/// 短路 helper：将已构造的错误响应包装成 `Pin<Box<dyn Future<...>>>` 供 `call` 直接返回。
///
/// 收拢 Deny/401/wildcard 三处 `Box::pin(async move { Ok(resp) })` 为单一调用点，
/// 降低认知复杂度（cognitive_complexity lint 目标 ≤ 15）。
fn short_circuit<E>(
    resp: axum::response::Response,
) -> Pin<Box<dyn Future<Output = Result<axum::response::Response, E>> + Send>> {
    Box::pin(async move { Ok(resp) })
}

/// 路由身份元数据（声明性 method + contract_id 进运行时请求 extension，供下游审计/可观测消费）。
#[derive(Clone, Debug)]
pub struct RouteMeta {
    pub method: axum::http::Method,
    pub contract_id: &'static str,
}

/// 认证证据 extension：验签桥在凭据校验通过后注入请求 extension，enforce 层据此对 `Require` 路由放行
/// （INVARIANT: AUTH-EVIDENCE-REQUIRE-01）。
///
/// 承载**脱敏标量**：已验证的 [`RequiredScheme`]（验签桥实际验证的凭据方案）+ [`PrincipalKind`]（主体类别）
/// ——无 subject / token / PII，零 authn 依赖（httpserve 是兄弟服务 authn 的不可依赖方，Service 层只依赖
/// Basis|Engine|DiPort，故放行机制由 httpserve own 类型承载）。`scheme` 用 [`RequiredScheme`]（非 `AuthScheme`）：
/// 类型层杜绝「`NoAuth` 证据」自相矛盾——无认证不产证据。私有字段 + [`Authenticated::new`] 构造 funnel：
/// 外部可命名 / 收发、不可篡字段；`new` callsite 由 `rss_authenticated_callsite` dylint 限组合根
/// （AUTH-EVIDENCE-MINT-01）。**不 derive `Serialize`**（内部证据，非 wire 类型）。
///
/// 注入方（验签桥）由组合根外层 `.layer()` 装配，本 crate 不构造（与 `AuthPlan` 同治理姿态：域 crate 不构造、
/// 组合根注入）；对标 tower-http `AsyncAuthorizeRequest::authorize` 内 `request.extensions_mut().insert(principal)`
/// 推送范式。
///
/// ref: tower-rs/tower-http tower-http/src/auth/async_require_authorization.rs@master
#[derive(Clone, Copy, Debug)]
pub struct Authenticated {
    scheme: RequiredScheme,
    principal_kind: PrincipalKind,
}

impl Authenticated {
    /// 构造认证证据（验签桥在凭据校验通过后调用）。`scheme` = 验签桥**实际验证的**凭据方案（enforce 按路由
    /// `Require(required)` exact-match 比对，scheme 不匹配 fail-closed 401，杜绝 scheme 混淆）；`principal_kind`
    /// 为脱敏分类标量。
    pub fn new(scheme: RequiredScheme, principal_kind: PrincipalKind) -> Self {
        Self {
            scheme,
            principal_kind,
        }
    }

    /// 已验证的凭据方案（enforce 按路由 `Require(required)` exact-match 比对）。
    pub fn scheme(&self) -> RequiredScheme {
        self.scheme
    }

    /// 已认证主体的脱敏分类（供下游审计 / 可观测 / 行级可见域派生消费）。
    pub fn principal_kind(&self) -> PrincipalKind {
        self.principal_kind
    }
}

// ── EnforceLayer ─────────────────────────────────────────────────────────────

/// 鉴权 enforce tower Layer（每路由 opt_out + RouteMeta；Copy + Clone 满足 MethodRouter::layer 约束）。
#[derive(Clone)]
pub(crate) struct EnforceLayer {
    opt_out: Option<RouteAuthOptOut>,
    meta: RouteMeta,
}

/// 返回每路由 enforce layer，可直接用于 `MethodRouter::layer()`。
pub(crate) fn enforce_layer(
    opt_out: Option<RouteAuthOptOut>,
    method: axum::http::Method,
    contract_id: &'static str,
) -> EnforceLayer {
    EnforceLayer {
        opt_out,
        meta: RouteMeta {
            method,
            contract_id,
        },
    }
}

/// 鉴权 enforce tower Service（包裹内层 Service，包含捕获的 opt_out + RouteMeta）。
pub(crate) struct EnforceService<S> {
    inner: S,
    opt_out: Option<RouteAuthOptOut>,
    meta: RouteMeta,
}

impl<S: Clone> Clone for EnforceService<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            opt_out: self.opt_out,
            meta: self.meta.clone(),
        }
    }
}

impl<S> Layer<S> for EnforceLayer {
    type Service = EnforceService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        EnforceService {
            inner,
            opt_out: self.opt_out,
            meta: self.meta.clone(),
        }
    }
}

/// 拒绝响应类型别名（降低类型复杂度）。
type DenyFuture<E> = Pin<Box<dyn Future<Output = Result<Response, E>> + Send>>;

/// Deny 分支：403 Forbidden + 日志。
fn deny_response<E>(contract_id: &'static str, rid: &str) -> DenyFuture<E> {
    tracing::warn!(contract_id, "auth deny");
    short_circuit(crate::error::forbidden(rid))
}

/// Require 分支：无 [`Authenticated`] 证据 / 证据方案与路由 `Require(required)` 不匹配时 fail-closed 401 + 日志。
///
/// httpserve 不验签（冻结 finalize_auth 签名无 verifier 参）：放行**仅**凭请求 extension 的 `Authenticated` 证据
/// **且其 `scheme()` exact-match 路由要求**——证据由组合根验签桥（外层 `.layer()`）在凭据校验通过后注入（见
/// [`reject_if_needed`]，AUTH-EVIDENCE-REQUIRE-01）。缺证据 / 方案不匹配 → 401；对外可达路由经
/// PrimaryRoute.opt_out(Public/PasswordResetExempt) 显式降级。
fn require_response<E>(contract_id: &'static str, rid: &str) -> DenyFuture<E> {
    tracing::warn!(contract_id, "auth require fail-closed 401");
    short_circuit(crate::error::unauthenticated(rid))
}

/// 决策结果转拒绝响应（`None` = Allow，`Some` = 短路响应）。
///
/// `evidence_scheme` = 请求所携 [`Authenticated`] 证据的已验证方案（无证据 / `Anonymous` 证据 → `None`，见 `call`）。
/// `Require(required)` 仅在 `evidence_scheme == Some(required)`（证据存在且**方案 exact-match**）时放行；无证据或
/// 方案不匹配（如 Jwt 证据撞 `Require(Mtls)`）→ fail-closed 401（AUTH-EVIDENCE-REQUIRE-01，杜绝 scheme 混淆）。
/// `Deny` / wildcard 永远 403，证据不参与（fail-closed 不可降级）。
fn reject_if_needed<E>(
    requirement: AuthRequirement,
    evidence_scheme: Option<RequiredScheme>,
    contract_id: &'static str,
    rid: &str,
) -> Option<DenyFuture<E>> {
    match requirement {
        AuthRequirement::Allow => None,
        // Require：携已验证证据**且方案 exact-match 路由要求** → 放行；否则 fail-closed 401。
        AuthRequirement::Require(required) if evidence_scheme == Some(required) => None,
        AuthRequirement::Require(_) => Some(require_response(contract_id, rid)),
        // Deny + #[non_exhaustive] wildcard 均 fail-closed 403。
        _ => Some(deny_response(contract_id, rid)),
    }
}

impl<S> Service<Request> for EnforceService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        // tower readiness 契约：poll_ready 的实例即 call 的实例。
        // clone-replace 模式：用已就绪的 self.inner 替换为新 clone，使 inner（旧实例）
        // 带走 poll_ready 状态；放行分支调 inner.call(req)，不调 self.inner.call(req)。
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        let opt_out = self.opt_out;
        let meta = self.meta.clone();
        let plan = req.extensions().get::<primitives::AuthPlan>().copied();
        // 验签桥（组合根外层 layer）校验通过后注入的认证证据；enforce 据其**已验证方案**放行 Require 路由。
        // fail-closed 防御纵深：`Anonymous` 证据视同无证据（→ None）——绝不过 Require（即便验签桥误注入；
        // 匿名可达路由经 PrimaryRoute.opt_out(Public) 而非 Require）。方案 exact-match 由 reject_if_needed 比对，
        // 杜绝 scheme 混淆（如 Jwt 证据撞 Require(Mtls)）。AUTH-EVIDENCE-REQUIRE-01。
        let evidence_scheme = req
            .extensions()
            .get::<Authenticated>()
            .filter(|ev| ev.principal_kind() != PrincipalKind::Anonymous)
            .map(|ev| ev.scheme());
        let rid = req
            .extensions()
            .get::<RequestId>()
            .map(|r| r.0.clone())
            .unwrap_or_default();

        // 运行期 route method drift 检测：声明 method 与实际请求 method 不一致时记 warn。
        if req.method() != meta.method {
            tracing::warn!(
                declared = %meta.method,
                actual = %req.method(),
                contract_id = meta.contract_id,
                "route method drift"
            );
        }

        // RouteMeta 进请求 extension，供下游审计/可观测消费。
        req.extensions_mut().insert(meta.clone());

        let requirement = match plan {
            // fail-closed：finalize_auth 未跑，没有 plan → 拒（AUTH-FAILCLOSED-01）。
            None => AuthRequirement::Deny,
            Some(p) => resolve_requirement(p, opt_out),
        };

        if let Some(resp) = reject_if_needed(requirement, evidence_scheme, meta.contract_id, &rid) {
            return resp;
        }
        Box::pin(inner.call(req))
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode, header};
    use axum::routing::get;
    use axum::{Extension, Router};
    use primitives::{AuthPlan, AuthScheme, ListenerKind, RequiredScheme, RouteAuthOptOut};
    use tower::ServiceExt;

    use super::*;

    const TEST_CONTRACT: &str = "test.contract";

    #[allow(clippy::unwrap_used)]
    fn build_router(opt_out: Option<RouteAuthOptOut>, plan: Option<AuthPlan>) -> Router {
        let mut router = Router::new().route(
            "/test",
            get(|| async { "ok" }).layer(enforce_layer(opt_out, Method::GET, TEST_CONTRACT)),
        );
        if let Some(p) = plan {
            router = router.layer(Extension(p));
        }
        router
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn no_plan_is_403() {
        let router = build_router(None, None);
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn public_opt_out_with_jwt_plan_is_200() {
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt).unwrap();
        let router = build_router(Some(RouteAuthOptOut::Public), Some(plan));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn require_without_auth_header_is_401() {
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt).unwrap();
        let router = build_router(None, Some(plan));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn require_with_authenticated_evidence_is_200() {
        // AUTH-EVIDENCE-REQUIRE-01：Require(Jwt) + 请求携 Authenticated 证据 → 放行 200。
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt).unwrap();
        let router = build_router(None, Some(plan));
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        // 验签桥范式：外层 layer 校验通过后注入证据；此处直接 insert 模拟该接缝。
        req.extensions_mut()
            .insert(Authenticated::new(RequiredScheme::Jwt, PrincipalKind::User));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn require_with_mismatched_scheme_is_401() {
        // AUTH-EVIDENCE-REQUIRE-01 scheme exact-match：Require(Jwt) 路由 + Mtls 方案证据 → scheme 不匹配 → 401。
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt).unwrap();
        let router = build_router(None, Some(plan));
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(Authenticated::new(
            RequiredScheme::Mtls,
            PrincipalKind::User,
        ));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn require_with_anonymous_evidence_is_401() {
        // AUTH-EVIDENCE-REQUIRE-01 fail-closed 防御纵深：`Anonymous` 证据视同无证据 → 仍 401。
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt).unwrap();
        let router = build_router(None, Some(plan));
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(Authenticated::new(
            RequiredScheme::Jwt,
            PrincipalKind::Anonymous,
        ));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn deny_with_evidence_is_still_403() {
        // 证据不降级 Deny：无 plan → Deny；即便携 Authenticated 证据，仍 fail-closed 403（AUTH-FAILCLOSED-01）。
        let router = build_router(None, None);
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(Authenticated::new(RequiredScheme::Jwt, PrincipalKind::User));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn require_with_auth_header_is_fail_closed_401() {
        // fail-closed：httpserve 不验签——裸 Authorization header 非证据，仅请求携 Authenticated
        // extension（验签桥注入）才放行，故带 header 仍 401。
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt).unwrap();
        let router = build_router(None, Some(plan));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .header(header::AUTHORIZATION, "Bearer token")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn require_with_empty_auth_header_is_401() {
        // F1 fail-closed：空 Authorization header 也一律 401。
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt).unwrap();
        let router = build_router(None, Some(plan));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .header(header::AUTHORIZATION, "")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn require_with_whitespace_auth_header_is_401() {
        // F1 fail-closed：纯空白 Authorization header 也一律 401。
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt).unwrap();
        let router = build_router(None, Some(plan));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .header(header::AUTHORIZATION, "   ")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn control_plane_opt_out_is_403() {
        // Internal listener + opt-out → Deny（AUTH-FAILCLOSED-01）。
        let plan = AuthPlan::new(ListenerKind::Internal, AuthScheme::ServiceToken).unwrap();
        let router = build_router(Some(RouteAuthOptOut::Public), Some(plan));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
