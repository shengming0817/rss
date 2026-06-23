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
//! tower readiness 契约：call 使用的 inner 实例必须是 poll_ready 的实例。
//! 采用 clone-replace 模式：call 入口 clone 一份新实例用于放行分支，原 self.inner
//! 保留 poll_ready 状态（见 `EnforceService::call` 注释）。
//!
//! ref: tokio-rs/axum axum/src/middleware/from_fn.rs@main

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::Response;
use primitives::{AuthRequirement, RouteAuthOptOut, resolve_requirement};
use tower::Layer;
use tower::Service;
use vocab::CoreErrorKind;

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
    short_circuit(crate::error::error_response(
        CoreErrorKind::Forbidden,
        StatusCode::FORBIDDEN,
        rid,
    ))
}

/// Require 分支：fail-closed 401 + 日志。
///
/// httpserve 无凭据验证能力（冻结 finalize_auth 签名无 verifier 参）：Require → fail-closed 401。
/// 真实 JWT/mTLS 校验由 authn 的独立 W 层提供——authn 接入后经 authenticated 标记接缝放行（authn PR 落地）。
/// 现状下需认证的路由一律 401；对外可达路由经 PrimaryRoute.opt_out(Public/PasswordResetExempt) 显式降级。
fn require_response<E>(contract_id: &'static str, rid: &str) -> DenyFuture<E> {
    tracing::warn!(contract_id, "auth require fail-closed 401");
    short_circuit(crate::error::error_response(
        CoreErrorKind::Unauthenticated,
        StatusCode::UNAUTHORIZED,
        rid,
    ))
}

/// 决策结果转拒绝响应（`None` = Allow，`Some` = 短路响应）。
fn reject_if_needed<E>(
    requirement: AuthRequirement,
    contract_id: &'static str,
    rid: &str,
) -> Option<DenyFuture<E>> {
    match requirement {
        AuthRequirement::Allow => None,
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

        if let Some(resp) = reject_if_needed(requirement, meta.contract_id, &rid) {
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
    use primitives::{AuthPlan, AuthScheme, ListenerKind, RouteAuthOptOut};
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
    async fn require_with_auth_header_is_fail_closed_401() {
        // F1 fail-closed：httpserve 无凭据验证能力，带 Authorization 也一律 401。
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
