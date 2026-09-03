//! httpserve 运行时切片 contract 测试（mock 驱动，`tower::ServiceExt::oneshot`）。
//!
//! 覆盖：generated endpoint mount + finalize_auth 鉴权闸（resolve_requirement→200/401/403、
//! 缺 plan fail-closed）+ wire error envelope（`vocab::CoreError`→`{"error":{...,requestId}}`）+
//! requestId 中间件 + panic-recovery（→500 envelope）+ health builders（healthz/readyz）。
//!
//! AUTH-EVIDENCE-REQUIRE-01（Medium）non-User `RssAccessToken`→401 的 canonical owner 是
//! 单测 `require_with_rss_access_token_non_user_evidence_is_401`（`crates/httpserve/src/auth.rs`）；
//! 本文件继续覆盖缺证据 / scheme mismatch / allow 路径，**不**再复制 non-User reject-matrix。
//!
//! 测试断言用 unwrap/expect：item-level carve-out。
//!
//! 注：本 contract 测试**不** feature-gate——rust-standards §命名的 `#[cfg(feature="integration")]`
//! 隔离针对需外部资源（DB/broker/网络）的集成测试；本测试全程 in-process（axum oneshot、
//! 确定性、毫秒级），是 `cargo test` 默认验收门，故有意不隔离。

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use axum::routing::get;
use primitives::{AuthPlan, AuthScheme, ListenerKind, RouteAuthOptOut};
use rss_request_context::PrincipalKind;
use std::future::Future;
use std::num::NonZeroU64;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tower::ServiceExt; // oneshot

use httpserve::{
    Authenticated, AuthenticatedRoutes, RouteAuthorizationDecision, RouteAuthorizationGrant,
    RouteAuthorizationRequest, RouteAuthorizer, RouteGroupError, RouteMeta,
    TestPrimaryRoute as PrimaryRoute, TestRoute as Route, TestRoutePermission as RoutePermission,
    TestRouteResourceScope as RouteResourceScope, UnfinalizedRoutes, finalize_auth,
    finalize_primary_auth,
};

// ── helpers ────────────────────────────────────────────────────────────────

#[allow(clippy::unwrap_used)]
fn empty_req(method: Method, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

#[allow(clippy::unwrap_used)]
async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[allow(clippy::unwrap_used)]
fn primary_plan(scheme: AuthScheme) -> AuthPlan {
    AuthPlan::new(ListenerKind::Primary, scheme).unwrap()
}

enum PermissionRouteMarker {}

impl vocab::http::OpenHttpResponseMarker for PermissionRouteMarker {}

async fn ok_handler(_: httpserve::ContractMarker<PermissionRouteMarker>) -> &'static str {
    "ok"
}

// item-level carve-out（workspace panic="deny"；test-only 故意 panic 验证 catch-panic 中间件）。
#[allow(clippy::panic)]
async fn panicking_handler() -> axum::response::Response {
    panic!("kaboom-secret-internal")
}

const C: &str = "httpserve.test";
const TEST_PERMISSION: vocab::RoutePermissionId = vocab::RoutePermissionId::IdentityPolicyRead;
const TEST_BINDING: vocab::ContractBinding = vocab::ContractBinding::from_static(
    "test",
    C,
    "v1",
    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
);
const TEST_EFFECTS: &[vocab::HttpEffectKind] = &[vocab::HttpEffectKind::Auth];
const X_REQUEST_ID: &str = "x-request-id";
const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const PRINCIPAL: &str = "11111111-2222-4333-8444-555555555555";

#[allow(clippy::unwrap_used)]
fn tenant() -> rss_request_context::TenantId {
    rss_request_context::TenantId::parse(TENANT).unwrap()
}

fn authed(scheme: httpserve::NonRssTestScheme, kind: PrincipalKind) -> Authenticated {
    Authenticated::new(scheme, kind, PRINCIPAL, Some(tenant()))
}

fn rss_user_authed() -> Authenticated {
    Authenticated::new_rss_user_for_test(PRINCIPAL, tenant())
}

fn permission_binding(
    path: &'static str,
    resource: Option<&'static str>,
    self_scoped: bool,
) -> vocab::HttpRouteBinding<PermissionRouteMarker, vocab::http::LocalOnly> {
    vocab::HttpRouteBinding::from_static(
        vocab::HttpContractOwner::domain("test"),
        TEST_BINDING,
        path,
        "GET",
        &[],
        vocab::HttpSuccessStatus::new(200),
        vocab::HttpIdempotency::Idempotent,
        vocab::HttpRouteAuth::Permission(TEST_PERMISSION),
        resource,
        self_scoped,
        vocab::http::HttpResourceSharing::TenantScoped,
        vocab::HttpEffectProfile::new(TEST_EFFECTS),
    )
}

#[derive(Clone)]
struct AllowAuthorizer;

impl RouteAuthorizer for AllowAuthorizer {
    fn authorize<'a>(
        &'a self,
        _request: RouteAuthorizationRequest,
    ) -> Pin<Box<dyn Future<Output = RouteAuthorizationDecision> + Send + 'a>> {
        Box::pin(async {
            RouteAuthorizationDecision::Allow(RouteAuthorizationGrant::authorizer_local())
        })
    }
}

fn allow_authorizer() -> Arc<dyn RouteAuthorizer> {
    Arc::new(AllowAuthorizer)
}

#[allow(clippy::unwrap_used)]
fn finalize_primary_test(routes: UnfinalizedRoutes, plan: AuthPlan) -> AuthenticatedRoutes {
    finalize_primary_auth(routes, plan, allow_authorizer()).unwrap()
}

#[allow(clippy::unwrap_used)]
fn test_routes<L: httpserve::Listener>(
    build: impl FnOnce(
        httpserve::ListenerRouter<L>,
    ) -> Result<httpserve::ListenerRouter<L>, RouteGroupError>,
) -> UnfinalizedRoutes {
    httpserve::routes::unfinalized_for_test(build).unwrap()
}

#[derive(Clone)]
struct DenyAuthorizer;

impl RouteAuthorizer for DenyAuthorizer {
    fn authorize<'a>(
        &'a self,
        _request: RouteAuthorizationRequest,
    ) -> Pin<Box<dyn Future<Output = RouteAuthorizationDecision> + Send + 'a>> {
        Box::pin(async { RouteAuthorizationDecision::Deny })
    }
}

#[derive(Clone, Default)]
struct RecordingAuthorizer {
    seen: Arc<Mutex<Vec<RouteAuthorizationRequest>>>,
}

impl RouteAuthorizer for RecordingAuthorizer {
    fn authorize<'a>(
        &'a self,
        request: RouteAuthorizationRequest,
    ) -> Pin<Box<dyn Future<Output = RouteAuthorizationDecision> + Send + 'a>> {
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(request);
        Box::pin(async {
            RouteAuthorizationDecision::Allow(RouteAuthorizationGrant::authorizer_local())
        })
    }
}

// ── mount / 路由匹配 ─────────────────────────────────────────────────────────

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn mount_non_primary_route_is_reachable_after_finalize() {
    // 非-Primary Route（无 opt-out 字段）+ NoAuth plan（Health listener 允许）→ Allow → 200。
    let routes = test_routes::<httpserve::Health>(|rb| {
        rb.mount_raw_for_test(
            Route {
                method: Method::GET,
                path: "/internal/v1/ping",
                contract_id: C,
            },
            get(ok_handler),
        )
    });
    let plan = AuthPlan::none(ListenerKind::Health).unwrap();
    let router = httpserve::finalize_health(routes, plan)
        .unwrap()
        .into_plaintext_router_for_test();

    let resp = router
        .clone()
        .oneshot(empty_req(Method::GET, "/internal/v1/ping"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 未匹配路径 → 404。
    let resp = router
        .oneshot(empty_req(Method::GET, "/nope"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── Primary endpoint + finalize_auth：resolve_requirement HTTP 落地 ──────────

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn primary_public_opt_out_allows() {
    let routes = test_routes::<httpserve::Primary>(|rb| {
        rb.mount_primary_raw_for_test(
            PrimaryRoute::opt_out(Method::GET, "/api/v1/x", C, RouteAuthOptOut::Public),
            get(ok_handler),
        )
    });
    let router = finalize_primary_test(routes, primary_plan(AuthScheme::RssAccessToken))
        .into_plaintext_router_for_test();

    // Public opt-out → Allow → 200，即便 plan 要求 Jwt 且无 Authorization。
    let resp = router
        .oneshot(empty_req(Method::GET, "/api/v1/x"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn primary_public_opt_out_with_evidence_is_200() {
    // 保险：opt_out=Public 是 Allow 分支，存在 Authenticated 证据不改变结论（证据不破坏 Allow）→ 仍 200。
    let routes = test_routes::<httpserve::Primary>(|rb| {
        rb.mount_primary_raw_for_test(
            PrimaryRoute::opt_out(Method::GET, "/api/v1/x", C, RouteAuthOptOut::Public),
            get(ok_handler),
        )
    });
    let router = finalize_primary_test(routes, primary_plan(AuthScheme::RssAccessToken))
        .into_plaintext_router_for_test();

    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/x")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(rss_user_authed());
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn primary_require_without_credential_is_401() {
    let routes = test_routes::<httpserve::Primary>(|rb| {
        let endpoint = httpserve::GeneratedPrimaryEndpoint::new(
            permission_binding("/api/v1/x", None, false),
            ok_handler,
        )?;
        rb.mount(endpoint)
    });
    let router = finalize_primary_test(routes, primary_plan(AuthScheme::RssAccessToken))
        .into_plaintext_router_for_test();

    // Require(Jwt) + 无 Authorization → 401 + ERR_CORE_UNAUTHENTICATED。
    let resp = router
        .oneshot(empty_req(Method::GET, "/api/v1/x"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "ERR_CORE_UNAUTHENTICATED");
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn primary_require_is_fail_closed_401() {
    // fail-closed：httpserve 不验签——裸 Authorization header 非证据，仅请求携 Authenticated 证据
    // extension（验签桥外层 layer 注入）才放行，故带 header 仍 401（AUTH-EVIDENCE-REQUIRE-01）。
    let routes = test_routes::<httpserve::Primary>(|rb| {
        rb.mount_primary_raw_for_test(
            PrimaryRoute::permission(
                Method::GET,
                "/api/v1/x",
                C,
                RoutePermission {
                    permission: TEST_PERMISSION,
                    scope: RouteResourceScope::None,
                },
            ),
            get(ok_handler),
        )
    });
    let router = finalize_primary_test(routes, primary_plan(AuthScheme::RssAccessToken))
        .into_plaintext_router_for_test();

    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/x")
        .header(header::AUTHORIZATION, "Bearer test-token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn primary_require_with_authenticated_evidence_allows() {
    // AUTH-EVIDENCE-REQUIRE-01：Require(Jwt) 路由 + 请求携 Authenticated 证据 → 放行 200。
    // 证据由组合根验签桥（外层 layer）注入；此处直接 insert 到请求 extension 模拟该接缝。
    let routes = test_routes::<httpserve::Primary>(|rb| {
        let endpoint = httpserve::GeneratedPrimaryEndpoint::new(
            permission_binding("/api/v1/x", None, false),
            ok_handler,
        )?;
        rb.mount(endpoint)
    });
    let router = finalize_primary_test(routes, primary_plan(AuthScheme::RssAccessToken))
        .into_plaintext_router_for_test();

    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/x")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(rss_user_authed());
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn primary_permission_authorizer_deny_is_403() {
    let routes = test_routes::<httpserve::Primary>(|rb| {
        let endpoint = httpserve::GeneratedPrimaryEndpoint::new(
            permission_binding("/api/v1/x", None, false),
            ok_handler,
        )?;
        rb.mount(endpoint)
    });
    let router = finalize_primary_auth(
        routes,
        primary_plan(AuthScheme::RssAccessToken),
        Arc::new(DenyAuthorizer),
    )
    .unwrap()
    .into_plaintext_router_for_test();
    let mut req = empty_req(Method::GET, "/api/v1/x");
    req.extensions_mut().insert(rss_user_authed());
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn primary_self_scoped_permission_uses_principal_subject_resource() {
    let recorder = RecordingAuthorizer::default();
    let seen = Arc::clone(&recorder.seen);
    let routes = test_routes::<httpserve::Primary>(|rb| {
        let endpoint = httpserve::GeneratedPrimaryEndpoint::new(
            permission_binding("/api/v1/me", None, true),
            |_: httpserve::ContractMarker<PermissionRouteMarker>,
             axum::Extension(subject): axum::Extension<httpserve::AuthorizedSubject>| async move {
                subject.principal_id().to_string()
            },
        )?;
        rb.mount(endpoint)
    });
    let router = finalize_primary_auth(
        routes,
        primary_plan(AuthScheme::RssAccessToken),
        Arc::new(recorder),
    )
    .unwrap()
    .into_plaintext_router_for_test();
    let mut req = empty_req(Method::GET, "/api/v1/me");
    req.extensions_mut()
        .insert(Authenticated::new_rss_user_for_test(PRINCIPAL, tenant()));
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let seen = seen.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(seen[0].resource.as_ref().map(|r| r.id()), Some(PRINCIPAL));
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn primary_path_param_permission_uses_axum_decoded_resource() {
    let recorder = RecordingAuthorizer::default();
    let seen = Arc::clone(&recorder.seen);
    let routes = test_routes::<httpserve::Primary>(|rb| {
        let endpoint = httpserve::GeneratedPrimaryEndpoint::new(
            permission_binding("/api/v1/roles/{roleId}", Some("roleId"), false),
            ok_handler,
        )?;
        rb.mount(endpoint)
    });
    let router = finalize_primary_auth(
        routes,
        primary_plan(AuthScheme::RssAccessToken),
        Arc::new(recorder),
    )
    .unwrap()
    .into_plaintext_router_for_test();
    let resource = "22222222-3333-4444-8555-666666666666";
    let mut req = empty_req(Method::GET, &format!("/api/v1/roles/{resource}"));
    req.extensions_mut().insert(rss_user_authed());
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let seen = seen.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(seen[0].resource.as_ref().map(|r| r.id()), Some(resource));
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn primary_path_param_noncanonical_resource_denies_before_authorizer() {
    let recorder = RecordingAuthorizer::default();
    let seen = Arc::clone(&recorder.seen);
    let routes = test_routes::<httpserve::Primary>(|rb| {
        let endpoint = httpserve::GeneratedPrimaryEndpoint::new(
            permission_binding("/api/v1/roles/{roleId}", Some("roleId"), false),
            ok_handler,
        )?;
        rb.mount(endpoint)
    });
    let router = finalize_primary_auth(
        routes,
        primary_plan(AuthScheme::RssAccessToken),
        Arc::new(recorder),
    )
    .unwrap()
    .into_plaintext_router_for_test();
    let mut req = empty_req(Method::GET, "/api/v1/roles/role-123");
    req.extensions_mut().insert(rss_user_authed());
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
        "non-canonical resource must fail before PDP call"
    );
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn primary_require_with_mismatched_scheme_is_401() {
    // AUTH-EVIDENCE-REQUIRE-01 scheme exact-match：Require(Jwt) 路由 + Mtls 方案证据 → scheme 不匹配 → 401
    // （#1109 验签桥接入后杜绝 Jwt 证据过 Require(Mtls) 类 scheme 混淆）。
    let routes = test_routes::<httpserve::Primary>(|rb| {
        rb.mount_primary_raw_for_test(
            PrimaryRoute::permission(
                Method::GET,
                "/api/v1/x",
                C,
                RoutePermission {
                    permission: TEST_PERMISSION,
                    scope: RouteResourceScope::None,
                },
            ),
            get(ok_handler),
        )
    });
    let router = finalize_primary_test(routes, primary_plan(AuthScheme::RssAccessToken))
        .into_plaintext_router_for_test();

    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/x")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(authed(
        httpserve::NonRssTestScheme::Mtls,
        PrincipalKind::User,
    ));
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn primary_route_under_control_plane_plan_is_finalize_error() {
    // Primary route 不得用控制面 plan 装配；listener mismatch 在 finalize 阶段 fail-fast。
    let routes = test_routes::<httpserve::Primary>(|rb| {
        rb.mount_primary_raw_for_test(
            PrimaryRoute::opt_out(Method::GET, "/api/v1/x", C, RouteAuthOptOut::Public),
            get(ok_handler),
        )
    });
    let plan = AuthPlan::new(ListenerKind::Internal, AuthScheme::ServiceToken).unwrap();
    let result = finalize_auth(routes, plan);
    assert!(matches!(
        result,
        Err(RouteGroupError::ListenerMismatch { .. })
    ));
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn missing_finalize_auth_is_fail_closed_403() {
    // finalize_auth 未跑 → enforce 层读不到 AuthPlan → fail-closed Deny → 403。
    let routes = test_routes::<httpserve::Primary>(|rb| {
        rb.mount_primary_raw_for_test(
            PrimaryRoute::permission(
                Method::GET,
                "/api/v1/x",
                C,
                RoutePermission {
                    permission: TEST_PERMISSION,
                    scope: RouteResourceScope::None,
                },
            ),
            get(ok_handler),
        )
    });
    let router = routes.into_router_for_test();

    let resp = router
        .oneshot(empty_req(Method::GET, "/api/v1/x"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── requestId 中间件 ─────────────────────────────────────────────────────────

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn request_id_is_generated_on_response() {
    let routes = test_routes::<httpserve::Primary>(|rb| {
        rb.mount_primary_raw_for_test(
            PrimaryRoute::opt_out(Method::GET, "/api/v1/x", C, RouteAuthOptOut::Public),
            get(ok_handler),
        )
    });
    let router = finalize_primary_test(routes, primary_plan(AuthScheme::RssAccessToken))
        .into_plaintext_router_for_test();

    let resp = router
        .oneshot(empty_req(Method::GET, "/api/v1/x"))
        .await
        .unwrap();
    let rid = resp.headers().get(X_REQUEST_ID);
    assert!(rid.is_some(), "响应必须带 x-request-id");
    assert!(!rid.unwrap().is_empty());
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn incoming_request_id_is_echoed_and_in_envelope() {
    // 入站 X-Request-Id 透传到响应 header + 4xx envelope.requestId（enforce 层有 request 上下文）。
    let routes = test_routes::<httpserve::Primary>(|rb| {
        rb.mount_primary_raw_for_test(
            PrimaryRoute::permission(
                Method::GET,
                "/api/v1/x",
                C,
                RoutePermission {
                    permission: TEST_PERMISSION,
                    scope: RouteResourceScope::None,
                },
            ),
            get(ok_handler),
        )
    });
    let router = finalize_primary_test(routes, primary_plan(AuthScheme::RssAccessToken))
        .into_plaintext_router_for_test();

    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/x")
        .header(X_REQUEST_ID, "fixed-rid-123")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(resp.headers().get(X_REQUEST_ID).unwrap(), "fixed-rid-123");
    let json = body_json(resp).await;
    // envelope 形状（camelCase）：error.{code,message,details,requestId}。
    assert_eq!(json["error"]["requestId"], "fixed-rid-123");
    assert!(json["error"]["details"].is_array());
    assert!(json["error"]["message"].is_string());
}

// ── panic-recovery ───────────────────────────────────────────────────────────

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn handler_panic_becomes_500_envelope_without_leaking_payload() {
    // F2：request-aware panic 中间件——requestId 来自请求上下文，panic payload 不泄漏 wire。
    let routes = test_routes::<httpserve::Primary>(|rb| {
        rb.mount_primary_raw_for_test(
            PrimaryRoute::opt_out(Method::GET, "/api/v1/boom", C, RouteAuthOptOut::Public),
            get(panicking_handler),
        )
    });
    let router = finalize_primary_test(routes, primary_plan(AuthScheme::RssAccessToken))
        .into_plaintext_router_for_test();

    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/boom")
        .header(X_REQUEST_ID, "panic-rid")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    // panic 路径由最外层 request_id 中间件补 header。
    assert_eq!(resp.headers().get(X_REQUEST_ID).unwrap(), "panic-rid");
    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "ERR_CORE_INTERNAL");
    // 5xx 不泄 panic payload（message=const，无 runtime 数据）。
    assert!(
        !json.to_string().contains("kaboom-secret-internal"),
        "panic payload 不得进 wire"
    );
    // F2：request-aware 中间件——panic(500) body.requestId 已填充（来自请求 extension）。
    assert_eq!(
        json["error"]["requestId"], "panic-rid",
        "panic 路径 body.requestId 应来自请求上下文"
    );
}

// ── 补充鉴权边界测试（F8.4）────────────────────────────────────────────────────

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn admin_opt_out_is_403() {
    // Primary endpoint 不能被 Admin plan 装配，避免把 listener mismatch 固化成请求期 403 seam。
    let routes = test_routes::<httpserve::Primary>(|rb| {
        rb.mount_primary_raw_for_test(
            PrimaryRoute::opt_out(Method::GET, "/api/v1/x", C, RouteAuthOptOut::Public),
            get(ok_handler),
        )
    });
    let plan = AuthPlan::new(ListenerKind::Admin, AuthScheme::RssAccessToken).unwrap();
    let result = finalize_auth(routes, plan);
    assert!(matches!(
        result,
        Err(RouteGroupError::ListenerMismatch { .. })
    ));
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn primary_password_reset_exempt_allows() {
    // Primary + PasswordResetExempt opt-out → Allow → 200（无需 Authorization）。
    let routes = test_routes::<httpserve::Primary>(|rb| {
        rb.mount_primary_raw_for_test(
            PrimaryRoute::opt_out(
                Method::GET,
                "/api/v1/x",
                C,
                RouteAuthOptOut::PasswordResetExempt,
            ),
            get(ok_handler),
        )
    });
    let router = finalize_primary_test(routes, primary_plan(AuthScheme::RssAccessToken))
        .into_plaintext_router_for_test();

    let resp = router
        .oneshot(empty_req(Method::GET, "/api/v1/x"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn primary_noauth_plan_allows() {
    // Primary + NoAuth scheme + explicit opt-out → Allow → 200（无需 Authorization header）。
    let routes = test_routes::<httpserve::Primary>(|rb| {
        rb.mount_primary_raw_for_test(
            PrimaryRoute::opt_out(Method::GET, "/api/v1/x", C, RouteAuthOptOut::Public),
            get(ok_handler),
        )
    });
    let plan = AuthPlan::none(ListenerKind::Primary).unwrap();
    let router = finalize_primary_test(routes, plan).into_plaintext_router_for_test();

    let resp = router
        .oneshot(empty_req(Method::GET, "/api/v1/x"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── RouteMeta in request extension（F4）─────────────────────────────────────

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn route_meta_in_request_extension() {
    // ROUTE-META-PROPAGATE-01：handler 读取到构造 endpoint 时传入的同一 evidence。
    const META_CONTRACT: &str = "httpserve.test.meta";
    const META_EFFECTS: &[vocab::HttpEffectKind] =
        &[vocab::HttpEffectKind::Auth, vocab::HttpEffectKind::Read];
    enum MetaRouteMarker {}

    impl vocab::http::OpenHttpResponseMarker for MetaRouteMarker {}
    const META_BINDING: vocab::HttpRouteBinding<MetaRouteMarker, vocab::http::LocalOnly> =
        vocab::HttpRouteBinding::from_static(
            vocab::HttpContractOwner::domain("test"),
            vocab::ContractBinding::from_static(
                "test",
                META_CONTRACT,
                "v1",
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ),
            "/api/v1/meta",
            "GET",
            &[],
            vocab::HttpSuccessStatus::new(200),
            vocab::HttpIdempotency::Idempotent,
            vocab::HttpRouteAuth::Public,
            None,
            false,
            vocab::http::HttpResourceSharing::TenantScoped,
            vocab::HttpEffectProfile::new(META_EFFECTS),
        );

    async fn meta_handler(
        _: httpserve::ContractMarker<MetaRouteMarker>,
        axum::Extension(meta): axum::Extension<RouteMeta>,
    ) -> String {
        assert_eq!(*meta.evidence(), META_BINDING.evidence());
        assert_eq!(meta.method(), Method::GET);
        meta.contract_id().to_owned()
    }

    let routes = test_routes::<httpserve::Primary>(|rb| {
        let endpoint = httpserve::GeneratedPrimaryEndpoint::new(META_BINDING, meta_handler)?;
        rb.mount(endpoint)
    });
    let router = finalize_primary_test(routes, primary_plan(AuthScheme::RssAccessToken))
        .into_plaintext_router_for_test();

    let resp = router
        .oneshot(empty_req(Method::GET, "/api/v1/meta"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    assert_eq!(body, META_CONTRACT);
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn route_meta_exposes_both_declared_idempotency_classes() {
    enum IdempotentMarker {}

    impl vocab::http::OpenHttpResponseMarker for IdempotentMarker {}
    enum NonIdempotentMarker {}
    impl vocab::http::OpenHttpResponseMarker for NonIdempotentMarker {}
    const IDEMPOTENT_BINDING: vocab::HttpRouteBinding<IdempotentMarker, vocab::http::LocalOnly> =
        vocab::HttpRouteBinding::from_static(
            vocab::HttpContractOwner::domain("test"),
            TEST_BINDING,
            "/api/v1/wire-idempotent",
            "GET",
            &[],
            vocab::HttpSuccessStatus::new(200),
            vocab::HttpIdempotency::Idempotent,
            vocab::HttpRouteAuth::Public,
            None,
            false,
            vocab::http::HttpResourceSharing::TenantScoped,
            vocab::HttpEffectProfile::new(TEST_EFFECTS),
        );
    const NON_IDEMPOTENT_BINDING: vocab::HttpRouteBinding<
        NonIdempotentMarker,
        vocab::http::LocalOnly,
    > = vocab::HttpRouteBinding::from_static(
        vocab::HttpContractOwner::domain("test"),
        TEST_BINDING,
        "/api/v1/wire-non-idempotent",
        "POST",
        &[],
        vocab::HttpSuccessStatus::new(201),
        vocab::HttpIdempotency::NonIdempotent,
        vocab::HttpRouteAuth::Public,
        None,
        false,
        vocab::http::HttpResourceSharing::TenantScoped,
        vocab::HttpEffectProfile::new(TEST_EFFECTS),
    );

    async fn idempotent_handler(
        _: httpserve::ContractMarker<IdempotentMarker>,
        axum::Extension(meta): axum::Extension<RouteMeta>,
    ) -> StatusCode {
        assert_eq!(meta.success_status().get(), 200);
        assert_eq!(meta.idempotency(), vocab::HttpIdempotency::Idempotent);
        StatusCode::OK
    }

    async fn non_idempotent_handler(
        _: httpserve::ContractMarker<NonIdempotentMarker>,
        axum::Extension(meta): axum::Extension<RouteMeta>,
    ) -> StatusCode {
        assert_eq!(meta.success_status().get(), 201);
        assert_eq!(meta.idempotency(), vocab::HttpIdempotency::NonIdempotent);
        StatusCode::CREATED
    }

    let routes = test_routes::<httpserve::Primary>(|rb| {
        let rb = rb.mount(httpserve::GeneratedPrimaryEndpoint::new(
            IDEMPOTENT_BINDING,
            idempotent_handler,
        )?)?;
        rb.mount(httpserve::GeneratedPrimaryEndpoint::new(
            NON_IDEMPOTENT_BINDING,
            non_idempotent_handler,
        )?)
    });
    let router = finalize_primary_test(routes, primary_plan(AuthScheme::RssAccessToken))
        .into_plaintext_router_for_test();

    let idempotent = router
        .clone()
        .oneshot(empty_req(Method::GET, "/api/v1/wire-idempotent"))
        .await
        .unwrap();
    assert_eq!(idempotent.status(), StatusCode::OK);
    let non_idempotent = router
        .oneshot(empty_req(Method::POST, "/api/v1/wire-non-idempotent"))
        .await
        .unwrap();
    assert_eq!(non_idempotent.status(), StatusCode::CREATED);
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn declared_success_status_drift_fails_closed() {
    enum DriftMarker {}

    impl vocab::http::OpenHttpResponseMarker for DriftMarker {}
    const DRIFT_BINDING: vocab::HttpRouteBinding<DriftMarker, vocab::http::LocalOnly> =
        vocab::HttpRouteBinding::from_static(
            vocab::HttpContractOwner::domain("test"),
            TEST_BINDING,
            "/api/v1/wire-status-drift",
            "POST",
            &[],
            vocab::HttpSuccessStatus::new(201),
            vocab::HttpIdempotency::NonIdempotent,
            vocab::HttpRouteAuth::Public,
            None,
            false,
            vocab::http::HttpResourceSharing::TenantScoped,
            vocab::HttpEffectProfile::new(TEST_EFFECTS),
        );

    async fn drifted_handler(_: httpserve::ContractMarker<DriftMarker>) -> StatusCode {
        StatusCode::OK
    }

    let routes = test_routes::<httpserve::Primary>(|rb| {
        rb.mount(httpserve::GeneratedPrimaryEndpoint::new(
            DRIFT_BINDING,
            drifted_handler,
        )?)
    });
    let router = finalize_primary_test(routes, primary_plan(AuthScheme::RssAccessToken))
        .into_plaintext_router_for_test();

    let response = router
        .oneshot(empty_req(Method::POST, "/api/v1/wire-status-drift"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body_json(response).await["error"]["code"],
        "ERR_CORE_INTERNAL"
    );
}

// ── success-status serving contract ──────────────────────────────────────────

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn undeclared_redirect_status_fails_closed() {
    enum RedirectMarker {}

    impl vocab::http::OpenHttpResponseMarker for RedirectMarker {}
    const REDIRECT_BINDING: vocab::HttpRouteBinding<RedirectMarker, vocab::http::LocalOnly> =
        vocab::HttpRouteBinding::from_static(
            vocab::HttpContractOwner::domain("test"),
            TEST_BINDING,
            "/api/v1/wire-status-redirect",
            "POST",
            &[],
            vocab::HttpSuccessStatus::new(201),
            vocab::HttpIdempotency::NonIdempotent,
            vocab::HttpRouteAuth::Public,
            None,
            false,
            vocab::http::HttpResourceSharing::TenantScoped,
            vocab::HttpEffectProfile::new(TEST_EFFECTS),
        );

    async fn redirect_handler(_: httpserve::ContractMarker<RedirectMarker>) -> StatusCode {
        StatusCode::FOUND
    }

    let routes = test_routes::<httpserve::Primary>(|rb| {
        rb.mount(httpserve::GeneratedPrimaryEndpoint::new(
            REDIRECT_BINDING,
            redirect_handler,
        )?)
    });
    let router = finalize_primary_test(routes, primary_plan(AuthScheme::RssAccessToken))
        .into_plaintext_router_for_test();

    let response = router
        .oneshot(empty_req(Method::POST, "/api/v1/wire-status-redirect"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body_json(response).await["error"]["code"],
        "ERR_CORE_INTERNAL"
    );
}

// ── health builders ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn healthz_is_200() {
    let routes =
        httpserve::health::routes(|| primitives::HealthReport::aggregate(vec![]), String::new);
    let router = httpserve::finalize_health(routes, AuthPlan::none(ListenerKind::Health).unwrap())
        .unwrap()
        .into_plaintext_router_for_test();
    let resp = router
        .oneshot(empty_req(Method::GET, "/health/v1/healthz"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[test]
#[allow(clippy::unwrap_used)]
fn health_authenticated_plan_is_rejected_before_serving() {
    for scheme in [
        AuthScheme::RssAccessToken,
        AuthScheme::Mtls,
        AuthScheme::ServiceToken,
        AuthScheme::FederatedAccessToken,
    ] {
        let routes =
            httpserve::health::routes(|| primitives::HealthReport::aggregate(vec![]), String::new);
        let plan = AuthPlan::new(ListenerKind::Health, scheme).unwrap();

        assert!(matches!(
            httpserve::finalize_health(routes, plan),
            Err(RouteGroupError::UnsupportedAuthPlan {
                listener: ListenerKind::Health,
                scheme: actual,
            }) if actual == scheme
        ));
    }
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn readyz_reflects_aggregated_health() {
    use primitives::{HealthCheck, HealthReport, HealthStatus, ProbeName};

    // 全 Healthy → 200。
    let healthy = || {
        HealthReport::aggregate(vec![HealthCheck::new(
            ProbeName::parse("db").unwrap(),
            HealthStatus::Healthy,
            "ok",
        )])
    };
    let router = httpserve::finalize_health(
        httpserve::health::routes(healthy, String::new),
        AuthPlan::none(ListenerKind::Health).unwrap(),
    )
    .unwrap()
    .into_plaintext_router_for_test();
    let resp = router
        .oneshot(empty_req(Method::GET, "/health/v1/readyz"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 含 Unhealthy → 503。
    let unhealthy = || {
        HealthReport::aggregate(vec![HealthCheck::new(
            ProbeName::parse("db").unwrap(),
            HealthStatus::Unhealthy,
            "down",
        )])
    };
    let router = httpserve::finalize_health(
        httpserve::health::routes(unhealthy, String::new),
        AuthPlan::none(ListenerKind::Health).unwrap(),
    )
    .unwrap()
    .into_plaintext_router_for_test();
    let resp = router
        .oneshot(empty_req(Method::GET, "/health/v1/readyz"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    // 空 checks（fail-closed→Unhealthy）→ 503。
    let empty = || HealthReport::aggregate(vec![]);
    let router = httpserve::finalize_health(
        httpserve::health::routes(empty, String::new),
        AuthPlan::none(ListenerKind::Health).unwrap(),
    )
    .unwrap()
    .into_plaintext_router_for_test();
    let resp = router
        .oneshot(empty_req(Method::GET, "/health/v1/readyz"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

struct HandlerDropSignal(Arc<AtomicBool>);

impl Drop for HandlerDropSignal {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn server_budget_times_out_whole_request_with_shared_envelope_and_drops_handler() {
    let dropped = Arc::new(AtomicBool::new(false));
    let routes = test_routes::<httpserve::Health>(|rb| {
        let dropped = Arc::clone(&dropped);
        rb.mount_raw_for_test(
            Route {
                method: Method::GET,
                path: "/slow",
                contract_id: "httpserve.test.slow",
            },
            get(move || {
                let dropped = Arc::clone(&dropped);
                async move {
                    let _drop_signal = HandlerDropSignal(dropped);
                    std::future::pending::<()>().await;
                    "unreachable"
                }
            }),
        )
    });
    let budget = httpserve::ServerRequestBudget::from_millis(NonZeroU64::new(20).unwrap());
    let router = httpserve::finalize_health(routes, AuthPlan::none(ListenerKind::Health).unwrap())
        .unwrap()
        .into_plaintext_router_for_test_with_budget(budget);

    let request = Request::builder()
        .method(Method::GET)
        .uri("/slow")
        .header(X_REQUEST_ID, "budget-rid")
        .header("x-correlation-id", "budget-correlation")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[X_REQUEST_ID], "budget-rid");
    assert_eq!(response.headers()["x-correlation-id"], "budget-correlation");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    let body = body_json(response).await;
    assert_eq!(body["error"]["code"], "ERR_CORE_UNAVAILABLE");
    assert_eq!(body["error"]["requestId"], "budget-rid");
    assert_eq!(body["error"]["retryable"], false);
    assert!(dropped.load(Ordering::Acquire));
}
