//! httpserve 运行时切片 contract 测试（mock 驱动，`tower::ServiceExt::oneshot`）。
//!
//! 覆盖：mount/mount_primary 路由挂载 + finalize_auth 鉴权闸（resolve_requirement→200/401/403、
//! 缺 plan fail-closed）+ wire error envelope（`vocab::CoreError`→`{"error":{...,requestId}}`）+
//! requestId 中间件 + panic-recovery（→500 envelope）+ health builders（healthz/readyz）。
//!
//! 测试断言用 unwrap/expect：item-level carve-out（error-handling.md §Carve-out）。
//!
//! 注：本 contract 测试**不** feature-gate——rust-standards §命名的 `#[cfg(feature="integration")]`
//! 隔离针对需外部资源（DB/broker/网络）的集成测试；本测试全程 in-process（axum oneshot、
//! 确定性、毫秒级），是 `cargo test` 默认验收门，故有意不隔离（同 journeys/tests）。

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use axum::routing::get;
use primitives::{AuthPlan, AuthScheme, ListenerKind, RequiredScheme, RouteAuthOptOut};
use tower::ServiceExt; // oneshot
use vocab::PrincipalKind;

use httpserve::{
    Authenticated, PrimaryRoute, Route, RouteMeta, finalize_auth, mount, mount_primary,
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

async fn ok_handler() -> &'static str {
    "ok"
}

// item-level carve-out（workspace panic="deny"；test-only 故意 panic 验证 catch-panic 中间件）。
#[allow(clippy::panic)]
async fn panicking_handler() -> axum::response::Response {
    panic!("kaboom-secret-internal")
}

const C: &str = "httpserve.test";
const X_REQUEST_ID: &str = "x-request-id";

// ── mount / 路由匹配 ─────────────────────────────────────────────────────────

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn mount_non_primary_route_is_reachable_after_finalize() {
    // 非-Primary Route（无 opt-out 字段）+ NoAuth plan（Health listener 允许）→ Allow → 200。
    let router = mount(
        Router::new(),
        Route {
            method: Method::GET,
            path: "/internal/v1/ping",
            contract_id: C,
        },
        get(ok_handler),
    );
    let plan = AuthPlan::none(ListenerKind::Health).unwrap();
    let router = finalize_auth(router, plan).unwrap();

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

// ── mount_primary + finalize_auth：resolve_requirement HTTP 落地 ──────────────

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn primary_public_opt_out_allows() {
    let router = mount_primary(
        Router::new(),
        PrimaryRoute {
            method: Method::GET,
            path: "/api/v1/x",
            contract_id: C,
            opt_out: Some(RouteAuthOptOut::Public),
        },
        get(ok_handler),
    );
    let router = finalize_auth(router, primary_plan(AuthScheme::Jwt)).unwrap();

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
    let router = mount_primary(
        Router::new(),
        PrimaryRoute {
            method: Method::GET,
            path: "/api/v1/x",
            contract_id: C,
            opt_out: Some(RouteAuthOptOut::Public),
        },
        get(ok_handler),
    );
    let router = finalize_auth(router, primary_plan(AuthScheme::Jwt)).unwrap();

    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/x")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(Authenticated::new(RequiredScheme::Jwt, PrincipalKind::User));
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn primary_require_without_credential_is_401() {
    let router = mount_primary(
        Router::new(),
        PrimaryRoute {
            method: Method::GET,
            path: "/api/v1/x",
            contract_id: C,
            opt_out: None,
        },
        get(ok_handler),
    );
    let router = finalize_auth(router, primary_plan(AuthScheme::Jwt)).unwrap();

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
    let router = mount_primary(
        Router::new(),
        PrimaryRoute {
            method: Method::GET,
            path: "/api/v1/x",
            contract_id: C,
            opt_out: None,
        },
        get(ok_handler),
    );
    let router = finalize_auth(router, primary_plan(AuthScheme::Jwt)).unwrap();

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
    let router = mount_primary(
        Router::new(),
        PrimaryRoute {
            method: Method::GET,
            path: "/api/v1/x",
            contract_id: C,
            opt_out: None,
        },
        get(ok_handler),
    );
    let router = finalize_auth(router, primary_plan(AuthScheme::Jwt)).unwrap();

    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/x")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(Authenticated::new(RequiredScheme::Jwt, PrincipalKind::User));
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn primary_require_with_mismatched_scheme_is_401() {
    // AUTH-EVIDENCE-REQUIRE-01 scheme exact-match：Require(Jwt) 路由 + Mtls 方案证据 → scheme 不匹配 → 401
    // （#1109 验签桥接入后杜绝 Jwt 证据过 Require(Mtls) 类 scheme 混淆）。
    let router = mount_primary(
        Router::new(),
        PrimaryRoute {
            method: Method::GET,
            path: "/api/v1/x",
            contract_id: C,
            opt_out: None,
        },
        get(ok_handler),
    );
    let router = finalize_auth(router, primary_plan(AuthScheme::Jwt)).unwrap();

    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/x")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(Authenticated::new(
        RequiredScheme::Mtls,
        PrincipalKind::User,
    ));
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn primary_route_finalized_under_control_plane_plan_is_403() {
    // 残留 seam fail-closed：Primary route 带 opt-out，却在控制面（Internal）plan 下 finalize
    // → resolve_requirement = Deny → 403 ERR_CORE_FORBIDDEN（AUTH-FAILCLOSED-01 的 HTTP 落地）。
    let router = mount_primary(
        Router::new(),
        PrimaryRoute {
            method: Method::GET,
            path: "/api/v1/x",
            contract_id: C,
            opt_out: Some(RouteAuthOptOut::Public),
        },
        get(ok_handler),
    );
    let plan = AuthPlan::new(ListenerKind::Internal, AuthScheme::ServiceToken).unwrap();
    let router = finalize_auth(router, plan).unwrap();

    let resp = router
        .oneshot(empty_req(Method::GET, "/api/v1/x"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "ERR_CORE_FORBIDDEN");
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn missing_finalize_auth_is_fail_closed_403() {
    // finalize_auth 未跑 → enforce 层读不到 AuthPlan → fail-closed Deny → 403。
    let router = mount_primary(
        Router::new(),
        PrimaryRoute {
            method: Method::GET,
            path: "/api/v1/x",
            contract_id: C,
            opt_out: None,
        },
        get(ok_handler),
    );

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
    let router = mount_primary(
        Router::new(),
        PrimaryRoute {
            method: Method::GET,
            path: "/api/v1/x",
            contract_id: C,
            opt_out: Some(RouteAuthOptOut::Public),
        },
        get(ok_handler),
    );
    let router = finalize_auth(router, primary_plan(AuthScheme::Jwt)).unwrap();

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
    let router = mount_primary(
        Router::new(),
        PrimaryRoute {
            method: Method::GET,
            path: "/api/v1/x",
            contract_id: C,
            opt_out: None,
        },
        get(ok_handler),
    );
    let router = finalize_auth(router, primary_plan(AuthScheme::Jwt)).unwrap();

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
    let router = mount_primary(
        Router::new(),
        PrimaryRoute {
            method: Method::GET,
            path: "/api/v1/boom",
            contract_id: C,
            opt_out: Some(RouteAuthOptOut::Public),
        },
        get(panicking_handler),
    );
    let router = finalize_auth(router, primary_plan(AuthScheme::Jwt)).unwrap();

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
    // Admin listener + opt-out Public → Deny → 403（控制面 listener 永不降级）。
    let router = mount_primary(
        Router::new(),
        PrimaryRoute {
            method: Method::GET,
            path: "/api/v1/x",
            contract_id: C,
            opt_out: Some(RouteAuthOptOut::Public),
        },
        get(ok_handler),
    );
    let plan = AuthPlan::new(ListenerKind::Admin, AuthScheme::Jwt).unwrap();
    let router = finalize_auth(router, plan).unwrap();

    let resp = router
        .oneshot(empty_req(Method::GET, "/api/v1/x"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "ERR_CORE_FORBIDDEN");
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn primary_password_reset_exempt_allows() {
    // Primary + PasswordResetExempt opt-out → Allow → 200（无需 Authorization）。
    let router = mount_primary(
        Router::new(),
        PrimaryRoute {
            method: Method::GET,
            path: "/api/v1/x",
            contract_id: C,
            opt_out: Some(RouteAuthOptOut::PasswordResetExempt),
        },
        get(ok_handler),
    );
    let router = finalize_auth(router, primary_plan(AuthScheme::Jwt)).unwrap();

    let resp = router
        .oneshot(empty_req(Method::GET, "/api/v1/x"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn primary_noauth_plan_allows() {
    // Primary + NoAuth scheme（AuthPlan::none）→ Allow → 200（无需 Authorization header）。
    let router = mount_primary(
        Router::new(),
        PrimaryRoute {
            method: Method::GET,
            path: "/api/v1/x",
            contract_id: C,
            opt_out: None,
        },
        get(ok_handler),
    );
    let plan = AuthPlan::none(ListenerKind::Primary).unwrap();
    let router = finalize_auth(router, plan).unwrap();

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
    // F4：enforce 层将 RouteMeta 插入请求 extension，handler 可读取 contract_id。
    const META_CONTRACT: &str = "httpserve.test.meta";

    async fn meta_handler(axum::Extension(meta): axum::Extension<RouteMeta>) -> String {
        meta.contract_id.to_owned()
    }

    let router = mount_primary(
        Router::new(),
        PrimaryRoute {
            method: Method::GET,
            path: "/api/v1/meta",
            contract_id: META_CONTRACT,
            opt_out: Some(RouteAuthOptOut::Public),
        },
        get(meta_handler),
    );
    let router = finalize_auth(router, primary_plan(AuthScheme::Jwt)).unwrap();

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

// ── health builders ──────────────────────────────────────────────────────────

#[tokio::test]
#[allow(clippy::unwrap_used)]
async fn healthz_is_200() {
    let router = Router::new().route("/healthz", httpserve::health::healthz());
    let resp = router
        .oneshot(empty_req(Method::GET, "/healthz"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
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
    let router = Router::new().route("/readyz", httpserve::health::readyz(healthy));
    let resp = router
        .oneshot(empty_req(Method::GET, "/readyz"))
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
    let router = Router::new().route("/readyz", httpserve::health::readyz(unhealthy));
    let resp = router
        .oneshot(empty_req(Method::GET, "/readyz"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    // 空 checks（fail-closed→Unhealthy）→ 503。
    let empty = || HealthReport::aggregate(vec![]);
    let router = Router::new().route("/readyz", httpserve::health::readyz(empty));
    let resp = router
        .oneshot(empty_req(Method::GET, "/readyz"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}
