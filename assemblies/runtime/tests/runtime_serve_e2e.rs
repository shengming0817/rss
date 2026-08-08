//! 运行时入口冒烟 e2e（#1320 DoD：绑真实 socket + serve + 优雅关停）。
//!
//! 经 fingerprint-verified RuntimePlan test-support façade 进入生产 Health finalizer，再
//! `into_server_service`
//! 交 `httpd::HttpServer` bind **真实 ephemeral socket** + `axum::serve` ——发真 HTTP 请求验证：
//! - readyz 反映探针聚合（Healthy 探针 → 200；空探针 → 503 fail-closed）；
//! - liveness `/health/v1/healthz` 恒 200；
//! - 响应带 `x-request-id`（request_id 中间件经唯一 bindable 出口封在最外层，跨真实 socket 生效，
//!   ROUTE-REQUESTID-OUTERMOST-01）；
//! - `ManagedResource::shutdown` 优雅关停后 serve task 收敛、后续连接被拒（socket 已释放）。
//!
//! **hermetic**：不依赖 postgres / env（pg-backed `run()` 全链路属 integration gate）；只验运行时入口骨架。

use std::net::SocketAddr;
use std::sync::Arc;

use diport::ManagedResource as _;
use httpd::HttpServer;
use primitives::{HealthCheck, HealthStatus, ProbeName};

mod common;
use common::{FixedMetrics, noop_metrics};

fn test_budget() -> httpserve::ServerRequestBudget {
    httpserve::ServerRequestBudget::for_test()
}

/// 健康探针替身（Healthy）。
struct HealthyProbe;
impl bootstrap::HealthProbe for HealthyProbe {
    #[allow(clippy::expect_used)]
    fn check(&self) -> HealthCheck {
        HealthCheck::new(
            ProbeName::parse("e2e").expect("probe name"),
            HealthStatus::Healthy,
            "ready",
        )
    }
}

/// 用给定探针集构造 reporter → health_listener → httpd bind 真实 socket，返回 server（已 serve）。
#[allow(clippy::expect_used)]
async fn serve_health(with_healthy_probe: bool) -> HttpServer {
    let mut reg = bootstrap::compose(&[]).expect("compose");
    if with_healthy_probe {
        reg.probe(
            ProbeName::parse("e2e").expect("probe name"),
            Box::new(HealthyProbe),
        )
        .expect("register probe");
    }
    let reporter = Arc::new(reg.take_health_reporter());
    let authed = runtime::test_support::finalize_health_listener(reporter, noop_metrics())
        .expect("health listener");
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    HttpServer::serve(
        "http-health",
        addr,
        authed.into_server_service(test_budget()),
    )
    .await
    .expect("bind + serve real socket")
}

/// 绑真实 socket → 真 HTTP readyz 200 + 带 x-request-id → liveness 200 → 优雅关停 → 后续连接被拒。
#[tokio::test]
#[allow(clippy::expect_used)]
async fn health_listener_serves_over_real_socket_then_graceful_shutdown() {
    let server = serve_health(true).await;
    let addr = server.local_addr();
    let client = reqwest::Client::new();

    // readyz：Healthy 探针 → 200，且响应带框架注入的 x-request-id（跨真实 socket 验 request_id 最外层封口）。
    let resp = client
        .get(format!("http://{addr}/health/v1/readyz"))
        .send()
        .await
        .expect("readyz request over real socket");
    assert_eq!(resp.status().as_u16(), 200, "Healthy 探针 → readyz 200");
    assert!(
        resp.headers().get("x-request-id").is_some(),
        "响应须带 x-request-id（request_id 中间件经 bindable 出口封最外层）"
    );

    // liveness 恒 200。
    let live = client
        .get(format!("http://{addr}/health/v1/healthz"))
        .send()
        .await
        .expect("healthz request");
    assert_eq!(live.status().as_u16(), 200, "liveness 恒 200");

    // 优雅关停：ManagedResource::shutdown 触发 graceful drain + await serve task 收敛干净。
    server.shutdown().await.expect("graceful shutdown clean");

    // 关停后 socket 已释放：后续连接被拒（不再 serve）。
    let after = client
        .get(format!("http://{addr}/health/v1/healthz"))
        .send()
        .await;
    assert!(after.is_err(), "优雅关停后 socket 已释放，后续请求应失败");
}

/// `/metrics` 经真实 socket 渲染 Prometheus exposition（200 + content-type + body 含指标名）——
/// 验证组合根把注入的 `Arc<dyn MetricsExporter>` 接到 Health listener 的 `/health/v1/metrics` 路由。
#[tokio::test]
#[allow(clippy::expect_used)]
async fn metrics_endpoint_renders_exposition_over_real_socket() {
    let mut reg = bootstrap::compose(&[]).expect("compose");
    let reporter = Arc::new(reg.take_health_reporter());
    // 固定 exposition 替身（含已知指标名），验证 render 出口接到了 /metrics 路由。
    let exporter: Arc<dyn diport::MetricsExporter> = Arc::new(FixedMetrics("rss_e2e_total 7\n"));
    let authed = runtime::test_support::finalize_health_listener(reporter, exporter)
        .expect("health listener");
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let server = HttpServer::serve(
        "http-health",
        addr,
        authed.into_server_service(test_budget()),
    )
    .await
    .expect("bind + serve real socket");
    let local = server.local_addr();

    let resp = reqwest::Client::new()
        .get(format!("http://{local}/health/v1/metrics"))
        .send()
        .await
        .expect("metrics request over real socket");
    assert_eq!(resp.status().as_u16(), 200, "/metrics → 200");
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("text/plain; version=0.0.4; charset=utf-8"),
        "/metrics content-type 为 Prometheus exposition media type"
    );
    let body = resp.text().await.expect("metrics body");
    assert!(
        body.contains("rss_e2e_total"),
        "exposition body 应含注入替身的指标名: {body}"
    );

    server.shutdown().await.expect("graceful shutdown clean");
}

/// 空探针集 → readyz 503（fail-closed）跨真实 socket 生效。
#[tokio::test]
#[allow(clippy::expect_used)]
async fn readyz_fail_closed_503_over_real_socket() {
    let server = serve_health(false).await;
    let addr = server.local_addr();

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/health/v1/readyz"))
        .send()
        .await
        .expect("readyz request");
    assert_eq!(
        resp.status().as_u16(),
        503,
        "空探针 → readyz fail-closed 503"
    );

    server.shutdown().await.expect("graceful shutdown clean");
}

/// **生产关停路径** SHUTDOWN-TOKEN-FUNNEL-01：bind → `ShutdownStack::register_with_token` 同步 funnel
/// 闭包内 `bound.serve(svc, token)` spawn（消费注入的 child token）→ 真请求 200 → `stack.shutdown()`
/// 阶段1广播 cancel + 阶段2 LIFO await 收敛无失败。区别于上面 detached `HttpServer::serve` 便捷构造。
#[tokio::test]
#[allow(clippy::expect_used)]
async fn serve_via_shutdownstack_funnel_path() {
    use bootstrap::shutdown::ShutdownStack;
    use diport::DynManagedResource;
    use tokio_util::sync::CancellationToken;

    let mut reg = bootstrap::compose(&[]).expect("compose");
    reg.probe(
        ProbeName::parse("e2e").expect("name"),
        Box::new(HealthyProbe),
    )
    .expect("register probe");
    let reporter = Arc::new(reg.take_health_reporter());
    let authed = runtime::test_support::finalize_health_listener(reporter, noop_metrics())
        .expect("health listener");
    let svc = authed.into_server_service(test_budget());

    let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let bound = HttpServer::bind("http-health", addr)
        .await
        .expect("bind real socket");
    let local = bound.local_addr();

    // 生产 funnel：register_with_token 注入 child token，同步闭包内 bound.serve spawn serve task。
    let mut stack = ShutdownStack::new(CancellationToken::new());
    stack.register_with_token(move |token| DynManagedResource::new_box(bound.serve(svc, token)));

    let resp = reqwest::Client::new()
        .get(format!("http://{local}/health/v1/readyz"))
        .send()
        .await
        .expect("readyz over funnel-served socket");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "funnel 路径 serve → readyz 200"
    );

    // 阶段1广播 cancel 触发 axum graceful drain，阶段2 LIFO await serve task 收敛。
    let failures = stack.shutdown().await;
    assert!(
        failures.is_empty(),
        "ShutdownStack 优雅 drain 无失败: {failures:?}"
    );
}
