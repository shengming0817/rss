//! Health endpoint builders：healthz（liveness）和 readyz（readiness）。
//!
//! DTO 为 wire 类型（非 domain entity），derive Serialize 合规。
//! `readyz` 的 `report` 参数用 `Fn() -> HealthReport` 闭包，每请求调用一次；
//! 每请求 clone 闭包满足 axum Handler 的 `Fn` 语义。
//!
//! ref: tokio-rs/axum examples/health-check.rs@main（健康端点范式）

use axum::http::StatusCode;
use primitives::{HealthReport, HealthStatus};
use serde::Serialize;

/// Liveness DTO（wire 类型，camelCase，Serialize 合规）。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LivenessDto {
    status: &'static str,
}

/// Readiness 聚合 DTO（wire 类型，camelCase，Serialize 合规）。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadyzDto {
    overall: &'static str,
    checks: Vec<CheckDto>,
}

/// 单条 probe DTO（wire 类型）。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckDto {
    name: String,
    status: &'static str,
    detail: &'static str,
}

impl ReadyzDto {
    fn from_report(r: &HealthReport) -> Self {
        Self {
            overall: r.overall().as_label(),
            checks: r
                .checks()
                .iter()
                .map(|c| CheckDto {
                    name: c.name().as_str().to_owned(),
                    status: c.status().as_label(),
                    detail: c.detail(),
                })
                .collect(),
        }
    }
}

/// liveness 端点：恒 200 `{"status":"ok"}`（存活即活）。
fn healthz() -> axum::routing::MethodRouter {
    axum::routing::get(|| async { (StatusCode::OK, axum::Json(LivenessDto { status: "ok" })) })
}

/// readiness 端点：聚合 `report()` 的 `HealthReport`；Unhealthy → 503，否则 200。
///
/// `report` 是 `Fn() -> HealthReport`——每请求调用一次，配合 `Clone` 满足 axum Handler 语义。
///
/// Degraded→200（运行但降级）：HTTP 状态仅区分 serving(200)/not-ready(503)，消费方解析
/// body.overall 判精确态（k8s readiness probe 据 2xx 判健康，Degraded 实例仍接流量是有意设计）。
fn readyz<F>(report: F) -> axum::routing::MethodRouter
where
    F: Fn() -> HealthReport + Clone + Send + Sync + 'static,
{
    axum::routing::get(move || {
        let report = report.clone();
        async move {
            let r = report();
            let overall = r.overall();
            let status = if overall == HealthStatus::Unhealthy {
                let failed: Vec<&str> = r
                    .checks()
                    .iter()
                    .filter(|c| c.status() != HealthStatus::Healthy)
                    .map(|c| c.name().as_str())
                    .collect();
                tracing::warn!(
                    overall = overall.as_label(),
                    failed_count = failed.len(),
                    failed_probes = ?failed,
                    "readyz not ready"
                );
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                if overall == HealthStatus::Degraded {
                    let degraded: Vec<&str> = r
                        .checks()
                        .iter()
                        .filter(|c| c.status() != HealthStatus::Healthy)
                        .map(|c| c.name().as_str())
                        .collect();
                    tracing::info!(
                        overall = "degraded",
                        degraded_count = degraded.len(),
                        degraded_probes = ?degraded,
                        "readyz degraded but serving"
                    );
                }
                StatusCode::OK
            };
            (status, axum::Json(ReadyzDto::from_report(&r)))
        }
    })
}

/// Prometheus exposition content-type（`metrics_exporter_prometheus` 渲染的 text exposition 标准 media type）。
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// `/metrics` 端点：渲染当前指标快照为 Prometheus exposition 文本（content-type [`PROMETHEUS_CONTENT_TYPE`]）。
///
/// `render` 是 `Fn() -> String`——每请求调用一次取 exposition body，配合 `Clone` 满足 axum Handler 语义（同
/// [`readyz`] 范式）。渲染源（组合根注入的 `Arc<dyn diport::MetricsExporter>` 等）由调用方决定，handler 层只渲染 +
/// 设 content-type，**不耦合** `diport`（保持 httpserve 对导出 provider 无知）。
///
/// 挂在 `Health` listener（health/ready/metrics 内部网络面）；固定 builder 不接受 route-level auth
/// metadata，故 `/metrics` 与 healthz/readyz 只服从 Health listener auth plan。
///
/// ref: tokio-rs/axum examples/health-check.rs@main（健康/探针端点 MethodRouter 范式）
fn metrics<F>(render: F) -> axum::routing::MethodRouter
where
    F: Fn() -> String + Clone + Send + Sync + 'static,
{
    axum::routing::get(move || {
        let render = render.clone();
        async move {
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
                render(),
            )
        }
    })
}

/// Build the fixed framework-owned health listener routes.
///
/// This is the only production API for mounting health, readiness, and metrics endpoints. Their
/// paths and methods are fixed inside `httpserve`; callers can only supply the dynamic report and
/// metrics render functions.
/// Opaque framework-owned health surface. Only this module can mint one.
pub struct HealthRoutes(pub(crate) axum::Router);

pub fn router<R, M>(report: R, render: M) -> HealthRoutes
where
    R: Fn() -> HealthReport + Clone + Send + Sync + 'static,
    M: Fn() -> String + Clone + Send + Sync + 'static,
{
    HealthRoutes(
        axum::Router::new()
            .route("/healthz", healthz())
            .route("/readyz", readyz(report))
            .route("/metrics", metrics(render)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use primitives::{HealthCheck, HealthReport, HealthStatus, ProbeName};
    use tower::ServiceExt;

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn healthz_is_200_with_ok_status() {
        let app = Router::new().route("/healthz", healthz());
        let req = Request::builder()
            .method(Method::GET)
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["status"], "ok");
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn readyz_healthy_is_200() {
        let app = Router::new().route(
            "/readyz",
            readyz(|| {
                HealthReport::aggregate(vec![HealthCheck::new(
                    ProbeName::parse("db").unwrap(),
                    HealthStatus::Healthy,
                    "ok",
                )])
            }),
        );
        let req = Request::builder()
            .method(Method::GET)
            .uri("/readyz")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn readyz_unhealthy_is_503() {
        let app = Router::new().route(
            "/readyz",
            readyz(|| {
                HealthReport::aggregate(vec![HealthCheck::new(
                    ProbeName::parse("db").unwrap(),
                    HealthStatus::Unhealthy,
                    "down",
                )])
            }),
        );
        let req = Request::builder()
            .method(Method::GET)
            .uri("/readyz")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn readyz_degraded_is_200() {
        // Degraded 不是 Unhealthy，返回 200（运行但降级）。
        let app = Router::new().route(
            "/readyz",
            readyz(|| {
                HealthReport::aggregate(vec![HealthCheck::new(
                    ProbeName::parse("cache").unwrap(),
                    HealthStatus::Degraded,
                    "slow",
                )])
            }),
        );
        let req = Request::builder()
            .method(Method::GET)
            .uri("/readyz")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn readyz_empty_checks_is_503() {
        // fail-closed：无探针 → Unhealthy → 503。
        let app = Router::new().route("/readyz", readyz(|| HealthReport::aggregate(vec![])));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/readyz")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn readyz_response_body_has_overall_and_checks() {
        let app = Router::new().route(
            "/readyz",
            readyz(|| {
                HealthReport::aggregate(vec![HealthCheck::new(
                    ProbeName::parse("db").unwrap(),
                    HealthStatus::Healthy,
                    "ok",
                )])
            }),
        );
        let req = Request::builder()
            .method(Method::GET)
            .uri("/readyz")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["overall"], "healthy");
        assert!(json["checks"].is_array());
        assert_eq!(json["checks"][0]["name"], "db");
        assert_eq!(json["checks"][0]["status"], "healthy");
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn metrics_renders_exposition_with_prometheus_content_type() {
        // 渲染源（组合根注入的 Arc<dyn MetricsExporter> 等）经闭包注入；handler 设 Prometheus exposition content-type。
        let app = Router::new().route("/metrics", metrics(|| "rss_unit_total 1\n".to_owned()));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            PROMETHEUS_CONTENT_TYPE // 断言绑定 const 单源，content-type 变更不漂移
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("rss_unit_total"), "body: {body}");
    }
}
