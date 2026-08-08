//! Regression proof: an external wrapper around the public request core cannot mint RSS's
//! transport-owned HTTP server observations.

#![allow(clippy::unwrap_used)]

use axum::body::Body;
use axum::http::{Request, uri::Scheme};
use axum::routing::get;
use tower::ServiceExt as _;

#[tokio::test]
async fn forged_scheme_around_core_emits_no_official_http_server_metrics() {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let service = httpserve::ServerService::from_router_for_test(
        axum::Router::new().route("/", get(|| async { "ok" })),
        httpserve::ServerRequestBudget::for_test(),
    );
    let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();
    request.extensions_mut().insert(Scheme::HTTPS);

    let response = metrics::with_local_recorder(&recorder, || service.oneshot(request))
        .await
        .unwrap();
    metrics::with_local_recorder(&recorder, || drop(response));

    let rendered = handle.render();
    assert!(
        !rendered.contains("http_server_request_duration")
            && !rendered.contains("http_server_active_requests"),
        "the unbound core must not emit transport evidence: {rendered}"
    );
}
