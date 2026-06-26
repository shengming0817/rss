//! HTTP 中间件：requestId 注入 + tracing span + panic recovery。
//!
//! `request_id`：接收或生成 `x-request-id`，写入 extensions，回填到响应 header。
//! `trace`：用 `tracing::Instrument` 包裹 `next.run`，不跨 await 持有 span guard。
//! `panic_recovery`：request-aware panic → 500 envelope（带 requestId，panic payload 不泄漏）。
//!
//! ref: tokio-rs/axum axum/src/middleware/from_fn.rs@main

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use futures::FutureExt;

const X_REQUEST_ID: &str = "x-request-id";

/// 入站 `X-Request-Id` 长度上限：超出则丢弃并生成新 UUID（防超大值污染 span/日志）。
const MAX_REQUEST_ID_LEN: usize = 128;

/// 请求 ID newtype（存入 extensions 供 enforce 层读取）。
#[derive(Clone, Debug)]
pub(crate) struct RequestId(pub(crate) String);

impl RequestId {
    /// 借出请求 id 字符串（供 [`crate::request_id_str`] 给组合根外层中间件读 request 关联）。
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// 中间件：接收 / 生成 `x-request-id`，注入 extensions，回填响应 header。
pub(crate) async fn request_id(mut req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get(X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .filter(|s| !s.is_empty() && s.len() <= MAX_REQUEST_ID_LEN)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    req.extensions_mut().insert(RequestId(id.clone()));

    let mut resp = next.run(req).await;

    if let Ok(val) = axum::http::HeaderValue::from_str(&id) {
        resp.headers_mut().insert(
            axum::http::header::HeaderName::from_static(X_REQUEST_ID),
            val,
        );
    }

    resp
}

/// 中间件：创建 `http.request` tracing span，不持有 guard 跨 await。
///
/// `status` 字段声明为 `Empty`，在响应返回后由 `span.record` 回填（可观测性：响应状态码可查）。
pub(crate) async fn trace(req: Request, next: Next) -> Response {
    let rid = req
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0.clone())
        .unwrap_or_default();
    let span = tracing::info_span!(
        "http.request",
        method = %req.method(),
        path = %req.uri().path(),
        request_id = %rid,
        status = tracing::field::Empty,
    );
    use tracing::Instrument;
    let resp = next.run(req).instrument(span.clone()).await;
    span.record("status", resp.status().as_u16());
    resp
}

/// 中间件：request-aware panic recovery → 500 envelope（requestId 来自请求 extension）。
///
/// 须在 trace 内侧挂载（panic_recovery 的 500 Response 对 trace 可见），在 request_id 外侧（
/// request_id 最外层，确保 panic 路径响应也回填 x-request-id header）。
///
/// panic payload 不解析、不泄漏：`_panic` 直接丢弃，仅用静态错误码生成 envelope。
pub(crate) async fn panic_recovery(req: Request, next: Next) -> Response {
    let rid = req
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0.clone())
        .unwrap_or_default();
    match std::panic::AssertUnwindSafe(next.run(req))
        .catch_unwind()
        .await
    {
        Ok(resp) => resp,
        // panic payload 不解析、不泄漏；统一 envelope，requestId 来自 request 上下文。
        Err(_panic) => crate::error::internal_error(&rid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::routing::get;
    use axum::{Router, middleware};
    use tower::ServiceExt;

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn request_id_generates_when_missing() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(middleware::from_fn(request_id));

        let req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let rid_header = resp.headers().get(X_REQUEST_ID);
        assert!(rid_header.is_some());
        assert!(!rid_header.unwrap().is_empty());
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn request_id_echoes_incoming() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(middleware::from_fn(request_id));

        let req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(X_REQUEST_ID, "my-fixed-id")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.headers().get(X_REQUEST_ID).unwrap().to_str().unwrap(),
            "my-fixed-id"
        );
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn request_id_rejects_oversized() {
        // F2：超过 MAX_REQUEST_ID_LEN(128) 的入站值被丢弃，生成新 UUID。
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(middleware::from_fn(request_id));

        let oversized = "x".repeat(129);
        let req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(X_REQUEST_ID, oversized.as_str())
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let rid = resp.headers().get(X_REQUEST_ID).unwrap().to_str().unwrap();
        // 超大值不得原样透传到响应。
        assert_ne!(rid, oversized.as_str(), "超大 request-id 不应透传");
        // 应生成新 UUID（非空）。
        assert!(!rid.is_empty());
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn request_id_ignores_empty_header() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(middleware::from_fn(request_id));

        let req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(X_REQUEST_ID, "")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        // 空 header 应被忽略，生成新 UUID。
        let rid = resp.headers().get(X_REQUEST_ID).unwrap().to_str().unwrap();
        assert!(!rid.is_empty());
        assert_ne!(rid, "");
    }
}
