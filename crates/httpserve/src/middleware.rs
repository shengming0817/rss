//! HTTP 中间件：requestId 注入 + correlation 诊断信道绑定 + tracing span + panic recovery。
//!
//! `request_id`：接收或生成 `x-request-id`，写入 extensions，回填到响应 header。
//! `correlation`：解析 `x-correlation-id`（回退链：入站 header → RequestId → UUID v4），
//!   经 `diagctx::scope` 绑定 [`diagctx::DiagnosticCtx`]，回填响应 header（ADR-002 §D1-bis）。
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

/// 入站 `X-Correlation-ID` header 名（小写，axum HeaderName 约定）。
const CORRELATION_HEADER: &str = "x-correlation-id";

/// 生成 UUID v4 并包装为 `CorrelationId`（此入口 parse 不可失败，UUID 字符集满足白名单）。
///
/// UUID v4 字符集 `[0-9a-f-]` ⊆ `CorrelationId` 白名单 `[A-Za-z0-9._-]`、长度 36 ≤ 128、非空 ⇒
/// `CorrelationId::parse` 在此入口**不可失败**（编译期可知的结构事实）。
///
/// item-level `expect_used` carve-out（error-handling.md §Carve-out）：
/// reason: UUID v4 满足 `CorrelationId` 的全部约束，parse 不可失败，`expect` 在此等价于不可达断言。
#[allow(clippy::expect_used)]
fn new_uuid_correlation_id() -> diagctx::CorrelationId {
    // reason: UUID v4 chars [0-9a-f-] ⊆ [A-Za-z0-9._-], len=36 ≤ 128, non-empty → parse infallible.
    diagctx::CorrelationId::parse(&uuid::Uuid::new_v4().to_string())
        .expect("uuid-v4-always-valid-correlation-id")
}

/// 中间件：解析 `X-Correlation-ID`，绑定 [`diagctx::DiagnosticCtx`] 诊断信道，回填响应 header。
///
/// **回退链**（按优先级）：
/// 1. 入站 `X-Correlation-ID` header（经 [`diagctx::CorrelationId::parse`] 校验）；
/// 2. 已注入的 [`RequestId`] extension（`request_id` 中间件为本层外层，先行运行）经 `CorrelationId::parse`
///    再校验（UUID v4 形态在白名单内，通常成功）；
/// 3. 生成 UUID v4（保底，与 `request_id` 同款 `uuid` crate）。
///
/// 挂载位置：`request_id` 内侧（[`crate::routes::AuthenticatedRoutes::sealed_router`]，
/// ROUTE-CORRELATION-INNER-REQUESTID-01）：request_id 先行保证 `RequestId` extension 在场；
/// `diagctx::scope` 包住验签桥 + handler + application + adapter emit，下游 outbox emit 可
/// 经 [`diagctx::correlation`] 读回 correlation id。
///
/// ADR-002 §D1-bis：correlation 是诊断信号，**不进** `runctx::RequestCtx`，经 `diagctx` 独立信道传播。
///
/// **跨服务约定**：调用方如需贯通跨服务事件/审计关联链路，须在请求携带 `X-Correlation-ID`
/// （白名单 `[A-Za-z0-9._-]`、≤128）；缺失时服务自动生成 UUID 保底，但跨服务链路不贯通。
pub(crate) async fn correlation(req: Request, next: Next) -> Response {
    // 回退链第 1 步：尝试入站 X-Correlation-ID。
    let from_header = req
        .headers()
        .get(CORRELATION_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| diagctx::CorrelationId::parse(s).ok());

    // 回退链第 2 步：入站 header 无效时读 RequestId extension（request_id 中间件已注入）。
    let corr = from_header
        .or_else(|| {
            req.extensions()
                .get::<RequestId>()
                .and_then(|r| diagctx::CorrelationId::parse(r.as_str()).ok())
        })
        // 回退链第 3 步：生成 UUID v4 保底。
        .unwrap_or_else(new_uuid_correlation_id);

    let corr_str = corr.as_str().to_owned();
    let ctx = diagctx::DiagnosticCtx::new(corr);

    let mut resp = diagctx::scope(ctx, next.run(req)).await;

    // 响应回填 X-Correlation-ID（镜像 request_id 的 echo；解析失败不致命）。
    if let Ok(val) = axum::http::HeaderValue::from_str(&corr_str) {
        resp.headers_mut().insert(
            axum::http::header::HeaderName::from_static(CORRELATION_HEADER),
            val,
        );
    }

    resp
}

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
/// `correlation` 从 ambient `diagctx`（correlation middleware 已在更外层绑定）读入 span 字段——入口请求
/// span 与 outbox envelope 的 `correlation` 同 key，使事件链路可反查入口请求（无 scope 时空串，F2 review）。
pub(crate) async fn trace(req: Request, next: Next) -> Response {
    let rid = req
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0.clone())
        .unwrap_or_default();
    let correlation = diagctx::correlation();
    let span = tracing::info_span!(
        "http.request",
        method = %req.method(),
        path = %req.uri().path(),
        request_id = %rid,
        correlation = correlation.as_ref().map_or("", |c| c.as_str()),
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

    // ── correlation middleware 测试 ──────────────────────────────────────────────────────────────

    /// 构建标准双层测试栈：request_id（外层）→ correlation（内层）→ handler。
    /// 保证 correlation 能从 request_id 中间件已注入的 RequestId extension 读到回退值。
    fn stacked_app(handler: axum::routing::MethodRouter) -> Router {
        Router::new()
            .route("/", handler)
            .layer(middleware::from_fn(correlation))
            .layer(middleware::from_fn(request_id))
    }

    /// 入站合法 `X-Correlation-ID` 透传：响应回填同值。
    #[allow(clippy::unwrap_used)]
    // reason: 测试层断言 HTTP 响应/header；tower oneshot Result + header Option 输入均已控制，unwrap 等价 assert。
    #[tokio::test]
    async fn correlation_echoes_valid_incoming_header() {
        let app = stacked_app(get(|| async { "ok" }));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(CORRELATION_HEADER, "my-trace-id-42")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let cid = resp
            .headers()
            .get(CORRELATION_HEADER)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cid, "my-trace-id-42");
    }

    /// 缺失 `X-Correlation-ID` → 回退到 `RequestId`：响应 `X-Correlation-ID` 应等于 `X-Request-ID`。
    ///
    /// 验证回退链第 2 步：`request_id` 先行注入的 `RequestId` extension 被 `correlation` 读回并采纳。
    #[allow(clippy::unwrap_used)]
    // reason: 测试层断言 HTTP 响应/header；tower oneshot Result + header Option 输入均已控制，unwrap 等价 assert。
    #[tokio::test]
    async fn correlation_falls_back_to_request_id_when_header_absent() {
        let app = stacked_app(get(|| async { "ok" }));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(X_REQUEST_ID, "req-id-fallback")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let cid = resp
            .headers()
            .get(CORRELATION_HEADER)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            cid, "req-id-fallback",
            "缺失 correlation header 须回退到 request_id 值"
        );
        // X-Request-ID 应同时存在且一致（request_id 中间件回填）。
        let rid = resp.headers().get(X_REQUEST_ID).unwrap().to_str().unwrap();
        assert_eq!(rid, "req-id-fallback");
    }

    /// 非法 `X-Correlation-ID`（超长 > 128）→ 回退 RequestId，不 500。
    ///
    /// 验证回退链：`CorrelationIdError::TooLong` → 被 `.ok()` 转 `None` → 进入第 2 步回退。
    #[allow(clippy::unwrap_used)]
    // reason: 测试层断言 HTTP 响应/header；tower oneshot Result + header Option 输入均已控制，unwrap 等价 assert。
    #[tokio::test]
    async fn correlation_rejects_oversized_header_falls_back() {
        let oversized = "x".repeat(129); // len=129 > MAX_CORRELATION_ID_LEN(128)
        let app = stacked_app(get(|| async { "ok" }));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(X_REQUEST_ID, "valid-req-id")
            .header(CORRELATION_HEADER, oversized.as_str())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "非法 correlation 不应导致 500"
        );
        let cid = resp
            .headers()
            .get(CORRELATION_HEADER)
            .unwrap()
            .to_str()
            .unwrap();
        assert_ne!(cid, oversized.as_str(), "超长 correlation 不应被采纳");
        assert_eq!(cid, "valid-req-id", "须回退到 request_id 值");
    }

    /// 入站 `X-Correlation-ID` 含非白名单字符（空格）→ 回退 RequestId，不 500。
    ///
    /// 覆盖 parse 拒绝 → 回退分支的中间件层端到端：非白名单字符导致 `CorrelationId::parse`
    /// 返回 `Err` → `.ok()` 转 `None` → 进入 RequestId 回退（第 2 步）→ 非法值不采纳、非 500。
    #[allow(clippy::unwrap_used)]
    // reason: 测试层断言 HTTP 响应/header；tower oneshot Result + header Option 输入均已控制，unwrap 等价 assert。
    #[tokio::test]
    async fn correlation_rejects_invalid_chars_falls_back() {
        let app = stacked_app(get(|| async { "ok" }));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(X_REQUEST_ID, "valid-req-id")
            .header(CORRELATION_HEADER, "bad id") // 含空格，非白名单字符
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "非法 correlation 不应导致 500"
        );
        let cid = resp
            .headers()
            .get(CORRELATION_HEADER)
            .unwrap()
            .to_str()
            .unwrap();
        assert_ne!(cid, "bad id", "含非白名单字符的 correlation 不应被采纳");
        assert_eq!(cid, "valid-req-id", "须回退到 request_id 值");
    }

    /// 无任何 header → UUID v4 保底：响应仍有非空 `X-Correlation-ID`。
    ///
    /// 验证回退链第 3 步（`new_uuid_correlation_id`）在两层都缺失时生效。
    #[allow(clippy::unwrap_used)]
    // reason: 测试层断言 HTTP 响应/header；tower oneshot Result + header Option 输入均已控制，unwrap 等价 assert。
    #[tokio::test]
    async fn correlation_generates_uuid_when_both_headers_absent() {
        // 仅 correlation middleware，没有 request_id → RequestId extension 不存在 → 走 UUID 保底。
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(middleware::from_fn(correlation));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let cid = resp.headers().get(CORRELATION_HEADER);
        assert!(cid.is_some(), "无 header 时须生成保底 UUID");
        assert!(!cid.unwrap().is_empty(), "保底 x-correlation-id 非空");
    }

    /// `diagctx::correlation()` 在 correlation 内侧中间件可见（scope 覆盖 `next.run` 全链）。
    ///
    /// INVARIANT: ROUTE-CORRELATION-INNER-REQUESTID-01 的层序核心不变式：探针中间件运行时
    /// `diagctx::correlation()` 须返回 `Some`，证明 diagctx scope 已由 correlation 中间件绑定。
    #[allow(clippy::unwrap_used)]
    // reason: 测试层断言 HTTP 响应/header；tower oneshot Result + header Option 输入均已控制，unwrap 等价 assert。
    #[tokio::test]
    async fn diagctx_correlation_visible_in_inner_middleware() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            // 探针层：在 correlation scope 内读 diagctx::correlation()，在场则写 marker header。
            .layer(middleware::from_fn(
                |req: axum::extract::Request, next: axum::middleware::Next| async move {
                    let saw = diagctx::correlation().is_some();
                    let mut resp = next.run(req).await;
                    if saw {
                        resp.headers_mut()
                            .insert("x-saw-diagctx", axum::http::HeaderValue::from_static("1"));
                    }
                    resp
                },
            ))
            .layer(middleware::from_fn(correlation))
            .layer(middleware::from_fn(request_id));

        let req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(CORRELATION_HEADER, "probe-corr-42")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.headers().get("x-saw-diagctx").map(|v| v.as_bytes()),
            Some(&b"1"[..]),
            "correlation 内层中间件须能读到 diagctx::correlation()（scope 已由 correlation 中间件绑定）"
        );
    }

    // F2（review）：`http.request` span 的 `correlation` 字段记录 `diagctx::correlation()`（入口 span ↔
    // outbox envelope 同 `correlation` key，事件链路可反查入口请求）。字段写入是 `info_span!` 宏的编译期事实；
    // 「correlation 在 trace 中间件层可读」由上方 `diagctx_correlation_visible_in_inner_middleware` 覆盖
    // （trace 与该探针同为 correlation scope 内层）。span 字段值的运行期断言需 process-isolated tracing
    // subscriber harness（`cargo test` 线程并行与 tracing 全局 callsite interest 缓存竞争）——本仓无此先例
    // （既有 `request_id` 进 span 同样未做字段级单测），不为单字段引入 racy harness。
}
