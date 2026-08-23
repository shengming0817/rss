//! HTTP 中间件：全请求 server budget + requestId 注入 + correlation 诊断信道绑定 + panic recovery。
//!
//! `request_id`：接收或生成 `x-request-id`，写入 extensions，回填到响应 header。
//! `correlation`：解析 `x-correlation-id`（回退链：入站 header → RequestId → UUID v4），
//!   经 `diagctx::scope` 绑定 [`diagctx::DiagnosticCtx`]，回填响应 header（ADR-002 §D1-bis）。
//! `server_request_budget`：drop 超时的完整 request future，返回统一 503 envelope（outcome 未知，
//!   `retryable=false`）。
//! `observation metadata`：仅回传 MatchedPath/闭值 cause 给 transport-owned observation seam。
//! `panic_recovery`：request-aware panic → 500 envelope（带 requestId，panic payload 不泄漏）。
//!
//! ref: tokio-rs/axum axum/src/middleware/from_fn.rs@main

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use diport::{RateLimitDecision, RateLimitKey, RateLimiter};
use futures::FutureExt;
use std::sync::Arc;

const X_REQUEST_ID: &str = "x-request-id";

/// 入站 `X-Request-Id` 长度上限：超出则丢弃并生成新 UUID（防超大值污染 span/日志）。

/// 入站 `X-Correlation-ID` header 名（小写，axum HeaderName 约定）。
const CORRELATION_HEADER: &str = "x-correlation-id";

/// 生成 UUID v4 并包装为 `CorrelationId`（此入口 parse 不可失败，UUID 字符集满足白名单）。
///
/// UUID v4 字符集 `[0-9a-f-]` ⊆ `CorrelationId` 白名单 `[A-Za-z0-9._-]`、长度 36 ≤ 128、非空 ⇒
/// `CorrelationId::parse` 在此入口**不可失败**（编译期可知的结构事实）。
///
/// item-level `expect_used` carve-out：
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
/// 2. 已注入的 [`VerifiedRequestId`] extension（`request_id` 中间件为本层外层，先行运行）经 `CorrelationId::parse`
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
                .get::<VerifiedRequestId>()
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

/// Enforce the non-zero wall-clock budget for the complete request future below the HTTP edge.
///
/// This layer is inside request-id/correlation setup and outside body/auth/handler processing. On
/// expiry Tokio drops `next.run(req)`, so an in-flight verifier, body reader, downstream call, or
/// handler cannot keep consuming a request task. The response uses the shared 503 envelope with
/// `retryable=false` because the request outcome is unknown, and emits only closed decision fields
/// plus the request correlation handle.
pub(crate) async fn server_request_budget(
    State(budget): State<crate::ServerRequestBudget>,
    mut req: Request,
    next: Next,
) -> Response {
    let request_id = req
        .extensions()
        .get::<VerifiedRequestId>()
        .map_or_else(String::new, |request_id| request_id.as_str().to_owned());
    let control = crate::budget::RequestControl::start(budget);
    req.extensions_mut().insert(control.clone());
    let _cancel_on_drop = crate::budget::CancelRequestOnDrop(control.clone());
    match tokio::time::timeout_at(control.deadline().instant().into(), next.run(req)).await {
        Ok(response) => response,
        Err(_elapsed) => {
            tracing::warn!(
                decision = "unavailable",
                reason = "server_request_budget_exhausted",
                request_id = %request_id,
                budget_ms = budget.millis().get(),
                "http server request budget exhausted"
            );
            mark_response_cause(
                crate::error::service_unavailable(&request_id),
                crate::server_observation::ServerResponseCause::timeout(),
            )
        }
    }
}

/// Request ID verified and minted by the transport middleware.
#[derive(Clone, Debug)]
pub struct VerifiedRequestId(requestidmint::WireRequestId);

impl VerifiedRequestId {
    pub(crate) fn from_middleware(value: String) -> Self {
        let request_id = rss_request_context::RequestId::parse(&value)
            .expect("HTTP middleware must validate request IDs before minting provenance");
        Self(requestidmint::WireRequestId::from_http_middleware(
            request_id,
        ))
    }

    /// 借出请求 id 字符串（供 [`crate::request_id_str`] 给组合根外层中间件读 request 关联）。
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Consume the transport proof at a generated typed response factory.
    #[must_use]
    pub fn into_wire(self) -> requestidmint::WireRequestId {
        self.0
    }

    /// Test-only mint for domain harnesses that do not execute the sealed middleware stack.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn for_test(value: impl Into<String>) -> Self {
        Self::from_middleware(value.into())
    }
}

/// 中间件：接收 / 生成 `x-request-id`，注入 extensions，回填响应 header。
pub(crate) async fn request_id(mut req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get(X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .filter(|value| rss_request_context::RequestId::parse(value).is_ok())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    req.extensions_mut()
        .insert(VerifiedRequestId::from_middleware(id.clone()));

    let mut resp = next.run(req).await;

    if let Ok(val) = axum::http::HeaderValue::from_str(&id) {
        resp.headers_mut().insert(
            axum::http::header::HeaderName::from_static(X_REQUEST_ID),
            val,
        );
    }

    resp
}

/// Preserve only Axum's matched route template for the transport-owned observation seam.
pub(crate) async fn http_server_observation_metadata(req: Request, next: Next) -> Response {
    let route = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(crate::server_observation::ServerObservationRoute::from_matched_path);
    let mut response = next.run(req).await;
    if let Some(route) = route {
        response.extensions_mut().insert(route);
    }
    response
}

fn mark_response_cause(
    mut response: Response,
    cause: crate::server_observation::ServerResponseCause,
) -> Response {
    response.extensions_mut().insert(cause);
    response
}

/// 中间件：Content-Length 检查 + stream-level 字节硬顶——超过 [`crate::protect::BodyLimit`] 上限则拦截。
///
/// 两层防护（互补，不互斥）：
/// 1. **CL fast-reject（before-auth clean 413）**：声明 `Content-Length` 超限 → 预知拒（pre-auth，
///    token 验证前 clean 413，`ERR_CORE_PAYLOAD_TOO_LARGE`）。
/// 2. **stream-level 字节硬顶（read-time，内存有界，非 before-auth 413）**：用
///    [`http_body_util::Limited`] 重包请求体——无声明或 chunked 体在**读取阶段**超限时返回 error，
///    内存被钳在 limit，防 DoS 内存耗尽。
///    // reason: 不选 option (a)（auth 前主动 buffer 全部请求体）：auth 前为未认证请求 buffer ≤limit
///    // 字节回归 unauth DoS 姿态；Limited wrap 下，未认证请求经 enforce 401 时 body **从不被读/buffer**，
///    // DoS 姿态更优（安全目标[内存有界]已由 Limited 达成，无需 option a）。
///
/// INVARIANT: BODYLIMIT-BEFORE-AUTH-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（精确语义）：
///   · **CL-declared 超限 → before-auth clean 413**（层1 fast-reject，auth 计算 + body 读取双重开销可避免）。
///   · **无声明/chunked → `http_body_util::Limited` 字节硬顶（read-time）**，内存有界，非 before-auth 413。
///     未认证请求经 enforce 401 时 body 从不被读 ⇒ 无 pre-auth buffer（DoS 优姿态，见 reason 注释）。
///   body-limit **层** outer 于 auth 验签桥；CL 路径拒绝决策 before-auth。
///
/// 通过 [`axum::middleware::from_fn_with_state`] 注入 [`crate::protect::BodyLimit`] 状态；
/// `sealed_router` 以 `EdgeHardening::body_limit` 填充，默认 1 MiB。
pub(crate) async fn body_limit(
    State(limit): State<crate::protect::BodyLimit>,
    req: Request,
    next: Next,
) -> Response {
    let rid = req
        .extensions()
        .get::<VerifiedRequestId>()
        .map(|r| r.0.as_str())
        .unwrap_or("")
        .to_owned();

    // 层1 CL fast-reject：声明超限 → 预知拒（pre-auth clean 413，token 验证前提前拦截）。
    let content_length = req
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    if let Some(len) = content_length
        && len > limit.bytes() as u64
    {
        tracing::warn!(
            content_length = len,
            limit = limit.bytes(),
            request_id = %rid,
            "body-limit exceeded (Content-Length fast-reject)"
        );
        return crate::error::payload_too_large(&rid);
    }

    // 层2 stream-level 字节硬顶：Limited wrap 钳制 body 读取字节数上限。
    // reason: 攻击者省略 Content-Length（chunked/流式）绕过层1时，层2钳制内存上限（防 DoS 内存耗尽）。
    let (parts, body) = req.into_parts();
    let limited = http_body_util::Limited::new(body, limit.bytes());
    let req = Request::from_parts(parts, axum::body::Body::new(limited));
    next.run(req).await
}

#[derive(Clone, Copy)]
enum RateLimitOutcome {
    Allowed,
    Limited,
    ProviderError,
    UnknownAllowed,
}

impl RateLimitOutcome {
    const fn as_label(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Limited => "limited",
            Self::ProviderError => "provider_error",
            Self::UnknownAllowed => "unknown_allowed",
        }
    }
}

fn record_rate_limit(outcome: RateLimitOutcome) {
    metrics::counter!(
        "http.server.rate_limit.decisions",
        "outcome" => outcome.as_label()
    )
    .increment(1);
}

struct ProviderFailureEpisode(std::sync::atomic::AtomicBool);

impl ProviderFailureEpisode {
    const fn new() -> Self {
        Self(std::sync::atomic::AtomicBool::new(false))
    }

    fn recover(&self) {
        self.0.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    fn begins(&self) -> bool {
        !self.0.swap(true, std::sync::atomic::Ordering::Relaxed)
    }
}

static RATE_LIMIT_PROVIDER_FAILURE_EPISODE: ProviderFailureEpisode = ProviderFailureEpisode::new();

/// Seal the production client-identification/rate-limit order around authenticated routes.
///
/// Axum applies the last layer outermost, so this sole funnel always yields
/// `RealIP -> rate-limit -> auth`; callers cannot install the limiter without supplying the closed
/// trusted-proxy policy.
pub fn with_client_rate_limit<S>(
    routes: crate::AuthenticatedRoutes,
    limiter: Arc<S>,
    trusted_proxy_config: crate::TrustedProxyConfig,
) -> crate::RateLimitedRoutes
where
    S: RateLimiter + Send + Sync + 'static,
{
    let routes = routes.layer(axum::middleware::from_fn_with_state(
        limiter,
        rate_limit::<S>,
    ));
    crate::RateLimitedRoutes::new(routes.layer(crate::RealIpLayer::new(trusted_proxy_config)))
}

/// 中间件：IP 级限流——经 [`diport::RateLimiter`] port 判定，超配额则 429 Too Many Requests。
///
/// **fail-open**：限流器 provider 故障（`Err`）时放行请求，不因 provider 不可用拒正常用户。
/// 未来 [`diport::RateLimitDecision`] 新增 variant 同样 fail-open（`_` arm）。
///
/// # reason (fail-open)
/// 限流器是 best-effort 防护，provider 故障时服务可用性优先于限流保护；
/// 极端 DDoS 场景下网络层（CDN/WAF）应作第一道防线。
///
/// peer IP 来自 [`axum::extract::ConnectInfo<SocketAddr>`] extension（生产经 `httpd` 的私有 transport
/// make-service 注入；缺失时 fallback "unknown"——仅限 oneshot 单测环境）。
///
/// # INVARIANT: RATE-LIMIT-PEER-IP-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
/// 生产路径经 `httpd::TransportMakeService` 绑定，`ConnectInfo<SocketAddr>` 天然在场；oneshot 测试
/// 环境手动插入或留 "unknown"（均合法）。
pub async fn rate_limit<S>(State(limiter): State<Arc<S>>, req: Request, next: Next) -> Response
where
    S: RateLimiter + Send + Sync + 'static,
{
    let rid = req
        .extensions()
        .get::<VerifiedRequestId>()
        .map(|r| r.0.as_str())
        .unwrap_or("")
        .to_owned();

    // RealIpLayer owns proxy trust. Direct test/router users still fall back to the socket peer.
    let ip = req
        .extensions()
        .get::<crate::ResolvedClientIp>()
        .map(|resolved| resolved.get().to_string())
        .or_else(|| {
            req.extensions()
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|ci| ci.0.ip().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());

    let key = RateLimitKey::new(ip);

    match limiter.check(key).await {
        Ok(RateLimitDecision::Allowed) => {
            RATE_LIMIT_PROVIDER_FAILURE_EPISODE.recover();
            record_rate_limit(RateLimitOutcome::Allowed);
            next.run(req).await
        }
        Ok(RateLimitDecision::Limited { retry_after }) => {
            RATE_LIMIT_PROVIDER_FAILURE_EPISODE.recover();
            record_rate_limit(RateLimitOutcome::Limited);
            crate::error::too_many_requests(&rid, retry_after)
        }
        // reason: fail-open — 未知未来 variant 保守放行（non_exhaustive 演进窗口）。
        Ok(_) => {
            RATE_LIMIT_PROVIDER_FAILURE_EPISODE.recover();
            record_rate_limit(RateLimitOutcome::UnknownAllowed);
            next.run(req).await
        }
        Err(e) => {
            // reason: fail-open — 限流器 provider 故障时服务可用性优先。
            record_rate_limit(RateLimitOutcome::ProviderError);
            if RATE_LIMIT_PROVIDER_FAILURE_EPISODE.begins() {
                tracing::error!(
                    error = %e,
                    request_id = %rid,
                    resource = "listener_rate_limiter",
                    operation = "check",
                    reason = "provider_error",
                    fail_open = true,
                    "rate limiter check failed; fail-open"
                );
            }
            next.run(req).await
        }
    }
}

/// 中间件：request-aware panic recovery → 500 envelope（requestId 来自请求 extension）。
///
/// 须挂载在 trace 内侧，使 panic recovery 的 500 response 对 trace 可见；同时位于 request_id 内侧，
/// 由最外层 request_id 确保 panic 路径响应也回填 x-request-id header。
///
/// panic payload 不解析、不泄漏：`_panic` 直接丢弃，仅用静态错误码生成 envelope。
pub(crate) async fn panic_recovery(req: Request, next: Next) -> Response {
    let rid = req
        .extensions()
        .get::<VerifiedRequestId>()
        .map(|r| r.as_str().to_owned())
        .unwrap_or_default();
    match std::panic::AssertUnwindSafe(next.run(req))
        .catch_unwind()
        .await
    {
        Ok(resp) => resp,
        // panic payload 不解析、不泄漏；统一 envelope，requestId 来自 request 上下文。
        Err(_panic) => mark_response_cause(
            crate::error::internal_error(&rid),
            crate::server_observation::ServerResponseCause::panic(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_failure_episode_resets_after_recovery() {
        let episode = ProviderFailureEpisode::new();
        assert!(episode.begins());
        assert!(!episode.begins());
        episode.recover();
        assert!(episode.begins());
    }
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
        let oversized = "x".repeat(129); // len=129 > CorrelationId::MAX_LEN (128)
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
    /// INVARIANT: ROUTE-CORRELATION-INNER-REQUESTID-01 { level = "Medium", exec = "manual/opt-in", source = "code" }的层序核心不变式：探针中间件运行时
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

    // `http.server.request` 的 HTTP semantic fields 独立断言在 routes.rs 覆盖；这里保留
    // correlation scope 层序的局部探针。

    // ── body_limit 测试 ──────────────────────────────────────────────────────────────────────────

    #[allow(clippy::unwrap_used)]
    // reason: test helper — cap is always a hard-coded non-zero constant supplied by test callers.
    fn body_limit_app(cap: usize) -> Router {
        use axum::routing::any;
        Router::new()
            .route("/", any(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(
                crate::protect::BodyLimit::new(std::num::NonZeroUsize::new(cap).unwrap()),
                body_limit,
            ))
    }

    /// 大幅超限（CL=10000 >> cap=100）：与 `one_over_cap` 覆盖不同场景（批量超限 vs. 边界 cap+1）。
    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn body_limit_content_length_over_cap_returns_413() {
        let app = body_limit_app(100);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/")
            .header("content-length", "10000") // 大幅超限（批量超限场景）
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn body_limit_content_length_equal_cap_returns_200() {
        let app = body_limit_app(100);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/")
            .header("content-length", "100")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn body_limit_content_length_one_over_cap_returns_413() {
        let app = body_limit_app(100);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/")
            .header("content-length", "101")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn body_limit_no_content_length_passes_through() {
        let app = body_limit_app(100);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "无 Content-Length 放行");
    }

    /// stream-level cap（read-time，**非** before-auth 413）：无 Content-Length 但 body 超 limit → 读取被 Limited 钳住（非 200）。
    ///
    /// 这是 BODYLIMIT-BEFORE-AUTH-01 的**无 CL 路径**：`http_body_util::Limited` 字节硬顶在 read-time 生效，
    /// 内存有界。注意：此路径**不**产生 before-auth 413——CL fast-reject（层1）未触发，Limited 错误由实际读 body
    /// 的 handler 遇到；与 `body_limit_blocks_before_jwt_auth_tripwire`（CL 路径 before-auth 413）语义不同。
    ///
    /// 用实际读 body 的 handler（`to_bytes`）触发 `Limited` 错误；断言超限 body ≠ 200（cap 生效），limit 内 200。
    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn body_limit_no_cl_stream_over_cap_is_not_200() {
        use axum::response::IntoResponse;
        use axum::routing::post;

        // handler：实际读 body，触发 Limited 错误（如 handler 不读 body 则 Limited 不生效）。
        async fn read_body_handler(req: Request<Body>) -> impl IntoResponse {
            let body = req.into_body();
            // reason: usize::MAX 让 to_bytes 不加额外限制——只有 Limited wrap 控制字节上限。
            match axum::body::to_bytes(body, usize::MAX).await {
                Ok(bytes) => (StatusCode::OK, bytes.len().to_string()),
                Err(_) => (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    String::from("body limit exceeded"),
                ),
            }
        }

        let cap = 10usize;
        let app = Router::new().route("/", post(read_body_handler)).layer(
            // reason: cap = 10, known non-zero constant.
            middleware::from_fn_with_state(
                crate::protect::BodyLimit::new(std::num::NonZeroUsize::new(cap).unwrap()),
                body_limit,
            ),
        );

        // 超 limit 的 body（无 content-length header → CL fast-reject 不触发；Limited wrap 生效）。
        let req_large = Request::builder()
            .method(Method::POST)
            .uri("/")
            // 故意省略 content-length header，测 stream-level cap（层2防护）。
            .body(Body::from(vec![0u8; cap + 100]))
            .unwrap();
        let resp = app.clone().oneshot(req_large).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "超 limit 无 CL body → 读取被 Limited 钳住，非 200"
        );

        // limit 内的小 body → 200。
        let req_small = Request::builder()
            .method(Method::POST)
            .uri("/")
            .body(Body::from(vec![0u8; cap - 1]))
            .unwrap();
        let resp_small = app.oneshot(req_small).await.unwrap();
        assert_eq!(resp_small.status(), StatusCode::OK, "limit 内的 body → 200");
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn body_limit_non_numeric_content_length_passes_through() {
        let app = body_limit_app(100);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/")
            .header("content-length", "not-a-number")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "非数字 Content-Length 放行");
    }

    // ── rate_limit 测试 ──────────────────────────────────────────────────────────────────────────

    struct AllowLimiter;
    impl diport::RateLimiter for AllowLimiter {
        async fn check(
            &self,
            _key: RateLimitKey,
        ) -> Result<RateLimitDecision, diport::RateLimitError> {
            Ok(RateLimitDecision::Allowed)
        }
        async fn shutdown(&self) -> Result<(), diport::RateLimitError> {
            Ok(())
        }
    }

    struct LimitedLimiter {
        retry_after: std::time::Duration,
    }
    impl diport::RateLimiter for LimitedLimiter {
        async fn check(
            &self,
            _key: RateLimitKey,
        ) -> Result<RateLimitDecision, diport::RateLimitError> {
            Ok(RateLimitDecision::Limited {
                retry_after: self.retry_after,
            })
        }
        async fn shutdown(&self) -> Result<(), diport::RateLimitError> {
            Ok(())
        }
    }

    struct ErrorLimiter;
    impl diport::RateLimiter for ErrorLimiter {
        async fn check(
            &self,
            _key: RateLimitKey,
        ) -> Result<RateLimitDecision, diport::RateLimitError> {
            Err(diport::RateLimitError::new(std::io::Error::other(
                "backend-down",
            )))
        }
        async fn shutdown(&self) -> Result<(), diport::RateLimitError> {
            Ok(())
        }
    }

    /// F2：recording limiter — `check` 把收到的 key.as_str() 追加入 shared Vec，再返回 Allowed。
    /// 用于断言 rate_limit 中间件实际传入的 key 字符串（peer IP / "unknown"），而非仅断言响应码。
    struct RecordingLimiter {
        recorded_keys: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl RecordingLimiter {
        fn new() -> (Self, Arc<std::sync::Mutex<Vec<String>>>) {
            let keys = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
            (
                Self {
                    recorded_keys: Arc::clone(&keys),
                },
                keys,
            )
        }
    }

    impl diport::RateLimiter for RecordingLimiter {
        async fn check(
            &self,
            key: RateLimitKey,
        ) -> Result<RateLimitDecision, diport::RateLimitError> {
            // reason: test-only recording — single-threaded test, lock cannot fail.
            #[allow(clippy::unwrap_used)]
            self.recorded_keys
                .lock()
                .unwrap()
                .push(key.as_str().to_owned());
            Ok(RateLimitDecision::Allowed)
        }
        async fn shutdown(&self) -> Result<(), diport::RateLimitError> {
            Ok(())
        }
    }

    #[allow(clippy::unwrap_used)]
    fn rate_limit_app<S>(limiter: Arc<S>) -> Router
    where
        S: diport::RateLimiter + Send + Sync + 'static,
    {
        Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(limiter, rate_limit::<S>))
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn rate_limit_allowed_returns_200() {
        let app = rate_limit_app(Arc::new(AllowLimiter));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn rate_limit_limited_returns_429_with_retry_after() {
        let app = rate_limit_app(Arc::new(LimitedLimiter {
            retry_after: std::time::Duration::from_secs(5),
        }));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after = resp.headers().get("retry-after").unwrap().to_str().unwrap();
        assert_eq!(retry_after, "5", "5s → Retry-After: 5");
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn rate_limit_provider_error_fail_open_returns_200() {
        // reason: fail-open — provider 故障不阻塞正常请求。
        let app = rate_limit_app(Arc::new(ErrorLimiter));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "provider 故障 fail-open → 200"
        );
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn rate_limit_no_connect_info_uses_unknown_key() {
        // 无 ConnectInfo extension → key = "unknown"，仍正常工作（不 panic / 不 500）。
        // reason: oneshot 测试环境缺 ConnectInfo，fallback "unknown" 合法。
        let app = rate_limit_app(Arc::new(AllowLimiter));
        let req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// F2：ConnectInfo 存在 → key == peer IP（非退化 "unknown"）。
    ///
    /// RecordingLimiter 捕获 `check()` 收到的 key 字符串，断言等于 ConnectInfo 中的 IP。
    /// AllowLimiter 测试无法证明这一点——实现退化成 `RateLimitKey::new("unknown")` 时 AllowLimiter 仍返回 200。
    #[allow(clippy::unwrap_used)]
    // reason: 测试层 unwrap：Mutex lock（单线程测试不竞争）和 oneshot Result（输入已控制）均不可失败。
    #[tokio::test]
    async fn rate_limit_with_connect_info_uses_peer_ip() {
        use axum::extract::ConnectInfo;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let (recorder, keys) = RecordingLimiter::new();
        let app =
            Router::new()
                .route("/", get(|| async { "ok" }))
                .layer(middleware::from_fn_with_state(
                    Arc::new(recorder),
                    rate_limit::<RecordingLimiter>,
                ));

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 12345);
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "携带 ConnectInfo 正常放行");
        // 关键断言：key == peer IP（而非退化 "unknown"）。
        let recorded = keys.lock().unwrap();
        assert_eq!(
            recorded.as_slice(),
            &["192.168.1.1"],
            "ConnectInfo IPv4 192.168.1.1:12345 → key 须为 \"192.168.1.1\""
        );
    }

    /// F2：无 ConnectInfo → key == "unknown"（录制验证，非仅状态码断言）。
    #[allow(clippy::unwrap_used)]
    // reason: 测试层 unwrap：Mutex lock 和 oneshot Result 均不可失败。
    #[tokio::test]
    async fn rate_limit_no_connect_info_key_is_unknown() {
        let (recorder, keys) = RecordingLimiter::new();
        let app =
            Router::new()
                .route("/", get(|| async { "ok" }))
                .layer(middleware::from_fn_with_state(
                    Arc::new(recorder),
                    rate_limit::<RecordingLimiter>,
                ));

        let req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "无 ConnectInfo fallback → 200"
        );
        let recorded = keys.lock().unwrap();
        assert_eq!(
            recorded.as_slice(),
            &["unknown"],
            "无 ConnectInfo → key 须为 \"unknown\""
        );
    }

    /// F2（彻底）：IPv6 ConnectInfo → key == IPv6 字符串（"::1"）。
    #[allow(clippy::unwrap_used)]
    // reason: 测试层 unwrap：Mutex lock 和 oneshot Result 均不可失败。
    #[tokio::test]
    async fn rate_limit_ipv6_connect_info_key() {
        use axum::extract::ConnectInfo;
        use std::net::{IpAddr, Ipv6Addr, SocketAddr};

        let (recorder, keys) = RecordingLimiter::new();
        let app =
            Router::new()
                .route("/", get(|| async { "ok" }))
                .layer(middleware::from_fn_with_state(
                    Arc::new(recorder),
                    rate_limit::<RecordingLimiter>,
                ));

        // [::1]:8080 → "::1"
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080);
        let mut req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "IPv6 ConnectInfo 放行");
        let recorded = keys.lock().unwrap();
        assert_eq!(
            recorded.as_slice(),
            &["::1"],
            "IPv6 [::1]:8080 → key 须为 \"::1\""
        );
    }
}
