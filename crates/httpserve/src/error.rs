//! Wire error mapper：`vocab::CoreError` → JSON envelope（error-handling.md §Wire 格式）。
//!
//! DTO 为 wire 类型（非 domain entity），derive Serialize 合规。
//! **detail 透传 + 5xx strip 已落地（#1361）**：[`core_error_response`] 对 4xx 下发 `public_details`、
//! 对 5xx 强制 strip；`internal_attrs` 永不进 wire（typed 通道分流即脱敏，`PublicDetail` 已是 vetted 公开值，
//! 不再对其二次 `redact`）。kind→status 单源 [`status_for`]；code/status/retryability 同出 `kind`，类型层杜绝错配。
//!
//! ref: tokio-rs/axum axum/src/response/mod.rs@main（IntoResponse 组合）

use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use vocab::{CoreError, CoreErrorKind, PublicDetail};

/// Returns whether an axum body collection error was caused by the configured byte limit.
///
/// Axum wraps body-provider errors, so callers must inspect the complete source chain rather than
/// classify every read failure as a payload overflow. This keeps transport error classification in
/// the HTTP service layer: only [`http_body_util::LengthLimitError`] maps to 413; other read errors
/// remain validation failures at bounded-body handlers.
pub fn body_error_is_length_limit(err: &axum::Error) -> bool {
    let mut source: &(dyn std::error::Error + 'static) = err;
    loop {
        if source.is::<http_body_util::LengthLimitError>() {
            return true;
        }
        match source.source() {
            Some(next) => source = next,
            None => return false,
        }
    }
}

/// Wire 错误响应 envelope（camelCase；error-handling.md §Wire 格式）。
#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

/// Wire 错误 body（camelCase；`requestId` 由框架中间件注入，`retryable` 由错误 kind 单源派生）。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
    retryable: bool,
    details: Vec<WireDetail>,
    request_id: String,
}

/// 单条公开明细的 wire DTO：序列化为单键对象 `{ "<key>": <typed value> }`。
struct WireDetail {
    key: &'static str,
    value: WireDetailValue,
}

enum WireDetailValue {
    Str(String),
    Int(i64),
    Bool(bool),
    DurationMillis(u64),
    UnixSecs(i64),
}

impl Serialize for WireDetail {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        match &self.value {
            WireDetailValue::Str(v) => map.serialize_entry(self.key, v)?,
            WireDetailValue::Int(v) | WireDetailValue::UnixSecs(v) => {
                map.serialize_entry(self.key, v)?;
            }
            WireDetailValue::Bool(v) => map.serialize_entry(self.key, v)?,
            WireDetailValue::DurationMillis(v) => map.serialize_entry(self.key, v)?,
        }
        map.end()
    }
}

/// kind → HTTP status 的**单一来源**。code 取 `kind.code()`、status 取此——二者同出 `kind`，
/// 类型层杜绝 code/status 错配（取代旧 raw `error_response(kind, status)` 的手配对）。
fn status_for(kind: CoreErrorKind) -> StatusCode {
    match kind {
        CoreErrorKind::NotFound => StatusCode::NOT_FOUND,
        CoreErrorKind::Unauthenticated => StatusCode::UNAUTHORIZED,
        CoreErrorKind::Forbidden => StatusCode::FORBIDDEN,
        CoreErrorKind::OutboxFactConflict
        | CoreErrorKind::VersionConflict
        | CoreErrorKind::Conflict => StatusCode::CONFLICT,
        CoreErrorKind::Validation => StatusCode::BAD_REQUEST,
        CoreErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        CoreErrorKind::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        CoreErrorKind::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
        CoreErrorKind::Unavailable | CoreErrorKind::ProviderUnavailable => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        CoreErrorKind::NotImplemented => StatusCode::NOT_IMPLEMENTED,
        // `CoreErrorKind` 是 `#[non_exhaustive]`：未知未来 kind fail-closed 映射 5xx
        // （→ details strip，绝不把未知 kind 当 4xx 误下发明细）。
        // 此 arm 在跨 crate 环境下结构上不可测试（外部无法构造新 variant），属预期覆盖盲区。
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// `SystemTime` → epoch 秒（i64；早于 epoch 取负秒）。wire 契约形（golden 锁）。
fn unix_secs(t: &std::time::SystemTime) -> i64 {
    match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        // 远古时间钳到 i64::MIN（epoch 前 ~292 亿年，不可达）
        Err(e) => i64::try_from(e.duration().as_secs()).map_or(i64::MIN, |s| -s),
    }
}

/// 单条 `PublicDetail` → wire DTO `{ "<key>": <typed value> }`。typed 值形固定（wire 契约，golden 锁）：
/// `Duration`→毫秒 `u64`、`Time`→epoch 秒 `i64`。未知未来 variant（`#[non_exhaustive]`）fail-closed 丢弃。
fn render_public_detail(detail: &PublicDetail) -> Option<WireDetail> {
    let (key, value) = match detail {
        PublicDetail::Str(k, v) => (k, WireDetailValue::Str(v.clone())),
        PublicDetail::Int(k, v) => (k, WireDetailValue::Int(*v)),
        PublicDetail::Bool(k, v) => (k, WireDetailValue::Bool(*v)),
        PublicDetail::Duration(k, d) => {
            let millis = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
            (k, WireDetailValue::DurationMillis(millis))
        }
        PublicDetail::Time(k, t) => (k, WireDetailValue::UnixSecs(unix_secs(t))),
        _ => return None,
    };
    Some(WireDetail { key, value })
}

/// 构造 axum 错误响应：`CoreError` → JSON envelope。**4xx 下发 `public_details`、5xx 强制 strip**
/// （error-handling.md §Message 与 PII）；`internal_attrs` 永不进 wire。status 经 [`status_for`] 由 `kind`
/// 派生（与 `code`、`retryable` 同源），杜绝 wire 分类错配。
pub fn core_error_response(err: &CoreError, request_id: &str) -> axum::response::Response {
    let kind = err.kind();
    let status = status_for(kind);
    let details = if status.is_server_error() {
        // 5xx：strip 全部公开明细（不向外部泄露 5xx 内部细节）。
        Vec::new()
    } else {
        // 4xx：下发 vetted 公开明细（typed 通道分流即脱敏，PublicDetail 已是公开值）。
        err.public_details()
            .iter()
            .filter_map(render_public_detail)
            .collect()
    };
    let envelope = ErrorEnvelope {
        error: ErrorBody {
            code: kind.code(),
            message: kind.message(),
            retryable: kind.retryable(),
            details,
            request_id: request_id.to_owned(),
        },
    };
    (status, axum::Json(envelope)).into_response()
}

/// Log one contract-classified failure at the canonical contract boundary.
///
/// Expected provider unavailability is not logged on a polling endpoint. Internal failures are
/// logged once with only stable contract, error-kind, request-id, and closed failure-stage
/// metadata; runtime values and internal attributes are never rendered.
pub fn log_contract_core_error(
    contract_id: &'static str,
    err: &CoreError,
    request_id: &str,
    failure_stage: Option<&'static str>,
) {
    if err.kind() == CoreErrorKind::Internal {
        tracing::error!(
            contract_id,
            error_code = err.kind().code(),
            request_id,
            failure_stage = failure_stage.unwrap_or("contract.internal"),
            "contract response failed"
        );
    }
}

/// 400 Validation 信封（参数 / 请求体校验失败）：`ERR_CORE_VALIDATION` + `BAD_REQUEST` 固定配对。
pub fn validation_bad_request(request_id: &str) -> axum::response::Response {
    core_error_response(&CoreError::new(CoreErrorKind::Validation), request_id)
}

/// 401 Unauthenticated 信封：`ERR_CORE_UNAUTHENTICATED` + `UNAUTHORIZED` 固定配对。
pub fn unauthenticated(request_id: &str) -> axum::response::Response {
    core_error_response(&CoreError::new(CoreErrorKind::Unauthenticated), request_id)
}

/// 403 Forbidden 信封：`ERR_CORE_FORBIDDEN` + `FORBIDDEN` 固定配对。
pub fn forbidden(request_id: &str) -> axum::response::Response {
    core_error_response(&CoreError::new(CoreErrorKind::Forbidden), request_id)
}

/// 500 Internal 信封：`ERR_CORE_INTERNAL` + `INTERNAL_SERVER_ERROR` 固定配对（5xx，公开明细 strip）。
pub fn internal_error(request_id: &str) -> axum::response::Response {
    core_error_response(&CoreError::new(CoreErrorKind::Internal), request_id)
}

/// 503 Service Unavailable 信封：全请求 server budget 耗尽时的唯一 wire 表达。
pub fn service_unavailable(request_id: &str) -> axum::response::Response {
    core_error_response(&CoreError::new(CoreErrorKind::Unavailable), request_id)
}

/// 503 Provider Unavailable 信封：必需 serving dependency 暂时不可用，且请求可安全重试。
pub fn provider_unavailable(request_id: &str) -> axum::response::Response {
    core_error_response(
        &CoreError::new(CoreErrorKind::ProviderUnavailable),
        request_id,
    )
}

/// 501 Not Implemented 信封：`ERR_CORE_NOT_IMPLEMENTED` + `NOT_IMPLEMENTED` 固定配对。
pub fn not_implemented(request_id: &str) -> axum::response::Response {
    core_error_response(&CoreError::new(CoreErrorKind::NotImplemented), request_id)
}

/// 413 Payload Too Large 信封：`ERR_CORE_PAYLOAD_TOO_LARGE` + `PAYLOAD_TOO_LARGE` 固定配对。
pub fn payload_too_large(request_id: &str) -> axum::response::Response {
    core_error_response(&CoreError::new(CoreErrorKind::PayloadTooLarge), request_id)
}

/// 429 Too Many Requests 信封：`ERR_CORE_TOO_MANY_REQUESTS` + `TOO_MANY_REQUESTS` 固定配对。
/// `Retry-After` header 设为 ceil 整数秒（GCRA 建议，避免客户端过早重试仍被拒）。
pub fn too_many_requests(
    request_id: &str,
    retry_after: std::time::Duration,
) -> axum::response::Response {
    let mut resp = core_error_response(&CoreError::new(CoreErrorKind::TooManyRequests), request_id);
    let secs = retry_after
        .as_secs()
        .saturating_add(u64::from(retry_after.subsec_nanos() != 0));
    if let Ok(val) = axum::http::HeaderValue::from_str(&secs.to_string()) {
        resp.headers_mut().insert(
            axum::http::header::HeaderName::from_static("retry-after"),
            val,
        );
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn body_read_error_classifies_length_limit_from_source_chain() {
        let err = axum::body::to_bytes(axum::body::Body::from("too large"), 1)
            .await
            .expect_err("body must exceed the collector limit");

        assert!(body_error_is_length_limit(&err));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn body_read_error_does_not_classify_provider_failure_as_length_limit() {
        let body = axum::body::Body::from_stream(futures::stream::once(async {
            Err::<axum::body::Bytes, _>(std::io::Error::other("body provider failed"))
        }));
        let err = axum::body::to_bytes(body, usize::MAX)
            .await
            .expect_err("provider failure must reach the collector");

        assert!(!body_error_is_length_limit(&err));
    }

    /// typed helper 固定 (code, status) 配对（取代 raw error_response 跨 crate 暴露）。
    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn typed_helpers_fix_code_status_pairing() {
        for (resp, want_status, want_code) in [
            (
                validation_bad_request("rid"),
                StatusCode::BAD_REQUEST,
                "ERR_CORE_VALIDATION",
            ),
            (
                unauthenticated("rid"),
                StatusCode::UNAUTHORIZED,
                "ERR_CORE_UNAUTHENTICATED",
            ),
            (
                forbidden("rid"),
                StatusCode::FORBIDDEN,
                "ERR_CORE_FORBIDDEN",
            ),
            (
                internal_error("rid"),
                StatusCode::INTERNAL_SERVER_ERROR,
                "ERR_CORE_INTERNAL",
            ),
            (
                service_unavailable("rid"),
                StatusCode::SERVICE_UNAVAILABLE,
                "ERR_CORE_UNAVAILABLE",
            ),
            (
                provider_unavailable("rid"),
                StatusCode::SERVICE_UNAVAILABLE,
                "ERR_CORE_PROVIDER_UNAVAILABLE",
            ),
            (
                payload_too_large("rid"),
                StatusCode::PAYLOAD_TOO_LARGE,
                "ERR_CORE_PAYLOAD_TOO_LARGE",
            ),
            (
                not_implemented("rid"),
                StatusCode::NOT_IMPLEMENTED,
                "ERR_CORE_NOT_IMPLEMENTED",
            ),
            (
                too_many_requests("rid", std::time::Duration::from_millis(1500)),
                StatusCode::TOO_MANY_REQUESTS,
                "ERR_CORE_TOO_MANY_REQUESTS",
            ),
        ] {
            assert_eq!(resp.status(), want_status);
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .expect("collect body");
            let json: serde_json::Value = serde_json::from_slice(&bytes).expect("parse json");
            assert_eq!(json["error"]["code"], want_code);
        }
    }

    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn typed_helper_body_has_request_id_and_details() {
        let resp = forbidden("test-rid");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect body");
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("parse json");
        assert_eq!(json["error"]["requestId"], "test-rid");
        assert!(json["error"]["details"].is_array());
    }

    // --- #1361 wire mapper：4xx 下发 / 5xx strip / internal 永不进 wire / detail JSON golden ---

    #[allow(clippy::expect_used)]
    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect body");
        serde_json::from_slice(&bytes).expect("parse json")
    }

    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn wire_4xx_includes_public_details() {
        let err = CoreError::new(CoreErrorKind::Validation)
            .with_details(PublicDetail::Str("field", "name".to_string()));
        let resp = core_error_response(&err, "rid");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = body_json(resp).await;
        let details = json["error"]["details"].as_array().expect("details array");
        assert_eq!(details.len(), 1);
        assert_eq!(details[0]["field"], "name");
    }

    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn wire_5xx_strips_public_details() {
        let err = CoreError::new(CoreErrorKind::Internal)
            .with_details(PublicDetail::Str("hint", "should-be-stripped".to_string()));
        let resp = core_error_response(&err, "rid");
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let json = body_json(resp).await;
        assert_eq!(json["error"]["details"].as_array().expect("array").len(), 0);
        assert!(!json.to_string().contains("should-be-stripped"));
    }

    #[test]
    fn contract_failure_logging_accepts_safe_correlation_metadata() {
        let internal = CoreError::new(CoreErrorKind::Internal)
            .with_details(PublicDetail::Str("must_strip", "secret".to_owned()));
        log_contract_core_error(
            "runtime.inventory",
            &internal,
            "rid",
            Some("projection.listener.id"),
        );
    }

    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn wire_never_emits_internal_attrs() {
        // internal_attrs 永不进 wire——4xx 与 5xx 两路径都不得泄露。
        for kind in [CoreErrorKind::Validation, CoreErrorKind::Internal] {
            let err = CoreError::new(kind).with_internal(vocab::InternalAttr::Str(
                "authorization",
                "Bearer s3cr3t".to_string(),
            ));
            let body = body_json(core_error_response(&err, "rid"))
                .await
                .to_string();
            assert!(
                !body.contains("s3cr3t"),
                "internal value leaked for {kind:?}: {body}"
            );
            assert!(
                !body.contains("authorization"),
                "internal key leaked for {kind:?}"
            );
        }
    }

    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn wire_public_detail_variants_render_golden() {
        let err = CoreError::new(CoreErrorKind::Validation)
            .with_details(PublicDetail::Str("s", "v".to_string()))
            .with_details(PublicDetail::Int("i", -7))
            .with_details(PublicDetail::Bool("b", true))
            .with_details(PublicDetail::Duration(
                "d",
                std::time::Duration::from_millis(1500),
            ))
            .with_details(PublicDetail::Time(
                "t",
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(1000),
            ));
        let json = body_json(core_error_response(&err, "rid")).await;
        let d = json["error"]["details"].as_array().expect("array");
        assert_eq!(d[0]["s"], "v");
        assert_eq!(d[1]["i"], -7);
        assert_eq!(d[2]["b"], true);
        assert_eq!(d[3]["d"], 1500, "Duration→毫秒"); // millis
        assert_eq!(d[4]["t"], 1000, "Time→epoch 秒"); // epoch secs
    }

    #[allow(clippy::expect_used)]
    #[test]
    fn wire_public_detail_renderer_returns_typed_dto() {
        let detail = render_public_detail(&PublicDetail::Duration(
            "retryAfter",
            std::time::Duration::from_millis(2500),
        ))
        .expect("known detail variant renders");
        let typed: &WireDetail = &detail;
        let json = serde_json::to_value(typed).expect("serialize typed detail");
        assert_eq!(json["retryAfter"], 2500);
    }

    #[test]
    fn status_for_covers_known_kinds() {
        let cases = [
            (CoreErrorKind::NotFound, StatusCode::NOT_FOUND),
            (CoreErrorKind::Unauthenticated, StatusCode::UNAUTHORIZED),
            (CoreErrorKind::Forbidden, StatusCode::FORBIDDEN),
            (CoreErrorKind::OutboxFactConflict, StatusCode::CONFLICT),
            (CoreErrorKind::VersionConflict, StatusCode::CONFLICT),
            (CoreErrorKind::Conflict, StatusCode::CONFLICT),
            (CoreErrorKind::Validation, StatusCode::BAD_REQUEST),
            (CoreErrorKind::Internal, StatusCode::INTERNAL_SERVER_ERROR),
            (CoreErrorKind::Unavailable, StatusCode::SERVICE_UNAVAILABLE),
            (
                CoreErrorKind::ProviderUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (CoreErrorKind::NotImplemented, StatusCode::NOT_IMPLEMENTED),
            (
                CoreErrorKind::PayloadTooLarge,
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                CoreErrorKind::TooManyRequests,
                StatusCode::TOO_MANY_REQUESTS,
            ),
        ];
        for (kind, want) in cases {
            assert_eq!(status_for(kind), want, "kind={kind:?}");
        }
    }

    /// `too_many_requests` 响应包含 `Retry-After: <ceil秒>` header。
    /// 1500ms → ceil(1500/1000) = 2s。
    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn too_many_requests_sets_retry_after_ceil_secs() {
        let resp = too_many_requests("rid", std::time::Duration::from_millis(1500));
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after = resp
            .headers()
            .get("retry-after")
            .expect("须有 Retry-After header")
            .to_str()
            .expect("header 值可转 str");
        assert_eq!(retry_after, "2", "1500ms ceil→2s");

        // 0ms → 0s（0.div_ceil(1000) = 0）。
        let resp0 = too_many_requests("rid", std::time::Duration::from_millis(0));
        let v0 = resp0
            .headers()
            .get("retry-after")
            .expect("须有 Retry-After")
            .to_str()
            .expect("str");
        assert_eq!(v0, "0", "0ms → 0s");

        // 1000ms → 1s（整除）。
        let resp1 = too_many_requests("rid", std::time::Duration::from_millis(1000));
        let v1 = resp1
            .headers()
            .get("retry-after")
            .expect("须有 Retry-After")
            .to_str()
            .expect("str");
        assert_eq!(v1, "1", "1000ms → 1s");

        let sub_millisecond = too_many_requests("rid", std::time::Duration::from_micros(1));
        let sub_millisecond_value = sub_millisecond
            .headers()
            .get("retry-after")
            .expect("须有 Retry-After")
            .to_str()
            .expect("str");
        assert_eq!(sub_millisecond_value, "1", "非零亚毫秒须向上取整为 1s");
    }

    #[tokio::test]
    async fn fact_conflict_has_dedicated_terminal_wire_contract() {
        let json = body_json(core_error_response(
            &CoreError::new(CoreErrorKind::OutboxFactConflict),
            "rid",
        ))
        .await;
        assert_eq!(json["error"]["code"], "ERR_CORE_OUTBOX_FACT_CONFLICT");
        assert_eq!(json["error"]["retryable"], false);
    }

    #[tokio::test]
    async fn cas_conflict_remains_retryable() {
        let json = body_json(core_error_response(
            &CoreError::new(CoreErrorKind::VersionConflict),
            "rid",
        ))
        .await;
        assert_eq!(json["error"]["code"], "ERR_CORE_VERSION_CONFLICT");
        assert_eq!(json["error"]["retryable"], true);
    }

    #[tokio::test]
    async fn provider_unavailable_is_retryable_but_budget_unavailable_is_not() {
        let provider = body_json(provider_unavailable("rid")).await;
        assert_eq!(provider["error"]["code"], "ERR_CORE_PROVIDER_UNAVAILABLE");
        assert_eq!(provider["error"]["retryable"], true);

        let budget = body_json(service_unavailable("rid")).await;
        assert_eq!(budget["error"]["code"], "ERR_CORE_UNAVAILABLE");
        assert_eq!(budget["error"]["retryable"], false);
    }
}
