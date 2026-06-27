//! Wire error mapper：`vocab::CoreError` → JSON envelope（error-handling.md §Wire 格式）。
//!
//! DTO 为 wire 类型（非 domain entity），derive Serialize 合规。
//! **detail 透传 + 5xx strip 已落地（#1361）**：[`core_error_response`] 对 4xx 下发 `public_details`、
//! 对 5xx 强制 strip；`internal_attrs` 永不进 wire（typed 通道分流即脱敏，`PublicDetail` 已是 vetted 公开值，
//! 不再对其二次 `redact`）。kind→status 单源 [`status_for`]——code 与 status 同出 `kind`，类型层杜绝错配。
//!
//! ref: tokio-rs/axum axum/src/response/mod.rs@main（IntoResponse 组合）

use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Serialize;
use vocab::{CoreError, CoreErrorKind, PublicDetail};

/// Wire 错误响应 envelope（camelCase；error-handling.md §Wire 格式）。
#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

/// Wire 错误 body（camelCase；`requestId` 由框架中间件注入）。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
    details: Vec<serde_json::Value>,
    request_id: String,
}

/// kind → HTTP status 的**单一来源**（全 6 kind）。code 取 `kind.code()`、status 取此——二者同出 `kind`，
/// 类型层杜绝 code/status 错配（取代旧 raw `error_response(kind, status)` 的手配对）。
fn status_for(kind: CoreErrorKind) -> StatusCode {
    match kind {
        CoreErrorKind::NotFound => StatusCode::NOT_FOUND,
        CoreErrorKind::Unauthenticated => StatusCode::UNAUTHORIZED,
        CoreErrorKind::Forbidden => StatusCode::FORBIDDEN,
        CoreErrorKind::Conflict => StatusCode::CONFLICT,
        CoreErrorKind::Validation => StatusCode::BAD_REQUEST,
        CoreErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
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

/// 单条 `PublicDetail` → wire JSON `{ "<key>": <typed value> }`。typed 值形固定（wire 契约，golden 锁）：
/// `Duration`→毫秒 `u64`、`Time`→epoch 秒 `i64`。未知未来 variant（`#[non_exhaustive]`）fail-closed 丢弃。
fn render_public_detail(detail: &PublicDetail) -> Option<serde_json::Value> {
    let (key, value): (&'static str, serde_json::Value) = match detail {
        PublicDetail::Str(k, v) => (k, serde_json::Value::from(v.as_str())),
        PublicDetail::Int(k, v) => (k, serde_json::Value::from(*v)),
        PublicDetail::Bool(k, v) => (k, serde_json::Value::from(*v)),
        PublicDetail::Duration(k, d) => (
            k,
            serde_json::Value::from(u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
        ),
        PublicDetail::Time(k, t) => (k, serde_json::Value::from(unix_secs(t))),
        _ => return None,
    };
    let mut map = serde_json::Map::new();
    map.insert(key.to_owned(), value);
    Some(serde_json::Value::Object(map))
}

/// 构造 axum 错误响应：`CoreError` → JSON envelope。**4xx 下发 `public_details`、5xx 强制 strip**
/// （error-handling.md §Message 与 PII）；`internal_attrs` 永不进 wire。status 经 [`status_for`] 由 `kind`
/// 派生（与 `code` 同源），杜绝 code/status 错配。
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
            details,
            request_id: request_id.to_owned(),
        },
    };
    (status, axum::Json(envelope)).into_response()
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn status_for_covers_known_kinds() {
        let cases = [
            (CoreErrorKind::NotFound, StatusCode::NOT_FOUND),
            (CoreErrorKind::Unauthenticated, StatusCode::UNAUTHORIZED),
            (CoreErrorKind::Forbidden, StatusCode::FORBIDDEN),
            (CoreErrorKind::Conflict, StatusCode::CONFLICT),
            (CoreErrorKind::Validation, StatusCode::BAD_REQUEST),
            (CoreErrorKind::Internal, StatusCode::INTERNAL_SERVER_ERROR),
        ];
        for (kind, want) in cases {
            assert_eq!(status_for(kind), want, "kind={kind:?}");
        }
    }
}
