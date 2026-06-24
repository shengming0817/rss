//! Wire error mapper：`vocab::CoreErrorKind` → JSON envelope（error-handling.md §Wire 格式）。
//!
//! DTO 为 wire 类型（非 domain entity），derive Serialize 合规。
//! detail 透传 + 5xx strip 待有 producer 时落地；本切片 `details` 恒空 `Vec::new()`。
//!
//! ref: tokio-rs/axum axum/src/response/mod.rs@main（IntoResponse 组合）

use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Serialize;
use vocab::CoreErrorKind;

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

/// 构造 axum 错误响应（`(StatusCode, Json(envelope)).into_response()`）——**raw 组合，crate 私有**。
///
/// `kind`/`status` 配对正确性由公开 typed helper 固化（[`validation_bad_request`] / [`unauthenticated`] /
/// [`forbidden`] / [`internal_error`]）；不暴露 raw `(kind, status)` 给跨 crate 调用方，杜绝 code/status
/// 错配（typed function choice + 可见性封装，Hard）。`details` 本切片恒空（生产者落地前不透传公开明细）。
pub(crate) fn error_response(
    kind: CoreErrorKind,
    status: StatusCode,
    request_id: &str,
) -> axum::response::Response {
    let envelope = ErrorEnvelope {
        error: ErrorBody {
            code: kind.code(),
            message: kind.message(),
            details: Vec::new(),
            request_id: request_id.to_owned(),
        },
    };
    (status, axum::Json(envelope)).into_response()
}

/// 400 Validation 信封（参数 / 请求体校验失败）：`ERR_CORE_VALIDATION` + `BAD_REQUEST` 固定配对。
pub fn validation_bad_request(request_id: &str) -> axum::response::Response {
    error_response(
        CoreErrorKind::Validation,
        StatusCode::BAD_REQUEST,
        request_id,
    )
}

/// 401 Unauthenticated 信封：`ERR_CORE_UNAUTHENTICATED` + `UNAUTHORIZED` 固定配对。
pub fn unauthenticated(request_id: &str) -> axum::response::Response {
    error_response(
        CoreErrorKind::Unauthenticated,
        StatusCode::UNAUTHORIZED,
        request_id,
    )
}

/// 403 Forbidden 信封：`ERR_CORE_FORBIDDEN` + `FORBIDDEN` 固定配对。
pub fn forbidden(request_id: &str) -> axum::response::Response {
    error_response(CoreErrorKind::Forbidden, StatusCode::FORBIDDEN, request_id)
}

/// 500 Internal 信封：`ERR_CORE_INTERNAL` + `INTERNAL_SERVER_ERROR` 固定配对（5xx，无公开明细）。
pub fn internal_error(request_id: &str) -> axum::response::Response {
    error_response(
        CoreErrorKind::Internal,
        StatusCode::INTERNAL_SERVER_ERROR,
        request_id,
    )
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
}
