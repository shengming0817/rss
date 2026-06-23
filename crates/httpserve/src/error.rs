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

/// 构造 axum 错误响应（`(StatusCode, Json(envelope)).into_response()`）。
///
/// `details` 本切片恒空（生产者落地前不透传公开明细）。
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_response_401_has_correct_code() {
        let resp = error_response(
            CoreErrorKind::Unauthenticated,
            StatusCode::UNAUTHORIZED,
            "rid1",
        );
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn error_response_403_has_correct_code() {
        let resp = error_response(CoreErrorKind::Forbidden, StatusCode::FORBIDDEN, "rid2");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[allow(clippy::expect_used)]
    #[tokio::test]
    async fn error_response_body_has_request_id() {
        let resp = error_response(CoreErrorKind::Forbidden, StatusCode::FORBIDDEN, "test-rid");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect body");
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("parse json");
        assert_eq!(json["error"]["requestId"], "test-rid");
        assert!(json["error"]["details"].is_array());
    }
}
