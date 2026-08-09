//! DECLARED-HTTP-RESPONSE-01: the exact generated result cannot carry a raw response in `Err`.

use axum::response::IntoResponse;
use generated::http::audit_v1::list_entries::AuditListEntriesHandlerResult;

fn handler_result() -> AuditListEntriesHandlerResult {
    Err((axum::http::StatusCode::IM_A_TEAPOT, "raw").into_response().into())
}

fn main() {
    let _ = handler_result();
}
