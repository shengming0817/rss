//! DECLARED-HTTP-RESPONSE-01: fixed error DTO fields cannot be injected into the closed envelope.

use generated::http::audit_v1::list_entries::{
    AuditListEntriesInternalServerError, AuditListEntriesInternalServerErrorCode,
    AuditListEntriesInternalServerErrorMessage, AuditListEntriesInternalServerErrorResponse,
    AuditListEntriesResponseError,
};

fn main() {
    let response = AuditListEntriesInternalServerErrorResponse {
        error: AuditListEntriesInternalServerError {
            code: AuditListEntriesInternalServerErrorCode::ErrCoreInternal,
            details: vec![std::collections::HashMap::from([(
                "secret".to_string(),
                "must-not-leak".to_string(),
            )])],
            message: AuditListEntriesInternalServerErrorMessage::InternalError,
            request_id: "rid".to_string(),
            retryable: true,
        },
    };
    let _ = AuditListEntriesResponseError::status_500(response);
}
