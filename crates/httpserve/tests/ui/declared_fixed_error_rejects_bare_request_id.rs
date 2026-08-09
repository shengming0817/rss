use generated::http::audit_v1::list_entries::AuditListEntriesResponseError;

fn main() {
    let _ = AuditListEntriesResponseError::status_500("forged-request-id".to_owned());
}
