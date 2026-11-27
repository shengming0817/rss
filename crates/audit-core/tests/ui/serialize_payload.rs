use rss_audit_core::AuditPayload;

fn main() {
    let payload = AuditPayload::new(Vec::new()).unwrap();
    let _ = serde_json::to_vec(&payload);
}
