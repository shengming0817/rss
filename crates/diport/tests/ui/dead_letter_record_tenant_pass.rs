use diport::{DeadLetterProvenance, DeadLetterRecord, DeadLetterSummary};
use rss_transactional_messaging::message::TransportContext;

fn main() {
    let tenant =
        rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant");
    let record = DeadLetterRecord::new(
        tenant,
        "message-1",
        DeadLetterProvenance::consumer("identity", "audit"),
        "contract-session",
        "session.created",
        Some("identity.session.consumer".to_string()),
        b"payload".to_vec(),
        DeadLetterSummary::new("max retries exhausted"),
        10,
        TransportContext::new(None, None),
    );
    let _ = (record.tenant(), record.message_id());
}
