use diport::{DeadLetterRecord, DeadLetterSummary};

fn main() {
    let tenant =
        vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant");
    let record = DeadLetterRecord::new(
        tenant,
        "message-1",
        "identity",
        "contract-session",
        "session.created",
        b"payload".to_vec(),
        DeadLetterSummary::new("max retries exhausted"),
        10,
    );
    let _ = (record.tenant(), record.message_id());
}
