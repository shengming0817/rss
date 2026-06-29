use diport::{DeadLetterRecord, DeadLetterSummary, EnvelopeMetadata, WritableDeadLetterSource};

fn main() {
    let tenant =
        vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant");
    let record = DeadLetterRecord::new(
        tenant,
        "message-1",
        "identity",
        "contract-session",
        "session.created",
        Some("identity.session.consumer".to_string()),
        b"payload".to_vec(),
        DeadLetterSummary::new("max retries exhausted"),
        10,
        WritableDeadLetterSource::Consumer,
        EnvelopeMetadata::empty(),
    );
    let _ = (record.tenant(), record.message_id());
}
