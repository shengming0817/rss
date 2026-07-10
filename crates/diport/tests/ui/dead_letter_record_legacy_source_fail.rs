use diport::{DeadLetterRecord, DeadLetterSource, DeadLetterSummary, EnvelopeMetadata};

fn main() {
    let tenant =
        vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant");
    let _ = DeadLetterRecord::new(
        tenant,
        "message-1",
        DeadLetterSource::Legacy,
        "contract-session",
        "session.created",
        None,
        b"payload".to_vec(),
        DeadLetterSummary::new("legacy rows are read-only"),
        10,
        EnvelopeMetadata::empty(),
    );
}
