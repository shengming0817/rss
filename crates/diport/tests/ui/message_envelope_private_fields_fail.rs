use diport::{
    EnvelopeHeader, EnvelopeMetadata, EnvelopeSchemaHash, EnvelopeSchemaVersion, MessageEnvelope,
    RedactedBytes,
};

fn main() {
    let tenant =
        rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant");
    let header = EnvelopeHeader::new(
        tenant,
        rss_contract::Timepoint::try_from(1_i64).expect("time"),
        EnvelopeSchemaVersion::parse("v1").expect("version"),
        EnvelopeSchemaHash::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("hash"),
    );
    let _ = MessageEnvelope {
        header,
        metadata: EnvelopeMetadata::empty(),
        payload: RedactedBytes::new(b"payload".to_vec()),
    };
}
