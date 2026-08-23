use diport::{
    EnvelopeHeader, EnvelopeMetadata, EnvelopeSchemaHash, EnvelopeSchemaVersion, MessageEnvelope,
};

fn main() {
    let tenant =
        rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
    let header = EnvelopeHeader::new(
        tenant,
        rss_contract::Timepoint::try_from(1_i64).unwrap(),
        EnvelopeSchemaVersion::parse("v1").unwrap(),
        EnvelopeSchemaHash::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap(),
    );
    let _ = MessageEnvelope::new(header, Vec::new(), EnvelopeMetadata::empty());
}
