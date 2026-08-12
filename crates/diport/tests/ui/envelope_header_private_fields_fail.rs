use diport::{EnvelopeHeader, EnvelopeSchemaHash, EnvelopeSchemaVersion};

fn main() {
    let tenant =
        rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant");
    let _ = EnvelopeHeader {
        tenant_id: tenant,
        schema_version: EnvelopeSchemaVersion::parse("v1").expect("version"),
        schema_hash: EnvelopeSchemaHash::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("hash"),
        occurred_at_secs: None,
        trace: None,
        correlation: None,
        tenant_authority: None,
        partition_key: None,
    };
}
