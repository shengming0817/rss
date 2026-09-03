use eventing::metadata::EventMetadata;

fn main() {
    let tenant = rss_request_context::TenantId::parse(
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    )
    .expect("canonical tenant");
    let occurred_at = rss_contract::Timepoint::try_from(1_i64).expect("valid time");
    let _ = EventMetadata {
        tenant_id: tenant,
        occurred_at,
        correlation: None,
    };
}
