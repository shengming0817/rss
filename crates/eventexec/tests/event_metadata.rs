use eventing::metadata::EventMetadata;

const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

#[test]
fn event_metadata_exposes_only_canonical_tenant_time_and_optional_correlation() {
    let tenant = rss_request_context::TenantId::parse(TENANT).expect("canonical tenant");
    let occurred_at =
        rss_contract::Timepoint::try_from(1_700_000_000_i64).expect("non-negative event time");
    let correlation = rss_diag_context::CorrelationId::parse("audit-correlation-1")
        .expect("valid audit correlation");

    let metadata = EventMetadata::new(tenant, occurred_at, Some(correlation));

    assert_eq!(metadata.tenant_id(), tenant);
    assert_eq!(metadata.occurred_at(), occurred_at);
    assert_eq!(
        metadata.audit_correlation().map(|value| value.as_str()),
        Some("audit-correlation-1")
    );
}

#[test]
fn event_metadata_accepts_absent_audit_correlation() {
    let tenant = rss_request_context::TenantId::parse(TENANT).expect("canonical tenant");
    let occurred_at = rss_contract::Timepoint::try_from(42_i64).expect("non-negative event time");

    let metadata = EventMetadata::new(tenant, occurred_at, None);

    assert!(metadata.audit_correlation().is_none());
}
