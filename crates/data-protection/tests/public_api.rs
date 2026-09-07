use rss_data_protection::{DerivedAad, ProtectionContext};
use rss_request_context::TenantId;

#[test]
fn coordinates_can_be_derived_without_authentication_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let tenant = TenantId::parse("11111111-2222-4333-8444-555555555555")?;
    let aad: DerivedAad = ProtectionContext::new(tenant, "db.dsn", "password", 1)?.derive();
    assert!(!aad.as_canonical_bytes().is_empty());
    Ok(())
}
