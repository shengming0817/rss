use rss_data_protection::{DerivedAad, ProtectionContext};
use rss_request_context::TenantId;

#[test]
fn trusted_context_is_the_only_public_aad_derivation_path() -> Result<(), Box<dyn std::error::Error>>
{
    let tenant = TenantId::parse("11111111-2222-4333-8444-555555555555")?;
    let aad: DerivedAad =
        ProtectionContext::authenticated_request(tenant, "db.dsn", "password", 1)?.derive();
    assert!(!aad.as_canonical_bytes().is_empty());
    Ok(())
}
