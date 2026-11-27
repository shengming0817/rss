fn main() {
    use rss_identity_postgres::{AuthorityConfig, SCHEMA_SIGNATURE};
    let _host_constructor = AuthorityConfig::new;
    let budget = rss_audit_postgres::WriteBudget::new(8, 1_048_576, 2_097_152).unwrap();
    fn host_boundary(_: rss_audit_postgres::Integrity, _: rss_audit_postgres::WriteBudget, _: rss_request_context::TenantId) {}
    host_boundary(rss_audit_postgres::Integrity::Plain, budget, rss_request_context::TenantId::parse("11111111-1111-4111-8111-111111111111").unwrap());
    assert_eq!(SCHEMA_SIGNATURE.trim().len(), 64);
    println!("passed");
}
