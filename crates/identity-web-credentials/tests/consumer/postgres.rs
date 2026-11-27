fn main() {
    use rss_identity_core::{InstanceId, session::SessionPolicy};
    use rss_identity_postgres::{AuthorityConfig, SCHEMA_SIGNATURE};
    let budget = rss_audit_postgres::WriteBudget::new(8, 1_048_576, 2_097_152).unwrap();
    let _host = AuthorityConfig::new(
        InstanceId::generate(),
        SessionPolicy::new(300, 3600).unwrap(),
        rss_audit_postgres::Integrity::Plain,
        budget,
    ).unwrap();
    assert_eq!(SCHEMA_SIGNATURE.trim().len(), 64);
    println!("passed");
}
