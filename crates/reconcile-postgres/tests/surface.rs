use rss_reconcile_postgres::MIGRATION_SQL;
#[test]
fn schema_is_component_owned() {
    assert!(MIGRATION_SQL.contains("CREATE SCHEMA rss_reconcile"));
    assert!(MIGRATION_SQL.contains("FORCE ROW LEVEL SECURITY"));
    assert!(!MIGRATION_SQL.contains("CREATE TABLE rss_transactional_messaging"));
    assert!(!MIGRATION_SQL.contains("device_certificate"));
}
