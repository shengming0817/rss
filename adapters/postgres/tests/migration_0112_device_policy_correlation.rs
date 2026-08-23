const MIGRATION: &str = include_str!("../migrations/0112_correlate_device_policy_operations.sql");
const PROVIDER: &str = include_str!("../src/device_certificate.rs");

#[test]
fn migration_hard_cuts_to_one_required_correlation_signature() {
    for required in [
        "migration_head IS DISTINCT FROM 111",
        "requires empty Draft device-policy operation state",
        "ADD COLUMN request_id text NOT NULL",
        "ADD COLUMN correlation_id text NOT NULL",
        "p_request_id text, p_correlation_id text",
        "p_request_id,p_correlation_id",
        "CHECK (principal_kind = 'user')",
        "p_principal_kind <> 'user'",
        "requires exactly one desired-policy accept function",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing hard-cut carrier: {required}"
        );
    }
    assert!(!MIGRATION.contains("DEFAULT"));
    assert!(
        !MIGRATION
            .contains("CREATE OR REPLACE FUNCTION public.rss_accept_device_certificate_desired")
    );
}

#[test]
fn provider_binds_typed_request_and_correlation_evidence_once() {
    assert!(PROVIDER.contains(".bind(input.request_id())"));
    assert!(PROVIDER.contains(".bind(input.correlation_id())"));
    assert_eq!(PROVIDER.matches(".bind(input.request_id())").count(), 1);
    assert_eq!(PROVIDER.matches(".bind(input.correlation_id())").count(), 1);
}
