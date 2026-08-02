const MIGRATION: &str =
    include_str!("../migrations/0096_enroll_device_certificate_reconcile_target.sql");
const REPOSITORY: &str = include_str!("../src/device_certificate.rs");

fn normalized_migration() -> String {
    MIGRATION.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn enrollment_and_fenced_view_are_exact_tenant_scoped_functions() {
    let sql = normalized_migration();
    for required in [
        "CREATE FUNCTION public.rss_enroll_device_certificate_reconcile_target(",
        "CREATE FUNCTION public.rss_lock_device_certificate_reconcile_view(",
        "p_tenant_id IS DISTINCT FROM NULLIF(pg_catalog.current_setting('rss.tenant_id', true), '')::uuid",
        "'identity.device-certificate'",
        "'device-certificate'",
        "p_device_id::text",
        "INSERT INTO public.reconcile_leases (tenant_id,target_id)",
        "FOR UPDATE OF target,lease,desired",
        "ON CONFLICT (tenant_id,target_id) DO NOTHING",
        "OWNER TO rss_device_certificate_funnel_owner",
        "FROM PUBLIC, rss_app, rss_app_read",
        "TO rss_app",
    ] {
        assert!(
            sql.contains(required),
            "missing enrollment boundary: {required}"
        );
    }
    assert!(!sql.contains("p_reconciler_id"));
    assert!(!sql.contains("p_resource_kind"));
    assert!(!sql.contains("p_resource_id"));
}

#[test]
fn repository_exposes_scope_only_enrollment_without_target_ids() {
    assert!(REPOSITORY.contains("pub async fn enroll_reconcile_target("));
    assert!(REPOSITORY.contains("scope: DeviceCertificateScope"));
    assert!(REPOSITORY.contains("initial_due: SystemTime"));
    assert!(!REPOSITORY.contains("pub async fn upsert_reconcile_target"));
}
