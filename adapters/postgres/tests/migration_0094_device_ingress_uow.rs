const MIGRATION: &str = include_str!("../migrations/0094_close_device_ingress_uow.sql");
const COMMAND_ADAPTER: &str = include_str!("../src/device_command.rs");
const CERTIFICATE_PORT: &str =
    include_str!("../../../crates/identity/src/device_certificate/port.rs");

#[test]
fn migration_closes_legacy_ingress_writers_and_installs_only_two_funnels() {
    let normalized = MIGRATION.split_whitespace().collect::<Vec<_>>().join(" ");
    for required in [
        "DROP FUNCTION public.rss_apply_device_command_ack(uuid,uuid,text,bigint,bigint,text)",
        "DROP FUNCTION public.rss_upsert_device_certificate_report( uuid,uuid,bigint,bigint,bytea,bytea,text,bigint,bigint,bigint )",
        "CREATE FUNCTION public.rss_commit_device_command_ack_ingress",
        "CREATE FUNCTION public.rss_commit_device_certificate_report_ingress",
        "SECURITY DEFINER",
        "OWNER TO rss_device_command_funnel_owner",
        "REVOKE INSERT,UPDATE,DELETE ON public.device_ingress_receipts",
        "public.device_certificate_reported_states,public.device_commands,public.device_certificate_conditions FROM rss_app",
        "pg_advisory_xact_lock",
        "device ingress fact conflict",
        "p_credential_generation bigint",
        "p_scope_matches IS NOT TRUE",
        "p_scope_matches IS NULL",
        "p_credential_generation IS DISTINCT FROM authority_generation",
        "CREATE INDEX device_ingress_receipts_high_water_idx ON public.device_ingress_receipts (tenant_id,device_id,generation,fence_epoch,device_sequence DESC) WHERE disposition IN ('advanced','device_rejected')",
    ] {
        assert!(
            normalized.contains(required),
            "missing hard-cut carrier: {required}"
        );
    }
    assert_eq!(
        normalized
            .matches("CREATE FUNCTION public.rss_commit_device_")
            .count(),
        2
    );
    assert_eq!(
        normalized.matches("p_credential_generation bigint").count(),
        2
    );
    assert_eq!(normalized.matches("p_scope_matches IS NOT TRUE").count(), 2);
    assert_eq!(normalized.matches("p_scope_matches IS NULL").count(), 2);
    assert_eq!(
        normalized
            .matches("p_credential_generation IS DISTINCT FROM authority_generation")
            .count(),
        2
    );
}

#[test]
fn ingress_outbox_lowering_has_one_canonical_owner() {
    const IDENTITY_TX: &str = include_str!("../src/cotx/identity.rs");

    assert!(IDENTITY_TX.contains("struct CanonicalDeviceIngressFact"));
    assert!(IDENTITY_TX.contains("fn from_reviewed_event"));
    assert!(IDENTITY_TX.contains("CanonicalOutboxFact::from_entry_env"));
    assert!(!COMMAND_ADAPTER.contains("CanonicalOutboxFact::from_entry_env"));
}

#[test]
fn rust_surface_has_no_independent_reported_writer_or_legacy_sql_call() {
    assert!(!CERTIFICATE_PORT.contains("advance_reported"));
    assert!(!COMMAND_ADAPTER.contains("FROM public.rss_apply_device_command_ack("));
    assert!(!COMMAND_ADAPTER.contains("FROM public.rss_upsert_device_certificate_report("));
    assert!(COMMAND_ADAPTER.contains("rss_commit_device_command_ack_ingress"));
    assert!(COMMAND_ADAPTER.contains("rss_commit_device_certificate_report_ingress"));
}
