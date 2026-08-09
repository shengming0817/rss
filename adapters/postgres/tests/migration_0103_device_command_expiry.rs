const MIGRATION: &str = include_str!("../migrations/0103_expire_device_commands.sql");
const COMMAND_PROVIDER: &str = include_str!("../src/device_command.rs");

#[test]
fn expiry_funnel_is_exact_fenced_and_database_timed() {
    for required in [
        "attempt.attempt_id=p_attempt_id",
        "attempt.lease_token=p_lease_token",
        "attempt.epoch=p_epoch",
        "attempt.claimed_wake_version=p_wake_version",
        "target.wake_version=p_wake_version",
        "lease.expires_at>pg_catalog.clock_timestamp()",
        "desired.generation=p_expected_generation",
        "command.deadline>authority_time",
        "command.deadline>pg_catalog.transaction_timestamp()",
        "terminal_at=pg_catalog.transaction_timestamp()",
        "stored.version=p_expected_version",
        "p_next_version IS DISTINCT FROM p_expected_version + 1",
        "p_terminal_at_micros IS DISTINCT FROM authority_micros",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing expiry fence: {required}"
        );
    }
    assert!(COMMAND_PROVIDER.contains("DeviceCommandMutation::timeout(authority)"));
    assert!(COMMAND_PROVIDER.contains("restore_command::<E>"));
}

#[test]
fn serving_role_gets_only_fixed_eligibility_wrappers() -> Result<(), &'static str> {
    assert!(MIGRATION.contains("OWNER TO rss_device_command_funnel_owner"));
    assert!(MIGRATION.contains("FROM PUBLIC, rss_app, rss_app_read"));
    assert!(MIGRATION.contains("TO rss_app;"));
    assert!(!MIGRATION.contains("GRANT UPDATE"));
    let grant = MIGRATION
        .rfind("GRANT EXECUTE ON FUNCTION")
        .ok_or("migration must grant the fixed eligibility wrappers to the serving role")?;
    let serving = &MIGRATION[grant..];
    for operation in ["select", "settle"] {
        assert!(serving.contains(&format!("rss_{operation}_due_current_device_command_draft")));
        assert!(serving.contains(&format!(
            "rss_{operation}_due_current_device_command_production"
        )));
        assert!(!serving.contains(&format!("rss_{operation}_due_current_device_command_core")));
    }
    Ok(())
}
