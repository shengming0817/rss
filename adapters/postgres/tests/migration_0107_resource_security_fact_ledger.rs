const MIGRATION: &str =
    include_str!("../migrations/0107_install_resource_security_fact_ledger.sql");

#[test]
fn migration_installs_one_append_only_typed_ledger() {
    for required in [
        "CREATE TABLE public.resource_security_fact_revisions",
        "PRIMARY KEY (tenant_id, device_id, fact_key, revision)",
        "fact_key IN ('resource.owner', 'resource.riskClass')",
        "revision > 0",
        "observed_at < expires_at",
        "risk_class IN ('normal', 'restricted', 'quarantined')",
        "ENABLE ROW LEVEL SECURITY",
        "FORCE ROW LEVEL SECURITY",
        "NULLIF(current_setting('rss.tenant_id', true), '')::uuid",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
    let lower = MIGRATION.to_ascii_lowercase();
    assert!(!lower.contains("create table public.resource_security_fact_current"));
    assert!(!lower.contains("update public.resource_security_fact_revisions"));
    assert!(!lower.contains("delete from public.resource_security_fact_revisions"));
}

#[test]
fn bootstrap_is_one_fixed_typed_function_with_no_table_acl() {
    for required in [
        "rss_resource_fact_bootstrap NOLOGIN NOINHERIT NOBYPASSRLS",
        "rss_apply_resource_security_fact_revision(",
        "SECURITY DEFINER",
        "SET search_path = pg_catalog, pg_temp",
        "p_fact_key text",
        "p_owner_principal_id text",
        "p_risk_class text",
        "RETURN 'Replay'",
        "revision conflict",
        "ERRCODE = 'P2111'",
        "acceptance_time := clock_timestamp()",
        "p_expires_at <= acceptance_time",
        "pg_advisory_xact_lock",
        "FROM PUBLIC, rss_app, rss_app_read, rss_audit_admin",
        "TO rss_resource_fact_bootstrap",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
    let bootstrap_signature = MIGRATION
        .split("CREATE FUNCTION public.rss_apply_resource_security_fact_revision(")
        .nth(1)
        .and_then(|tail| tail.split(") RETURNS").next())
        .expect("bootstrap signature");
    assert!(
        !bootstrap_signature.contains("jsonb"),
        "bootstrap ingress must not accept JSON"
    );
    assert!(!MIGRATION.contains("GRANT INSERT ON TABLE public.resource_security_fact_revisions TO rss_resource_fact_bootstrap"));
    assert!(!MIGRATION.contains(
        "GRANT SELECT ON TABLE public.resource_security_fact_revisions TO rss_app, rss_app_read, rss_audit_admin"
    ));
}

#[test]
fn migration_hard_fails_legacy_data_and_replaces_policy_authority() {
    let lock = MIGRATION
        .find("LOCK TABLE public.resource_attributes")
        .unwrap();
    let preflight = MIGRATION
        .find("legacy resource_attributes require external re-authoring")
        .unwrap();
    let drop_legacy = MIGRATION
        .find("DROP TABLE public.resource_attributes")
        .unwrap();
    assert!(lock < preflight && preflight < drop_legacy);
    for required in [
        "unsupported resource facts",
        "LIMIT 20",
        "rss_abac_policy_operator_values_valid_v2",
        "rss_abac_policy_validator_owner NOLOGIN NOINHERIT NOBYPASSRLS",
        "resource fact security role attributes are unsafe",
        "resource fact security roles must not have memberships",
        "SECURITY DEFINER",
        "DROP CONSTRAINT abac_policies_operator_values_v1",
        "RENAME TO rss_abac_policy_operator_values_structurally_valid",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing invariant: {required}"
        );
    }
    assert!(
        !MIGRATION
            .to_ascii_lowercase()
            .contains("insert into public.resource_security_fact_revisions select")
    );
}
