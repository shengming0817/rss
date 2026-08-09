const MIGRATION: &str = include_str!("../migrations/0104_enforce_abac_policy_operator_values.sql");

#[test]
fn migration_installs_a_versioned_closed_validator_and_validated_check() {
    for required in [
        "rss_abac_policy_operator_values_valid_v1(jsonb)",
        "IMMUTABLE",
        "STRICT",
        "PARALLEL SAFE",
        "SET search_path = pg_catalog, pg_temp",
        "current_setting('server_encoding') IS DISTINCT FROM 'UTF8'",
        "pg_catalog.convert_to",
        "abac_policies_operator_values_v1",
        "CHECK (public.rss_abac_policy_operator_values_valid_v1(rules))",
        "REVOKE ALL ON FUNCTION public.rss_abac_policy_operator_values_valid_v1(jsonb) FROM PUBLIC",
        "GRANT EXECUTE ON FUNCTION public.rss_abac_policy_operator_values_valid_v1(jsonb) TO rss_app",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing durable invariant: {required}"
        );
    }
    assert!(!MIGRATION.contains("NOT VALID"));
}

#[test]
fn migration_is_atomic_and_preflights_before_constraint_installation() {
    let lock = MIGRATION
        .find("LOCK TABLE public.abac_policies IN ACCESS EXCLUSIVE MODE")
        .unwrap_or(usize::MAX);
    let audit = MIGRATION
        .find("invalid ABAC policy operator values")
        .unwrap_or(usize::MAX);
    let constraint = MIGRATION
        .find("ADD CONSTRAINT abac_policies_operator_values_v1")
        .unwrap_or(usize::MAX);
    assert!(
        lock < audit && audit < constraint,
        "lock, audit and CHECK must be fail-closed and ordered"
    );
    assert!(MIGRATION.contains("SET LOCAL lock_timeout = '5s'"));
    assert!(MIGRATION.contains("SET LOCAL statement_timeout = '5min'"));
    assert!(
        !MIGRATION
            .to_ascii_lowercase()
            .contains("delete from abac_policies")
    );
    assert!(
        !MIGRATION
            .to_ascii_lowercase()
            .contains("update abac_policies")
    );
}

#[test]
fn validator_closes_only_operator_value_subtrees_and_all_value_families() {
    for required in [
        "'equality'",
        "'ordering'",
        "'membership'",
        "'string'",
        "octet_length",
        "BETWEEN 1 AND 256",
        "BETWEEN 1 AND 32",
        "previous_scalar",
        "pg_catalog.convert_to(previous_scalar #>> '{}', 'UTF8') >=",
        "-9223372036854775808",
        "9223372036854775807",
        "BETWEEN 1 AND 64",
        "principal.kind",
        "resource.id",
        "[[:cntrl:]]",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing operator-value invariant: {required}"
        );
    }
    assert!(!MIGRATION.contains("rowScope"));
    assert!(!MIGRATION.contains("fieldMask"));
    assert!(!MIGRATION.contains("effectiveFrom"));
}

#[test]
fn migration_bounds_locked_preflight_diagnostics() {
    for required in [
        "invalid_count bigint",
        "LIMIT 20",
        "sample coordinates",
        "truncated=%",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing bounded preflight diagnostic: {required}"
        );
    }
}
