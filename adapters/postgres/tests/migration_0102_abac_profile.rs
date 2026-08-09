const MIGRATION: &str = include_str!("../migrations/0102_retype_abac_policy_values.sql");

#[test]
fn migration_fails_closed_before_rewriting_ambiguous_numeric_rules() {
    let guard = MIGRATION
        .find("ambiguous legacy numeric policies")
        .unwrap_or(MIGRATION.len());
    let rewrite = MIGRATION
        .find("UPDATE abac_policies")
        .unwrap_or(MIGRATION.len());
    assert!(
        guard < rewrite && rewrite < MIGRATION.len(),
        "ambiguity guard and policy rewrite must both exist, in fail-closed order"
    );
    assert!(MIGRATION.contains("IN ('gt', 'lt')"));
    assert!(
        !MIGRATION
            .to_ascii_lowercase()
            .contains("delete from abac_policies")
    );
    assert!(
        !MIGRATION
            .to_ascii_lowercase()
            .contains("delete from resource_attributes")
    );
}

#[test]
fn migration_installs_single_typed_resource_value_authority() {
    for required in [
        "ALTER COLUMN attribute_value TYPE jsonb",
        "resource_attributes_typed_value",
        "WHEN 'string'",
        "WHEN 'boolean'",
        "WHEN 'integer'",
        "WHEN 'decimal'",
        "octet_length(attribute_value ->> 'value') <= 256",
        "-9223372036854775808 AND 9223372036854775807",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing typed-value invariant: {required}"
        );
    }
}

#[test]
fn migration_preflights_the_complete_legacy_rule_shape() {
    for required in [
        "jsonb_object_keys(CASE WHEN jsonb_typeof(rule) = 'object' THEN rule ELSE '{}'::jsonb END)) <> 3",
        "ARRAY['condition', 'effect', 'obligations']",
        "ARRAY['attribute', 'operator']",
        "('allow', 'deny')",
        "ARRAY['rowScope', 'fieldMask']",
        "[[:cntrl:]]",
        "malformed or out-of-bounds legacy ABAC policies",
    ] {
        assert!(
            MIGRATION.contains(required),
            "missing complete legacy preflight: {required}"
        );
    }
}

#[test]
fn migration_maps_only_lossless_legacy_operators() {
    for mapping in [
        "WHEN 'eq'",
        "WHEN 'ne'",
        "WHEN 'like'",
        "WHEN 'eqAttr'",
        "'family', 'equality'",
        "'family', 'string'",
        "'predicate', 'glob'",
        "'kind', 'attribute'",
    ] {
        assert!(
            MIGRATION.contains(mapping),
            "missing lossless mapping: {mapping}"
        );
    }
}
