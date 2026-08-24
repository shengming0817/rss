#[cfg(feature = "backend")]
#[test]
fn token_profile_builders_enforce_profile_specific_configuration() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/rss_access_rejects_trust_kind_override_fail.rs");
    tests.compile_fail("tests/ui/rss_access_rejects_tenant_claim_override_fail.rs");
    tests.compile_fail("tests/ui/rss_access_rejects_kind_claim_override_fail.rs");
    tests.compile_fail("tests/ui/federated_constructor_requires_permissions_fail.rs");
    tests.compile_fail("tests/ui/projection_operator_rejects_hs256_keys_fail.rs");
}
