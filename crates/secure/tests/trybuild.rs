//! Password production type-wall regressions.

#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/password_raw_cannot_hash.rs");
    t.compile_fail("tests/ui/password_receipts_cannot_be_forged.rs");
    t.compile_fail("tests/ui/password_verified_cannot_be_forged.rs");
    t.compile_fail("tests/ui/password_ad_hoc_blocklist_provider_rejected.rs");
}

// A dedicated typed CI gate invokes this test in a feature-isolated Cargo process. Workspace
// tests may legitimately unify secure/test-support through identity's seed-login test graph.
#[test]
#[cfg(not(feature = "test-support"))]
fn production_seams_absent() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/password_test_constructors_are_not_production_api.rs");
}
