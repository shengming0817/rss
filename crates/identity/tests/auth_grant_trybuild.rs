//! Medium external-consumer evidence for the production AuthGrant and bearer release funnel.

#[test]
fn auth_grant_ui_boundaries() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/auth_grant_private_fields_fail.rs");
    tests.compile_fail("tests/ui/auth_grant_split_refresh_insert_fail.rs");
    tests.compile_fail("tests/ui/auth_grant_pending_bearer_private_fail.rs");
    tests.compile_fail("tests/ui/auth_grant_persisted_receipt_forge_fail.rs");
    tests.compile_fail("tests/ui/auth_grant_split_provider_constructor_fail.rs");
}
