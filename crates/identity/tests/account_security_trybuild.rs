//! Hard negative proofs for the account-security authentication funnel.

#[test]
fn account_security_ui_boundaries() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/account_security_active_receipt_private_fail.rs");
    tests.compile_fail("tests/ui/account_security_mutation_fields_private_fail.rs");
    tests.compile_fail("tests/ui/account_security_refresh_principal_removed_fail.rs");
    tests.compile_fail("tests/ui/account_security_lockout_status_removed_fail.rs");
    tests.compile_fail("tests/ui/account_security_refresh_reader_required_fail.rs");
    tests.compile_fail("tests/ui/account_security_bare_refresh_issue_fail.rs");
}
