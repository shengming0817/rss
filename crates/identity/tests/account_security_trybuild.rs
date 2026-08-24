//! Medium external-consumer evidence for the production account-security authentication funnel.

#[test]
fn account_security_ui_boundaries() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/account_security_active_receipt_private_fail.rs");
    tests.compile_fail("tests/ui/account_security_mutation_fields_private_fail.rs");
    tests.compile_fail("tests/ui/account_security_authenticate_requires_password_fail.rs");
    tests.compile_fail("tests/ui/account_security_refresh_reader_required_fail.rs");
    tests.compile_fail("tests/ui/account_security_bare_refresh_issue_fail.rs");
}
