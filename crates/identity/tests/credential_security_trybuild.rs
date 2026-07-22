//! Hard positive proof for the closed credential-security event protocol.

#[test]
fn credential_security_protocol_is_closed_and_typed() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/ui/credential_security_protocol_pass.rs");
    tests.compile_fail("tests/ui/credential_security_command_private_fail.rs");
    tests.compile_fail("tests/ui/credential_security_command_non_clone_fail.rs");
    tests.compile_fail("tests/ui/credential_security_authorization_private_fail.rs");
    tests.compile_fail("tests/ui/credential_security_account_grant_close_fail.rs");
    tests.compile_fail("tests/ui/credential_security_legacy_reason_removed_fail.rs");
}
