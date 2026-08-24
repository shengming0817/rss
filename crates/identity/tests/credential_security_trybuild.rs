//! Medium external-consumer evidence for the closed production credential-security protocol.

#[test]
fn credential_security_protocol_is_closed_and_typed() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/ui/credential_security_protocol_pass.rs");
    tests.compile_fail("tests/ui/credential_security_command_private_fail.rs");
    tests.compile_fail("tests/ui/credential_security_command_non_clone_fail.rs");
    tests.compile_fail("tests/ui/credential_security_route_command_swap_fail.rs");
    tests.compile_fail("tests/ui/credential_security_account_grant_close_fail.rs");
    tests.compile_fail("tests/ui/password_change_raw_string_fail.rs");
    tests.compile_fail("tests/ui/current_auth_grant_cannot_be_forged.rs");
    tests.compile_fail("tests/ui/refresh_writer_receipt_swap_fail.rs");
    tests.compile_fail("tests/ui/refresh_pending_secrets_private_fail.rs");
}
