#[cfg(feature = "managed-runtime")]
#[test]
fn registration_cancellation_token_remains_private() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/registration_token_private_fail.rs");
}
