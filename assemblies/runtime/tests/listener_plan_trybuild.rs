//! Compile-time regression locks for plan-minted listener execution and launch capabilities.

#[test]
fn listener_execution_and_finalization_types_cannot_be_minted_externally() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/listener_execution_spec_private_fail.rs");
    tests.compile_fail("tests/ui/assembled_listener_private_fail.rs");
    tests.compile_fail("tests/ui/finalized_listener_set_private_fail.rs");
    tests.compile_fail("tests/ui/finalized_probe_receipt_private_fail.rs");
    tests.compile_fail("tests/ui/prepared_runtime_listeners_private_fail.rs");
}
