//! Compile-time regression lock for the shared launch kernel's completion capability.

#[test]
fn runtime_outputs_can_only_be_minted_by_the_launch_kernel() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/runtime_outputs_direct_construct_fail.rs");
    tests.compile_fail("tests/ui/runtime_outputs_completed_is_private_fail.rs");
}
