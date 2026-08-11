#[test]
fn domain_execution_capability_stays_runtime_private() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/domain_execution_plan_private_fail.rs");
    tests.compile_fail("tests/ui/placed_provider_execution_private_fail.rs");
}
