#[test]
fn runtime_inventory_response_is_generated_projection_only() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/runtime_inventory_response_direct.rs");
    tests.compile_fail("tests/ui/runtime_inventory_response_bypass.rs");
    tests.compile_fail("tests/ui/runtime_inventory_observation_forge.rs");
}
