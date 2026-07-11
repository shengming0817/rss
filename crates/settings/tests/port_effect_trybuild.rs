#[test]
fn settings_port_effect_is_owner_sealed() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/settings_port_effect_external_impl_fail.rs");
}
