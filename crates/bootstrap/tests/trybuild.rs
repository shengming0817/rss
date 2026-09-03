#[test]
fn hard_api_boundaries_fail_to_compile() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/domain_module_result_outputs_are_private.rs");
}
