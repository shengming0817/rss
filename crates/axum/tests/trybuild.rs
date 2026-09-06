#[test]
fn contract_bindings_preserve_identity_and_types() {
    let cases = trybuild::TestCases::new();
    cases.pass("tests/ui/correct.rs");
    cases.compile_fail("tests/ui/*_fail.rs");
}
