#[test]
fn raw_foundation_values_cannot_enter_dispatch() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/raw_context_dispatch_fail.rs");
    cases.compile_fail("tests/ui/trusted_context_minter_forge_fail.rs");
}
