#[test]
fn contract_bindings_preserve_identity_and_types() {
    let cases = trybuild::TestCases::new();
    #[cfg(any(feature = "http1", feature = "http2"))]
    cases.compile_fail("tests/ui/accepted_info_private.rs");
    cases.pass("tests/ui/correct.rs");
    cases.compile_fail("tests/ui/*_fail.rs");
}
