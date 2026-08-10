#[test]
fn public_authority_boundary_is_compile_time_closed() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/*.rs");
}
