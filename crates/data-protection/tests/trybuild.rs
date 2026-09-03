#[test]
fn protected_data_type_walls() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/open_rejects_stored_aad.rs");
    cases.compile_fail("tests/ui/open_rejects_stored_aad_rederived.rs");
    cases.compile_fail("tests/ui/open_rejects_raw_plaintext_vec.rs");
}
