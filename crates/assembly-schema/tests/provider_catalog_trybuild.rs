#[test]
fn provider_catalog_rejects_forged_or_mismatched_evidence() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/provider_catalog_checked_mismatch.rs");
    cases.compile_fail("tests/ui/provider_catalog_checked_matrix.rs");
    cases.compile_fail("tests/ui/provider_catalog_entry_private.rs");
    cases.compile_fail("tests/ui/provider_evidence_private.rs");
}
