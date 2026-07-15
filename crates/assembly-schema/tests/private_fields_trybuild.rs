#[test]
fn assembly_lock_construction_is_sealed() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/*_private.rs");
}
