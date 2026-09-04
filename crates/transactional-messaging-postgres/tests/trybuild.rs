#[test]
fn transaction_authority_is_enforced_for_external_consumers() {
    trybuild::TestCases::new().compile_fail("tests/ui/*.rs");
}
