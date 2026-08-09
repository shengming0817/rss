//! INVARIANT: IDENTITY-ABAC-OPERATOR-OPAQUE-01 { level = "Hard", exec = "test", source = "trybuild" }

#[test]
fn operator_representation_is_not_an_adapter_api() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/abac_operator_direct_variant_fail.rs");
}
