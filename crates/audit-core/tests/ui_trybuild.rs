#![allow(missing_docs)]

#[test]
fn public_construction_and_serialization_boundaries() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/*.rs");
}
