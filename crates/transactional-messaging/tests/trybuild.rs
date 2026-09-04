#[test]
fn move_only_authorities_and_private_constructors_are_enforced() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/*.rs");
}
