#[test]
fn raw_loops_and_cancellation_tokens_remain_private() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/*.rs");
}
