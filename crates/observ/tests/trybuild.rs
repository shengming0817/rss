#[test]
fn localtx_observation_is_closed_by_route_consistency_and_private_state() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/localtx_observation_*.rs");
}
