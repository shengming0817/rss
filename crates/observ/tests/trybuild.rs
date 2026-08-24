#[test]
fn localtx_observation_is_closed_by_route_consistency_and_private_state() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/localtx_observation_local_only.rs");
    tests.compile_fail("tests/ui/localtx_observation_outbox_fact.rs");
    tests.compile_fail("tests/ui/localtx_observation_private_fields.rs");
    tests.compile_fail("tests/ui/localtx_observation_route_marker_mismatch.rs");
    tests.compile_fail("tests/ui/cert_label_rejects_tenant_dimension.rs");
}
