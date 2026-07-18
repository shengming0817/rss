#[test]
fn reconcile_registration_rejects_untyped_executors() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/reconcile_raw_closure_fail.rs");
    tests.compile_fail("tests/ui/reconcile_wide_service_fail.rs");
    tests.compile_fail("tests/ui/reconcile_wide_wrapper_fail.rs");
}
