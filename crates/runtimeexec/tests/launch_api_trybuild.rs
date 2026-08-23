//! Compile-time regression locks for the shared launch kernel's ownership surface.

#[test]
fn launch_ownership_capabilities_cannot_be_forged_or_reused() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/launch_registrar_fields_private_fail.rs");
    tests.compile_fail("tests/ui/launch_registrar_no_root_token_fail.rs");
    tests.compile_fail("tests/ui/launch_registrar_no_detached_fail.rs");
    tests.compile_fail("tests/ui/launch_transaction_fields_private_fail.rs");
    tests.compile_fail("tests/ui/activated_fields_private_fail.rs");
    tests.compile_fail("tests/ui/launch_plan_fields_private_fail.rs");
    tests.compile_fail("tests/ui/launch_plan_clone_fail.rs");
    tests.compile_fail("tests/ui/launch_plan_missing_probe_receipt_fail.rs");
    tests.compile_fail("tests/ui/launch_lifecycle_batches_swapped_fail.rs");
    tests.compile_fail("tests/ui/launch_registrar_raw_resource_fail.rs");
    tests.compile_fail("tests/ui/launch_registrar_managed_task_fail.rs");
}
