#[test]
fn lifecycle_capabilities_are_not_forgeable() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/task_status_forge_fail.rs");
    t.compile_fail("tests/ui/managed_task_registration_forge_fail.rs");
    t.compile_fail("tests/ui/blocking_worker_registration_forge_fail.rs");
    t.compile_fail("tests/ui/managed_task_spawn_raw_future_fail.rs");
    t.compile_fail("tests/ui/shutdown_stack_token_accessor_fail.rs");
    t.compile_fail("tests/ui/startup_transaction_forge_fail.rs");
    t.compile_fail("tests/ui/shutdown_receipt_forge_fail.rs");
    t.compile_fail("tests/ui/managed_task_detached_registration_fail.rs");
    t.compile_fail("tests/ui/blocking_worker_detached_registration_fail.rs");
}
