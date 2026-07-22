//! Compile-time locks for the canonical operator and runtime-support module boundaries.

#[test]
fn canonical_runtime_public_surface_is_compile_time_locked() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/ui/operator_surface_pass.rs");
    tests.compile_fail("tests/ui/operator_root_paths_removed_fail.rs");
    tests.compile_fail("tests/ui/support_root_paths_removed_fail.rs");
    tests.compile_fail("tests/ui/runtime_internal_module_paths_removed_fail.rs");
}
