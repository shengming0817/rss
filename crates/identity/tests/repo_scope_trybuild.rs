#[test]
fn identity_repo_scope_ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/identity_scope_private_fields_fail.rs");
    t.compile_fail("tests/ui/identity_scope_private_ctor_fail.rs");
    t.compile_fail("tests/ui/identity_repo_bare_tenant_fail.rs");
    t.compile_fail("tests/ui/identity_row_visibility_all_fail.rs");
    t.compile_fail("tests/ui/refresh_producer_receipts_private_fail.rs");
    t.compile_fail("tests/ui/refresh_execution_command_private_fail.rs");
    t.pass("tests/ui/identity_repo_scope_pass.rs");
}
