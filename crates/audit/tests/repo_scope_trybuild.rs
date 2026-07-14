#[test]
fn audit_repo_scope_ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/audit_scope_private_fields_fail.rs");
    t.compile_fail("tests/ui/audit_scope_private_ctor_fail.rs");
    t.compile_fail("tests/ui/audit_repo_bare_tenant_fail.rs");
    t.compile_fail("tests/ui/audit_admin_repo_bare_tenant_fail.rs");
    t.compile_fail("tests/ui/audit_cross_tenant_scope_private_ctor_fail.rs");
    t.compile_fail("tests/ui/audit_cross_tenant_scope_private_fields_fail.rs");
    t.compile_fail("tests/ui/audit_cross_tenant_scope_non_clone_fail.rs");
    t.compile_fail("tests/ui/audit_list_tenant_append_private_fields_fail.rs");
    t.compile_fail("tests/ui/audit_row_visibility_all_fail.rs");
    t.pass("tests/ui/audit_repo_scope_pass.rs");
    t.pass("tests/ui/audit_admin_repo_scope_pass.rs");
}
