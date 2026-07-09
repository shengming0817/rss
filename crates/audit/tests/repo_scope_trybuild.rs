#[test]
fn audit_repo_scope_ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/audit_scope_private_fields_fail.rs");
    t.compile_fail("tests/ui/audit_scope_private_ctor_fail.rs");
    t.compile_fail("tests/ui/audit_repo_bare_tenant_fail.rs");
    t.compile_fail("tests/ui/audit_row_visibility_all_fail.rs");
    t.pass("tests/ui/audit_repo_scope_pass.rs");
}
