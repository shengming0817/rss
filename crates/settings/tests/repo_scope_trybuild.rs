#[test]
fn settings_repo_scope_ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/settings_scope_private_fields_fail.rs");
    t.compile_fail("tests/ui/settings_scope_private_ctor_fail.rs");
    t.compile_fail("tests/ui/settings_repo_bare_tenant_fail.rs");
    t.compile_fail("tests/ui/settings_repo_read_only_fail.rs");
    t.compile_fail("tests/ui/secret_repo_read_only_fail.rs");
    t.compile_fail("tests/ui/settings_row_visibility_all_fail.rs");
    t.compile_fail("tests/ui/settings_projection_read_scope_bare_tenant_fail.rs");
    t.compile_fail("tests/ui/settings_projection_read_scope_selector_fail.rs");
    t.compile_fail("tests/ui/settings_projection_read_scope_private_fields_fail.rs");
    t.compile_fail("tests/ui/settings_projection_read_scope_private_ctor_fail.rs");
    t.compile_fail("tests/ui/settings_projection_apply_scope_private_fields_fail.rs");
    t.compile_fail("tests/ui/settings_projection_mutation_private_fields_fail.rs");
    t.pass("tests/ui/settings_repo_scope_pass.rs");
}
