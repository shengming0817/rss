#[test]
fn identity_repo_scope_ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/identity_scope_private_fields_fail.rs");
    t.compile_fail("tests/ui/identity_scope_private_ctor_fail.rs");
    t.compile_fail("tests/ui/identity_repo_bare_tenant_fail.rs");
    t.compile_fail("tests/ui/identity_row_visibility_all_fail.rs");
    t.compile_fail("tests/ui/identity_localtx_mutation_private_ctor_fail.rs");
    t.compile_fail("tests/ui/identity_localtx_mutation_private_fields_fail.rs");
    t.pass("tests/ui/identity_repo_scope_pass.rs");
}
