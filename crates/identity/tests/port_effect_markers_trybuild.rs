//! INVARIANT: IDENTITY-PORT-CLASSIFICATION-01 { level = "Medium", exec = "test", source = "trybuild" }

#[test]
fn identity_port_effect_markers_are_closed_and_exact() {
    let t = trybuild::TestCases::new();
    t.pass("tests/ui/identity_port_effect_pass.rs");
    t.compile_fail("tests/ui/identity_port_effect_external_impl_fail.rs");
    t.compile_fail("tests/ui/identity_port_effect_wrong_class_fail.rs");
    t.compile_fail("tests/ui/identity_port_effect_refresh_write_fail.rs");
    t.compile_fail("tests/ui/identity_port_effect_role_auth_fail.rs");
    t.compile_fail("tests/ui/identity_port_effect_role_read_fail.rs");
    t.compile_fail("tests/ui/identity_port_effect_wrappers_fail.rs");
    t.compile_fail("tests/ui/identity_port_effect_alias_fail.rs");
    t.compile_fail("tests/ui/identity_raw_resource_fact_repo_effect_fail.rs");
    t.compile_fail("tests/ui/role_definition_actor_required_fail.rs");
}
