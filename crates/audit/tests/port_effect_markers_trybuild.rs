//! INVARIANT: AUDIT-PORT-CLASSIFICATION-01 { level = "Hard", exec = "verify", source = "trybuild" }

#[test]
fn audit_port_effect_markers_ui() {
    let t = trybuild::TestCases::new();
    t.pass("tests/ui/audit_port_effect_pass.rs");
    t.compile_fail("tests/ui/audit_port_effect_external_impl_fail.rs");
    t.compile_fail("tests/ui/audit_port_effect_write_as_read_fail.rs");
    t.compile_fail("tests/ui/audit_port_effect_admin_as_local_fail.rs");
}
