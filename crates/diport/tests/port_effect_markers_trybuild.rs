//! Port effect 分类的编译期契约。
//!
//! INVARIANT: PORT-CLASSIFICATION-CLOSED-01 { level = "Hard", exec = "test", source = "trybuild" }

#[test]
fn port_effect_markers() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/ui/port_effect_exact_pass.rs");
    tests.compile_fail("tests/ui/port_effect_external_impl_fail.rs");
    tests.compile_fail("tests/ui/port_effect_wrong_class_fail.rs");
    tests.compile_fail("tests/ui/port_effect_arc_box_bypass_fail.rs");
    tests.compile_fail("tests/ui/port_effect_legacy_write_fail.rs");
}
