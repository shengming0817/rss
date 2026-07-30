//! Projection target canonical enrollment compile-time reds.

#[test]
fn projection_target_exact_set_and_behavior_signature_compile_reds() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/projection_target_*.rs");
}
