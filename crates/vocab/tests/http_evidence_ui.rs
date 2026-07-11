//! Compile-time validation for generated HTTP effect profiles.

#[test]
fn invalid_const_effect_profiles_do_not_compile() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/http_effect_profile_empty.rs");
    tests.compile_fail("tests/ui/http_effect_profile_duplicate.rs");
    tests.compile_fail("tests/ui/http_consistency_class_is_sealed.rs");
}
