#[test]
fn raw_subscriber_registration_is_not_public() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/raw_subscriber_registration_fail.rs");
}
