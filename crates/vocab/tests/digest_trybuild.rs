#[test]
fn canonical_sha256_digest_fields_are_private() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/canonical_sha256_digest_fields_are_private.rs");
}
