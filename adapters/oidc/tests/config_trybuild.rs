#[cfg(feature = "backend")]
#[test]
fn rss_access_builder_has_no_kind_allowlist() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/rss_access_trust_kind_removed_fail.rs");
}
