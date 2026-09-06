#[test]
fn saga_idempotency_storage_hydration_keeps_raw_fields_private() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/saga_idempotency_key_forge_fail.rs");
}
