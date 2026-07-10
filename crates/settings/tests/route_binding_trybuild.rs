//! Contract-specific route identity must make evidence/handler exchange unrepresentable.

#[test]
fn generated_route_evidence_cannot_bind_another_contract_handler() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/config_get_evidence_cannot_bind_delete_handler.rs");
}
