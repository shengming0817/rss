//! trybuild 回归锁：consistency 引擎策略端口是 native AFIT + 泛型静态分发，不可 `Box<dyn ...>`。

#[test]
fn native_afit_ports_are_not_dyn_compatible() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/dyn_incompatible_reconciler.rs");
}

#[test]
fn reconcile_model_public_api_compiles() {
    let t = trybuild::TestCases::new();
    t.pass("tests/ui/reconcile_model_public_api_pass.rs");
}

#[test]
fn saga_idempotency_storage_hydration_keeps_raw_fields_private() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/saga_idempotency_key_forge_fail.rs");
}
