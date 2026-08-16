//! trybuild 回归锁：consistency 引擎策略端口是 native AFIT + 泛型静态分发，不可 `Box<dyn ...>`。

#[test]
fn native_afit_ports_are_not_dyn_compatible() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/dyn_incompatible_inbox_store.rs");
    t.compile_fail("tests/ui/dyn_incompatible_retention_sweeper.rs");
    t.compile_fail("tests/ui/dyn_incompatible_projection_event_source.rs");
    t.compile_fail("tests/ui/projection_serial_witness_non_serial_fail.rs");
    t.compile_fail("tests/ui/dyn_incompatible_reconciler.rs");
    t.pass("tests/ui/projection_event_source_serial_pass.rs");
}

#[test]
fn reconcile_model_public_api_compiles() {
    let t = trybuild::TestCases::new();
    t.pass("tests/ui/reconcile_model_public_api_pass.rs");
}

#[test]
fn legacy_outbox_authoring_api_is_absent() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/legacy_outbox_authoring_api_fail.rs");
}

#[test]
fn claimed_outbox_capability_is_type_enforced() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/legacy_outbox_source_fail.rs");
    t.compile_fail("tests/ui/claimed_outbox_relay_unclaimed_fail.rs");
    t.compile_fail("tests/ui/claimed_outbox_missing_lease_fail.rs");
    t.compile_fail("tests/ui/claimed_outbox_clone_fail.rs");
    t.compile_fail("tests/ui/claimed_outbox_relay_twice_fail.rs");
    t.compile_fail("tests/ui/claimed_outbox_raw_domain_fail.rs");
    t.pass("tests/ui/claimed_outbox_relay_pass.rs");
}

#[test]
fn saga_idempotency_storage_hydration_keeps_raw_fields_private() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/saga_idempotency_key_forge_fail.rs");
}
