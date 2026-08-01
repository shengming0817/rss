//! Exact-lane tenant transaction external-boundary compile lock.
//!
//! INVARIANT: PG-TX-CAPABILITY-SEAL-01 · PG-OUTBOX-SETTLEMENT-CAPABILITY-01 { level = "Hard", exec = "test", source = "trybuild" }：
//! 外部 crate 不能构造 `TenantDb` / `TenantTx`，也不能构造 / mint 全局 postgres 事务能力令牌；
//! 租户能力只能由 postgres adapter 在完成 tenant setup 的真实事务内部铸造。LocalTxAttempt mint 密封另由 `cotx::settlement` 的
//! PG-LOCALTX-SETTLEMENT-01（`pub(super)` + 下列 trybuild）守住；outbox claim 的 monotonic
//! deadline 与 settlement capability/outcome 同样不能从 adapter 外部读取或构造。

#[test]
fn tenant_transaction_ui() {
    let t = trybuild::TestCases::new();
    if cfg!(feature = "integration") {
        t.pass("tests/ui/tenant_transaction_boundary_surface_pass.rs");
        t.compile_fail("tests/ui/tenant_db_private_fields_fail.rs");
        t.compile_fail("tests/ui/tenant_tx_private_fields_fail.rs");
        t.compile_fail("tests/ui/tenant_tx_executor_absent_fail.rs");
        t.compile_fail("tests/ui/tenant_tx_lifecycle_absent_fail.rs");
        t.compile_fail("tests/ui/tenant_tx_wrong_lane_fail.rs");
        t.compile_fail("tests/ui/tenant_identity_operation_wrong_lane_fail.rs");
        t.compile_fail("tests/ui/tenant_identity_facade_forge_fail.rs");
        t.compile_fail("tests/ui/tenant_identity_outbox_operation_fail.rs");
        t.compile_fail("tests/ui/tenant_outbox_reconcile_operation_fail.rs");
        t.compile_fail("tests/ui/tenant_tx_global_substitute_fail.rs");
        t.compile_fail("tests/ui/tenant_tx_hrtb_escape_fail.rs");
    }
    t.compile_fail("tests/ui/localtx_attempt_external_mint_fail.rs");
    t.compile_fail("tests/ui/localtx_attempt_sibling_path_mint_fail.rs");
    t.compile_fail("tests/ui/pg_store_private_fail.rs");
    t.compile_fail("tests/ui/pg_maintenance_infra_absent_fail.rs");
    t.compile_fail("tests/ui/pg_projection_replay_fields_private_fail.rs");
    t.compile_fail("tests/ui/pg_projection_replay_capability_required_fail.rs");
    t.compile_fail("tests/ui/pg_runtime_owner_clone_fail.rs");
    t.compile_fail("tests/ui/pg_runtime_owner_consume_twice_fail.rs");
    t.compile_fail("tests/ui/pg_runtime_owner_legacy_api_fail.rs");
    t.compile_fail("tests/ui/pg_runtime_setup_legacy_signature_fail.rs");
    t.compile_fail("tests/ui/pg_runtime_setup_legacy_policy_signature_fail.rs");
    t.compile_fail("tests/ui/pg_runtime_setup_audit_admin_signature_fail.rs");
    t.compile_fail("tests/ui/pg_runtime_setup_plain_read_config_fail.rs");
    t.compile_fail("tests/ui/pg_runtime_migration_capability_absent_fail.rs");
    t.compile_fail("tests/ui/pg_runtime_capabilities_private_fail.rs");
    t.compile_fail("tests/ui/pg_runtime_handle_lifecycle_fail.rs");
    t.compile_fail("tests/ui/pg_runtime_handle_replay_store_fail.rs");
    #[cfg(feature = "domain-settings")]
    t.compile_fail("tests/ui/pg_settings_projection_bundle_apply_absent_fail.rs");
    t.compile_fail("tests/ui/pg_readiness_sampler_factory_clone_fail.rs");
    t.compile_fail("tests/ui/pg_readiness_sampler_factory_consume_twice_fail.rs");
    t.compile_fail("tests/ui/pg_outbox_claim_clone_fail.rs");
    t.compile_fail("tests/ui/pg_outbox_claim_lease_read_fail.rs");
    t.compile_fail("tests/ui/pg_outbox_claim_monotonic_deadline_read_fail.rs");
    t.compile_fail("tests/ui/pg_outbox_claim_construct_fail.rs");
    t.compile_fail("tests/ui/pg_outbox_settlement_capability_access_fail.rs");
    if cfg!(feature = "integration") {
        t.compile_fail("tests/ui/consumer_tx_commit_proof_construct_fail.rs");
        t.compile_fail("tests/ui/consumer_tx_commit_proof_substitute_fail.rs");
        t.compile_fail("tests/ui/device_ingress_commit_proof_construct_fail.rs");
    }
    t.pass("tests/ui/pg_public_funnels_pass.rs");
}

#[test]
fn workflow_projection_raw_signature_is_absent() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/pg_runtime_projection_raw_signature_fail.rs");
}

#[test]
fn production_event_writers_reject_raw_entries() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/pg_event_writer_raw_entry_fail.rs");
}
