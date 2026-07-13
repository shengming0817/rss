//! TxCapability 外部边界编译锁。
//!
//! INVARIANT: PG-TX-CAPABILITY-SEAL-01 · AUDIT-CONSUMER-WRITE-ERASURE-01 { level = "Hard", exec = "verify", source = "trybuild" }：
//! 外部 crate 不能构造 / mint postgres 事务能力令牌；只能由 postgres adapter 在真实
//! `sqlx::Transaction` 内部铸造。LocalTxAttempt mint 密封另由 `cotx::settlement` 的
//! PG-LOCALTX-SETTLEMENT-01（`pub(super)` + 下列 trybuild）守住。

#[test]
fn tx_capability_ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/tx_capability_external_construct_fail.rs");
    t.compile_fail("tests/ui/tx_capability_external_mint_fail.rs");
    t.compile_fail("tests/ui/localtx_attempt_external_mint_fail.rs");
    t.compile_fail("tests/ui/localtx_attempt_sibling_path_mint_fail.rs");
    t.compile_fail("tests/ui/pg_store_private_fail.rs");
    t.compile_fail("tests/ui/pg_maintenance_infra_absent_fail.rs");
    t.compile_fail("tests/ui/pg_projection_replay_fields_private_fail.rs");
    t.compile_fail("tests/ui/pg_projection_replay_capability_required_fail.rs");
    t.compile_fail("tests/ui/audit_consumer_read_erasure_fail.rs");
    t.compile_fail("tests/ui/pg_runtime_owner_clone_fail.rs");
    t.compile_fail("tests/ui/pg_runtime_owner_consume_twice_fail.rs");
    t.compile_fail("tests/ui/pg_runtime_owner_legacy_api_fail.rs");
    t.compile_fail("tests/ui/pg_runtime_handle_lifecycle_fail.rs");
    t.compile_fail("tests/ui/pg_readiness_sampler_factory_clone_fail.rs");
    t.compile_fail("tests/ui/pg_readiness_sampler_factory_consume_twice_fail.rs");
    t.compile_fail("tests/ui/pg_outbox_claim_clone_fail.rs");
    t.compile_fail("tests/ui/pg_outbox_claim_lease_read_fail.rs");
    t.compile_fail("tests/ui/pg_outbox_claim_construct_fail.rs");
    t.pass("tests/ui/pg_public_funnels_pass.rs");
}
