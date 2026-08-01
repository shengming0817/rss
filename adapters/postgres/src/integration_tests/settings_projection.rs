//! Dedicated Settings projection replay journeys.
//!
//! Each failure settlement owns an independently filterable test symbol; the A/B/C parity journey
//! remains separate in the parent fixture because it exercises the full projection-source stack.

use super::{SettingsReplayFailureCase, TestResult};

testkit::projection_target_conformance! {
    cases: {
        atomic_apply => { #[tokio::test] pg_settings_conformance_atomic => super::pg_settings_atomic },
        same_fact_duplicate => { #[tokio::test] pg_settings_conformance_duplicate => super::pg_settings_duplicate },
        same_key_conflict => { #[tokio::test] pg_settings_conformance_conflict => super::pg_settings_conflict },
        persistent_out_of_order => { #[tokio::test] pg_settings_conformance_order => super::pg_settings_order },
        identity_mismatch => { #[tokio::test] pg_settings_conformance_identity => super::pg_settings_identity },
        confirmed_rollback => { #[tokio::test] pg_settings_conformance_rollback => super::pg_settings_rollback },
        commit_unknown_replay => { #[tokio::test] pg_settings_conformance_commit_unknown => super::pg_settings_commit_unknown },
        rollback_failed => { #[tokio::test] pg_settings_conformance_rollback_failed => super::pg_settings_rollback_failed },
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_first_apply_read_update_tombstone_and_scope_isolation() -> TestResult {
    super::settings_projection_first_apply_read_update_tombstone_and_scope_isolation().await
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_real_roles_enforce_rls_and_exact_acl_negatives() -> TestResult {
    super::settings_projection_real_roles_enforce_rls_and_exact_acl_negatives().await
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_operator_lane_reuses_the_only_apply_function() -> TestResult {
    super::settings_projection_operator_lane_reuses_the_only_apply_function().await
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_generation_bytes_are_bounded_in_all_three_tables() -> TestResult {
    super::settings_projection_generation_bytes_are_bounded_in_all_three_tables().await
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_receipt_precedes_ordering_and_persists_across_reconstruction()
-> TestResult {
    super::settings_projection_receipt_precedes_ordering_and_persists_across_reconstruction().await
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_concurrent_duplicate_is_single_effect() -> TestResult {
    super::settings_projection_concurrent_duplicate_is_single_effect().await
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_direct_commit_unknown_replay_converges_by_receipt() -> TestResult {
    super::settings_projection_commit_unknown_replay_converges_by_persistent_receipt().await
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_direct_rollback_failed_leaves_no_state() -> TestResult {
    super::settings_projection_rollback_failed_is_fail_closed_without_state_advance().await
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_receipt_failure_rolls_back_row_and_high_water() -> TestResult {
    super::settings_projection_receipt_failure_rolls_back_row_and_high_water().await
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_shadow_replay_a_b_c_converges_after_restart_and_checkpoint_loss()
-> TestResult {
    super::settings_projection_shadow_replay_a_b_c_journey().await
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_commit_unknown_preserves_checkpoint_and_dlx() -> TestResult {
    super::settings_projection_operator_replay_failure_case(
        SettingsReplayFailureCase::CommitUnknown,
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_rollback_failed_preserves_checkpoint_and_dlx() -> TestResult {
    super::settings_projection_operator_replay_failure_case(
        SettingsReplayFailureCase::RollbackFailed,
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_tenant_drift_is_controlled_poison() -> TestResult {
    super::settings_projection_operator_replay_failure_case(SettingsReplayFailureCase::TenantDrift)
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_persistent_order_is_controlled_poison() -> TestResult {
    super::settings_projection_operator_replay_failure_case(
        SettingsReplayFailureCase::PersistentOrder,
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_projection_schema_drift_is_controlled_poison() -> TestResult {
    super::settings_projection_operator_replay_failure_case(SettingsReplayFailureCase::SchemaDrift)
        .await
}
