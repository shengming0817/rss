//! Exact-image SettingsOnly production acceptance over the closed join-hazard set.

#[path = "support/settingsonly_production_artifact.rs"]
mod settingsonly_production_artifact;

use settingsonly_production_artifact::{EvidenceCase, run_case};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settingsonly_image_mount_spiffe_readiness_join() -> anyhow::Result<()> {
    run_case(EvidenceCase::InputReady).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settingsonly_image_pg_outbox_amqp_inbox_join() -> anyhow::Result<()> {
    run_case(EvidenceCase::L2Join).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settingsonly_image_sigkill_redelivery_join() -> anyhow::Result<()> {
    run_case(EvidenceCase::Sigkill).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settingsonly_image_sigterm_drain_join() -> anyhow::Result<()> {
    run_case(EvidenceCase::Sigterm).await
}
