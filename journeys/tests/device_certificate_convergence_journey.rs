#![allow(clippy::disallowed_methods)] // reason: the hermetic pilot receives a process-real Clock.

#[path = "support/device_certificate_convergence.rs"]
mod support;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offline_device_reconnects_and_converges_only_after_matching_report() -> anyhow::Result<()>
{
    support::run().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_candidate_acquires_vault_artifact_and_restarts_from_durable_state()
-> anyhow::Result<()> {
    support::run_production_candidate_acquisition_and_restart().await
}
