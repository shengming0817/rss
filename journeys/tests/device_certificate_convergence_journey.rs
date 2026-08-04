#![allow(clippy::disallowed_methods)] // reason: the hermetic pilot receives a process-real Clock.

#[path = "support/device_certificate_convergence.rs"]
mod support;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offline_device_reconnects_and_converges_only_after_matching_report() -> anyhow::Result<()>
{
    support::run().await
}
