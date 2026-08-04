#![allow(clippy::disallowed_methods)] // reason: the hermetic pilot receives a process-real Clock.

#[path = "support/mqtt_backpressure_fault.rs"]
mod support;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn broker_delivery_disconnect_before_ingress_commit_replays_to_one_canonical_receipt()
-> anyhow::Result<()> {
    support::broker_delivery_disconnect_before_ingress_commit_replays_to_one_canonical_receipt()
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn saturated_ingress_persistent_session_reconnect_reaches_one_canonical_outcome()
-> anyhow::Result<()> {
    support::saturated_ingress_persistent_session_reconnect_reaches_one_canonical_outcome().await
}
