//! Compile the independently optional provider ports; behavioral proof lives in the runnable examples.
#[cfg(feature = "recovery-pg")]
pub async fn dr_store<C: rss_request_context::ExecutionTimer + 'static>(
    config: rss_transactional_messaging_postgres::PgConfig,
    timer: C,
    binding: rss_transactional_messaging::fence::ExecutionBinding,
) -> Result<
    rss_transactional_messaging_postgres::PgDrStore,
    rss_transactional_messaging_recovery::Error,
> {
    rss_transactional_messaging_postgres::PgDrStore::connect(config, timer, binding).await
}
#[cfg(feature = "recovery-pg")]
pub fn capture<H, K>(
    effect: H,
    capture: rss_transactional_messaging_postgres::PgRecoveryCapture<K>,
) -> rss_transactional_messaging_postgres::PgConsumerTx<
    H,
    rss_transactional_messaging_postgres::PgRecoveryCapture<K>,
> {
    rss_transactional_messaging_postgres::PgConsumerTx::with_recovery(effect, capture)
}
#[cfg(feature = "recovery-s3")]
pub async fn verify_bucket(
    client: aws_sdk_s3::Client,
    bucket: String,
    clock: &impl rss_transactional_messaging_recovery_s3::Clock,
    deadline: rss_transactional_messaging::policy::OperationDeadline,
) -> Result<
    rss_transactional_messaging_recovery_s3::S3ArchiveStore,
    rss_transactional_messaging_recovery::archive::Error,
> {
    rss_transactional_messaging_recovery_s3::Unverified::new(client, bucket)?
        .verify(clock, deadline)
        .await
}
fn main() {}
