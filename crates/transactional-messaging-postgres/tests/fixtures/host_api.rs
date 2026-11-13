use rss_request_context::{ExecutionTimer};
use adapter::{PgConfig, PgError, PgRuntime};
use message_core::{policy::{OperationDeadline}, transaction::LocalTxAttempt};

pub async fn own_host<C: ExecutionTimer + 'static>(
    config: PgConfig, timer: C, binding: message_core::fence::ExecutionBinding, deadline: OperationDeadline,
) -> Result<LocalTxAttempt<(), PgError>, PgError> {
    let runtime = PgRuntime::connect(config, timer, (binding).storage()).await?;
    let result = runtime.local_tx(binding, deadline, |_| Box::pin(async { Ok(()) })).await;
    runtime.close().await;
    Ok(result)
}

#[cfg(any(feature = "rss-runtime", feature = "trait-probe"))]
pub fn managed_bridge() {
    fn requires_resource<T: rss_runtime::ManagedResource>() {}
    requires_resource::<PgRuntime>();
}
