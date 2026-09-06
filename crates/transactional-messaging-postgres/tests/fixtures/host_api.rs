use adapter::{PgConfig, PgError, PgRuntime};
use message_core::{policy::{ExecutionTimer, OperationDeadline}, transaction::LocalTxAttempt};
use rss_request_context::TenantId;

pub async fn own_host<C: ExecutionTimer + 'static>(
    config: PgConfig, timer: C, tenant: TenantId, deadline: OperationDeadline,
) -> Result<LocalTxAttempt<(), PgError>, PgError> {
    let runtime = PgRuntime::connect(config, timer).await?;
    let result = runtime.local_tx(tenant, deadline, |_| Box::pin(async { Ok(()) })).await;
    runtime.close().await;
    Ok(result)
}

#[cfg(any(feature = "rss-runtime", feature = "trait-probe"))]
pub fn managed_bridge() {
    fn requires_resource<T: rss_runtime::ManagedResource>() {}
    requires_resource::<PgRuntime>();
}
