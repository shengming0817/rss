//! Common execution admission, held by PostgreSQL through commit/rollback.
use crate::{PgError, PgRuntime, transaction::Profile};
use rss_request_context::TenantId;
use rss_transactional_messaging::{
    fence::ExecutionBinding,
    policy::{AbsoluteDeadline, within},
};
use sqlx::PgConnection;

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) async fn setup(
    connection: &mut PgConnection,
    binding: &ExecutionBinding,
    tenant: TenantId,
    lock: bool,
) -> Result<(), PgError> {
    let epoch = binding.epoch(tenant).ok_or_else(PgError::lost)?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('rss.storage_target',$2,true),set_config('rss.storage_lineage',$3,true),set_config('rss.execution_epoch',$4,true)")
        .bind(tenant.to_string())
        .bind(hex(&binding.storage().target()))
        .bind(hex(&binding.storage().lineage()))
        .bind(epoch.get().to_string())
        .execute(&mut *connection)
        .await?;
    if lock {
        sqlx::query("SELECT rss_transactional_messaging.check_execution()")
            .execute(connection)
            .await?;
    }
    Ok(())
}
pub(crate) async fn probe(
    runtime: &PgRuntime,
    profile: Profile,
    cutoff: AbsoluteDeadline,
) -> Result<(), PgError> {
    let operator = false;
    #[cfg(feature = "recovery")]
    let operator = operator || profile == Profile::Dr;
    #[cfg(not(feature = "recovery"))]
    let _ = profile;
    let valid = within(&runtime.timer, cutoff, |_| async {
        sqlx::query_scalar::<_, bool>(include_str!("fence_probe.sql"))
            .bind(operator)
            .fetch_one(&runtime.pool)
            .await
    })
    .await?
    .map_err(PgError::probe)?;
    if !valid {
        return Err(PgError::IncompatibleStorageContract(
            crate::PgStorageContractFailure::Functions,
        ));
    }
    Ok(())
}
