//! Host-selected retention, bounded independently of the number of retained bodies.
use crate::{PgConfig, PgError, PgRuntime, PgStorageContractFailure, transaction::Profile};
use rss_request_context::{Deadline, ExecutionTimer};
use rss_transactional_messaging::{
    fence::{ExecutionBinding, StorageIdentity},
    policy::{OperationDeadline, within},
    transaction::LocalTxAttempt,
};
use sqlx::Row;

/// Explicit host retention decision. Credentials authorize this capability; the host
/// authorizes the tenant and policy before calling it. The database additionally requires
/// expiration of the original delivery deadline and absence of active DR dependencies.
#[derive(Clone, Copy)]
pub struct PublishedBodyRetention {
    before_us: i64,
    after: i64,
    limit: u16,
}
impl PublishedBodyRetention {
    /// Scan at most `limit` (1..=1024) retained bodies after `after` (initially zero).
    /// `before_us` is an inclusive original-delivery-deadline cutoff in Unix microseconds.
    /// Resume with the returned coordinate; start a new sweep at zero to revisit skipped rows.
    pub fn new(before_us: i64, after: i64, limit: u16) -> Result<Self, PgError> {
        if before_us < 0 || after < 0 || !(1..=1024).contains(&limit) {
            return Err(PgError::invariant());
        }
        Ok(Self {
            before_us,
            after,
            limit,
        })
    }
}
/// Committed logical release. PostgreSQL MVCC/VACUUM owns physical space reuse.
#[derive(Debug)]
pub struct PublishedBodyPage {
    /// Candidate headers visited, including locked, retained or DR-blocked rows.
    pub scanned: u32,
    /// Bodies actually cleared by this transaction.
    pub reclaimed: u32,
    /// Logical payload bytes cleared; this is not a disk-space promise.
    pub released_bytes: u64,
    /// Last examined Outbox sequence. A short page ends this sweep.
    pub next_seq: i64,
}
/// Separate maintenance credential and private transaction owner. No ordinary runtime
/// profile acquires the release capability. Cancellation never proves rollback.
pub struct PgPublishedBodyMaintenance {
    runtime: PgRuntime,
}
impl PgPublishedBodyMaintenance {
    /// Connect a maintenance-only login with EXECUTE on check_execution and
    /// reclaim_published_bodies(bigint,bigint,integer), plus schema USAGE.
    pub async fn connect<C: ExecutionTimer + 'static>(
        config: PgConfig,
        timer: C,
        storage: StorageIdentity,
    ) -> Result<Self, PgError> {
        Ok(Self {
            runtime: PgRuntime::connect_profile(config, timer, storage, Profile::BodyMaintenance)
                .await?,
        })
    }
    /// Drain the private pool under the host's shutdown budget.
    pub async fn close(&self) {
        self.runtime.close().await;
    }
    /// Apply one explicitly selected tenant/policy page under an absolute operation budget.
    /// Retrying after uncertain commit is safe, but can report fewer releases; counts are
    /// not durable operation receipts and must not be interpreted as proof of rollback.
    pub async fn reclaim(
        &self,
        binding: ExecutionBinding,
        retention: PublishedBodyRetention,
        deadline: OperationDeadline,
    ) -> LocalTxAttempt<PublishedBodyPage, PgError> {
        let cutoff = match self.runtime.cutoff(deadline) {
            Ok(v) => v,
            Err(e) => return LocalTxAttempt::not_started(e),
        };
        self.runtime.transaction_until(binding, cutoff, retention, true,
            #[cfg(feature = "integration")] None,
            |r, tx| Box::pin(async move {
                let row = sqlx::query("SELECT * FROM rss_transactional_messaging.reclaim_published_bodies($1,$2,$3)")
                    .bind(r.before_us).bind(r.after).bind(i32::from(r.limit))
                    .fetch_one(&mut *tx.connection).await?;
                Ok(PublishedBodyPage {
                    scanned: u32::try_from(row.try_get::<i32,_>("scanned")?).map_err(|_| PgError::invariant())?,
                    reclaimed: u32::try_from(row.try_get::<i32,_>("reclaimed")?).map_err(|_| PgError::invariant())?,
                    released_bytes: u64::try_from(row.try_get::<i64,_>("released_bytes")?).map_err(|_| PgError::invariant())?,
                    next_seq: row.try_get("next_seq")?,
                })
            })).await
    }
}
pub(crate) async fn check(runtime: &PgRuntime, cutoff: Deadline) -> Result<(), PgError> {
    let body =
        crate::consumer_profile::function_body(crate::MIGRATION_SQL, "reclaim_published_bodies")?;
    let valid = within(&runtime.timer, cutoff, |_| async {
        sqlx::query_scalar::<_, bool>(include_str!("body_maintenance_probe.sql"))
            .bind(body)
            .fetch_one(&runtime.pool)
            .await
    })
    .await?
    .map_err(PgError::probe)?;
    if !valid {
        return Err(PgError::IncompatibleStorageContract(
            PgStorageContractFailure::Functions,
        ));
    }
    Ok(())
}
