//! Durable, scoped service-token replay storage.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use diport::{
    ServiceTokenReplayDeadline, ServiceTokenReplayDeadlineError, ServiceTokenReplayDisposition,
    ServiceTokenReplayKey, ServiceTokenReplayStore, ServiceTokenReplayStoreError,
};
use sqlx::PgPool;

use crate::PgStore;

/// PostgreSQL-backed atomic service-token replay-key store.
///
/// Authentication calls one fixed `SECURITY DEFINER` function and never performs cleanup.
pub struct PgServiceTokenReplayStore {
    pool: PgPool,
}

/// Narrow maintenance capability for bounded replay-key retention.
pub struct PgServiceTokenReplaySweeper {
    pool: PgPool,
}

impl PgServiceTokenReplayStore {
    pub(crate) fn new(store: Arc<PgStore>) -> Self {
        Self {
            pool: store.pool.clone(),
        }
    }
}

impl PgServiceTokenReplaySweeper {
    pub(crate) fn new(store: Arc<PgStore>) -> Self {
        Self {
            pool: store.pool.clone(),
        }
    }

    /// Delete at most one bounded batch of safely expired replay keys.
    pub async fn sweep_expired(
        &self,
        deadline: ServiceTokenReplayDeadline,
    ) -> Result<u64, ServiceTokenReplayStoreError> {
        match execute_replay_operation(&self.pool, deadline, ReplayDbOperation::SweepExpired)
            .await?
        {
            ReplayDbOutcome::Swept(deleted) => {
                u64::try_from(deleted).map_err(|_| ServiceTokenReplayStoreError::Unavailable)
            }
            ReplayDbOutcome::Recorded(_) => Err(map_unexpected_outcome("sweep_expired")),
        }
    }
}

impl ServiceTokenReplayStore for PgServiceTokenReplayStore {
    async fn check_and_record(
        &self,
        key: &ServiceTokenReplayKey,
        expires_at: SystemTime,
        deadline: ServiceTokenReplayDeadline,
    ) -> Result<ServiceTokenReplayDisposition, ServiceTokenReplayStoreError> {
        let expires_at = expires_at
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ServiceTokenReplayStoreError::Unavailable)?
            .as_secs();
        let expires_at =
            i64::try_from(expires_at).map_err(|_| ServiceTokenReplayStoreError::Unavailable)?;
        match execute_replay_operation(
            &self.pool,
            deadline,
            ReplayDbOperation::CheckAndRecord {
                key_digest: *key.digest_bytes(),
                expires_at,
            },
        )
        .await?
        {
            ReplayDbOutcome::Recorded(true) => Ok(ServiceTokenReplayDisposition::Recorded),
            ReplayDbOutcome::Recorded(false) => Ok(ServiceTokenReplayDisposition::Replayed),
            ReplayDbOutcome::Swept(_) => Err(map_unexpected_outcome("check_and_record")),
        }
    }
}

enum ReplayDbOperation {
    CheckAndRecord {
        key_digest: [u8; 32],
        expires_at: i64,
    },
    SweepExpired,
}

enum ReplayDbOutcome {
    Recorded(bool),
    Swept(i64),
}

enum ReplayExecutionError {
    Deadline(ServiceTokenReplayDeadlineError),
    Store(sqlx::Error),
}

async fn execute_replay_operation(
    pool: &PgPool,
    deadline: ServiceTokenReplayDeadline,
    operation: ReplayDbOperation,
) -> Result<ReplayDbOutcome, ServiceTokenReplayStoreError> {
    match deadline
        .run(async {
            let mut transaction = pool.begin().await.map_err(ReplayExecutionError::Store)?;
            let (statement_timeout_ms, lock_timeout_ms) = deadline
                .server_timeout_millis()
                .map_err(ReplayExecutionError::Deadline)?;
            sqlx::query(
                "SELECT set_config('statement_timeout', $1, true), \
                        set_config('lock_timeout', $2, true)",
            )
            .bind(format!("{statement_timeout_ms}ms"))
            .bind(format!("{lock_timeout_ms}ms"))
            .execute(&mut *transaction)
            .await
            .map_err(ReplayExecutionError::Store)?;

            let outcome = match operation {
                ReplayDbOperation::CheckAndRecord {
                    key_digest,
                    expires_at,
                } => {
                    let recorded: bool = sqlx::query_scalar(
                        "SELECT public.rss_service_token_replay_check_and_record($1::bytea, \
                         to_timestamp($2))",
                    )
                    .bind(key_digest.as_slice())
                    .bind(expires_at)
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(ReplayExecutionError::Store)?;
                    ReplayDbOutcome::Recorded(recorded)
                }
                ReplayDbOperation::SweepExpired => {
                    let deleted: i64 = sqlx::query_scalar(
                        "SELECT public.rss_service_token_replay_sweep_expired()::bigint",
                    )
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(ReplayExecutionError::Store)?;
                    ReplayDbOutcome::Swept(deleted)
                }
            };
            transaction
                .commit()
                .await
                .map_err(ReplayExecutionError::Store)?;
            Ok(outcome)
        })
        .await
    {
        Ok(Ok(outcome)) => Ok(outcome),
        Ok(Err(ReplayExecutionError::Store(error))) => Err(map_store_error(error)),
        Ok(Err(ReplayExecutionError::Deadline(error))) | Err(error) => {
            Err(map_deadline_error(error))
        }
    }
}

fn map_store_error(error: sqlx::Error) -> ServiceTokenReplayStoreError {
    tracing::warn!(
        target: "postgres",
        error = %secure::redact_error(&error),
        "service-token replay store operation failed"
    );
    ServiceTokenReplayStoreError::Unavailable
}

fn map_deadline_error(error: ServiceTokenReplayDeadlineError) -> ServiceTokenReplayStoreError {
    tracing::warn!(
        target: "postgres",
        error = %error,
        "service-token replay store operation exceeded its deadline"
    );
    ServiceTokenReplayStoreError::Unavailable
}

fn map_unexpected_outcome(operation: &'static str) -> ServiceTokenReplayStoreError {
    tracing::error!(
        target: "postgres",
        operation,
        "service-token replay store produced an impossible operation outcome"
    );
    ServiceTokenReplayStoreError::Unavailable
}

#[cfg(test)]
mod smoke {
    use super::{PgServiceTokenReplayStore, PgServiceTokenReplaySweeper};

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn pg_service_token_replay_capabilities_are_send_sync() {
        assert_send_sync::<PgServiceTokenReplayStore>();
        assert_send_sync::<PgServiceTokenReplaySweeper>();
    }
}
