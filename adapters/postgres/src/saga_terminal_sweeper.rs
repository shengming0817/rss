//! Fixed, bounded retention for terminal Saga aggregates.

use std::time::Duration;

use consistency::{EngineError, EngineErrorKind};
use sqlx::PgPool;

use crate::cotx::deadline_global_transaction;
use crate::pool::VerifiedPgWriteStore;
use crate::saga_receipt_capability::SagaReceiptCapabilityReceipt;

/// One absolute deadline covering acquire, transaction setup, the fixed sweep and commit.
#[derive(Clone, Copy, Debug)]
pub struct SagaTerminalSweepDeadline {
    operation: tokio::time::Instant,
}

impl SagaTerminalSweepDeadline {
    pub fn from_timeout(timeout: Duration) -> Result<Self, EngineError> {
        if timeout.is_zero() {
            return Err(EngineError::new(EngineErrorKind::Permanent));
        }
        #[allow(clippy::disallowed_methods)]
        let operation = tokio::time::Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| EngineError::new(EngineErrorKind::Permanent))?;
        Ok(Self { operation })
    }
}

/// Narrow runtime capability for the migration-owned 30-day, 1,000-row Saga sweep.
pub struct PgSagaTerminalSweeper {
    pool: PgPool,
    _receipt: SagaReceiptCapabilityReceipt,
}

/// Atomic result of one fixed sweep and its post-delete backlog observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SagaTerminalSweepReport {
    deleted: u64,
    backlog_depth: u64,
    oldest_expired_age_seconds: u64,
}

impl SagaTerminalSweepReport {
    pub const fn deleted(self) -> u64 {
        self.deleted
    }

    pub const fn backlog_depth(self) -> u64 {
        self.backlog_depth
    }

    pub const fn oldest_expired_age_seconds(self) -> u64 {
        self.oldest_expired_age_seconds
    }
}

impl PgSagaTerminalSweeper {
    pub(crate) fn new(
        writer: &VerifiedPgWriteStore,
        receipt: SagaReceiptCapabilityReceipt,
    ) -> Self {
        Self {
            pool: writer.pool().clone(),
            _receipt: receipt,
        }
    }

    /// Delete one fixed database-owned batch of terminal Saga aggregates older than 30 days.
    pub async fn sweep_expired(
        &self,
        deadline: SagaTerminalSweepDeadline,
    ) -> Result<SagaTerminalSweepReport, EngineError> {
        let (deleted, backlog_depth, oldest_expired_age_seconds): (i64, i64, i64) =
            deadline_global_transaction(
                &self.pool,
                deadline.operation,
                |connection| {
                    Box::pin(async move {
                        sqlx::query_as("SELECT * FROM public.rss_sweep_terminal_sagas()")
                            .fetch_one(&mut *connection)
                            .await
                            .map_err(sweep_database_error)
                    })
                },
                sweep_database_error,
                sweep_timeout_error,
            )
            .await?;
        Ok(SagaTerminalSweepReport {
            deleted: nonnegative(deleted)?,
            backlog_depth: nonnegative(backlog_depth)?,
            oldest_expired_age_seconds: nonnegative(oldest_expired_age_seconds)?,
        })
    }
}

fn nonnegative(value: i64) -> Result<u64, EngineError> {
    u64::try_from(value).map_err(|_| EngineError::new(EngineErrorKind::Invariant))
}

fn sweep_database_error(error: sqlx::Error) -> EngineError {
    tracing::warn!(
        target: "postgres",
        error = %secure::redact_error(&error),
        "Saga terminal retention database operation failed"
    );
    EngineError::new(EngineErrorKind::Transient)
}

fn sweep_timeout_error() -> EngineError {
    tracing::warn!(target: "postgres", "Saga terminal retention deadline elapsed");
    EngineError::new(EngineErrorKind::Transient)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{PgSagaTerminalSweeper, SagaTerminalSweepDeadline};

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn saga_terminal_sweeper_is_send_sync() {
        assert_send_sync::<PgSagaTerminalSweeper>();
    }

    #[test]
    fn saga_terminal_sweep_deadline_rejects_zero_budget() {
        assert!(SagaTerminalSweepDeadline::from_timeout(Duration::ZERO).is_err());
    }
}
