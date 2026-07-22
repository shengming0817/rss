//! Fixed, bounded physical retention for expired certificate revocation evidence.

use std::time::Duration;

use consistency::{EngineError, EngineErrorKind};
use sqlx::PgPool;

use crate::cotx::deadline_global_transaction;
use crate::pool::VerifiedPgWriteStore;
use crate::revocation::RevocationCapabilityReceipt;

/// One absolute deadline covering pool acquire, transaction setup, the fixed function and commit.
#[derive(Clone, Copy, Debug)]
pub struct RevocationSweepDeadline {
    operation: tokio::time::Instant,
}

impl RevocationSweepDeadline {
    /// Mint a deadline from a non-zero caller budget.
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

/// Narrow serving capability for the fixed revocation-retention function.
pub struct PgRevocationSweeper {
    pool: PgPool,
    _receipt: RevocationCapabilityReceipt,
}

/// Aggregate rows that remain eligible after the database-owned five-minute grace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevocationRetentionBacklog {
    depth: u64,
    oldest_age_seconds: u64,
}

impl RevocationRetentionBacklog {
    pub const fn depth(self) -> u64 {
        self.depth
    }

    /// Age beyond `not_after + 5 minutes`; a row is observed at age zero when it first qualifies.
    pub const fn oldest_age_seconds(self) -> u64 {
        self.oldest_age_seconds
    }
}

/// One atomic retention tick: bounded deletion followed by a global aggregate backlog sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevocationRetentionReport {
    deleted: u64,
    backlog: RevocationRetentionBacklog,
}

impl RevocationRetentionReport {
    pub const fn deleted(self) -> u64 {
        self.deleted
    }

    pub const fn backlog(self) -> RevocationRetentionBacklog {
        self.backlog
    }
}

impl PgRevocationSweeper {
    pub(crate) fn new(writer: &VerifiedPgWriteStore, receipt: RevocationCapabilityReceipt) -> Self {
        Self {
            pool: writer.pool().clone(),
            _receipt: receipt,
        }
    }

    /// Delete at most the fixed 1,000-row batch and sample the remaining eligible global backlog.
    ///
    /// Both statements share one transaction and one absolute deadline. A failed aggregate sample
    /// therefore rolls back the deletion instead of publishing a success with stale/unknown gauges.
    pub async fn sweep_expired(
        &self,
        deadline: RevocationSweepDeadline,
    ) -> Result<RevocationRetentionReport, EngineError> {
        let (deleted, depth, oldest_age_seconds): (i64, i64, i64) = deadline_global_transaction(
            &self.pool,
            deadline.operation,
            |connection| {
                Box::pin(async move {
                    let deleted = sqlx::query_scalar(
                        "SELECT public.rss_sweep_expired_certificate_revocations()::bigint",
                    )
                    .fetch_one(&mut *connection)
                    .await
                    .map_err(sweep_database_error)?;
                    let (depth, oldest_age_seconds) = sqlx::query_as(
                        "SELECT depth, oldest_age_seconds \
                         FROM public.rss_certificate_revocation_retention_backlog()",
                    )
                    .fetch_one(&mut *connection)
                    .await
                    .map_err(sweep_database_error)?;
                    Ok((deleted, depth, oldest_age_seconds))
                })
            },
            sweep_database_error,
            sweep_timeout_error,
        )
        .await?;
        Ok(RevocationRetentionReport {
            deleted: u64::try_from(deleted)
                .map_err(|_| EngineError::new(EngineErrorKind::Permanent))?,
            backlog: RevocationRetentionBacklog {
                depth: u64::try_from(depth)
                    .map_err(|_| EngineError::new(EngineErrorKind::Permanent))?,
                oldest_age_seconds: u64::try_from(oldest_age_seconds)
                    .map_err(|_| EngineError::new(EngineErrorKind::Permanent))?,
            },
        })
    }
}

fn sweep_database_error(error: sqlx::Error) -> EngineError {
    tracing::warn!(
        target: "postgres",
        error = %secure::redact_error(&error),
        "certificate revocation retention database operation failed"
    );
    EngineError::new(EngineErrorKind::Transient)
}

fn sweep_timeout_error() -> EngineError {
    tracing::warn!(
        target: "postgres",
        "certificate revocation retention deadline elapsed"
    );
    EngineError::new(EngineErrorKind::Transient)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        PgRevocationSweeper, RevocationRetentionBacklog, RevocationRetentionReport,
        RevocationSweepDeadline,
    };

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn postgres_revocation_sweeper_is_send_sync() {
        assert_send_sync::<PgRevocationSweeper>();
    }

    #[test]
    fn postgres_revocation_sweep_deadline_rejects_zero_budget() {
        assert!(RevocationSweepDeadline::from_timeout(Duration::ZERO).is_err());
    }

    #[test]
    fn retention_report_exposes_only_aggregate_values() {
        let report = RevocationRetentionReport {
            deleted: 7,
            backlog: RevocationRetentionBacklog {
                depth: 11,
                oldest_age_seconds: 23,
            },
        };
        assert_eq!(report.deleted(), 7);
        assert_eq!(report.backlog().depth(), 11);
        assert_eq!(report.backlog().oldest_age_seconds(), 23);
    }
}
