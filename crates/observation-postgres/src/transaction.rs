// ref: launchbadge/sqlx sqlx-core/src/transaction.rs@v0.9.0
// ref: baseline 5b63e10 adapters/postgres/src/cotx/settlement.rs
use rss_observation::{Error, ErrorKind};
use sqlx::{Postgres, pool::PoolConnection};
pub(crate) struct Lease {
    pub connection: PoolConnection<Postgres>,
    pub settled: bool,
}
impl Drop for Lease {
    fn drop(&mut self) {
        if !self.settled {
            self.connection.close_on_drop();
        }
    }
}
pub(crate) fn sql_error(error: sqlx::Error) -> Error {
    let kind = match error.as_database_error().and_then(|e| e.code()).as_deref() {
        // Server cancellation is an operation failure. The transaction owner must acknowledge
        // rollback before exposing Deadline; commit/rollback errors have separate classifiers.
        Some("57014" | "55P03") => ErrorKind::Deadline,
        Some("23505" | "OB001") => ErrorKind::Conflict,
        Some("OB002") => ErrorKind::StaleEpoch,
        Some("OB003") => ErrorKind::LifecycleConflict,
        Some("OB004" | "23514" | "23503" | "42501" | "42P01" | "42703") => ErrorKind::Invariant,
        _ => {
            if matches!(error, sqlx::Error::PoolClosed) {
                ErrorKind::Closed
            } else {
                ErrorKind::Storage
            }
        }
    };
    Error::provider(kind, error)
}
/// One-shot integration transport/transaction faults; defaults expose no injection API.
#[cfg(feature = "integration")]
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Fault {
    /// Roll back after the operation staged its work but before issuing COMMIT.
    BeforeCommit = 1,
    /// Commit on the real backend, then hide its acknowledgment to exercise exact readback.
    CommitAckLost = 2,
    /// Commit but suppress both acknowledgment and the following recovery read.
    CommitAckAndReadLost = 3,
    /// Hold COMMIT unresolved until the caller deadline cancels the transaction.
    CommitPending = 4,
    /// Perform rollback on the backend but hide acknowledgment; report RollbackFailed.
    RollbackAckLost = 5,
    /// Hold rollback unresolved until the caller deadline cancels it.
    RollbackPending = 6,
    /// Set a short server statement watchdog before the operation (real SQLSTATE 57014).
    ShortStatementWatchdog = 7,
    /// Set a short server lock watchdog before the operation (real SQLSTATE 55P03).
    ShortLockWatchdog = 8,
    /// Trigger a real statement timeout after staging all writes, before commit.
    StatementTimeoutAfterWrite = 9,
    /// Disable server watchdogs only to isolate client-deadline cancellation in a test.
    ClientDeadlineOnly = 10,
}

use rss_observation::Clock;
use rss_request_context::Deadline;
use std::{
    future::Future,
    sync::atomic::{AtomicU8, Ordering},
    time::Duration,
};
/// Private settlement progress survives cancellation of the inner future.
pub(crate) struct Progress(AtomicU8);
#[derive(Clone, Copy)]
#[repr(u8)]
pub(crate) enum Stage {
    Waiting = 0,
    Effects = 1,
    Rollback = 2,
}
impl Progress {
    pub fn new() -> Self {
        Self(AtomicU8::new(Stage::Waiting as u8))
    }
    pub fn set(&self, stage: Stage) {
        self.0.store(stage as u8, Ordering::SeqCst);
    }
    fn timed_out(&self) -> ErrorKind {
        match self.0.load(Ordering::SeqCst) {
            0 => ErrorKind::Deadline,
            1 => ErrorKind::CommitUnknown,
            2 => ErrorKind::RollbackFailed,
            _ => ErrorKind::Invariant,
        }
    }
}
pub(crate) async fn within<C: Clock, T>(
    clock: &C,
    deadline: Deadline,
    progress: &Progress,
    future: impl Future<Output = T>,
) -> Result<T, Error> {
    let remaining = deadline.remaining(clock.now()).ok_or(ErrorKind::Deadline)?;
    tokio::time::timeout(remaining, future)
        .await
        .map_err(|_| Error::new(progress.timed_out()))
}
pub(crate) fn watchdog(remaining: Duration) -> String {
    format!("{}ms", remaining.as_millis().clamp(1, i32::MAX as u128))
}
#[cfg(feature = "integration")]
pub(crate) async fn watchdog_fault(
    connection: &mut sqlx::PgConnection,
    fault: u8,
) -> Result<(), Error> {
    let values = match fault {
        7 => Some(("10ms", "0")),
        8 => Some(("0", "10ms")),
        10 => Some(("0", "0")),
        _ => None,
    };
    if let Some((statement, lock)) = values {
        sqlx::query(
            "SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$2,true)",
        )
        .bind(statement)
        .bind(lock)
        .execute(connection)
        .await
        .map_err(sql_error)?;
    }
    Ok(())
}
#[cfg(feature = "integration")]
pub(crate) async fn after_write_fault<T>(
    connection: &mut sqlx::PgConnection,
    fault: u8,
    result: Result<T, Error>,
) -> Result<T, Error> {
    if fault == 9 && result.is_ok() {
        sqlx::query("SELECT set_config('statement_timeout','10ms',true)")
            .execute(&mut *connection)
            .await
            .map_err(sql_error)?;
        sqlx::query("SELECT pg_sleep(1)")
            .execute(connection)
            .await
            .map_err(sql_error)?;
        return Err(ErrorKind::Invariant.into()); // The injected server timeout must actually fire.
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn postgres_watchdog_bounds() {
        assert_eq!(watchdog(Duration::ZERO), "1ms");
        assert_eq!(watchdog(Duration::from_millis(42)), "42ms");
        assert_eq!(
            watchdog(Duration::from_millis(i32::MAX as u64)),
            "2147483647ms"
        );
        assert_eq!(watchdog(Duration::MAX), "2147483647ms");
    }
}
