//! One owner for bounded execution, exact receipt readback and settlement observation.
use crate::AttemptStatus;
use rss_transactional_messaging::{
    policy::{ExecutionDeadlines, ExecutionTimer, OperationDeadline, within},
    transaction::LocalTxAttempt,
};

// ref: futures-rs 0.3.32 future/select.rs; core `within` owns cancellation at each absolute cutoff.
pub(crate) async fn execute<T: Send, E: Copy + Send, C: ExecutionTimer, A, R>(
    clock: &C,
    deadlines: ExecutionDeadlines,
    expired: E,
    apply: impl FnOnce(OperationDeadline) -> A,
    readback: impl FnOnce(OperationDeadline) -> R,
    observe: impl Fn(AttemptStatus, Option<&T>, Option<E>),
) -> LocalTxAttempt<T, E>
where
    A: Future<Output = LocalTxAttempt<T, E>> + Send,
    R: Future<Output = Result<Option<T>, E>> + Send,
{
    let attempt = if deadlines.operation().remaining(clock).is_zero() {
        LocalTxAttempt::not_started(expired)
    } else {
        match within(clock, deadlines.operation(), apply).await {
            Ok(attempt) => attempt,
            Err(_) => LocalTxAttempt::commit_unknown(expired),
        }
    };
    let (unknown, attempt) = attempt.fold(
        |v| (false, LocalTxAttempt::committed(v)),
        |e| (false, LocalTxAttempt::not_started(e)),
        |e| (false, LocalTxAttempt::rolled_back(e)),
        |e| (false, LocalTxAttempt::rollback_failed(e)),
        |e| (true, LocalTxAttempt::commit_unknown(e)),
        |e| (false, LocalTxAttempt::fenced(e)),
    );
    let attempt = if unknown {
        match within(clock, deadlines.settlement(), readback).await {
            Ok(Ok(Some(receipt))) => LocalTxAttempt::committed(receipt),
            _ => attempt,
        }
    } else {
        attempt
    };
    attempt.fold(
        |v| {
            observe(AttemptStatus::Committed, Some(&v), None);
            LocalTxAttempt::committed(v)
        },
        |e| {
            observe(AttemptStatus::NotStarted, None, Some(e));
            LocalTxAttempt::not_started(e)
        },
        |e| {
            observe(AttemptStatus::RolledBack, None, Some(e));
            LocalTxAttempt::rolled_back(e)
        },
        |e| {
            observe(AttemptStatus::RollbackFailed, None, Some(e));
            LocalTxAttempt::rollback_failed(e)
        },
        |e| {
            observe(AttemptStatus::CommitUnknown, None, Some(e));
            LocalTxAttempt::commit_unknown(e)
        },
        |e| {
            observe(AttemptStatus::Fenced, None, Some(e));
            LocalTxAttempt::fenced(e)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rss_transactional_messaging::policy::{
        AbsoluteDeadline, Clock, ExecutionBudget, MonotonicInstant,
    };
    use std::{
        cell::RefCell,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    struct Timer;
    impl Clock for Timer {
        fn now(&self) -> MonotonicInstant {
            MonotonicInstant::from_elapsed(Duration::ZERO)
        }
    }
    impl ExecutionTimer for Timer {
        async fn sleep_until(&self, _: AbsoluteDeadline) {
            std::future::pending::<()>().await;
        }
    }
    #[tokio::test]
    async fn every_settlement_is_preserved_and_only_unknown_reads_back()
    -> Result<(), Box<dyn std::error::Error>> {
        use AttemptStatus::*;
        for status in [
            Committed,
            NotStarted,
            RolledBack,
            RollbackFailed,
            CommitUnknown,
            Fenced,
        ] {
            for receipt in [None, Some(42)] {
                let reads = AtomicUsize::new(0);
                let events = RefCell::new(Vec::new());
                let deadlines = ExecutionDeadlines::from_budget(&Timer, ExecutionBudget::STANDARD)?;
                let attempt = execute(
                    &Timer,
                    deadlines,
                    9u8,
                    |_| async move {
                        match status {
                            Committed => LocalTxAttempt::committed(7),
                            NotStarted => LocalTxAttempt::not_started(1),
                            RolledBack => LocalTxAttempt::rolled_back(2),
                            RollbackFailed => LocalTxAttempt::rollback_failed(3),
                            CommitUnknown => LocalTxAttempt::commit_unknown(4),
                            Fenced => LocalTxAttempt::fenced(5),
                        }
                    },
                    |_| async {
                        reads.fetch_add(1, Ordering::Relaxed);
                        Ok(receipt)
                    },
                    |state, value, error| events.borrow_mut().push((state, value.copied(), error)),
                )
                .await;
                let result = attempt.fold(
                    |v| (Committed, Some(v), None),
                    |e| (NotStarted, None, Some(e)),
                    |e| (RolledBack, None, Some(e)),
                    |e| (RollbackFailed, None, Some(e)),
                    |e| (CommitUnknown, None, Some(e)),
                    |e| (Fenced, None, Some(e)),
                );
                let recovered = status == CommitUnknown && receipt.is_some();
                assert_eq!(result.0, if recovered { Committed } else { status });
                assert_eq!(
                    reads.load(Ordering::Relaxed),
                    usize::from(status == CommitUnknown)
                );
                assert_eq!(
                    *events.borrow(),
                    vec![result],
                    "one observation matches the returned settlement"
                );
                if recovered {
                    assert_eq!(result.1, receipt);
                }
            }
        }
        Ok(())
    }
}
