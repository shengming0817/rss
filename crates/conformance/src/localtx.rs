//! LocalTx settlement/no-write conformance helpers（#1702）。
//!
//! Every assertion consumes its action exactly once, then evaluates probes in this order:
//! `action -> snapshot -> count`. Counts are action-local deltas, not process-global totals; each
//! case must use an isolated fixture so concurrent tests cannot change its probes.
//!
//! Provider errors are wrapped in [`ClassifiedError`]. The caller supplies a low-cardinality,
//! non-sensitive closed category; the underlying error never needs `Debug` or `Display` and is
//! never rendered by this module.
//!
//! ```
//! use std::cell::Cell;
//! use rss_conformance::{ConformanceErrorCategory, localtx::{ClassifiedError, CommitCase, assert_commit}};
//!
//! struct SecretProviderError;
//! #[derive(PartialEq)]
//! struct Snapshot(u32);
//!
//! # async fn example() -> Result<(), rss_conformance::localtx::LocalTxConformanceError> {
//! let _classified = ClassifiedError::new(ConformanceErrorCategory::Storage, SecretProviderError);
//! let writes = Cell::new(0_u32);
//! assert_commit(CommitCase::new(
//!     || async { writes.set(writes.get() + 1); Ok::<_, ClassifiedError<SecretProviderError>>(()) },
//!     || async { Ok::<_, ClassifiedError<SecretProviderError>>(Snapshot(writes.get())) },
//!     Snapshot(1),
//!     || writes.get() as usize,
//! )).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ref: sqlx sqlx-core/src/transaction.rs@v0.8.6

use crate::ConformanceErrorCategory;
use std::future::Future;

/// A typed execution stage safe to include in conformance diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LocalTxStage {
    CommitAction,
    CommitSnapshot,
    RollbackAction,
    RollbackSnapshot,
    RejectedAction,
    RejectedSnapshot,
    CommitUnknownAction,
    RollbackFailedAction,
}

impl LocalTxStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CommitAction => "commit action",
            Self::CommitSnapshot => "commit snapshot",
            Self::RollbackAction => "rollback action",
            Self::RollbackSnapshot => "rollback snapshot",
            Self::RejectedAction => "rejected action",
            Self::RejectedSnapshot => "rejected snapshot",
            Self::CommitUnknownAction => "commit unknown action",
            Self::RollbackFailedAction => "rollback failed action",
        }
    }
}

impl std::fmt::Display for LocalTxStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A provider error paired with a caller-selected, low-sensitivity closed category.
///
/// The closed category cannot carry a tenant, key, credential, payload, or provider message.
pub struct ClassifiedError<E> {
    category: ConformanceErrorCategory,
    _source: E,
}

impl<E> ClassifiedError<E> {
    /// Classifies a provider error without requiring or exposing formatting traits on `E`.
    pub const fn new(category: ConformanceErrorCategory, source: E) -> Self {
        Self {
            category,
            _source: source,
        }
    }

    /// Returns the safe closed category used by conformance diagnostics.
    pub const fn category(&self) -> ConformanceErrorCategory {
        self.category
    }
}

/// LocalTx conformance assertion failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LocalTxConformanceError {
    #[error("localtx conformance: provider operation failed during {stage} ({category})")]
    Provider {
        stage: LocalTxStage,
        category: ConformanceErrorCategory,
    },
    #[error("localtx conformance: {stage} unexpectedly succeeded; expected {expected_category}")]
    ExpectedErrorMissing {
        stage: LocalTxStage,
        expected_category: ConformanceErrorCategory,
    },
    #[error(
        "localtx conformance: {stage} returned {actual_category}; expected {expected_category}"
    )]
    WrongErrorKind {
        stage: LocalTxStage,
        expected_category: ConformanceErrorCategory,
        actual_category: ConformanceErrorCategory,
    },
    #[error("localtx conformance: snapshot mismatch after {stage}")]
    SnapshotMismatch { stage: LocalTxStage },
    #[error("localtx conformance: {stage} write count mismatch; expected {expected}, got {actual}")]
    WriteCountMismatch {
        stage: LocalTxStage,
        expected: usize,
        actual: usize,
    },
    #[error(
        "localtx conformance: {stage} attempt count mismatch; expected {expected}, got {actual}"
    )]
    AttemptMismatch {
        stage: LocalTxStage,
        expected: usize,
        actual: usize,
    },
}

/// Fixture for a successful LocalTx commit.
pub struct CommitCase<A, S, V, W> {
    action: A,
    snapshot: S,
    expected_snapshot: V,
    durable_write_count: W,
}

impl<A, S, V, W> CommitCase<A, S, V, W> {
    /// Builds an isolated fixture evaluated as action, snapshot, then action-local durable-write
    /// delta. The expected delta is exactly one.
    pub fn new(action: A, snapshot: S, expected_snapshot: V, durable_write_count: W) -> Self {
        Self {
            action,
            snapshot,
            expected_snapshot,
            durable_write_count,
        }
    }
}

/// Asserts successful commit, expected durable state, and exactly one durable write.
pub async fn assert_commit<A, S, V, W, AF, SF, E, SE>(
    case: CommitCase<A, S, V, W>,
) -> Result<(), LocalTxConformanceError>
where
    A: FnOnce() -> AF,
    S: FnOnce() -> SF,
    W: FnOnce() -> usize,
    AF: Future<Output = Result<(), ClassifiedError<E>>>,
    SF: Future<Output = Result<V, ClassifiedError<SE>>>,
    V: PartialEq,
{
    let CommitCase {
        action,
        snapshot,
        expected_snapshot,
        durable_write_count,
    } = case;
    action()
        .await
        .map_err(|error| provider(LocalTxStage::CommitAction, &error))?;
    let actual = snapshot()
        .await
        .map_err(|error| provider(LocalTxStage::CommitSnapshot, &error))?;
    if actual != expected_snapshot {
        return Err(LocalTxConformanceError::SnapshotMismatch {
            stage: LocalTxStage::CommitSnapshot,
        });
    }
    expect_write_count(LocalTxStage::CommitAction, durable_write_count(), 1)
}

/// Fixture for an expected error whose transaction was durably rolled back.
pub struct RollbackCase<A, S, V> {
    action: A,
    expected_category: ConformanceErrorCategory,
    snapshot: S,
    baseline: V,
}

impl<A, S, V> RollbackCase<A, S, V> {
    /// Builds an isolated fixture. After the expected categorized action error, `snapshot` must
    /// equal the pre-action `baseline`.
    pub fn new(
        action: A,
        expected_category: ConformanceErrorCategory,
        snapshot: S,
        baseline: V,
    ) -> Self {
        Self {
            action,
            expected_category,
            snapshot,
            baseline,
        }
    }
}

/// Asserts the expected error category and that rollback restored the baseline snapshot.
pub async fn assert_rollback<A, S, V, AF, SF, E, SE>(
    case: RollbackCase<A, S, V>,
) -> Result<(), LocalTxConformanceError>
where
    A: FnOnce() -> AF,
    S: FnOnce() -> SF,
    AF: Future<Output = Result<(), ClassifiedError<E>>>,
    SF: Future<Output = Result<V, ClassifiedError<SE>>>,
    V: PartialEq,
{
    let RollbackCase {
        action,
        expected_category,
        snapshot,
        baseline,
    } = case;
    expect_rejection(
        LocalTxStage::RollbackAction,
        action().await,
        expected_category,
    )?;
    expect_baseline(LocalTxStage::RollbackSnapshot, snapshot, baseline).await
}

/// Fixture for validation or authorization rejection with no durable mutation.
pub struct RejectedNoWriteCase<A, S, V, W> {
    action: A,
    expected_category: ConformanceErrorCategory,
    snapshot: S,
    baseline: V,
    mutation_count: W,
}

impl<A, S, V, W> RejectedNoWriteCase<A, S, V, W> {
    /// Builds an isolated fixture. The snapshot and action-local mutation delta are sampled only
    /// after the categorized rejection; the required delta is zero.
    pub fn new(
        action: A,
        expected_category: ConformanceErrorCategory,
        snapshot: S,
        baseline: V,
        mutation_count: W,
    ) -> Self {
        Self {
            action,
            expected_category,
            snapshot,
            baseline,
            mutation_count,
        }
    }
}

/// Asserts an expected validation/authorization rejection made no durable mutation.
pub async fn assert_rejected_no_write<A, S, V, W, AF, SF, E, SE>(
    case: RejectedNoWriteCase<A, S, V, W>,
) -> Result<(), LocalTxConformanceError>
where
    A: FnOnce() -> AF,
    S: FnOnce() -> SF,
    W: FnOnce() -> usize,
    AF: Future<Output = Result<(), ClassifiedError<E>>>,
    SF: Future<Output = Result<V, ClassifiedError<SE>>>,
    V: PartialEq,
{
    let RejectedNoWriteCase {
        action,
        expected_category,
        snapshot,
        baseline,
        mutation_count,
    } = case;
    expect_rejection(
        LocalTxStage::RejectedAction,
        action().await,
        expected_category,
    )?;
    expect_baseline(LocalTxStage::RejectedSnapshot, snapshot, baseline).await?;
    expect_write_count(LocalTxStage::RejectedAction, mutation_count(), 0)
}

/// Commit-unknown fixture. It deliberately has no snapshot or write-count probe.
pub struct CommitUnknownCase<A, C> {
    action: A,
    expected_category: ConformanceErrorCategory,
    attempt_count: C,
}

impl<A, C> CommitUnknownCase<A, C> {
    /// Builds an isolated commit-unknown fixture; the action-local attempt count must be one.
    pub fn new(action: A, expected_category: ConformanceErrorCategory, attempt_count: C) -> Self {
        Self {
            action,
            expected_category,
            attempt_count,
        }
    }
}

/// Rollback-failed fixture. It deliberately has no snapshot or write-count probe.
pub struct RollbackFailedCase<A, C> {
    action: A,
    expected_category: ConformanceErrorCategory,
    attempt_count: C,
}

impl<A, C> RollbackFailedCase<A, C> {
    /// Builds an isolated rollback-failed fixture; the action-local attempt count must be one.
    pub fn new(action: A, expected_category: ConformanceErrorCategory, attempt_count: C) -> Self {
        Self {
            action,
            expected_category,
            attempt_count,
        }
    }
}

/// Asserts a commit-unknown outcome has the expected category and was attempted exactly once.
pub async fn assert_commit_unknown_no_replay<A, C, AF, E>(
    case: CommitUnknownCase<A, C>,
) -> Result<(), LocalTxConformanceError>
where
    A: FnOnce() -> AF,
    C: FnOnce() -> usize,
    AF: Future<Output = Result<(), ClassifiedError<E>>>,
{
    assert_no_replay(
        LocalTxStage::CommitUnknownAction,
        case.action,
        case.expected_category,
        case.attempt_count,
    )
    .await
}

/// Asserts a rollback-failed outcome has the expected category and was attempted exactly once.
pub async fn assert_rollback_failed_no_replay<A, C, AF, E>(
    case: RollbackFailedCase<A, C>,
) -> Result<(), LocalTxConformanceError>
where
    A: FnOnce() -> AF,
    C: FnOnce() -> usize,
    AF: Future<Output = Result<(), ClassifiedError<E>>>,
{
    assert_no_replay(
        LocalTxStage::RollbackFailedAction,
        case.action,
        case.expected_category,
        case.attempt_count,
    )
    .await
}

async fn assert_no_replay<A, C, AF, E>(
    stage: LocalTxStage,
    action: A,
    expected_category: ConformanceErrorCategory,
    attempt_count: C,
) -> Result<(), LocalTxConformanceError>
where
    A: FnOnce() -> AF,
    C: FnOnce() -> usize,
    AF: Future<Output = Result<(), ClassifiedError<E>>>,
{
    expect_rejection(stage, action().await, expected_category)?;
    let actual = attempt_count();
    if actual == 1 {
        Ok(())
    } else {
        Err(LocalTxConformanceError::AttemptMismatch {
            stage,
            expected: 1,
            actual,
        })
    }
}

fn provider<E>(stage: LocalTxStage, error: &ClassifiedError<E>) -> LocalTxConformanceError {
    LocalTxConformanceError::Provider {
        stage,
        category: error.category(),
    }
}

fn expect_rejection<E>(
    stage: LocalTxStage,
    result: Result<(), ClassifiedError<E>>,
    expected_category: ConformanceErrorCategory,
) -> Result<(), LocalTxConformanceError> {
    match result {
        Ok(()) => Err(LocalTxConformanceError::ExpectedErrorMissing {
            stage,
            expected_category,
        }),
        Err(error) if error.category() == expected_category => Ok(()),
        Err(error) => Err(LocalTxConformanceError::WrongErrorKind {
            stage,
            expected_category,
            actual_category: error.category(),
        }),
    }
}

async fn expect_baseline<S, SF, V, E>(
    stage: LocalTxStage,
    snapshot: S,
    baseline: V,
) -> Result<(), LocalTxConformanceError>
where
    S: FnOnce() -> SF,
    SF: Future<Output = Result<V, ClassifiedError<E>>>,
    V: PartialEq,
{
    let actual = snapshot().await.map_err(|error| provider(stage, &error))?;
    if actual == baseline {
        Ok(())
    } else {
        Err(LocalTxConformanceError::SnapshotMismatch { stage })
    }
}

fn expect_write_count(
    stage: LocalTxStage,
    actual: usize,
    expected: usize,
) -> Result<(), LocalTxConformanceError> {
    if actual == expected {
        Ok(())
    } else {
        Err(LocalTxConformanceError::WriteCountMismatch {
            stage,
            expected,
            actual,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[derive(Clone, Copy, PartialEq)]
    struct Snapshot(u32);
    struct SensitiveError;

    fn error(category: ConformanceErrorCategory) -> ClassifiedError<SensitiveError> {
        ClassifiedError::new(category, SensitiveError)
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn happy_paths_pass_without_formatting_provider_errors() {
        let writes = Cell::new(0);
        assert_commit(CommitCase::new(
            || async {
                writes.set(1);
                Ok::<_, ClassifiedError<SensitiveError>>(())
            },
            || async { Ok::<_, ClassifiedError<SensitiveError>>(Snapshot(writes.get())) },
            Snapshot(1),
            || writes.get() as usize,
        ))
        .await
        .expect("commit passes");

        let state = Cell::new(7);
        assert_rollback(RollbackCase::new(
            || async { Err::<(), _>(error(ConformanceErrorCategory::Conflict)) },
            ConformanceErrorCategory::Conflict,
            || async { Ok::<_, ClassifiedError<SensitiveError>>(Snapshot(state.get())) },
            Snapshot(7),
        ))
        .await
        .expect("rollback passes");

        let mutations = Cell::new(0);
        assert_rejected_no_write(RejectedNoWriteCase::new(
            || async { Err::<(), _>(error(ConformanceErrorCategory::Authorization)) },
            ConformanceErrorCategory::Authorization,
            || async { Ok::<_, ClassifiedError<SensitiveError>>(Snapshot(state.get())) },
            Snapshot(7),
            || mutations.get(),
        ))
        .await
        .expect("rejection passes");

        assert_commit_unknown_no_replay(CommitUnknownCase::new(
            || async { Err::<(), _>(error(ConformanceErrorCategory::CommitUnknown)) },
            ConformanceErrorCategory::CommitUnknown,
            || 1,
        ))
        .await
        .expect("commit unknown passes");
        assert_rollback_failed_no_replay(RollbackFailedCase::new(
            || async { Err::<(), _>(error(ConformanceErrorCategory::RollbackFailed)) },
            ConformanceErrorCategory::RollbackFailed,
            || 1,
        ))
        .await
        .expect("rollback failed passes");
    }

    #[tokio::test]
    async fn commit_zero_or_duplicate_writes_are_caught() {
        for writes in [0, 2] {
            let result = assert_commit(CommitCase::new(
                || async { Ok::<_, ClassifiedError<SensitiveError>>(()) },
                || async { Ok::<_, ClassifiedError<SensitiveError>>(Snapshot(1)) },
                Snapshot(1),
                || writes,
            ))
            .await;
            assert!(
                matches!(result, Err(LocalTxConformanceError::WriteCountMismatch { expected: 1, actual, .. }) if actual == writes)
            );
        }
    }

    #[tokio::test]
    async fn commit_snapshot_and_provider_failures_are_actionable_and_sanitized() {
        let mismatch = assert_commit(CommitCase::new(
            || async { Ok::<_, ClassifiedError<SensitiveError>>(()) },
            || async { Ok::<_, ClassifiedError<SensitiveError>>(Snapshot(2)) },
            Snapshot(1),
            || 1,
        ))
        .await;
        assert!(matches!(
            mismatch,
            Err(LocalTxConformanceError::SnapshotMismatch {
                stage: LocalTxStage::CommitSnapshot
            })
        ));

        let provider_error = assert_commit(CommitCase::new(
            || async { Err::<(), _>(error(ConformanceErrorCategory::Storage)) },
            || async { Ok::<_, ClassifiedError<SensitiveError>>(Snapshot(1)) },
            Snapshot(1),
            || 1,
        ))
        .await;
        assert!(matches!(
            provider_error,
            Err(LocalTxConformanceError::Provider {
                stage: LocalTxStage::CommitAction,
                category: ConformanceErrorCategory::Storage
            })
        ));
    }

    #[tokio::test]
    async fn rollback_residual_write_wrong_kind_and_missing_error_are_caught() {
        let residual = assert_rollback(RollbackCase::new(
            || async { Err::<(), _>(error(ConformanceErrorCategory::Conflict)) },
            ConformanceErrorCategory::Conflict,
            || async { Ok::<_, ClassifiedError<SensitiveError>>(Snapshot(8)) },
            Snapshot(7),
        ))
        .await;
        assert!(matches!(
            residual,
            Err(LocalTxConformanceError::SnapshotMismatch { .. })
        ));

        let wrong = assert_rollback(RollbackCase::new(
            || async { Err::<(), _>(error(ConformanceErrorCategory::Permanent)) },
            ConformanceErrorCategory::Conflict,
            || async { Ok::<_, ClassifiedError<SensitiveError>>(Snapshot(7)) },
            Snapshot(7),
        ))
        .await;
        assert!(matches!(
            wrong,
            Err(LocalTxConformanceError::WrongErrorKind {
                expected_category: ConformanceErrorCategory::Conflict,
                actual_category: ConformanceErrorCategory::Permanent,
                ..
            })
        ));

        let missing = assert_rollback(RollbackCase::new(
            || async { Ok::<_, ClassifiedError<SensitiveError>>(()) },
            ConformanceErrorCategory::Conflict,
            || async { Ok::<_, ClassifiedError<SensitiveError>>(Snapshot(7)) },
            Snapshot(7),
        ))
        .await;
        assert!(matches!(
            missing,
            Err(LocalTxConformanceError::ExpectedErrorMissing { .. })
        ));
    }

    #[tokio::test]
    async fn rejected_operation_that_mutates_is_caught() {
        let result = assert_rejected_no_write(RejectedNoWriteCase::new(
            || async { Err::<(), _>(error(ConformanceErrorCategory::Validation)) },
            ConformanceErrorCategory::Validation,
            || async { Ok::<_, ClassifiedError<SensitiveError>>(Snapshot(7)) },
            Snapshot(7),
            || 1,
        ))
        .await;
        assert!(matches!(
            result,
            Err(LocalTxConformanceError::WriteCountMismatch {
                expected: 0,
                actual: 1,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn settlement_categories_and_replays_are_caught_without_cross_wiring_types() {
        let wrong_commit = assert_commit_unknown_no_replay(CommitUnknownCase::new(
            || async { Err::<(), _>(error(ConformanceErrorCategory::RollbackFailed)) },
            ConformanceErrorCategory::CommitUnknown,
            || 1,
        ))
        .await;
        assert!(matches!(
            wrong_commit,
            Err(LocalTxConformanceError::WrongErrorKind {
                stage: LocalTxStage::CommitUnknownAction,
                ..
            })
        ));

        let wrong_rollback = assert_rollback_failed_no_replay(RollbackFailedCase::new(
            || async { Err::<(), _>(error(ConformanceErrorCategory::CommitUnknown)) },
            ConformanceErrorCategory::RollbackFailed,
            || 1,
        ))
        .await;
        assert!(matches!(
            wrong_rollback,
            Err(LocalTxConformanceError::WrongErrorKind {
                stage: LocalTxStage::RollbackFailedAction,
                ..
            })
        ));

        let commit = assert_commit_unknown_no_replay(CommitUnknownCase::new(
            || async { Err::<(), _>(error(ConformanceErrorCategory::CommitUnknown)) },
            ConformanceErrorCategory::CommitUnknown,
            || 2,
        ))
        .await;
        assert!(matches!(
            commit,
            Err(LocalTxConformanceError::AttemptMismatch {
                expected: 1,
                actual: 2,
                ..
            })
        ));

        let rollback = assert_rollback_failed_no_replay(RollbackFailedCase::new(
            || async { Err::<(), _>(error(ConformanceErrorCategory::RollbackFailed)) },
            ConformanceErrorCategory::RollbackFailed,
            || 3,
        ))
        .await;
        assert!(matches!(
            rollback,
            Err(LocalTxConformanceError::AttemptMismatch {
                expected: 1,
                actual: 3,
                ..
            })
        ));
    }
}
