//! Postgres LocalTx settlement carrier — mint sealed inside `cotx`.
//!
//! ref: sqlx sqlx-core/src/transaction.rs@v0.8.6
//!
//! `LocalTxAttempt` is an opaque sum type: success and every failure settlement are distinct
//! states, so contradictory combinations such as `Ok + RolledBack` cannot be represented.
//! Production constructors are `pub(super)` so only the parent `cotx` funnel can mint evidence;
//! sibling postgres modules and the retry boundary may only consume settlement methods.
//!
//! INVARIANT: PG-LOCALTX-SETTLEMENT-01 { level = "Hard", exec = "native-compile", source = "code", native = "opaque sum type; pub(super) mint under cotx; run_pg_tx_retry consumes LocalTxAttempt only" }
//! INVARIANT: PG-LOCALTX-QUARANTINE-TYPE-01 { level = "Hard", exec = "native-compile", source = "code", native = "private armed RAII lease borrow-splits its PoolConnection transaction and closed quarantine stage into LocalTxTransaction; only that wrapper's consuming commit/rollback ACK methods can disarm the originating lease" }

#[cfg(any(test, feature = "domain-settings", feature = "domain-audit"))]
use consistency::LocalTxDeadlineStage;
use consistency::LocalTxFinalStatus;
#[cfg(any(test, feature = "domain-settings", feature = "domain-audit"))]
use consistency::TxRetryClass;
use sqlx::{Acquire, PgPool, Postgres, Transaction, pool::PoolConnection};

use crate::tx_retry::{
    LocalTxAcquireDeadline, LocalTxBeginDeadline, LocalTxCommitDeadline, LocalTxOperationDeadline,
    LocalTxRollbackDeadline, LocalTxSetupDeadline,
};

/// One complete Postgres LocalTx attempt and its settlement evidence.
#[derive(Debug)]
pub(crate) struct LocalTxAttempt<T, E> {
    state: LocalTxAttemptState<T, E>,
}

#[derive(Debug)]
enum LocalTxAttemptState<T, E> {
    Committed(T),
    Unsettled(E, LocalTxDeadlineEvidence),
    RolledBack(E, LocalTxDeadlineEvidence),
    RollbackFailed(E, LocalTxDeadlineEvidence),
    CommitUnknown(E, LocalTxDeadlineEvidence),
}

/// Opaque deadline proof minted only by the transaction/settlement funnel.
#[derive(Clone, Copy, Debug)]
enum LocalTxDeadlineEvidence {
    None,
    Acquire(LocalTxAcquireDeadline),
    Begin(LocalTxBeginDeadline),
    Setup(LocalTxSetupDeadline),
    Operation(LocalTxOperationDeadline),
    Rollback(LocalTxRollbackDeadline),
    SetupRollback(LocalTxSetupDeadline, LocalTxRollbackDeadline),
    OperationRollback(LocalTxOperationDeadline, LocalTxRollbackDeadline),
    Commit(LocalTxCommitDeadline),
}

impl LocalTxDeadlineEvidence {
    const fn none() -> Self {
        Self::None
    }

    #[cfg(any(test, feature = "domain-settings", feature = "domain-audit"))]
    const fn stages(self) -> [Option<LocalTxDeadlineStage>; 2] {
        match self {
            Self::None => [None, None],
            Self::Acquire(_) => [Some(LocalTxDeadlineStage::Acquire), None],
            Self::Begin(_) => [Some(LocalTxDeadlineStage::Begin), None],
            Self::Setup(_) => [Some(LocalTxDeadlineStage::Setup), None],
            Self::Operation(_) => [Some(LocalTxDeadlineStage::Operation), None],
            Self::Rollback(_) => [None, Some(LocalTxDeadlineStage::Rollback)],
            Self::SetupRollback(_, _) => [
                Some(LocalTxDeadlineStage::Setup),
                Some(LocalTxDeadlineStage::Rollback),
            ],
            Self::OperationRollback(_, _) => [
                Some(LocalTxDeadlineStage::Operation),
                Some(LocalTxDeadlineStage::Rollback),
            ],
            Self::Commit(_) => [Some(LocalTxDeadlineStage::Commit), None],
        }
    }
}

/// A pooled connection whose default drop behavior is quarantine.
///
/// The parent `cotx` module can acquire and begin this lease, but it cannot inject a reuse decision
/// or recover the raw pooled connection. The returned [`LocalTxTransaction`] exclusively holds the
/// transaction together with the originating lease's quarantine flag, so another attempt cannot
/// authorize reuse. Missing settlement and cancelled futures keep `quarantine_stage` armed.
pub(super) struct LocalTxConnectionLease {
    connection: PoolConnection<Postgres>,
    quarantine_stage: Option<LocalTxQuarantineStage>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalTxQuarantineStage {
    Begin,
    Body,
    Commit,
    Rollback,
}

impl LocalTxQuarantineStage {
    const fn as_label(self) -> &'static str {
        match self {
            Self::Begin => "begin",
            Self::Body => "body",
            Self::Commit => "commit",
            Self::Rollback => "rollback",
        }
    }
}

impl LocalTxConnectionLease {
    pub(super) async fn acquire(pool: &PgPool) -> Result<Self, sqlx::Error> {
        Ok(Self {
            connection: pool.acquire().await?,
            quarantine_stage: Some(LocalTxQuarantineStage::Begin),
        })
    }

    pub(super) async fn begin(&mut self) -> Result<LocalTxTransaction<'_>, sqlx::Error> {
        let Self {
            connection,
            quarantine_stage,
        } = self;
        #[cfg(all(test, feature = "integration"))]
        super::pause_localtx_stage_for_test(super::LocalTxTestPauseStage::Begin).await;
        let transaction = (&mut *connection).begin().await?;
        *quarantine_stage = Some(LocalTxQuarantineStage::Body);
        Ok(LocalTxTransaction {
            transaction,
            quarantine_stage,
        })
    }
}

/// A transaction branded with the quarantine flag of the lease that began it.
///
/// There is no constructor and no way to extract the transaction or flag. Consuming settlement
/// methods are therefore the only safe-reuse authority, and they disarm only after a real ACK.
pub(super) struct LocalTxTransaction<'lease> {
    transaction: Transaction<'lease, Postgres>,
    quarantine_stage: &'lease mut Option<LocalTxQuarantineStage>,
}

impl LocalTxTransaction<'_> {
    pub(super) fn capability(&mut self) -> super::TxCapability<'_> {
        super::TxCapability::from_transaction(&mut self.transaction)
    }

    pub(super) async fn commit(self) -> Result<(), sqlx::Error> {
        let Self {
            transaction,
            quarantine_stage,
        } = self;
        *quarantine_stage = Some(LocalTxQuarantineStage::Commit);
        #[cfg(all(test, feature = "integration"))]
        super::pause_localtx_stage_for_test(super::LocalTxTestPauseStage::Commit).await;
        transaction.commit().await?;
        *quarantine_stage = None;
        Ok(())
    }

    pub(super) async fn rollback(self) -> Result<(), sqlx::Error> {
        let Self {
            transaction,
            quarantine_stage,
        } = self;
        *quarantine_stage = Some(LocalTxQuarantineStage::Rollback);
        transaction.rollback().await?;
        *quarantine_stage = None;
        Ok(())
    }

    #[cfg(any(all(test, feature = "integration"), feature = "journey-fault-support"))]
    pub(super) async fn commit_unknown_after_ack(self) -> Result<(), sqlx::Error> {
        let Self {
            transaction,
            quarantine_stage,
        } = self;
        *quarantine_stage = Some(LocalTxQuarantineStage::Commit);
        transaction.commit().await?;
        Err(sqlx::Error::PoolTimedOut)
    }

    #[cfg(all(test, feature = "integration"))]
    pub(super) async fn rollback_failed_after_ack(self) -> Result<(), sqlx::Error> {
        let Self {
            transaction,
            quarantine_stage,
        } = self;
        *quarantine_stage = Some(LocalTxQuarantineStage::Rollback);
        transaction.rollback().await?;
        Err(sqlx::Error::PoolTimedOut)
    }

    #[cfg(all(test, feature = "integration"))]
    pub(super) async fn rollback_paused_before_ack(self) -> Result<(), sqlx::Error> {
        let Self {
            transaction,
            quarantine_stage,
        } = self;
        *quarantine_stage = Some(LocalTxQuarantineStage::Rollback);
        super::notify_rollback_pause_entered_for_test();
        std::future::pending::<()>().await;
        drop(transaction);
        Ok(())
    }
}

impl Drop for LocalTxConnectionLease {
    fn drop(&mut self) {
        if let Some(stage) = self.quarantine_stage {
            metrics::counter!(
                "postgres_localtx_connection_quarantine_total",
                "stage" => stage.as_label()
            )
            .increment(1);
            tracing::warn!(
                target: "postgres",
                quarantine_stage = stage.as_label(),
                "localtx connection quarantined"
            );
            self.connection.close_on_drop();
        }
    }
}

impl<T, E> LocalTxAttempt<T, E> {
    #[cfg(test)]
    fn has_acknowledged_settlement(&self) -> bool {
        matches!(
            &self.state,
            LocalTxAttemptState::Committed(_) | LocalTxAttemptState::RolledBack(_, _)
        )
    }

    /// Construct a successfully committed attempt.
    pub(super) fn committed(value: T) -> Self {
        Self {
            state: LocalTxAttemptState::Committed(value),
        }
    }

    /// Construct an error observed before a transaction existed.
    pub(super) fn unsettled(error: E) -> Self {
        Self {
            state: LocalTxAttemptState::Unsettled(error, LocalTxDeadlineEvidence::none()),
        }
    }

    pub(super) fn unsettled_acquire_deadline(error: E, evidence: LocalTxAcquireDeadline) -> Self {
        Self {
            state: LocalTxAttemptState::Unsettled(
                error,
                LocalTxDeadlineEvidence::Acquire(evidence),
            ),
        }
    }

    pub(super) fn unsettled_begin_deadline(error: E, evidence: LocalTxBeginDeadline) -> Self {
        Self {
            state: LocalTxAttemptState::Unsettled(error, LocalTxDeadlineEvidence::Begin(evidence)),
        }
    }

    /// Construct an attempt whose explicit rollback completed.
    pub(super) fn rolled_back(error: E) -> Self {
        Self {
            state: LocalTxAttemptState::RolledBack(error, LocalTxDeadlineEvidence::none()),
        }
    }

    pub(super) fn rolled_back_setup_deadline(error: E, evidence: LocalTxSetupDeadline) -> Self {
        Self {
            state: LocalTxAttemptState::RolledBack(error, LocalTxDeadlineEvidence::Setup(evidence)),
        }
    }

    pub(super) fn rolled_back_operation_deadline(
        error: E,
        evidence: LocalTxOperationDeadline,
    ) -> Self {
        Self {
            state: LocalTxAttemptState::RolledBack(
                error,
                LocalTxDeadlineEvidence::Operation(evidence),
            ),
        }
    }

    /// Construct an attempt whose explicit rollback failed.
    pub(super) fn rollback_failed(error: E) -> Self {
        Self {
            state: LocalTxAttemptState::RollbackFailed(error, LocalTxDeadlineEvidence::none()),
        }
    }

    pub(super) fn rollback_failed_deadline(error: E, rollback: LocalTxRollbackDeadline) -> Self {
        Self {
            state: LocalTxAttemptState::RollbackFailed(
                error,
                LocalTxDeadlineEvidence::Rollback(rollback),
            ),
        }
    }

    pub(super) fn rollback_failed_setup_deadline(
        error: E,
        setup: LocalTxSetupDeadline,
        rollback: LocalTxRollbackDeadline,
    ) -> Self {
        Self {
            state: LocalTxAttemptState::RollbackFailed(
                error,
                LocalTxDeadlineEvidence::SetupRollback(setup, rollback),
            ),
        }
    }

    pub(super) fn rollback_failed_operation_deadline(
        error: E,
        operation: LocalTxOperationDeadline,
        rollback: LocalTxRollbackDeadline,
    ) -> Self {
        Self {
            state: LocalTxAttemptState::RollbackFailed(
                error,
                LocalTxDeadlineEvidence::OperationRollback(operation, rollback),
            ),
        }
    }

    /// Construct an attempt whose commit result is unknown.
    pub(super) fn commit_unknown(error: E) -> Self {
        Self {
            state: LocalTxAttemptState::CommitUnknown(error, LocalTxDeadlineEvidence::none()),
        }
    }

    pub(super) fn commit_unknown_deadline(error: E, evidence: LocalTxCommitDeadline) -> Self {
        Self {
            state: LocalTxAttemptState::CommitUnknown(
                error,
                LocalTxDeadlineEvidence::Commit(evidence),
            ),
        }
    }

    /// Transaction settlement, or `None` when begin failed before a transaction existed.
    #[cfg_attr(
        not(any(feature = "domain-settings", feature = "domain-identity")),
        allow(dead_code)
    )]
    pub(crate) fn settlement(&self) -> Option<LocalTxFinalStatus> {
        match self.state {
            LocalTxAttemptState::Committed(_) => Some(LocalTxFinalStatus::Committed),
            LocalTxAttemptState::Unsettled(_, _) => None,
            LocalTxAttemptState::RolledBack(_, _) => Some(LocalTxFinalStatus::RolledBack),
            LocalTxAttemptState::RollbackFailed(_, _) => Some(LocalTxFinalStatus::RollbackFailed),
            LocalTxAttemptState::CommitUnknown(_, _) => Some(LocalTxFinalStatus::CommitUnknown),
        }
    }

    /// Retry classification after settlement safety is applied.
    #[cfg(test)]
    pub(crate) fn retry_class(
        &self,
        classify: impl FnOnce(&E) -> TxRetryClass,
    ) -> Option<TxRetryClass> {
        match &self.state {
            LocalTxAttemptState::Committed(_) => None,
            LocalTxAttemptState::Unsettled(error, _)
            | LocalTxAttemptState::RolledBack(error, _) => Some(classify(error)),
            LocalTxAttemptState::RollbackFailed(_, _)
            | LocalTxAttemptState::CommitUnknown(_, _) => Some(TxRetryClass::Permanent),
        }
    }

    /// Consume settlement evidence at a non-retrying call site.
    pub(crate) fn into_result(self) -> Result<T, E> {
        match self.state {
            LocalTxAttemptState::Committed(value) => Ok(value),
            LocalTxAttemptState::Unsettled(error, _)
            | LocalTxAttemptState::RolledBack(error, _)
            | LocalTxAttemptState::RollbackFailed(error, _)
            | LocalTxAttemptState::CommitUnknown(error, _) => Err(error),
        }
    }

    /// Map the carrier error without changing settlement or deadline evidence.
    pub(super) fn map_error<M>(self, map: impl FnOnce(E) -> M) -> LocalTxAttempt<T, M> {
        let state = match self.state {
            LocalTxAttemptState::Committed(value) => LocalTxAttemptState::Committed(value),
            LocalTxAttemptState::Unsettled(error, deadline) => {
                LocalTxAttemptState::Unsettled(map(error), deadline)
            }
            LocalTxAttemptState::RolledBack(error, deadline) => {
                LocalTxAttemptState::RolledBack(map(error), deadline)
            }
            LocalTxAttemptState::RollbackFailed(error, deadline) => {
                LocalTxAttemptState::RollbackFailed(map(error), deadline)
            }
            LocalTxAttemptState::CommitUnknown(error, deadline) => {
                LocalTxAttemptState::CommitUnknown(map(error), deadline)
            }
        };
        LocalTxAttempt { state }
    }

    /// Consume settlement evidence at the bounded retry boundary.
    #[cfg(any(feature = "domain-settings", feature = "domain-audit"))]
    pub(crate) fn into_retry_result(
        self,
        classify: impl FnOnce(&E) -> TxRetryClass,
    ) -> Result<T, LocalTxRetryError<E>> {
        let settlement = self.settlement();
        match self.state {
            LocalTxAttemptState::Committed(value) => Ok(value),
            LocalTxAttemptState::Unsettled(error, deadline)
            | LocalTxAttemptState::RolledBack(error, deadline)
            | LocalTxAttemptState::RollbackFailed(error, deadline)
            | LocalTxAttemptState::CommitUnknown(error, deadline) => {
                let class = match settlement {
                    Some(
                        LocalTxFinalStatus::Committed
                        | LocalTxFinalStatus::RollbackFailed
                        | LocalTxFinalStatus::CommitUnknown,
                    ) => TxRetryClass::Permanent,
                    None | Some(LocalTxFinalStatus::RolledBack) => classify(&error),
                };
                Err(LocalTxRetryError {
                    error,
                    class,
                    deadline,
                })
            }
        }
    }
}

/// Failure shape consumed only by the generic retry engine.
#[cfg(any(feature = "domain-settings", feature = "domain-audit"))]
#[derive(Debug)]
pub(crate) struct LocalTxRetryError<E> {
    error: E,
    class: TxRetryClass,
    deadline: LocalTxDeadlineEvidence,
}

#[cfg(any(feature = "domain-settings", feature = "domain-audit"))]
impl<E> LocalTxRetryError<E> {
    /// Settlement-safe retry class.
    pub(crate) fn class(&self) -> TxRetryClass {
        self.class
    }

    /// Borrow the domain error for closed-label diagnostics before it is returned to the caller.
    pub(crate) fn error(&self) -> &E {
        &self.error
    }

    /// Closed deadline stages proven by the transaction/settlement funnel.
    pub(crate) fn deadline_stages(&self) -> [Option<LocalTxDeadlineStage>; 2] {
        self.deadline.stages()
    }

    /// Recover the caller's original domain error.
    pub(crate) fn into_error(self) -> E {
        self.error
    }
}

/// Wrap a failed commit so ordinary sqlx classification cannot treat it as transient.
pub(crate) fn commit_unknown(source: sqlx::Error) -> sqlx::Error {
    sqlx::Error::AnyDriverError(Box::new(PgTxCommitError { source }))
}

/// Wrap a failed explicit rollback, preserving the primary error in the causal chain.
///
/// Callers must map the returned `sqlx::Error` through `map_storage` so wire/HTTP surfaces a
/// non-retryable storage failure instead of the original domain conflict.
pub(super) fn rollback_failed(
    primary: impl std::error::Error + Send + Sync + 'static,
    rollback: sqlx::Error,
) -> sqlx::Error {
    sqlx::Error::AnyDriverError(Box::new(PgTxRollbackFailedError {
        primary: Box::new(primary),
        rollback,
    }))
}

/// Commit returned after the server may already have accepted the transaction.
#[derive(Debug, thiserror::Error)]
#[error("postgres transaction commit result is unknown")]
struct PgTxCommitError {
    #[source]
    source: sqlx::Error,
}

/// Explicit rollback failed after a primary LocalTx error.
///
/// `primary` is the business/storage error that triggered rollback; `rollback` is the settlement
/// failure. Display stays settlement-focused so domain conflicts cannot resurface as the outer
/// error kind after `map_storage`.
#[derive(Debug, thiserror::Error)]
#[error("postgres transaction rollback failed during localtx settlement")]
struct PgTxRollbackFailedError {
    primary: Box<dyn std::error::Error + Send + Sync>,
    #[source]
    rollback: sqlx::Error,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use consistency::{LocalTxDeadlineStage, LocalTxFinalStatus, TxRetryClass};

    use super::{LocalTxAttempt, LocalTxQuarantineStage};
    #[cfg(feature = "domain-settings")]
    use super::{commit_unknown, rollback_failed};
    use crate::tx_retry::{LocalTxStageResult, localtx_deadline_for_test};

    #[cfg(any(
        feature = "domain-settings",
        feature = "domain-identity",
        feature = "domain-audit"
    ))]
    #[tokio::test(start_paused = true)]
    async fn deadline_evidence_is_typed_and_preserves_primary_plus_settlement_stage() {
        let deadline = localtx_deadline_for_test();
        tokio::time::advance(consistency::LocalTxExecutionBudget::DEFAULT.operation()).await;
        let operation_evidence = match deadline.operation(async { Ok::<(), FakeError>(()) }).await {
            LocalTxStageResult::Deadline { evidence, .. } => evidence,
            _ => panic!("operation stage must mint its typed deadline evidence"),
        };
        let operation = LocalTxAttempt::<(), _>::rolled_back_operation_deadline(
            FakeError::Transient,
            operation_evidence,
        )
        .into_retry_result(|_| TxRetryClass::Transient)
        .expect_err("operation deadline must remain an error");
        assert_eq!(
            operation.deadline_stages(),
            [Some(LocalTxDeadlineStage::Operation), None]
        );

        tokio::time::advance(consistency::LocalTxExecutionBudget::DEFAULT.settlement_reserve())
            .await;
        let rollback_evidence = match deadline.rollback(async { Ok(()) }).await {
            LocalTxStageResult::Deadline { evidence, .. } => evidence,
            _ => panic!("rollback stage must mint its typed deadline evidence"),
        };
        let rollback = LocalTxAttempt::<(), _>::rollback_failed_operation_deadline(
            FakeError::Transient,
            operation_evidence,
            rollback_evidence,
        )
        .into_retry_result(|_| TxRetryClass::Transient)
        .expect_err("rollback deadline must remain an error");
        assert_eq!(
            rollback.deadline_stages(),
            [
                Some(LocalTxDeadlineStage::Operation),
                Some(LocalTxDeadlineStage::Rollback),
            ]
        );

        let commit_evidence = match deadline.commit(async { Ok(()) }).await {
            LocalTxStageResult::Deadline { evidence, .. } => evidence,
            _ => panic!("commit stage must mint its typed deadline evidence"),
        };
        let commit =
            LocalTxAttempt::<(), _>::commit_unknown_deadline(FakeError::Transient, commit_evidence)
                .into_retry_result(|_| TxRetryClass::Transient)
                .expect_err("commit deadline must remain an error");
        assert_eq!(
            commit.deadline_stages(),
            [Some(LocalTxDeadlineStage::Commit), None]
        );
    }
    #[cfg(feature = "domain-settings")]
    use std::error::Error;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
    enum FakeError {
        #[error("transient")]
        Transient,
        #[error("conflict")]
        Conflict,
    }

    fn classify(error: &FakeError) -> TxRetryClass {
        match error {
            FakeError::Transient => TxRetryClass::Transient,
            FakeError::Conflict => TxRetryClass::Conflict,
        }
    }

    #[test]
    fn settlement_states_derive_result_status_and_retry_class() {
        let committed = LocalTxAttempt::<u32, FakeError>::committed(7);
        assert_eq!(committed.settlement(), Some(LocalTxFinalStatus::Committed));
        assert_eq!(committed.retry_class(classify), None);
        assert_eq!(committed.into_result(), Ok(7));

        let unsettled = LocalTxAttempt::<(), _>::unsettled(FakeError::Transient);
        assert_eq!(unsettled.settlement(), None);
        assert_eq!(
            unsettled.retry_class(classify),
            Some(TxRetryClass::Transient)
        );

        let rolled_back = LocalTxAttempt::<(), _>::rolled_back(FakeError::Conflict);
        assert_eq!(
            rolled_back.settlement(),
            Some(LocalTxFinalStatus::RolledBack)
        );
        assert_eq!(
            rolled_back.retry_class(classify),
            Some(TxRetryClass::Conflict)
        );

        let rollback_failed = LocalTxAttempt::<(), _>::rollback_failed(FakeError::Transient);
        assert_eq!(
            rollback_failed.settlement(),
            Some(LocalTxFinalStatus::RollbackFailed)
        );
        assert_eq!(
            rollback_failed.retry_class(classify),
            Some(TxRetryClass::Permanent)
        );

        let commit_unknown = LocalTxAttempt::<(), _>::commit_unknown(FakeError::Transient);
        assert_eq!(
            commit_unknown.settlement(),
            Some(LocalTxFinalStatus::CommitUnknown)
        );
        assert_eq!(
            commit_unknown.retry_class(classify),
            Some(TxRetryClass::Permanent)
        );
    }

    #[test]
    fn only_commit_and_rollback_states_represent_acknowledged_settlement() {
        let cases = [
            (LocalTxAttempt::<(), _>::committed(()), true, "committed"),
            (
                LocalTxAttempt::<(), _>::unsettled(FakeError::Transient),
                false,
                "unsettled",
            ),
            (
                LocalTxAttempt::<(), _>::rolled_back(FakeError::Transient),
                true,
                "rolled_back",
            ),
            (
                LocalTxAttempt::<(), _>::rollback_failed(FakeError::Transient),
                false,
                "rollback_failed",
            ),
            (
                LocalTxAttempt::<(), _>::commit_unknown(FakeError::Transient),
                false,
                "commit_unknown",
            ),
        ];

        for (attempt, expected, state) in cases {
            assert_eq!(
                attempt.has_acknowledged_settlement(),
                expected,
                "unexpected connection policy for {state}"
            );
        }
    }

    #[test]
    fn quarantine_stage_labels_are_closed_and_low_cardinality() {
        assert_eq!(
            [
                LocalTxQuarantineStage::Begin,
                LocalTxQuarantineStage::Body,
                LocalTxQuarantineStage::Commit,
                LocalTxQuarantineStage::Rollback,
            ]
            .map(LocalTxQuarantineStage::as_label),
            ["begin", "body", "commit", "rollback"]
        );
    }

    #[test]
    fn failed_attempts_preserve_carrier_error() {
        for attempt in [
            LocalTxAttempt::<(), _>::unsettled(FakeError::Transient),
            LocalTxAttempt::rolled_back(FakeError::Transient),
            LocalTxAttempt::rollback_failed(FakeError::Transient),
            LocalTxAttempt::commit_unknown(FakeError::Transient),
        ] {
            assert_eq!(attempt.into_result(), Err(FakeError::Transient));
        }
    }

    #[cfg(feature = "domain-settings")]
    #[test]
    fn rollback_failed_wrap_is_storage_shaped_and_keeps_primary_cause() {
        use settings::ports::ConfigRepoError;

        let wrapped = rollback_failed(ConfigRepoError::VersionConflict, sqlx::Error::PoolTimedOut);
        let storage = ConfigRepoError::Storage(Box::new(wrapped));
        assert!(matches!(storage, ConfigRepoError::Storage(_)));
        assert!(!matches!(storage, ConfigRepoError::VersionConflict));

        let source = match &storage {
            ConfigRepoError::Storage(source) => source.as_ref(),
            other => panic!("expected storage settlement error, got {other:?}"),
        };
        let Some(sqlx_err) = source.downcast_ref::<sqlx::Error>() else {
            panic!("map_storage must wrap sqlx::Error");
        };
        let sqlx::Error::AnyDriverError(inner) = sqlx_err else {
            panic!("expected AnyDriverError wrapper, got {sqlx_err:?}");
        };
        let display = inner.to_string();
        assert!(
            display.contains("rollback failed"),
            "settlement display must describe rollback failure: {display}"
        );
        assert!(
            format!("{inner:?}").contains("VersionConflict"),
            "debug form must retain primary VersionConflict: {inner:?}"
        );
        let Some(rollback_source) = Error::source(inner.as_ref()) else {
            panic!("rollback error must be #[source]");
        };
        assert!(
            format!("{rollback_source:?}").contains("PoolTimedOut")
                || rollback_source.to_string().contains("pool timed out"),
            "causal chain must retain rollback detail: {rollback_source:?}"
        );
        let _ = commit_unknown(sqlx::Error::PoolClosed);
    }
}
