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

use consistency::LocalTxFinalStatus;
#[cfg(any(
    test,
    feature = "domain-settings",
    feature = "domain-identity",
    feature = "domain-audit"
))]
use consistency::TxRetryClass;
use sqlx::{Acquire, PgPool, Postgres, Transaction, pool::PoolConnection};

/// One complete Postgres LocalTx attempt and its settlement evidence.
#[derive(Debug)]
pub(crate) struct LocalTxAttempt<T, E> {
    state: LocalTxAttemptState<T, E>,
}

#[derive(Debug)]
enum LocalTxAttemptState<T, E> {
    Committed(T),
    Unsettled(E),
    RolledBack(E),
    RollbackFailed(E),
    CommitUnknown(E),
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
            LocalTxAttemptState::Committed(_) | LocalTxAttemptState::RolledBack(_)
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
            state: LocalTxAttemptState::Unsettled(error),
        }
    }

    /// Construct an attempt whose explicit rollback completed.
    pub(super) fn rolled_back(error: E) -> Self {
        Self {
            state: LocalTxAttemptState::RolledBack(error),
        }
    }

    /// Construct an attempt whose explicit rollback failed.
    pub(super) fn rollback_failed(error: E) -> Self {
        Self {
            state: LocalTxAttemptState::RollbackFailed(error),
        }
    }

    /// Construct an attempt whose commit result is unknown.
    pub(super) fn commit_unknown(error: E) -> Self {
        Self {
            state: LocalTxAttemptState::CommitUnknown(error),
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
            LocalTxAttemptState::Unsettled(_) => None,
            LocalTxAttemptState::RolledBack(_) => Some(LocalTxFinalStatus::RolledBack),
            LocalTxAttemptState::RollbackFailed(_) => Some(LocalTxFinalStatus::RollbackFailed),
            LocalTxAttemptState::CommitUnknown(_) => Some(LocalTxFinalStatus::CommitUnknown),
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
            LocalTxAttemptState::Unsettled(error) | LocalTxAttemptState::RolledBack(error) => {
                Some(classify(error))
            }
            LocalTxAttemptState::RollbackFailed(_) | LocalTxAttemptState::CommitUnknown(_) => {
                Some(TxRetryClass::Permanent)
            }
        }
    }

    /// Consume settlement evidence at a non-retrying call site.
    pub(crate) fn into_result(self) -> Result<T, E> {
        match self.state {
            LocalTxAttemptState::Committed(value) => Ok(value),
            LocalTxAttemptState::Unsettled(error)
            | LocalTxAttemptState::RolledBack(error)
            | LocalTxAttemptState::RollbackFailed(error)
            | LocalTxAttemptState::CommitUnknown(error) => Err(error),
        }
    }

    /// Consume settlement evidence at the bounded retry boundary.
    #[cfg(any(
        feature = "domain-settings",
        feature = "domain-identity",
        feature = "domain-audit"
    ))]
    pub(crate) fn into_retry_result(
        self,
        classify: impl FnOnce(&E) -> TxRetryClass,
    ) -> Result<T, LocalTxRetryError<E>> {
        let settlement = self.settlement();
        match self.state {
            LocalTxAttemptState::Committed(value) => Ok(value),
            LocalTxAttemptState::Unsettled(error)
            | LocalTxAttemptState::RolledBack(error)
            | LocalTxAttemptState::RollbackFailed(error)
            | LocalTxAttemptState::CommitUnknown(error) => {
                let class = match settlement {
                    Some(
                        LocalTxFinalStatus::Committed
                        | LocalTxFinalStatus::RollbackFailed
                        | LocalTxFinalStatus::CommitUnknown,
                    ) => TxRetryClass::Permanent,
                    None | Some(LocalTxFinalStatus::RolledBack) => classify(&error),
                };
                Err(LocalTxRetryError { error, class })
            }
        }
    }
}

/// Failure shape consumed only by the generic retry engine.
#[cfg(any(
    feature = "domain-settings",
    feature = "domain-identity",
    feature = "domain-audit"
))]
#[derive(Debug)]
pub(crate) struct LocalTxRetryError<E> {
    error: E,
    class: TxRetryClass,
}

#[cfg(any(
    feature = "domain-settings",
    feature = "domain-identity",
    feature = "domain-audit"
))]
impl<E> LocalTxRetryError<E> {
    /// Settlement-safe retry class.
    pub(crate) fn class(&self) -> TxRetryClass {
        self.class
    }

    /// Borrow the domain error for closed-label diagnostics before it is returned to the caller.
    pub(crate) fn error(&self) -> &E {
        &self.error
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
    use consistency::{LocalTxFinalStatus, TxRetryClass};

    use super::{LocalTxAttempt, LocalTxQuarantineStage};
    #[cfg(feature = "domain-settings")]
    use super::{commit_unknown, rollback_failed};
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
