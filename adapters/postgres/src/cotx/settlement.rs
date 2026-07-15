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

use consistency::LocalTxFinalStatus;
#[cfg(any(
    test,
    feature = "domain-settings",
    feature = "domain-identity",
    feature = "domain-audit"
))]
use consistency::TxRetryClass;

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

impl<T, E> LocalTxAttempt<T, E> {
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

    use super::LocalTxAttempt;
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
