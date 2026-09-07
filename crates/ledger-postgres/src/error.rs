/// Closed, redacted admission failure category; contains no database identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionViolation {
    /// Schema revision, relation identity or durability differs.
    Schema,
    /// Runtime or definer role violates the contract.
    Role,
    /// Object access or delegation privileges violate the contract.
    Permissions,
    /// Row-level isolation differs.
    Rls,
    /// Function signature, body or execution configuration differs.
    Functions,
    /// Column shape differs.
    Columns,
    /// Validated constraints differ.
    Constraints,
}
use rss_redact::RedactedSource;
/// Ledger operation error. Transaction settlement is represented separately by canonical `LocalTxAttempt`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Live admission contract violation, without provider or tenant data.
    #[error("ledger admission violation: {0:?}")]
    Admission(AdmissionViolation),
    /// Both the operation error and an actually attempted rollback failure.
    #[error("ledger rollback unconfirmed")]
    Rollback {
        /// Failure triggering rollback.
        operation: Box<Error>,
        /// Failure to acknowledge rollback.
        settlement: Box<Error>,
    },
    /// Protocol rejection.
    #[error(transparent)]
    Protocol(#[from] rss_ledger::Error),
    /// Stable record identity was reused with different bytes.
    #[error("ledger record identity conflict")]
    Conflict,
    /// Live schema or role contract is unsafe or stored state is inconsistent.
    #[error("incompatible ledger storage contract")]
    StorageContract,
    /// The caller rejected its business operation.
    #[error("ledger transaction operation rejected")]
    Rejected,
    /// Remaining operation budget elapsed.
    #[error("ledger deadline elapsed")]
    Deadline(rss_transactional_messaging::transaction::LocalTxDeadlineStage),
    /// Caller cancellation was observed.
    #[error("ledger operation cancelled")]
    Cancelled(rss_transactional_messaging::transaction::LocalTxDeadlineStage),
    /// Redacted database failure; classification alone does not authorize retry.
    #[error("ledger storage unavailable")]
    Storage(#[source] RedactedSource),
}
pub(crate) fn sql_error(e: sqlx::Error) -> Error {
    match e.as_database_error().and_then(|e| e.code()).as_deref() {
        Some("PL001") => rss_ledger::Error::ScopeMismatch.into(),
        Some("PL002") => rss_ledger::Error::UnsupportedKey.into(),
        Some("PL003") => rss_ledger::Error::UnsupportedEncoding.into(),
        Some("PL004") => rss_ledger::Error::SequenceExhausted.into(),
        Some("PL005") => rss_ledger::Error::SequenceGap.into(),
        Some("23505") => Error::StorageContract,
        Some("42501" | "42P01" | "42883" | "23514" | "23503") => Error::StorageContract,
        _ => Error::Storage(RedactedSource::new(e)),
    }
}

impl From<sqlx::Error> for Error {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(RedactedSource::new(error))
    }
}
