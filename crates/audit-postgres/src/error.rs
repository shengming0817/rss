use rss_redact::RedactedSource;
use rss_transactional_messaging::transaction::LocalTxDeadlineStage;

/// Closed startup storage admission categories without database identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionViolation {
    /// Missing or changed durable schema.
    Schema,
    /// Unsafe runtime or owner role.
    Role,
    /// Excessive, missing or delegated access.
    Permissions,
    /// Row-level isolation differs from the contract.
    Rls,
    /// Definer function differs from the migration.
    Functions,
    /// Persisted column or constraint shape differs.
    Shape,
}

/// Closed infrastructure retry classification; not transaction settlement evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageFailure {
    /// Connection interruption, resource contention or cancellation may recover.
    Transient,
    /// Permissions, schema, invalid queries or closed resources require intervention.
    Permanent,
}

/// Operation failure. Settlement remains a separate canonical `LocalTxAttempt`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Installation/startup schema or role validation failed.
    #[error("audit admission violation: {0:?}")]
    Admission(AdmissionViolation),
    /// Caller supplied an invalid cursor or bound.
    #[error("invalid audit read bound")]
    InvalidBound,
    /// The actual transaction tenant differs from the requested tenant.
    #[error("audit tenant mismatch")]
    ScopeMismatch,
    /// Stable identity has different bytes or integrity mode.
    #[error("audit identity conflict")]
    Conflict,
    /// Stored data violates the adapter contract.
    #[error("invalid audit storage contract")]
    StorageContract,
    /// The complete selected page exceeds the canonical byte budget; no partial page is returned.
    #[error("audit read byte budget exceeded")]
    ReadBudgetExceeded,
    /// Invalid write budget, reservation or batch dimensions.
    #[error("audit write limit exceeded")]
    WriteLimit,
    /// The shared preparation capacity cannot admit this write immediately.
    #[error("audit write capacity busy")]
    WriteBusy,
    /// A ledger-only operation was requested from an explicitly plain owner.
    #[error("audit ledger integrity is not enabled")]
    IntegrityRequired,
    /// Absolute deadline expired at the named stage.
    #[error("audit deadline elapsed")]
    Deadline(LocalTxDeadlineStage),
    /// Host cancellation was observed at the named stage.
    #[error("audit operation cancelled")]
    Cancelled(LocalTxDeadlineStage),
    /// Invalid canonical audit protocol input.
    #[error(transparent)]
    Protocol(#[from] rss_audit_core::Error),
    /// Ledger integrity failures never downgrade to plain persistence.
    #[cfg(feature = "ledger")]
    #[error(transparent)]
    Ledger(rss_ledger_postgres::Error),
    /// Enclosing message owner's original classified error, including ownership loss.
    #[cfg(feature = "messaging")]
    #[error(transparent)]
    Messaging(#[from] rss_transactional_messaging_postgres::PgError),
    /// Provider error text is not exposed by formatting or source traversal.
    #[error("audit storage unavailable")]
    Storage {
        /// Safe classification; the host decides whether to stop or retry.
        kind: StorageFailure,
        /// Opaque diagnostics, never exposed through formatting or source traversal.
        #[source]
        source: RedactedSource,
    },
    /// Rollback was not acknowledged; retain the operation and settlement failures.
    #[error("audit rollback unconfirmed")]
    Rollback {
        /// Original operation failure.
        operation: Box<Error>,
        /// Rollback settlement failure.
        settlement: Box<Error>,
    },
}

impl Error {
    /// The Audit or Ledger operation was interrupted by its deadline or cancellation.
    /// This classifies the cause only; it does not establish rollback or retry safety.
    pub fn is_interrupted(&self) -> bool {
        match self {
            Self::Deadline(_) | Self::Cancelled(_) => true,
            #[cfg(feature = "ledger")]
            Self::Ledger(
                rss_ledger_postgres::Error::Deadline(_) | rss_ledger_postgres::Error::Cancelled(_),
            ) => true,
            _ => false,
        }
    }
}

/// Failure of an Audit-owned transaction with the host's original operation error.
/// Settlement authority remains in `LocalTxAttempt`, never in this error value.
/// Formatting and source traversal do not expose the host error; match `Operation`
/// explicitly to recover its typed reason and host-owned retry classification.
pub enum TransactionError<E> {
    /// Audit admission, control or provider failure.
    Audit(Error),
    /// The callback's original error, without formatting or type erasure.
    Operation(E),
    /// Rollback was not acknowledged; preserve both the original cause and cleanup error.
    Rollback {
        /// Original callback or Audit failure.
        operation: Box<Self>,
        /// Rollback admission or execution failure.
        settlement: Error,
    },
}

impl<E> std::fmt::Display for TransactionError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Audit(_) => "audit transaction failed",
            Self::Operation(_) => "host operation failed",
            Self::Rollback { .. } => "audit rollback unconfirmed",
        })
    }
}
impl<E> std::fmt::Debug for TransactionError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Audit(error) => f.debug_tuple("Audit").field(error).finish(),
            Self::Operation(_) => f.write_str("Operation([redacted])"),
            Self::Rollback {
                operation,
                settlement,
            } => f
                .debug_struct("Rollback")
                .field("operation", operation)
                .field("settlement", settlement)
                .finish(),
        }
    }
}
impl<E> std::error::Error for TransactionError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Audit(error) => Some(error),
            Self::Operation(_) => None,
            Self::Rollback { settlement, .. } => Some(settlement),
        }
    }
}
impl TransactionError<Error> {
    // Standalone append/read callbacks contain only Audit errors, never host errors.
    pub(crate) fn into_audit(self) -> Error {
        match self {
            Self::Audit(error) | Self::Operation(error) => error,
            Self::Rollback {
                operation,
                settlement,
            } => Error::Rollback {
                operation: Box::new(operation.into_audit()),
                settlement: Box::new(settlement),
            },
        }
    }
}

#[cfg(feature = "ledger")]
impl From<rss_ledger_postgres::Error> for Error {
    fn from(error: rss_ledger_postgres::Error) -> Self {
        match error {
            rss_ledger_postgres::Error::Conflict => Self::Conflict,
            other => Self::Ledger(other),
        }
    }
}

impl From<sqlx::Error> for Error {
    fn from(error: sqlx::Error) -> Self {
        match error.as_database_error().and_then(|e| e.code()).as_deref() {
            Some("PA001") => Self::ScopeMismatch,
            Some("PA002" | "23505" | "23514" | "23503") => Self::StorageContract,
            _ => {
                let kind = match &error {
                    sqlx::Error::Database(db) => db
                        .code()
                        .map_or(StorageFailure::Permanent, |code| database_failure(&code)),
                    sqlx::Error::Io(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput
                        ) =>
                    {
                        StorageFailure::Permanent
                    }
                    sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut | sqlx::Error::WorkerCrashed => {
                        StorageFailure::Transient
                    }
                    _ => StorageFailure::Permanent,
                };
                Self::Storage {
                    kind,
                    source: RedactedSource::new(error),
                }
            }
        }
    }
}

// SQLSTATE classes also contain permanent protocol/configuration failures.
// ref: PostgreSQL errcodes-appendix.html; postgres.c ProcessInterrupts timeout codes.
fn database_failure(code: &str) -> StorageFailure {
    match code {
        "08000" | "08001" | "08003" | "08006" | "08007" | "40001" | "40P01" | "53200" | "53300"
        | "55P03" | "57014" | "57P01" | "57P02" | "57P03" | "25P03" | "25P04" | "57P05" => {
            StorageFailure::Transient
        }
        _ => StorageFailure::Permanent,
    }
}

#[cfg(test)]
mod storage_tests {
    use super::*;
    #[cfg(feature = "ledger")]
    #[test]
    fn ledger_interruptions_share_audit_cause_classification() {
        let stage = LocalTxDeadlineStage::Operation;
        for error in [
            Error::Deadline(stage),
            Error::Cancelled(stage),
            Error::Ledger(rss_ledger_postgres::Error::Deadline(stage)),
            Error::Ledger(rss_ledger_postgres::Error::Cancelled(stage)),
        ] {
            assert!(error.is_interrupted());
        }
        assert!(!Error::Ledger(rss_ledger_postgres::Error::StorageContract).is_interrupted());
        assert!(!Error::Conflict.is_interrupted());
    }
    #[test]
    fn io_classification_keeps_permanent_data_errors_and_redacts_sources() {
        for (io, expected) in [
            (std::io::ErrorKind::InvalidData, StorageFailure::Permanent),
            (std::io::ErrorKind::InvalidInput, StorageFailure::Permanent),
            (
                std::io::ErrorKind::ConnectionReset,
                StorageFailure::Transient,
            ),
        ] {
            let error = Error::from(sqlx::Error::Io(std::io::Error::new(
                io,
                "private-io-marker",
            )));
            assert!(matches!(&error,Error::Storage {kind,..} if *kind==expected));
            assert!(!format!("{error:?}").contains("private-io-marker"));
        }
    }
    #[test]
    fn permanent_sqlstates_in_connection_rollback_and_resource_classes() {
        for code in ["08P01", "08004", "40002", "53100", "53400", "ZZ999"] {
            assert_eq!(database_failure(code), StorageFailure::Permanent, "{code}");
        }
    }
    #[test]
    fn server_timeout_disconnects_remain_recoverable() {
        for code in ["25P03", "25P04", "57P05"] {
            assert_eq!(database_failure(code), StorageFailure::Transient, "{code}");
        }
    }
    #[test]
    fn sqlstates_preserve_retryability_without_diagnostics() {
        for code in ["42501", "42P01", "42883", "22012", "XX000"] {
            assert_eq!(database_failure(code), StorageFailure::Permanent);
        }
        for code in [
            "08006", "40001", "40P01", "53300", "55P03", "57014", "57P01",
        ] {
            assert_eq!(database_failure(code), StorageFailure::Transient);
        }
    }
}
