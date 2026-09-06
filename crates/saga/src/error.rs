/// Closed recovery decisions; diagnostics never change their meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ErrorKind {
    /// Definition metadata is structurally invalid.
    #[error("invalid saga definition")]
    Definition,
    #[error("exact saga definition unavailable")]
    /// Restore the exact registered definition before attempting further effects.
    UnsupportedDefinition,
    #[error("saga durable integrity failure")]
    /// Durable state is inconsistent; stop and investigate without replaying effects blindly.
    Integrity,
    #[error("saga receipt protection failed")]
    /// Receipt authentication failed; preserve state and resolve the trusted key/provider mismatch.
    Protection,
    #[error("saga store unavailable")]
    /// Provider operation failed; safe diagnostics identify its stage and SQLSTATE when available.
    Store,
    #[error("saga commit outcome unknown")]
    /// Commit may have succeeded; recover through a locked snapshot instead of blindly retrying.
    CommitUnknown,
    #[error("saga rollback unacknowledged")]
    /// Rollback was not acknowledged; the provider must discard the connection and recover.
    RollbackUnknown,
    #[error("saga write authority lost")]
    /// Write authority was lost or unavailable; this worker must stop.
    Fenced,
    #[error("saga revision conflict")]
    /// Expected revision or immutable identity differs; reload authoritative state.
    Conflict,
    #[error("saga cancelled")]
    /// Caller cancelled. This does not prove the absence of an admitted effect or write.
    Cancelled,
    #[error("saga deadline exceeded")]
    /// Total deadline expired. Recover any unfinished intent before retrying effects.
    Deadline,
    #[error("saga effect outcome unknown")]
    /// An admitted external effect has an uncertain outcome and must be probed.
    EffectUnknown,
    #[error("saga execution budget exhausted")]
    /// A supplied execution bound is invalid; normal budget yield uses Report instead.
    Budget,
    /// The configured database schema or runtime role violates the storage contract.
    #[error("saga storage contract not accepted")]
    StorageContract,
    /// Invalid lease duration supplied by the caller.
    #[error("invalid saga lease duration")]
    LeaseInput,
    /// No immutable successful result is available at the requested scope.
    #[error("saga has no successful receipt")]
    ReceiptUnavailable,
    /// A typed receipt handle does not match the registered final action.
    #[error("saga receipt type or definition mismatch")]
    ReceiptType,
}

use rss_redact::RedactedSource;
use std::sync::Arc;

/// Provider operation stage, safe to record without application data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticPhase {
    /// Storage catalog and runtime role verification.
    Probe,
    /// Pool checkout.
    Acquire,
    /// Transaction start.
    Begin,
    /// Tenant and deadline setup.
    Setup,
    /// Component SQL operation.
    Operation,
    /// Transaction commit acknowledgment.
    Commit,
    /// Transaction rollback acknowledgment.
    Rollback,
}
/// Safe provider context with an opaque, owned original source.
#[derive(Debug)]
pub struct Diagnostic {
    phase: DiagnosticPhase,
    sqlstate: Option<String>,
    source: RedactedSource,
}
impl Diagnostic {
    /// Stage at which the provider failed.
    pub const fn phase(&self) -> DiagnosticPhase {
        self.phase
    }
    /// Validated five-character SQLSTATE, when available.
    pub fn sqlstate(&self) -> Option<&str> {
        self.sqlstate.as_deref()
    }
}
/// Recovery classification plus optional redacted provider evidence.
/// Equality compares recovery decisions; diagnostics do not alter control flow.
#[derive(Debug, Clone)]
pub struct Error {
    kind: ErrorKind,
    diagnostic: Option<Arc<Diagnostic>>,
}
impl Error {
    /// Construct a classified failure without provider evidence.
    pub const fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            diagnostic: None,
        }
    }
    /// Attach provider evidence. Raw source text is never exposed through formatting or chains.
    pub fn provider<E: std::error::Error + Send + Sync + 'static>(
        kind: ErrorKind,
        phase: DiagnosticPhase,
        sqlstate: Option<&str>,
        source: E,
    ) -> Self {
        let sqlstate = sqlstate
            .filter(|s| {
                s.len() == 5
                    && s.bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            })
            .map(str::to_owned);
        Self {
            kind,
            diagnostic: Some(Arc::new(Diagnostic {
                phase,
                sqlstate,
                source: RedactedSource::new(source),
            })),
        }
    }
    /// Closed recovery decision.
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }
    /// Safe diagnostic context, if the provider supplied it.
    pub fn diagnostic(&self) -> Option<&Diagnostic> {
        self.diagnostic.as_deref()
    }
    /// Conservatively classify interruption around a potentially mutating operation.
    pub fn uncertain(mut self) -> Self {
        if matches!(self.kind, ErrorKind::Cancelled | ErrorKind::Deadline) {
            self.kind = ErrorKind::CommitUnknown;
        }
        self
    }
}
impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self::new(kind)
    }
}
impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
    }
}
impl Eq for Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.kind.fmt(f)
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.diagnostic
            .as_ref()
            .map(|d| &d.source as &(dyn std::error::Error + 'static))
    }
}
