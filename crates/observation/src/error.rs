use rss_redact::RedactedSource;
/// Closed recovery categories; no report content is included in diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ErrorKind {
    #[error("invalid observation input")]
    /// Malformed, oversized or unsupported-version caller input.
    InvalidInput,
    #[error("observation authority denied")]
    /// The product authority refused the exact requested access.
    Unauthorized,
    #[error("observation identity conflict")]
    /// An immutable batch identity or producer sequence is already bound to different facts.
    Conflict,
    #[error("observation lifecycle conflict")]
    /// Expected lifecycle revision, policy or never-used identity requirements were not met.
    LifecycleConflict,
    #[error("observation stream is not active")]
    /// New facts target a registration or epoch that is not currently active.
    StaleEpoch,
    #[error("observation stream does not exist")]
    /// No activation exists for the requested historical state lookup.
    UnknownStream,
    #[error("observation storage unavailable")]
    /// Provider access failed; this classification alone is not evidence of settlement.
    Storage,
    #[error("observation storage contract violated")]
    /// Stored evidence or provider configuration contradicts the component contract.
    Invariant,
    #[error("observation commit outcome unknown")]
    /// An effect or commit may have occurred without confirmation; read or explicitly retry the same identity.
    CommitUnknown,
    #[error("observation rollback unconfirmed")]
    /// Rollback was not acknowledged; never infer that the attempt made no writes.
    RollbackFailed,
    #[error("observation deadline exceeded")]
    /// The operation budget expired before effects or server cancellation was followed by acknowledged rollback.
    Deadline,
    #[error("observation store closed")]
    /// The adopted provider no longer accepts work.
    Closed,
}
/// Classified error with an opaque provider source. Formatting never reveals payloads or SQL.
#[derive(Debug, thiserror::Error)]
#[error("{kind}")]
pub struct Error {
    kind: ErrorKind,
    #[source]
    source: Option<RedactedSource>,
}
impl Error {
    /// Construct a closed recovery classification without provider diagnostics.
    pub const fn new(kind: ErrorKind) -> Self {
        Self { kind, source: None }
    }
    /// Attach the original provider error behind a redacted source; raw text is not exposed by formatting.
    pub fn provider(
        kind: ErrorKind,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            source: Some(RedactedSource::new(source)),
        }
    }
    /// Recovery classification; diagnostics do not change the required settlement handling.
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }
}
impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self::new(kind)
    }
}
impl From<serde_json::Error> for Error {
    fn from(source: serde_json::Error) -> Self {
        Self::provider(ErrorKind::InvalidInput, source)
    }
}
