use crate::ErrorKind;
use rss_redact::RedactedSource;
use std::sync::Arc;

/// Provider operation stage, safe to record without application data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Runtime admission.
    Admission,
    /// Pool checkout.
    Acquire,
    /// Transaction start.
    Begin,
    /// Tenant and deadline setup.
    Setup,
    /// Component SQL operation.
    Operation,
    /// Trusted application SQL.
    Application,
    /// Transaction commit acknowledgment.
    Commit,
    /// Transaction rollback acknowledgment.
    Rollback,
}
/// Safe provider context with an opaque, owned original source.
#[derive(Debug)]
pub struct Diagnostic {
    phase: Phase,
    sqlstate: Option<String>,
    source: RedactedSource,
}
impl Diagnostic {
    /// Stage at which the provider failed.
    pub const fn phase(&self) -> Phase {
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
        phase: Phase,
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
