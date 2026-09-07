//! Closed, payload-free diagnostic output. Component errors retain their own semantics.

/// A fixed diagnostic summary, selected explicitly at a component's output boundary.
///
/// This vocabulary does not determine retries, authorization, HTTP responses or terminal outcomes.
/// Components retain their own errors and classifications; no error text is inspected here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorSummary {
    /// I/O failed.
    Io,
    /// A protocol operation failed.
    Protocol,
    /// The operation encountered an invalid state.
    State,
    /// Runtime execution failed.
    Runtime,
    /// A heartbeat was missed.
    Heartbeat,
    /// A client operation failed.
    Client,
    /// The caller cannot provide a more specific safe summary.
    Unknown,
}

impl ErrorSummary {
    /// A fixed, low-cardinality label with no caller-controlled text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Io => "io",
            Self::Protocol => "protocol",
            Self::State => "state",
            Self::Runtime => "runtime",
            Self::Heartbeat => "heartbeat",
            Self::Client => "client",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for ErrorSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A last-error value containing only a closed diagnostic summary.
///
/// No string, error formatter, open renderer or general redaction result can populate this value.
/// The guarantee is local to this value. This type has no production persistence consumer or
/// storage schema and does not enforce the types accepted by external writers.
///
/// ```
/// use rss_redact::{ErrorSummary, LastError};
/// assert_eq!(LastError::from_summary(ErrorSummary::Io).as_str(), "io");
/// ```
///
/// ```compile_fail
/// rss_redact::LastError::from_summary("secret");
/// ```
///
/// ```compile_fail
/// rss_redact::LastError::from_summary(std::io::Error::other("secret"));
/// ```
///
/// ```compile_fail
/// let value = rss_redact::redact_field("public", "secret");
/// rss_redact::LastError::from_summary(value);
/// ```
///
/// ```compile_fail
/// struct Untrusted;
/// impl rss_redact::Redact for Untrusted {
///     fn redact_scoped(&self, _: rss_redact::RedactScope) -> String { "secret".into() }
/// }
/// rss_redact::LastError::from_summary(Untrusted);
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct LastError(ErrorSummary);

impl LastError {
    /// Construct from the payload-free output vocabulary.
    pub const fn from_summary(summary: ErrorSummary) -> Self {
        Self(summary)
    }

    /// Borrow the fixed diagnostic label.
    pub const fn as_str(&self) -> &'static str {
        self.0.as_str()
    }
}

impl std::fmt::Display for LastError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::fmt::Debug for LastError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LastError({})", self.as_str())
    }
}
