//! Opaque HTTP request-id carrier minted only by the transport middleware dependency owner.
//!
//! `deny.toml` restricts this crate to `httpserve` (mint) and `generated` (consume). Domain crates
//! can receive the carrier through `httpserve::VerifiedRequestId`, but cannot name this crate or
//! invoke the mint constructor without failing the dependency-graph gate.
//!
//! INVARIANT: HTTP-REQUEST-ID-AUTHORITY-01 { level = "Hard", exec = "native-compile", source = "code", native = "opaque carrier + crate graph wrapper allowlist" }

/// Request ID proven to originate at the HTTP middleware boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireRequestId(String);

impl WireRequestId {
    /// Mint after HTTP middleware has accepted or generated the request ID.
    ///
    /// Dependency governance permits this call only from `httpserve`; generated code may name the
    /// carrier in signatures but never calls this constructor.
    #[must_use]
    pub fn from_http_middleware(value: String) -> Self {
        Self(value)
    }

    /// Borrow the verified request ID for wire serialization and structured diagnostics.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
