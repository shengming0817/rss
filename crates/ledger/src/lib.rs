#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
mod model;
mod protocol;
pub use model::*;
pub use protocol::{Authenticator, Verification};

/// Closed protocol errors; never include payload, identifiers or key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Invalid identity or payload size.
    #[error("invalid ledger input")]
    InvalidInput,
    /// Authentication keys require at least 256 bits of supplied material.
    #[error("invalid ledger key")]
    InvalidKey,
    /// Only V1 is supported.
    #[error("unsupported ledger encoding")]
    UnsupportedEncoding,
    /// A chain cannot silently change its configured key identity.
    #[error("unsupported ledger key identity")]
    UnsupportedKey,
    /// Canonical input authentication failed.
    #[error("ledger authentication failed")]
    Authentication,
    /// A record belongs to a different ledger.
    #[error("ledger identity mismatch")]
    ScopeMismatch,
    /// Sequence or predecessor does not match the anchor.
    #[error("ledger sequence or predecessor gap")]
    SequenceGap,
    /// The next sequence cannot be represented.
    #[error("ledger sequence exhausted")]
    SequenceExhausted,
}
