/// Audit V1 field names safe to expose in low-cardinality diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// Stable source identity.
    SourceId,
    /// Stable event identity.
    EventId,
    /// Source contract identity, version, or digest.
    SourceContract,
    /// Actor kind.
    ActorKind,
    /// Actor identifier.
    ActorId,
    /// Source-owned action token.
    Action,
    /// Resource kind.
    ResourceKind,
    /// Resource identifier.
    ResourceId,
    /// Correlation coordinate.
    CorrelationId,
    /// Request coordinate.
    RequestId,
    /// Operation coordinate.
    OperationId,
    /// Payload bytes.
    Payload,
}

/// Closed Audit V1 protocol errors. Variants never contain rejected input bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A required field was empty.
    #[error("audit field is empty: {0:?}")]
    Empty(Field),
    /// A field exceeded its byte bound.
    #[error("audit field is too long: {0:?}")]
    TooLong(Field),
    /// A field contained a character outside its grammar.
    #[error("audit field has an invalid character: {0:?}")]
    InvalidCharacter(Field),
    /// The complete canonical record exceeded the Audit V1 bound.
    #[error("audit record is too large")]
    RecordTooLarge,
    /// The record encoding version is not supported.
    #[error("unsupported audit record version")]
    UnsupportedVersion,
    /// An enum or optional-presence tag is unknown.
    #[error("unsupported audit record tag")]
    UnsupportedTag,
    /// Extra bytes would add an unknown V1 field.
    #[error("unknown audit record field")]
    UnknownField,
    /// Canonical bytes were malformed or truncated.
    #[error("malformed audit record encoding")]
    MalformedEncoding,
    /// Ledger and Audit identities did not describe the same record.
    #[error("audit record identity mismatch")]
    IdentityMismatch,
    /// The composed ledger protocol rejected the operation.
    #[cfg(feature = "ledger")]
    #[error("ledger protocol rejected audit record: {0}")]
    Ledger(#[from] rss_ledger::Error),
}
