#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
mod control;
mod model;
mod ports;
mod runner;
pub use control::{Control, Timer};
pub use model::{
    ApplyOutcome, BaselineReceipt, BatchLimit, Checkpoint, Event, GenerationStart, Position,
    ProjectionScope, ReplayBound, SourceScope,
};
pub use ports::{AtLeastOnce, Execution, ExternalCheckpoint, ExternalTarget, Source};
pub(crate) use runner::validate_next;
pub use runner::{Observer, Report, RunLimit, Stop, run};

mod error;
pub use error::{Diagnostic, Error, Phase};

/// Closed recovery decisions, independent of diagnostic details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ErrorKind {
    /// Invalid name, coordinate, payload or budget.
    #[error("invalid projection input")]
    InvalidInput,
    /// Event belongs to another tenant or source.
    #[error("projection scope mismatch")]
    ScopeMismatch,
    /// Source returned a decreasing or repeated position.
    #[error("projection source out of order")]
    OutOfOrder,
    /// Source violated its immutable committed-prefix or batch contract.
    #[error("projection source contract violated")]
    SourceContract,
    /// Same identity described a different fact or generation definition.
    #[error("projection fact conflict")]
    Conflict,
    /// A newer worker owns this scope or progress changed.
    #[error("projection worker fenced")]
    Fenced,
    /// Retry may be attempted from durable state after confirmed non-commit.
    #[error("projection provider unavailable")]
    Unavailable,
    /// Callback rejected an event. No automatic skip is performed.
    #[error("projection apply rejected")]
    Rejected,
    /// Cancellation before a known mutating operation was admitted.
    #[error("projection cancelled")]
    Cancelled,
    /// Total deadline elapsed.
    #[error("projection deadline elapsed")]
    Deadline,
    /// An effect or commit may have completed. Recover using the same identity.
    #[error("projection commit outcome unknown")]
    CommitUnknown,
    /// Rollback was not acknowledged. Stop and discard the connection.
    #[error("projection rollback failed")]
    RollbackFailed,
    /// Component schema or runtime privileges violate the storage contract.
    #[error("projection storage contract mismatch")]
    StorageContract,
}
