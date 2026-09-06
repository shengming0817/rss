//! Durable, tenant-scoped Saga execution with exact definitions and protected receipts.
//!
//! Stored ciphertext cannot mint decryption authority:
//! ```compile_fail
//! fn forge() -> rss_saga::ReceiptContext {
//!     rss_saga::ReceiptContext::from_bytes(vec![0])
//! }
//! ```
//! Effects cannot be invoked with a fabricated context:
//! ```compile_fail
//! let context = rss_saga::EffectContext { };
//! ```
//! Durable mutations cannot be constructed from caller-selected events:
//! ```compile_fail
//! fn forge(event: rss_saga::Event) -> rss_saga::Mutation {
//!     rss_saga::Mutation { event }
//! }
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]
mod action;
mod control;
mod definition;
mod error;
mod integrity;
mod model;
mod receipt;
mod store;
pub use action::{
    Completion, DefinitionBuilder, EffectOutcome, ProbeOutcome, Registry, RegistryBuilder, Step,
};
pub use control::{Control, LeasePolicy, Timer};
pub use definition::{ActionGeneration, Definition, EffectKey, Identity, StepSpec};
pub use error::{Diagnostic, DiagnosticPhase, Error, ErrorKind};
pub use integrity::{
    SagaReceiptFingerprint, SagaReceiptIntegrityError, SagaReceiptIntegrityKeyId,
    SagaReceiptIntegrityKeyring, VersionedSagaReceiptIntegrityKey,
};
pub use model::{Event, EventKind, Phase, Scope, Snapshot, Status};
pub use receipt::{
    Ciphertext, EffectContext, ProtectedReceipt, ReceiptContext, ReceiptProtection,
    SagaReceiptProtector,
};
pub use store::{Lease, Mutation, Store};
mod executor;
pub use executor::{
    Executor, Failure, FailureKind, InstanceResult, Report, RunStop, SuccessReference, SweepBudget,
    SweepReport, SweepStop,
};
