#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
mod admission;
mod error;
mod identity;
#[cfg(feature = "integration")]
pub mod measurement;
mod report;
mod retention;
pub use retention::{MaintenanceGrant, ObservationMaintenance, RetentionPage, ScanWindow};
mod state;
mod store;
pub use admission::{
    Access, Authority, JournalReadGrant, LifecycleGrant, ReadGrant, VerifiedBatch,
};
pub use error::{Error, ErrorKind};
pub use identity::{Epoch, Id, Registration, Scope};
pub use report::{Batch, Body, Change, Coverage};
pub use state::{Decision, NeedSnapshot, Policy, State, SyncOutcome};
pub use store::{ApplicableRecord, Clock, LookupOutcome, ObservationStore, ReceiveOutcome, Record};
