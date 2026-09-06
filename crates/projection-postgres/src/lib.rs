#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
mod execution;
mod journal;
mod probe;
mod transaction;
pub use execution::{PgCheckpoint, PgClaim, PgEffect, PgEffectOutcome, PgProjection};
pub use journal::append_in_transaction;
#[cfg(feature = "integration")]
pub use transaction::PgFault;
pub use transaction::{CloseOutcome, PgOperationError, PgStore, PgTransaction};
/// Fresh component schema for a dedicated external migrator. Executes nothing.
pub const MIGRATION_SQL: &str = concat!(
    include_str!("../migrations/0001_create_projection.sql"),
    "\n",
    include_str!("../migrations/0002_require_baseline_receipts.sql"),
);
