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
    "\n",
    include_str!("../migrations/0003_bind_definition_identity.sql"),
);

/// One-way v2 to v3 upgrade, requiring no existing generations.
/// Execute outside another transaction as the dedicated owner with workers stopped.
/// Nonempty checkpoints abort and must be rolled back; no data adoption is provided.
pub const UPGRADE_SQL: &str = include_str!("../migrations/0003_bind_definition_identity.sql");
