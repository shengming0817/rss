//! PostgreSQL transactional messaging with tenant-scoped transactions and durable receipts.
//!
//! Schema installation and role provisioning belong to the external migrator.
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
mod config;
mod consumer;
mod envelope;
mod inbox;
mod outbox;
mod transaction;

pub use config::{PgConfig, PgPassword, PgPrivateCa, PgPrivateCaError};
pub use consumer::{
    ConsumerRecoveryMode, PgConsumerEffect, PgConsumerEffectFailure, PgConsumerTx, ReceiptOnly,
};
pub use inbox::{PgInboxClaim, PgInboxStore};
pub use outbox::{PgOutboxClaim, PgOutboxStore};
#[cfg(feature = "integration")]
pub use transaction::PgTransactionFault;
pub use transaction::{PgError, PgRuntime, PgStorageContractFailure, PgTransaction};

/// Version-matched fresh-install SQL for an external migrator. This constant executes nothing;
/// role provisioning, migration execution and application grants remain consumer responsibilities.
pub const MIGRATION_SQL: &str = concat!(
    include_str!("../migrations/0001_create_transactional_messaging.sql"),
    "\n",
    include_str!("../migrations/0002_add_message_recovery.sql"),
    "\n",
    include_str!("../migrations/0003_enforce_replay_identity.sql")
);
/// One-way upgrade from the original component schema; executed only by the external migrator.
pub const RECOVERY_UPGRADE_SQL: &str = concat!(
    include_str!("../migrations/0002_add_message_recovery.sql"),
    "\n",
    include_str!("../migrations/0003_enforce_replay_identity.sql")
);
#[cfg(feature = "recovery")]
mod recovery;
#[cfg(feature = "recovery")]
pub use recovery::{PgRecoveryCapture, PgRecoveryStore};
