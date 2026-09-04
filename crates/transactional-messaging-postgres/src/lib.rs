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
pub use consumer::{PgConsumerEffect, PgConsumerEffectFailure, PgConsumerTx};
pub use inbox::{PgInboxClaim, PgInboxStore};
pub use outbox::{PgOutboxClaim, PgOutboxStore};
#[cfg(feature = "integration")]
pub use transaction::PgTransactionFault;
pub use transaction::{PgError, PgRuntime, PgStorageContractFailure, PgTransaction};

/// Version-matched fresh-install SQL for an external migrator. This constant executes nothing;
/// role provisioning, migration execution and application grants remain consumer responsibilities.
pub const MIGRATION_SQL: &str =
    include_str!("../migrations/0001_create_transactional_messaging.sql");
