//! PostgreSQL transactional messaging with tenant-scoped transactions and durable receipts.
//!
//! Schema installation and role provisioning belong to the external migrator.
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
mod body_maintenance;
pub use body_maintenance::{PgPublishedBodyMaintenance, PublishedBodyPage, PublishedBodyRetention};
mod config;
mod consumer;
mod consumer_profile;
mod envelope;
mod fence;
mod inbox;
mod outbox;
mod outbox_admission;
#[cfg(feature = "recovery")]
mod projection;
mod transaction;
#[cfg(feature = "recovery")]
pub use projection::{
    PgLocalProjection, PgProjectionAttempt, PgProjectionItem, PgProjectionOutcome,
    PgProjectionReceipt, PgProjectionRecovery,
};

pub use config::{PgConfig, PgPassword, PgPrivateCa, PgPrivateCaError};
pub use consumer::{
    ConsumerRecoveryMode, PgConsumerEffect, PgConsumerEffectFailure, PgConsumerTx, ReceiptOnly,
};
pub use consumer_profile::{grant_consumer, grant_local_projection};
pub use inbox::{PgInboxClaim, PgInboxStore};
pub use outbox::{OutboxWakeup, PgOutboxClaim, PgOutboxStore, PgOutboxWriter};
#[cfg(feature = "integration")]
pub use transaction::PgTransactionFault;
pub use transaction::{PgError, PgRuntime, PgStorageContractFailure, PgTransaction};

/// Version-matched fresh-install SQL for an external migrator. This constant executes nothing;
/// role provisioning, migration execution and application grants remain consumer responsibilities.
pub const MIGRATION_SQL: &str = include_str!("../migrations/install.sql");

#[cfg(feature = "recovery")]
mod recovery;
#[cfg(feature = "recovery")]
pub use recovery::{PgRecoveryCapture, PgRecoveryStore};

#[cfg(feature = "recovery")]
mod archive;
#[cfg(feature = "recovery")]
pub use archive::PgArchiveRepository;

#[cfg(feature = "recovery")]
mod dr;
#[cfg(feature = "recovery")]
pub use dr::PgDrStore;
