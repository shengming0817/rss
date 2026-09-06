//! Independent PostgreSQL durable reconciliation with optional atomic messaging.
#![forbid(unsafe_code)]
#[cfg(feature = "transactional-messaging")]
pub mod messaging;
mod probe;
mod store;
mod transaction;
pub use store::PgClaim;
#[cfg(feature = "integration")]
pub use transaction::PgFault;
pub use transaction::{CloseOutcome, PgOperationError, PgStore, PgTransaction};
/// Fresh version-bound component schema. Production migrators execute it.
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001_create_reconcile.sql");
