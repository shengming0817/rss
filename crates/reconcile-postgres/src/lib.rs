//! Independent PostgreSQL durable reconciliation with optional atomic messaging.
#![forbid(unsafe_code)]
#[cfg(feature = "transactional-messaging")]
mod messaging;
#[cfg(feature = "transactional-messaging")]
pub use messaging::PgMessagingStore;
mod probe;
mod store;
mod transaction;
pub use store::PgClaim;
#[cfg(feature = "integration")]
pub use transaction::PgFault;
pub use transaction::{CloseOutcome, PgOperation, PgOperationError, PgStore, PgTransaction};
/// Fresh version-bound component schema. Production migrators execute it.
pub const MIGRATION_SQL: &str = include_str!("../migrations/install.sql");
/// Transaction-local decision; only acknowledged commit yields a ReconcileStep to the runner.
#[derive(Debug)]
pub enum ProtectedStep<T> {
    Ready(T),
    Deferred(std::time::Duration),
    Rebind(rss_reconcile::ResourceSet, std::time::Duration),
}
