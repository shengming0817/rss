#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#[cfg(feature = "projection")]
mod projection;
#[cfg(feature = "projection")]
pub use projection::PgSource;
mod probe;
mod store;
mod transaction;
pub use store::PgStore;
#[cfg(feature = "integration")]
pub use transaction::Fault;
/// Fresh-install definition; only an external owner/migrator executes it.
pub const MIGRATION_SQL: &str = include_str!("../migrations/0003_create_observation.sql");
