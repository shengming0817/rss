#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#[cfg(feature = "projection")]
mod projection;
#[cfg(feature = "projection")]
pub use projection::{JournalBounds, PgSource};
#[cfg(all(feature = "projection", feature = "integration"))]
pub mod read_profile;
#[cfg(feature = "projection-postgres")]
pub use projection::{LocalPages, VerifiedObservation};
mod maintenance;
pub use maintenance::PgMaintenance;
mod probe;
mod store;
mod transaction;
pub use store::PgStore;
#[cfg(feature = "integration")]
pub use transaction::Fault;
/// Fresh-install definition; only an external owner/migrator executes it.
pub const MIGRATION_SQL: &str = include_str!("../migrations/0004_create_observation.sql");
