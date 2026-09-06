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
pub const MIGRATION_SQL: &str = concat!(
    include_str!("../migrations/0001_create_observation.sql"),
    "\n",
    include_str!("../migrations/0002_add_journal.sql")
);
/// One-way V1 to V2 upgrade; stop writers and execute as the external schema owner.
pub const UPGRADE_SQL: &str = include_str!("../migrations/0002_add_journal.sql");
