#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
mod clock;
mod persistence;
mod probe;
mod store;
pub use clock::CommandClock;
#[cfg(feature = "integration")]
pub use clock::IntegrationClock;
pub use store::PgStore;
#[cfg(all(test, feature = "integration"))]
#[path = "../tests/unit/time.rs"]
mod time_tests;
/// Fresh component schema, executed only by an external migration owner.
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001_create_device_command.sql");
