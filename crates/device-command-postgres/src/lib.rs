#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
mod persistence;
mod store;
pub use store::PgStore;
/// Fresh component schema, executed only by an external migration owner.
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001_create_device_command.sql");
