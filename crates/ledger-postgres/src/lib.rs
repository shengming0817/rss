#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
mod control;
mod error;
#[cfg(feature = "messaging")]
mod messaging;
#[cfg(feature = "messaging")]
pub use messaging::append_in;
mod probe;
mod repository;
mod transaction;
pub use control::{Control, Timer};
pub use error::{AdmissionViolation, Error};
pub use repository::{ReadLimit, StagedAppend, Window};
#[cfg(feature = "integration")]
pub use transaction::PgFault;
pub use transaction::{Committed, LedgerTransaction, PgLedger};
/// Fresh V1 schema. Execute externally under a dedicated non-superuser, non-BYPASSRLS owner.
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001_create_ledger.sql");
