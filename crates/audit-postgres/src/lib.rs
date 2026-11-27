#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod append;
mod borrowed;
mod budget;
pub use budget::{AdmittedBatch, WriteBudget, WriteReservation};
mod control;
mod error;
#[cfg(feature = "messaging")]
mod messaging;
#[cfg(feature = "messaging")]
pub use messaging::{lock_head_in, validate_in};
mod model;
mod probe;
pub use probe::validate_structure;
mod reader;
mod repository;
mod runtime;
pub use reader::PgAuditReader;
mod transaction;
#[cfg(feature = "ledger")]
mod verified;

pub use control::Control;
pub use error::{AdmissionViolation, Error, StorageFailure, TransactionError};
pub use model::{Cursor, Page, ReadLimit, Record, StagedAppend};
#[cfg(feature = "integration")]
pub use runtime::PgFault;
pub use runtime::{Committed, Integrity, PgAudit};
pub use transaction::{ReadAuditTransaction, WriteAuditTransaction};

/// Fresh PostgreSQL schema; execute only through the separately provisioned migration owner.
pub const MIGRATION_SQL: &str = include_str!("../migrations/install.sql");
