#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
mod aggregate;
mod config;
mod control;
mod control_probe;
mod cursor;
mod definition;
mod install;
mod lifecycle;
mod maintain;
mod probe;
mod projection;
mod read;
mod transaction;
mod write;
pub use config::{ConnectionConfig, Credentials, Limits};
pub use cursor::CursorKey;
pub use install::{CONTROL_SQL, installation_sql};
pub use lifecycle::{ChOwner, ChStore};
use lifecycle::Operation;
#[cfg(feature = "integration")]
pub use write::Fault;
pub use write::ProjectionProgress;
