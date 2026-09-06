#![doc = include_str!("../README.md")]

mod ctx;
#[cfg(feature = "task-local")]
mod local;

pub use ctx::{CorrelationId, CorrelationIdError, DiagnosticCtx};
#[cfg(feature = "task-local")]
pub use local::{correlation, current, scope};
