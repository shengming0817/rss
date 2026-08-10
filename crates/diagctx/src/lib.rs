#![doc = include_str!("../README.md")]

mod ctx;
mod local;

pub use ctx::{CorrelationId, CorrelationIdError, DiagnosticCtx};
pub use local::{correlation, current, scope};
