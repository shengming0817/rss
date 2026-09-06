//! Durable, tenant-scoped reconciliation; provider owns claims, caller owns execution.
#![forbid(unsafe_code)]
mod control;
mod diff;
mod model;
mod policy;
mod ports;
mod worker;
pub use control::{Control, Timer};
pub use diff::{ActualState, ConvergeAction, DesiredState, DriftKind, ReconcileDiff};
pub use model::{Completion, Error, ErrorKind, Scope, Target};
pub use policy::{Policy, PolicyConfig};
pub use ports::{Claim, DurableStore, Reconciler};
pub use worker::{Observation, Report, Stage, run, run_with_notify};
