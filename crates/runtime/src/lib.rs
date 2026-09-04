//! Provider-neutral lifecycle ownership and bounded shutdown.

#![forbid(unsafe_code)]

mod blocking;
mod resource;
mod shutdown;
mod transaction;

pub use blocking::{
    ManagedBlockingWorker, ManagedBlockingWorkerRegistration, ManagedBlockingWorkerStartError,
    blocking_worker_registration, dedicated_runtime_registration, spawn_on_dedicated_runtime,
};
pub use resource::{
    DEFAULT_SHUTDOWN_TIMEOUT, DynManagedResource, ManagedResource, ManagedTask,
    ManagedTaskRegistration, ShutdownError, ShutdownErrorKind, TaskExit, TaskStart, TaskState,
    TaskStatus, join_owned_task,
};
pub use shutdown::{
    DrainCompletion, RegistrationPhaseError, ResourceShutdownError, ShutdownFailureKind,
    ShutdownReceipt, ShutdownStack, ShutdownStackError, TotalDrainBudget, TotalDrainBudgetError,
};
pub use transaction::{LaunchTransaction, StartupTransaction};
