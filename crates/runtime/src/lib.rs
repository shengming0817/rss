#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod admission;
mod blocking;
mod resource;
mod scope;
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
    DrainCompletion, RegistrationPhaseError, ResourceShutdownError, ShutdownDrain,
    ShutdownFailureKind, ShutdownReceipt, ShutdownStack, ShutdownStackError, TotalDrainBudget,
    TotalDrainBudgetError,
};
pub use transaction::{LaunchTransaction, StartupTransaction};

pub use scope::{
    CriticalTaskExit, CriticalTasks, LifecycleOutcome, LifecycleScope, ScopeExit, ScopeStateError,
};

pub use admission::{AdmissionControl, AdmissionError, AdmissionGate, AdmissionPermit};
