//! Phase-typed immediate lifecycle ownership.

use tokio_util::sync::CancellationToken;

use crate::{
    DynManagedResource, ManagedBlockingWorkerRegistration, ManagedBlockingWorkerStartError,
    ManagedTaskRegistration, ShutdownStack, TaskStatus,
};

struct TransactionCore<'stack> {
    stack: &'stack mut ShutdownStack,
}

impl TransactionCore<'_> {
    fn stage_resource(&mut self, resource: Box<DynManagedResource<'static>>) {
        self.stack.register_detached(resource);
    }

    fn stage_with_token<F>(&mut self, make: F)
    where
        F: FnOnce(CancellationToken) -> Box<DynManagedResource<'static>>,
    {
        self.stack.register_with_token(make);
    }

    fn stage_task_with_token(&mut self, registration: ManagedTaskRegistration) -> TaskStatus {
        self.stack.register_managed_task_with_token(registration)
    }

    fn try_stage_blocking_with_token(
        &mut self,
        registration: ManagedBlockingWorkerRegistration,
    ) -> Result<TaskStatus, ManagedBlockingWorkerStartError> {
        self.stack
            .try_register_blocking_worker_with_token(registration)
    }

    fn stage_deferred_with_token<F>(&mut self, make: F)
    where
        F: FnOnce(CancellationToken) -> Box<DynManagedResource<'static>>,
    {
        self.stack.register_deferred_with_token(make);
    }

    fn stage_deferred_task_with_token(
        &mut self,
        registration: ManagedTaskRegistration,
    ) -> TaskStatus {
        self.stack
            .register_deferred_managed_task_with_token(registration)
    }

    fn try_stage_deferred_blocking_with_token(
        &mut self,
        registration: ManagedBlockingWorkerRegistration,
    ) -> Result<TaskStatus, ManagedBlockingWorkerStartError> {
        self.stack
            .try_register_deferred_blocking_worker_with_token(registration)
    }
}

/// Immediate ownership boundary for resources created during startup.
#[must_use = "startup resources must be committed into the launch phase"]
pub struct StartupTransaction<'stack> {
    core: TransactionCore<'stack>,
}

impl<'stack> StartupTransaction<'stack> {
    pub(crate) fn new(stack: &'stack mut ShutdownStack) -> Self {
        Self {
            core: TransactionCore { stack },
        }
    }

    /// Transfer an already-created resource before the next cancellation point.
    pub fn stage_resource(&mut self, resource: Box<DynManagedResource<'static>>) {
        self.core.stage_resource(resource);
    }

    /// Create a resource with a child of the stack-owned root token.
    pub fn stage_with_token<F>(&mut self, make: F)
    where
        F: FnOnce(CancellationToken) -> Box<DynManagedResource<'static>>,
    {
        self.core.stage_with_token(make);
    }

    /// Register an opaque managed-task owner and return its same-source status.
    pub fn stage_task_with_token(&mut self, registration: ManagedTaskRegistration) -> TaskStatus {
        self.core.stage_task_with_token(registration)
    }

    /// Start and own a fallible dedicated-thread registration with a stack-owned child token.
    pub fn try_stage_blocking_with_token(
        &mut self,
        registration: ManagedBlockingWorkerRegistration,
    ) -> Result<TaskStatus, ManagedBlockingWorkerStartError> {
        self.core.try_stage_blocking_with_token(registration)
    }

    /// Register a resource whose token is cancelled only at its own LIFO phase.
    pub fn stage_deferred_with_token<F>(&mut self, make: F)
    where
        F: FnOnce(CancellationToken) -> Box<DynManagedResource<'static>>,
    {
        self.core.stage_deferred_with_token(make);
    }

    /// Register a managed task whose token is cancelled only at its own LIFO phase.
    pub fn stage_deferred_task_with_token(
        &mut self,
        registration: ManagedTaskRegistration,
    ) -> TaskStatus {
        self.core.stage_deferred_task_with_token(registration)
    }

    /// Start a fallible dedicated-thread registration cancelled at its own LIFO phase.
    pub fn try_stage_deferred_blocking_with_token(
        &mut self,
        registration: ManagedBlockingWorkerRegistration,
    ) -> Result<TaskStatus, ManagedBlockingWorkerStartError> {
        self.core
            .try_stage_deferred_blocking_with_token(registration)
    }

    /// Seal startup and transfer the same owner into the launch registration phase.
    pub fn commit(self) -> LaunchTransaction<'stack> {
        let core = self.core;
        core.stack.enter_launch();
        LaunchTransaction { core }
    }
}

/// Immediate ownership boundary for resources created while launching.
#[must_use = "the launch registration phase must be explicitly finished"]
pub struct LaunchTransaction<'stack> {
    core: TransactionCore<'stack>,
}

impl LaunchTransaction<'_> {
    /// Transfer an already-created resource before the next cancellation point.
    pub fn stage_resource(&mut self, resource: Box<DynManagedResource<'static>>) {
        self.core.stage_resource(resource);
    }

    /// Create a resource with a child of the stack-owned root token.
    pub fn stage_with_token<F>(&mut self, make: F)
    where
        F: FnOnce(CancellationToken) -> Box<DynManagedResource<'static>>,
    {
        self.core.stage_with_token(make);
    }

    /// Register an opaque managed-task owner and return its same-source status.
    pub fn stage_task_with_token(&mut self, registration: ManagedTaskRegistration) -> TaskStatus {
        self.core.stage_task_with_token(registration)
    }

    /// Start and own a fallible dedicated-thread registration with a stack-owned child token.
    pub fn try_stage_blocking_with_token(
        &mut self,
        registration: ManagedBlockingWorkerRegistration,
    ) -> Result<TaskStatus, ManagedBlockingWorkerStartError> {
        self.core.try_stage_blocking_with_token(registration)
    }

    /// Register a resource whose token is cancelled only at its own LIFO phase.
    pub fn stage_deferred_with_token<F>(&mut self, make: F)
    where
        F: FnOnce(CancellationToken) -> Box<DynManagedResource<'static>>,
    {
        self.core.stage_deferred_with_token(make);
    }

    /// Register a managed task whose token is cancelled only at its own LIFO phase.
    pub fn stage_deferred_task_with_token(
        &mut self,
        registration: ManagedTaskRegistration,
    ) -> TaskStatus {
        self.core.stage_deferred_task_with_token(registration)
    }

    /// Start a fallible dedicated-thread registration cancelled at its own LIFO phase.
    pub fn try_stage_deferred_blocking_with_token(
        &mut self,
        registration: ManagedBlockingWorkerRegistration,
    ) -> Result<TaskStatus, ManagedBlockingWorkerStartError> {
        self.core
            .try_stage_deferred_blocking_with_token(registration)
    }

    /// Finish registration and release the exclusive borrow of the shutdown owner.
    pub fn finish(self) {
        self.core.stack.seal_registration();
    }
}
