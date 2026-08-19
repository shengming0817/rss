//! Provider-independent runtime launch and shutdown kernel.
//!
//! Assemblies retain their provider, route, transport, and inventory types. This crate owns the
//! one-way launch lifecycle: accept completed module outputs, prepare every listener, activate the
//! ready set, publish the assembly-owned inventory, wait for shutdown, and drain exactly once.
//!
//! Once [`launch`] has been polled far enough to create its shutdown owner, dropping or aborting
//! the caller transfers the complete stack to a task on the originating Tokio runtime. A future
//! that is never polled has not created the executor stack: dropping such a future synchronously
//! drops its plan-owned inputs without asynchronous shutdown, so callers must poll [`launch`] to
//! transfer lifecycle ownership. As with every Tokio task, the originating runtime must remain
//! alive for asynchronous cleanup to finish.

pub mod config;
pub mod inventory;
mod platform_host;
pub use platform_host::RuntimeHostView;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

use std::future::Future;
use std::io::Write as _;
use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context as _;
use bootstrap::shutdown::ShutdownStack;
use bootstrap::{DomainModuleResult, WorkerSpec};
use diport::DynManagedResource;
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

static INSTALL_REDACTED_PANIC_HOOK: Once = Once::new();
static STRUCTURED_PANIC_OBSERVATION: AtomicBool = AtomicBool::new(false);

/// Install the process panic boundary before any production worker can be spawned.
///
/// Production assembly façades call this before executable entrypoints parse or construct a
/// runtime. Binaries and ordinary libraries must not import this capability crate directly or
/// replace the process-global hook. Panic payloads are never delegated to the default hook.
pub fn install_redacted_panic_hook() {
    INSTALL_REDACTED_PANIC_HOOK.call_once(|| {
        std::panic::set_hook(Box::new(|_| {
            if STRUCTURED_PANIC_OBSERVATION.load(Ordering::Acquire) {
                let panic_scope = if eventexec::managed_panic_scope_active() {
                    "managed_blocking_worker"
                } else {
                    "process_task_or_thread"
                };
                tracing::error!(panic_scope, "process panic observed; payload redacted");
            } else {
                let _ = writeln!(
                    std::io::stderr().lock(),
                    "process task or thread panicked; payload redacted"
                );
            }
        }));
    });
}

/// Switch the process panic dispatcher to the installed structured tracing generation.
pub fn activate_structured_panic_observation() {
    STRUCTURED_PANIC_OBSERVATION.store(true, Ordering::Release);
}

/// Assembly-owned launch behavior consumed by the common executor.
///
/// `prepare` must complete every fallible preparation and preflight step before returning its
/// associated `Prepared` state. The assembly keeps that state private, so its production code
/// cannot activate a partially prepared listener set. `activate` can fail only when sealing the
/// non-empty activation proof.
pub trait LaunchAdapter<ProbeReceipt>: Sized {
    /// Assembly-private state proving every listener is activation-ready.
    type Prepared;
    /// Assembly-private ready inventory passed once to the required ready hook.
    type Inventory;

    /// Consume the finalized-probe receipt and prepare every listener without activating one.
    /// Resources whose background lifecycle starts during preparation must be staged immediately in
    /// `transaction`, before preparation reaches another cancellation point.
    fn prepare(
        self,
        probe_receipt: ProbeReceipt,
        transaction: &mut LaunchTransaction<'_>,
    ) -> impl Future<Output = anyhow::Result<Self::Prepared>> + Send;

    /// Activate a fully prepared set through the restricted listener registrar. The returned
    /// capability can only be minted after at least one listener was actually registered.
    fn activate(
        prepared: Self::Prepared,
        registrar: LaunchRegistrar<'_>,
    ) -> anyhow::Result<Activated<Self::Inventory>>;
}

/// Prepare-stage lifecycle transaction owned by the launch kernel.
///
/// Staged resources enter the kernel's shutdown stack immediately. A prepare error or cancellation
/// therefore rolls them back through the same awaited, failure-reporting drain as committed runtime
/// resources. Only successful preparation can consume this transaction into [`LaunchRegistrar`].
pub struct LaunchTransaction<'stack> {
    stack: &'stack mut ShutdownStack,
}

impl<'stack> LaunchTransaction<'stack> {
    /// Stage a prepare-created resource before the next cancellation point.
    pub fn stage_resource(&mut self, resource: Box<DynManagedResource<'static>>) {
        self.stack.register_detached(resource);
    }

    fn commit(self) -> LaunchRegistrar<'stack> {
        LaunchRegistrar {
            stack: self.stack,
            listener_count: 0,
        }
    }
}

/// Cancellation-safe owner for provider/domain outputs created during startup.
///
/// Startup code must merge each completed stage before its next cancellation point. If the
/// startup future is dropped, this transaction discards probes that were never registered and
/// transfers every staged resource/worker into the executor's shutdown stack before the outer
/// [`ShutdownOwner`] begins its bounded asynchronous drain.
pub struct StartupTransaction<'stack> {
    stack: &'stack mut ShutdownStack,
    provider: DomainModuleResult,
    domain: DomainModuleResult,
    expected_workers: Option<bootstrap::ExpectedWorkerInventory>,
    armed: bool,
}

impl<'stack> StartupTransaction<'stack> {
    fn new(stack: &'stack mut ShutdownStack) -> Self {
        Self {
            stack,
            provider: DomainModuleResult::default(),
            domain: DomainModuleResult::default(),
            expected_workers: None,
            armed: true,
        }
    }

    /// Merge a completed provider stage by value, preserving probe/resource/worker order.
    pub fn stage_provider_output(&mut self, output: DomainModuleResult) {
        merge_module_output(&mut self.provider, output);
    }

    /// Merge a completed domain stage by value, preserving probe/resource/worker order.
    pub fn stage_domain_output(&mut self, output: DomainModuleResult) {
        merge_module_output(&mut self.domain, output);
    }

    /// Borrow the transaction-owned provider output for builders that stage outputs incrementally.
    ///
    /// Builders must append every already-created resource/worker before their next cancellable
    /// await; resources retained only in builder-local state cannot be recovered after cancellation.
    pub fn provider_output_mut(&mut self) -> &mut DomainModuleResult {
        &mut self.provider
    }

    /// Borrow both transaction-owned outputs to consume registered probes before launch sealing.
    pub fn outputs_mut(&mut self) -> (&mut DomainModuleResult, &mut DomainModuleResult) {
        (&mut self.provider, &mut self.domain)
    }

    /// Install the plan-derived, closed mutating-worker inventory exactly once.
    pub fn expect_workers(
        &mut self,
        expected: bootstrap::ExpectedWorkerInventory,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.expected_workers.replace(expected).is_none(),
            "expected worker inventory was installed more than once"
        );
        Ok(())
    }

    fn discard_unregistered_probes(&mut self) {
        discard_module_probes(&mut self.provider);
        discard_module_probes(&mut self.domain);
    }

    fn take_lifecycle_batches(&mut self) -> LaunchLifecycleBatches {
        self.armed = false;
        LaunchLifecycleBatches::new(
            ProviderLifecycleBatch::from_provider_output(std::mem::take(&mut self.provider)),
            DomainLifecycleBatch::from_domain_output(std::mem::take(&mut self.domain)),
            self.expected_workers.take(),
        )
    }

    fn into_lifecycle_batches(
        mut self,
        discard_unregistered_probes: bool,
    ) -> LaunchLifecycleBatches {
        if discard_unregistered_probes {
            self.discard_unregistered_probes();
        }
        self.take_lifecycle_batches()
    }
}

impl Drop for StartupTransaction<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.discard_unregistered_probes();
        let batches = self.take_lifecycle_batches();
        if let Err(error) = register_lifecycle_outputs(self.stack, None, batches, false) {
            tracing::error!(
                error = %secure::redact_error(error.as_ref()),
                "cancelled startup failed to transfer lifecycle outputs"
            );
        }
    }
}

fn merge_module_output(target: &mut DomainModuleResult, output: DomainModuleResult) {
    target.merge(output);
}

/// The only listener activation capability exposed to launch adapters.
///
/// Its constructor and underlying [`ShutdownStack`] stay private. Adapters can register a managed
/// listener only through the cancellation-token funnel.
///
/// ```compile_fail
/// use runtimeexec::LaunchRegistrar;
/// let _ = LaunchRegistrar { stack: todo!(), listener_count: 0 };
/// ```
pub struct LaunchRegistrar<'stack> {
    stack: &'stack mut ShutdownStack,
    listener_count: usize,
}

impl LaunchRegistrar<'_> {
    /// Register a background resource with a token derived from the executor's root token.
    pub fn register_listener_with_token<F>(&mut self, make: F)
    where
        F: FnOnce(CancellationToken) -> Box<DynManagedResource<'static>>,
    {
        self.stack.register_with_token(make);
        self.listener_count += 1;
    }

    /// Seal the activation inventory after proving that at least one listener entered the funnel.
    pub fn complete<Inventory>(self, inventory: Inventory) -> anyhow::Result<Activated<Inventory>> {
        anyhow::ensure!(
            self.listener_count > 0,
            "no listener was activated (refusing to start with zero bound sockets)"
        );
        Ok(Activated { inventory })
    }
}

/// Capability proving that listener activation registered a non-empty set.
pub struct Activated<Inventory> {
    inventory: Inventory,
}

impl<Inventory> Activated<Inventory> {
    fn into_inventory(self) -> Inventory {
        self.inventory
    }
}

/// Provider-owned lifecycle output. Its distinct type prevents role inversion at launch handoff.
pub struct ProviderLifecycleBatch(DomainModuleResult);

impl ProviderLifecycleBatch {
    /// Wrap the completed provider output in its launch role.
    pub fn from_provider_output(output: DomainModuleResult) -> Self {
        Self(output)
    }
}

/// Domain-owned lifecycle output. Its distinct type prevents role inversion at launch handoff.
pub struct DomainLifecycleBatch(DomainModuleResult);

impl DomainLifecycleBatch {
    /// Wrap the completed domain output in its launch role.
    pub fn from_domain_output(output: DomainModuleResult) -> Self {
        Self(output)
    }
}

/// Typed provider/domain lifecycle handoff consumed as one launch input.
pub struct LaunchLifecycleBatches {
    provider: ProviderLifecycleBatch,
    domain: DomainLifecycleBatch,
    expected_workers: Option<bootstrap::ExpectedWorkerInventory>,
}

/// Validated total budget for the complete LIFO drain.
///
/// The assembly-owned budget must be positive. This keeps cleanup bounded without relying on an
/// outer timeout that could cancel the shutdown driver between resources.
#[derive(Clone, Copy)]
pub struct TotalDrainBudget(Duration);

impl TotalDrainBudget {
    /// Validate an assembly-owned total drain deadline.
    pub fn new(total: Duration) -> anyhow::Result<Self> {
        anyhow::ensure!(!total.is_zero(), "total drain budget must be positive");
        Ok(Self(total))
    }

    const fn duration(self) -> Duration {
        self.0
    }
}

struct LaunchLifecycle {
    batches: LaunchLifecycleBatches,
    total_drain_budget: TotalDrainBudget,
}

impl LaunchLifecycleBatches {
    /// Preserve provider-before-domain registration order with non-interchangeable role types.
    pub fn new(
        provider: ProviderLifecycleBatch,
        domain: DomainLifecycleBatch,
        expected_workers: Option<bootstrap::ExpectedWorkerInventory>,
    ) -> Self {
        Self {
            provider,
            domain,
            expected_workers,
        }
    }
}

/// Single-use launch ownership transferred from an assembly to the executor.
///
/// All fields are private and every lifecycle input is consumed by [`launch`]. The probe receipt
/// and ready hook are mandatory; only the trace exporter is semantically optional.
///
/// ```compile_fail
/// use runtimeexec::LaunchPlan;
/// let _ = LaunchPlan {
///     adapter: (),
///     probe_receipt: (),
///     on_ready: |_| Ok(()),
///     trace_exporter: None,
///     lifecycle_batches: todo!(),
/// };
/// ```
///
/// ```compile_fail
/// use runtimeexec::LaunchPlan;
/// let plan = LaunchPlan::new(
///     (),
///     (),
///     |_: ()| std::future::ready(Ok(())),
///     None,
///     runtimeexec::LaunchLifecycleBatches::new(
///         runtimeexec::ProviderLifecycleBatch::from_provider_output(
///             bootstrap::DomainModuleResult::default(),
///         ),
///         runtimeexec::DomainLifecycleBatch::from_domain_output(
///             bootstrap::DomainModuleResult::default(),
///         ),
///         Some(bootstrap::ExpectedWorkerInventory::closed([])?),
///     ),
///     runtimeexec::TotalDrainBudget::new(std::time::Duration::from_secs(20))?,
/// );
/// let _second_owner = plan.clone();
/// # Ok::<(), anyhow::Error>(())
/// ```
#[must_use = "a launch plan owns lifecycle resources and must be executed"]
pub struct LaunchPlan<Adapter, ProbeReceipt, ReadyHook> {
    adapter: Adapter,
    probe_receipt: ProbeReceipt,
    on_ready: ReadyHook,
    trace_exporter: Option<Box<DynManagedResource<'static>>>,
    lifecycle_batches: LaunchLifecycle,
    platform_host: Option<RuntimeHostView>,
}

impl<Adapter, ProbeReceipt, ReadyHook> LaunchPlan<Adapter, ProbeReceipt, ReadyHook> {
    /// Seal the exact provider/domain lifecycle batches and mandatory assembly hooks.
    pub fn new(
        adapter: Adapter,
        probe_receipt: ProbeReceipt,
        on_ready: ReadyHook,
        trace_exporter: Option<Box<DynManagedResource<'static>>>,
        lifecycle_batches: LaunchLifecycleBatches,
        total_drain_budget: TotalDrainBudget,
    ) -> Self {
        Self {
            adapter,
            probe_receipt,
            on_ready,
            trace_exporter,
            lifecycle_batches: LaunchLifecycle {
                batches: lifecycle_batches,
                total_drain_budget,
            },
            platform_host: None,
        }
    }

    /// Attach the sole RuntimeExec-owned Platform host projection to this launch lifecycle.
    pub fn with_platform_host(mut self, host: RuntimeHostView) -> Self {
        self.platform_host = Some(host);
        self
    }
}

/// Launch material produced only after every startup phase completes successfully.
pub struct PreparedLaunch<Adapter, ProbeReceipt, ReadyHook> {
    adapter: Adapter,
    probe_receipt: ProbeReceipt,
    on_ready: ReadyHook,
    trace_exporter: Option<Box<DynManagedResource<'static>>>,
}

impl<Adapter, ProbeReceipt, ReadyHook> PreparedLaunch<Adapter, ProbeReceipt, ReadyHook> {
    /// Seal the successful startup output before listener preparation begins.
    pub fn new(
        adapter: Adapter,
        probe_receipt: ProbeReceipt,
        on_ready: ReadyHook,
        trace_exporter: Option<Box<DynManagedResource<'static>>>,
    ) -> Self {
        Self {
            adapter,
            probe_receipt,
            on_ready,
            trace_exporter,
        }
    }
}

/// Assembly-owned startup behavior driven under the executor's signal and drain owner.
pub trait StartupAdapter: Sized {
    /// Listener adapter produced after startup succeeds.
    type Adapter: LaunchAdapter<Self::ProbeReceipt>;
    /// Finalized probe receipt consumed by listener preparation.
    type ProbeReceipt;
    /// Async readiness hook run after listeners activate.
    type ReadyHook: FnOnce(
        <Self::Adapter as LaunchAdapter<Self::ProbeReceipt>>::Inventory,
    ) -> Self::Ready;
    /// Readiness future raced against the already-installed shutdown signal.
    type Ready: Future<Output = anyhow::Result<()>>;

    /// Run startup while staging every completed lifecycle output in `transaction`.
    fn prepare(
        self,
        transaction: &mut StartupTransaction<'_>,
    ) -> impl Future<
        Output = anyhow::Result<PreparedLaunch<Self::Adapter, Self::ProbeReceipt, Self::ReadyHook>>,
    > + Send;
}

/// Single-use startup state machine input with a mandatory bounded drain contract.
pub struct StartupPlan<Startup> {
    startup: Startup,
    total_drain_budget: TotalDrainBudget,
}

impl<Startup> StartupPlan<Startup> {
    /// Construct the sole startup-to-launch handoff.
    pub fn new(startup: Startup, total_drain_budget: TotalDrainBudget) -> Self {
        Self {
            startup,
            total_drain_budget,
        }
    }
}

/// Completion capability minted only after launch and shutdown both complete successfully.
///
/// ```compile_fail
/// use runtimeexec::RuntimeOutputs;
/// let _ = RuntimeOutputs { completed: () };
/// ```
#[must_use = "runtime completion must be observed by the assembly lifecycle owner"]
pub struct RuntimeOutputs {
    _completed: LaunchCompleted,
}

struct LaunchCompleted;

impl RuntimeOutputs {
    const fn completed() -> Self {
        Self {
            _completed: LaunchCompleted,
        }
    }
}

/// Run the production launch lifecycle until SIGTERM/SIGINT and then drain all resources.
///
/// Once polled into the executor, caller cancellation transfers cleanup to the originating Tokio
/// runtime; cancelling the waiter does not cancel the LIFO drain. A never-polled future has not
/// accepted lifecycle ownership and therefore cannot perform asynchronous cleanup.
pub async fn launch<Adapter, ProbeReceipt, ReadyHook, Ready>(
    plan: LaunchPlan<Adapter, ProbeReceipt, ReadyHook>,
) -> anyhow::Result<RuntimeOutputs>
where
    Adapter: LaunchAdapter<ProbeReceipt>,
    ReadyHook: FnOnce(Adapter::Inventory) -> Ready,
    Ready: Future<Output = anyhow::Result<()>>,
{
    launch_until(plan, install_shutdown_signal).await
}

/// Run assembly startup and listener launch under one signal owner and total drain deadline.
pub async fn launch_startup<Startup>(plan: StartupPlan<Startup>) -> anyhow::Result<RuntimeOutputs>
where
    Startup: StartupAdapter,
{
    launch_startup_until(plan, install_shutdown_signal).await
}

enum StartupRace<Prepared> {
    Shutdown(anyhow::Result<()>),
    Startup(anyhow::Result<Prepared>),
}

async fn launch_startup_until<Startup, InstallShutdown, Shutdown>(
    plan: StartupPlan<Startup>,
    install_shutdown: InstallShutdown,
) -> anyhow::Result<RuntimeOutputs>
where
    Startup: StartupAdapter,
    InstallShutdown: FnOnce() -> anyhow::Result<Shutdown>,
    Shutdown: Future<Output = anyhow::Result<()>>,
{
    let StartupPlan {
        startup,
        total_drain_budget,
    } = plan;
    let mut owner = ShutdownOwner::new(total_drain_budget, None);
    let shutdown = match install_shutdown() {
        Ok(shutdown) => shutdown,
        Err(error) => {
            let (runtime, stack) = owner.into_parts();
            return finish_launch(runtime, stack, total_drain_budget, Err(error), None).await;
        }
    };
    let mut shutdown = Box::pin(shutdown);
    let mut transaction = StartupTransaction::new(owner.stack_mut());
    let race = {
        // Signal sources are installed before the startup future is constructed or polled.
        let startup = startup.prepare(&mut transaction);
        tokio::pin!(startup);
        tokio::select! {
            biased;
            result = &mut shutdown => StartupRace::Shutdown(result),
            result = &mut startup => StartupRace::Startup(result),
        }
    };

    let launch_result = match race {
        StartupRace::Shutdown(signal_result) => {
            let batches = transaction.into_lifecycle_batches(true);
            let transfer = register_lifecycle_outputs(owner.stack_mut(), None, batches, false);
            preserve_startup_result(signal_result, transfer)
        }
        StartupRace::Startup(Err(startup_error)) => {
            let batches = transaction.into_lifecycle_batches(true);
            let transfer = register_lifecycle_outputs(owner.stack_mut(), None, batches, false);
            preserve_startup_result(Err(startup_error), transfer)
        }
        StartupRace::Startup(Ok(prepared)) => {
            let batches = transaction.into_lifecycle_batches(false);
            let PreparedLaunch {
                adapter,
                probe_receipt,
                on_ready,
                trace_exporter,
            } = prepared;
            execute_launch(
                owner.stack_mut(),
                adapter,
                probe_receipt,
                on_ready,
                trace_exporter,
                batches,
                || Ok(shutdown),
                None,
            )
            .await
        }
    };

    let (runtime, stack) = owner.into_parts();
    finish_launch(runtime, stack, total_drain_budget, launch_result, None).await
}

fn preserve_startup_result(
    primary: anyhow::Result<()>,
    transfer: anyhow::Result<()>,
) -> anyhow::Result<()> {
    match (primary, transfer) {
        (Ok(()), result) | (result @ Err(_), Ok(())) => result,
        (Err(primary), Err(transfer)) => {
            tracing::error!(
                cleanup_error = %secure::redact_error(transfer.as_ref()),
                "startup failed and lifecycle transfer also failed; preserving primary error"
            );
            Err(primary)
        }
    }
}

fn install_shutdown_signal() -> anyhow::Result<impl Future<Output = anyhow::Result<()>>> {
    // Tokio's signal constructor installs the handler synchronously. Keeping that constructor
    // outside the returned future closes both startup -> signal and ready -> signal races.
    let shutdown = wait_for_shutdown_signal()?;
    Ok(shutdown)
}

async fn launch_until<Adapter, ProbeReceipt, ReadyHook, Ready, InstallShutdown, Shutdown>(
    plan: LaunchPlan<Adapter, ProbeReceipt, ReadyHook>,
    install_shutdown: InstallShutdown,
) -> anyhow::Result<RuntimeOutputs>
where
    Adapter: LaunchAdapter<ProbeReceipt>,
    ReadyHook: FnOnce(Adapter::Inventory) -> Ready,
    Ready: Future<Output = anyhow::Result<()>>,
    InstallShutdown: FnOnce() -> anyhow::Result<Shutdown>,
    Shutdown: Future<Output = anyhow::Result<()>>,
{
    let LaunchPlan {
        adapter,
        probe_receipt,
        on_ready,
        trace_exporter,
        lifecycle_batches,
        platform_host,
    } = plan;
    let LaunchLifecycle {
        batches: lifecycle_batches,
        total_drain_budget,
    } = lifecycle_batches;
    let mut owner = ShutdownOwner::new(total_drain_budget, platform_host.clone());
    let launch_result = execute_launch(
        owner.stack_mut(),
        adapter,
        probe_receipt,
        on_ready,
        trace_exporter,
        lifecycle_batches,
        install_shutdown,
        platform_host.as_ref(),
    )
    .await;

    let (runtime, stack) = owner.into_parts();
    finish_launch(
        runtime,
        stack,
        total_drain_budget,
        launch_result,
        platform_host,
    )
    .await
}

/// Cancellation-safe owner for the execute phase.
///
/// Rust has no async Drop. If the caller drops the launch future while an execute-stage await is
/// pending, this guard transfers the whole stack to the originating runtime instead of
/// synchronously dropping registered resources. Normal completion disarms the guard by taking the
/// stack before entering [`finish_launch`].
struct ShutdownOwner {
    runtime: Handle,
    stack: Option<ShutdownStack>,
    total_drain_budget: TotalDrainBudget,
    platform_host: Option<RuntimeHostView>,
}

impl ShutdownOwner {
    fn new(total_drain_budget: TotalDrainBudget, platform_host: Option<RuntimeHostView>) -> Self {
        Self {
            runtime: Handle::current(),
            stack: Some(ShutdownStack::new(CancellationToken::new())),
            total_drain_budget,
            platform_host,
        }
    }

    fn stack_mut(&mut self) -> &mut ShutdownStack {
        self.stack
            .as_mut()
            .unwrap_or_else(|| unreachable!("shutdown stack is taken exactly once"))
    }

    fn into_parts(mut self) -> (Handle, ShutdownStack) {
        let stack = self
            .stack
            .take()
            .unwrap_or_else(|| unreachable!("shutdown stack is taken exactly once"));
        (self.runtime.clone(), stack)
    }
}

impl Drop for ShutdownOwner {
    fn drop(&mut self) {
        let Some(stack) = self.stack.take() else {
            return;
        };
        tracing::warn!("launch future dropped; continuing runtime resource drain in background");
        let _drain = spawn_drain(
            &self.runtime,
            stack,
            self.total_drain_budget,
            self.platform_host.clone(),
        );
    }
}

async fn finish_launch(
    runtime: Handle,
    stack: ShutdownStack,
    total_drain_budget: TotalDrainBudget,
    launch_result: anyhow::Result<()>,
    platform_host: Option<RuntimeHostView>,
) -> anyhow::Result<RuntimeOutputs> {
    log_drain_start(&launch_result);
    // The drain task owns the stack before this function reaches its first await. Dropping the
    // outer launch future therefore detaches only this JoinHandle; Tokio keeps the drain task
    // running to complete the full LIFO sequence.
    let drain = spawn_drain(&runtime, stack, total_drain_budget, platform_host.clone());
    let drain_result = match drain.await {
        Ok(result) => result,
        Err(error) => Err(anyhow::anyhow!(
            "runtime shutdown driver task failed: {}",
            secure::redact_error(&error)
        )),
    };
    preserve_launch_error(launch_result, drain_result)
}

fn spawn_drain(
    runtime: &Handle,
    stack: ShutdownStack,
    total_drain_budget: TotalDrainBudget,
    platform_host: Option<RuntimeHostView>,
) -> JoinHandle<anyhow::Result<()>> {
    runtime.spawn(async move {
        let result =
            report_shutdown_failures(stack.shutdown_within(total_drain_budget.duration()).await);
        if let Some(host) = platform_host {
            host.mark_stopped();
        }
        result
    })
}

// reason: the two closed log outcomes intentionally preserve the existing success/failure wording;
// tracing's macro expansion alone exceeds the cognitive-complexity threshold.
#[allow(clippy::cognitive_complexity)]
fn log_drain_start(launch_result: &anyhow::Result<()>) {
    if launch_result.is_ok() {
        tracing::info!("draining listeners (graceful)");
    } else {
        tracing::warn!("launch lifecycle failed; draining registered resources");
    }
}

// reason: this private boundary consumes the complete sealed launch plan without introducing a
// generic service-bag type or a second lifecycle owner.
#[allow(clippy::too_many_arguments)]
async fn execute_launch<Adapter, ProbeReceipt, ReadyHook, Ready, InstallShutdown, Shutdown>(
    stack: &mut ShutdownStack,
    adapter: Adapter,
    probe_receipt: ProbeReceipt,
    on_ready: ReadyHook,
    trace_exporter: Option<Box<DynManagedResource<'static>>>,
    lifecycle_batches: LaunchLifecycleBatches,
    install_shutdown: InstallShutdown,
    platform_host: Option<&RuntimeHostView>,
) -> anyhow::Result<()>
where
    Adapter: LaunchAdapter<ProbeReceipt>,
    ReadyHook: FnOnce(Adapter::Inventory) -> Ready,
    Ready: Future<Output = anyhow::Result<()>>,
    InstallShutdown: FnOnce() -> anyhow::Result<Shutdown>,
    Shutdown: Future<Output = anyhow::Result<()>>,
{
    register_lifecycle_outputs(stack, trace_exporter, lifecycle_batches, true)?;
    // The complete provider/domain lifecycle is accepted by the cancellation-safe owner before a
    // platform signal constructor can fail. Installation still precedes listener preparation and
    // readiness publication, so no ready -> signal race is reintroduced.
    let shutdown = install_shutdown()?;
    let mut transaction = LaunchTransaction { stack };
    let prepared = adapter.prepare(probe_receipt, &mut transaction).await?;
    let activated = Adapter::activate(prepared, transaction.commit())?;
    if let Some(host) = platform_host {
        // Listener activation has finished registering resources. Push admission last so LIFO
        // closes it first and waits for admitted handlers before any listener/provider drain.
        register_platform_admission(stack, host);
    }
    let readiness = on_ready(activated.into_inventory());
    tokio::pin!(readiness);
    tokio::pin!(shutdown);
    tokio::select! {
        biased;
        result = &mut shutdown => return result,
        result = &mut readiness => {
            result?;
            if let Some(host) = platform_host { host.mark_ready(); }
        },
    }
    shutdown.await
}

fn register_platform_admission(stack: &mut ShutdownStack, host: &RuntimeHostView) {
    stack.register_detached(host.managed_resource());
}

fn register_lifecycle_outputs(
    stack: &mut ShutdownStack,
    trace_exporter: Option<Box<DynManagedResource<'static>>>,
    lifecycle_batches: LaunchLifecycleBatches,
    require_exact_inventory: bool,
) -> anyhow::Result<()> {
    // Register trace first so LIFO drains it last, after all shutdown-period spans stop.
    if let Some(exporter) = trace_exporter {
        stack.register_detached(exporter);
    }
    let LaunchLifecycleBatches {
        mut provider,
        mut domain,
        expected_workers,
    } = lifecycle_batches;
    let workers = || provider.0.workers().chain(domain.0.workers());
    let validation: anyhow::Result<bootstrap::WorkerInventory> = match expected_workers.as_ref() {
        Some(expected) => bootstrap::validate_worker_inventory_exact(workers(), expected)
            .map_err(anyhow::Error::from),
        None if require_exact_inventory => Err(anyhow::anyhow!(
            "successful launch requires a plan-derived exact mutating-worker inventory"
        )),
        None => {
            let inventory = bootstrap::validate_worker_inventory(workers()).map_err(Into::into);
            discard_module_workers(&mut provider.0);
            discard_module_workers(&mut domain.0);
            inventory
        }
    };
    let inventory = match validation {
        Ok(inventory) => inventory,
        Err(error) => {
            register_module_resources(stack, &mut provider.0);
            register_module_resources(stack, &mut domain.0);
            return Err(error);
        }
    };
    tracing::info!(
        worker_count = inventory.descriptors.len(),
        worker_inventory_digest = format_args!("{:016x}", inventory.digest),
        "validated exact lifecycle worker inventory before spawn"
    );
    let provider = partition_module_output(provider.0);
    let domain = partition_module_output(domain.0);
    if provider.has_probes || domain.has_probes {
        register_partitioned_resources(stack, provider.resources);
        register_partitioned_resources(stack, domain.resources);
        anyhow::bail!("launch lifecycle output still contains undrained probes");
    }
    register_partitioned_module(stack, provider);
    register_partitioned_module(stack, domain);
    Ok(())
}

fn register_module_resources(stack: &mut ShutdownStack, output: &mut DomainModuleResult) {
    for output in output.drain_outputs() {
        match output {
            bootstrap::DomainLifecycleOutput::Probe(_, _) => {}
            bootstrap::DomainLifecycleOutput::Resource(resource) => {
                stack.register_detached(resource);
            }
            bootstrap::DomainLifecycleOutput::Worker(_) => {}
        }
    }
}

fn discard_module_probes(output: &mut DomainModuleResult) {
    let mut retained = DomainModuleResult::default();
    for output in output.drain_outputs() {
        match output {
            bootstrap::DomainLifecycleOutput::Probe(_, _) => {}
            bootstrap::DomainLifecycleOutput::Resource(resource) => {
                retained.push_resource(resource);
            }
            bootstrap::DomainLifecycleOutput::Worker(worker) => retained.push_worker(worker),
        }
    }
    *output = retained;
}

fn discard_module_workers(output: &mut DomainModuleResult) {
    let mut retained = DomainModuleResult::default();
    for output in output.drain_outputs() {
        match output {
            bootstrap::DomainLifecycleOutput::Probe(name, probe) => {
                retained.push_probe((name, probe));
            }
            bootstrap::DomainLifecycleOutput::Resource(resource) => {
                retained.push_resource(resource);
            }
            bootstrap::DomainLifecycleOutput::Worker(_) => {}
        }
    }
    *output = retained;
}

struct PartitionedModuleOutput {
    has_probes: bool,
    resources: Vec<Box<DynManagedResource<'static>>>,
    workers: Vec<WorkerSpec>,
}

fn partition_module_output(output: DomainModuleResult) -> PartitionedModuleOutput {
    let mut has_probes = false;
    let mut resources = Vec::new();
    let mut workers = Vec::new();
    for output in output.into_outputs() {
        match output {
            bootstrap::DomainLifecycleOutput::Probe(_, _) => has_probes = true,
            bootstrap::DomainLifecycleOutput::Resource(resource) => resources.push(resource),
            bootstrap::DomainLifecycleOutput::Worker(worker) => workers.push(worker),
        }
    }
    PartitionedModuleOutput {
        has_probes,
        resources,
        workers,
    }
}

fn register_partitioned_resources(
    stack: &mut ShutdownStack,
    resources: Vec<Box<DynManagedResource<'static>>>,
) {
    for resource in resources {
        stack.register_detached(resource);
    }
}

fn register_partitioned_module(stack: &mut ShutdownStack, output: PartitionedModuleOutput) {
    register_partitioned_resources(stack, output.resources);
    for worker in output.workers {
        match worker {
            WorkerSpec::PhaseOne(worker) => stack.register_with_token(worker.into_factory()),
            WorkerSpec::Deferred(worker) => {
                stack.register_deferred_with_token(worker.into_factory());
            }
        }
    }
}

fn report_shutdown_failures(
    failures: Vec<bootstrap::shutdown::ResourceShutdownError>,
) -> anyhow::Result<()> {
    if failures.is_empty() {
        tracing::info!("all runtime resources drained; exiting");
        return Ok(());
    }
    for failure in &failures {
        tracing::error!(
            error = %secure::redact_error(failure),
            "runtime resource shutdown failure"
        );
    }
    anyhow::bail!(
        "graceful shutdown completed with {} runtime resource failure(s)",
        failures.len()
    )
}

fn preserve_launch_error(
    launch_result: anyhow::Result<()>,
    drain_result: anyhow::Result<()>,
) -> anyhow::Result<RuntimeOutputs> {
    match (launch_result, drain_result) {
        (Ok(()), Ok(())) => Ok(RuntimeOutputs::completed()),
        (Ok(()), Err(drain_error)) => Err(drain_error),
        (Err(launch_error), Ok(())) => Err(launch_error),
        (Err(launch_error), Err(drain_error)) => {
            tracing::error!(
                cleanup_error = %secure::redact_error(drain_error.as_ref()),
                "launch failed and cleanup also failed; preserving primary launch error"
            );
            Err(launch_error)
        }
    }
}

#[cfg(unix)]
// reason: the platform boundary must install both closed Unix signal streams and select the first
// one without moving signal ownership or shutdown policy into an assembly.
#[allow(clippy::cognitive_complexity)]
fn wait_for_shutdown_signal() -> anyhow::Result<impl Future<Output = anyhow::Result<()>>> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
    let mut int = signal(SignalKind::interrupt()).context("install SIGINT handler")?;
    Ok(async move {
        tokio::select! {
            _ = term.recv() => tracing::info!(signal = "SIGTERM", "shutdown signal received"),
            _ = int.recv() => tracing::info!(signal = "SIGINT", "shutdown signal received"),
        }
        Ok(())
    })
}

#[cfg(windows)]
fn wait_for_shutdown_signal() -> anyhow::Result<impl Future<Output = anyhow::Result<()>>> {
    use tokio::signal::windows::{ctrl_break, ctrl_c};
    let mut ctrl_c = ctrl_c().context("install ctrl-c handler")?;
    let mut ctrl_break = ctrl_break().context("install ctrl-break handler")?;
    Ok(async move {
        tokio::select! {
            _ = ctrl_c.recv() => tracing::info!(signal = "ctrl-c", "shutdown signal received"),
            _ = ctrl_break.recv() => tracing::info!(signal = "ctrl-break", "shutdown signal received"),
        }
        Ok(())
    })
}

#[cfg(not(any(unix, windows)))]
fn wait_for_shutdown_signal() -> anyhow::Result<impl Future<Output = anyhow::Result<()>>> {
    Ok(async {
        tokio::signal::ctrl_c()
            .await
            .context("install ctrl-c handler")?;
        tracing::info!(signal = "ctrl-c", "shutdown signal received");
        Ok(())
    })
}

#[cfg(test)]
mod tests;
