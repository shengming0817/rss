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

use std::future::Future;

use anyhow::Context as _;
use bootstrap::DomainModuleResult;
use bootstrap::shutdown::ShutdownStack;
use diport::DynManagedResource;
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

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
}

impl LaunchLifecycleBatches {
    /// Preserve provider-before-domain registration order with non-interchangeable role types.
    pub fn new(provider: ProviderLifecycleBatch, domain: DomainLifecycleBatch) -> Self {
        Self { provider, domain }
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
///     |_: ()| Ok(()),
///     None,
///     runtimeexec::LaunchLifecycleBatches::new(
///         runtimeexec::ProviderLifecycleBatch::from_provider_output(
///             bootstrap::DomainModuleResult::default(),
///         ),
///         runtimeexec::DomainLifecycleBatch::from_domain_output(
///             bootstrap::DomainModuleResult::default(),
///         ),
///     ),
/// );
/// let _second_owner = plan.clone();
/// ```
#[must_use = "a launch plan owns lifecycle resources and must be executed"]
pub struct LaunchPlan<Adapter, ProbeReceipt, ReadyHook> {
    adapter: Adapter,
    probe_receipt: ProbeReceipt,
    on_ready: ReadyHook,
    trace_exporter: Option<Box<DynManagedResource<'static>>>,
    lifecycle_batches: LaunchLifecycleBatches,
}

impl<Adapter, ProbeReceipt, ReadyHook> LaunchPlan<Adapter, ProbeReceipt, ReadyHook> {
    /// Seal the exact provider/domain lifecycle batches and mandatory assembly hooks.
    pub fn new(
        adapter: Adapter,
        probe_receipt: ProbeReceipt,
        on_ready: ReadyHook,
        trace_exporter: Option<Box<DynManagedResource<'static>>>,
        lifecycle_batches: LaunchLifecycleBatches,
    ) -> Self {
        Self {
            adapter,
            probe_receipt,
            on_ready,
            trace_exporter,
            lifecycle_batches,
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
pub async fn launch<Adapter, ProbeReceipt, ReadyHook>(
    plan: LaunchPlan<Adapter, ProbeReceipt, ReadyHook>,
) -> anyhow::Result<RuntimeOutputs>
where
    Adapter: LaunchAdapter<ProbeReceipt>,
    ReadyHook: FnOnce(Adapter::Inventory) -> anyhow::Result<()>,
{
    launch_until(plan, wait_for_shutdown_signal()).await
}

async fn launch_until<Adapter, ProbeReceipt, ReadyHook, Shutdown>(
    plan: LaunchPlan<Adapter, ProbeReceipt, ReadyHook>,
    shutdown: Shutdown,
) -> anyhow::Result<RuntimeOutputs>
where
    Adapter: LaunchAdapter<ProbeReceipt>,
    ReadyHook: FnOnce(Adapter::Inventory) -> anyhow::Result<()>,
    Shutdown: Future<Output = anyhow::Result<()>>,
{
    let LaunchPlan {
        adapter,
        probe_receipt,
        on_ready,
        trace_exporter,
        lifecycle_batches,
    } = plan;
    let mut owner = ShutdownOwner::new();
    let launch_result = execute_launch(
        owner.stack_mut(),
        adapter,
        probe_receipt,
        on_ready,
        trace_exporter,
        lifecycle_batches,
        shutdown,
    )
    .await;

    let (runtime, stack) = owner.into_parts();
    finish_launch(runtime, stack, launch_result).await
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
}

impl ShutdownOwner {
    fn new() -> Self {
        Self {
            runtime: Handle::current(),
            stack: Some(ShutdownStack::new(CancellationToken::new())),
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
        let _drain = spawn_drain(&self.runtime, stack);
    }
}

async fn finish_launch(
    runtime: Handle,
    stack: ShutdownStack,
    launch_result: anyhow::Result<()>,
) -> anyhow::Result<RuntimeOutputs> {
    log_drain_start(&launch_result);
    // The drain task owns the stack before this function reaches its first await. Dropping the
    // outer launch future therefore detaches only this JoinHandle; Tokio keeps the drain task
    // running to complete the full LIFO sequence.
    let drain = spawn_drain(&runtime, stack);
    let drain_result = match drain.await {
        Ok(result) => result,
        Err(error) => Err(anyhow::anyhow!(
            "runtime shutdown driver task failed: {}",
            secure::redact_error(&error)
        )),
    };
    preserve_launch_error(launch_result, drain_result)
}

fn spawn_drain(runtime: &Handle, stack: ShutdownStack) -> JoinHandle<anyhow::Result<()>> {
    runtime.spawn(async move { report_shutdown_failures(stack.shutdown().await) })
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
async fn execute_launch<Adapter, ProbeReceipt, ReadyHook, Shutdown>(
    stack: &mut ShutdownStack,
    adapter: Adapter,
    probe_receipt: ProbeReceipt,
    on_ready: ReadyHook,
    trace_exporter: Option<Box<DynManagedResource<'static>>>,
    lifecycle_batches: LaunchLifecycleBatches,
    shutdown: Shutdown,
) -> anyhow::Result<()>
where
    Adapter: LaunchAdapter<ProbeReceipt>,
    ReadyHook: FnOnce(Adapter::Inventory) -> anyhow::Result<()>,
    Shutdown: Future<Output = anyhow::Result<()>>,
{
    register_lifecycle_outputs(stack, trace_exporter, lifecycle_batches)?;
    let mut transaction = LaunchTransaction { stack };
    let prepared = adapter.prepare(probe_receipt, &mut transaction).await?;
    let activated = Adapter::activate(prepared, transaction.commit())?;
    on_ready(activated.into_inventory())?;
    shutdown.await
}

fn register_lifecycle_outputs(
    stack: &mut ShutdownStack,
    trace_exporter: Option<Box<DynManagedResource<'static>>>,
    lifecycle_batches: LaunchLifecycleBatches,
) -> anyhow::Result<()> {
    // Register trace first so LIFO drains it last, after all shutdown-period spans stop.
    if let Some(exporter) = trace_exporter {
        stack.register_detached(exporter);
    }
    let LaunchLifecycleBatches { provider, domain } = lifecycle_batches;
    let provider_result = register_module_output(stack, provider.0);
    let domain_result = register_module_output(stack, domain.0);

    // Both owned batches must cross into the async shutdown stack before either validation error is
    // propagated; otherwise the later batch would be synchronously dropped.
    provider_result?;
    domain_result
}

fn register_module_output(
    stack: &mut ShutdownStack,
    output: DomainModuleResult,
) -> anyhow::Result<()> {
    let DomainModuleResult {
        probes,
        resources,
        workers,
    } = output;
    for resource in resources {
        stack.register_detached(resource);
    }
    for worker in workers {
        stack.register_with_token(worker);
    }
    anyhow::ensure!(
        probes.is_empty(),
        "launch lifecycle output still contains undrained probes"
    );
    Ok(())
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

async fn wait_for_shutdown_signal() -> anyhow::Result<()> {
    wait_for_platform_shutdown_signal().await
}

#[cfg(unix)]
// reason: the platform boundary must install both closed Unix signal streams and select the first
// one without moving signal ownership or shutdown policy into an assembly.
#[allow(clippy::cognitive_complexity)]
async fn wait_for_platform_shutdown_signal() -> anyhow::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
    let mut int = signal(SignalKind::interrupt()).context("install SIGINT handler")?;
    tokio::select! {
        _ = term.recv() => tracing::info!(signal = "SIGTERM", "shutdown signal received"),
        _ = int.recv() => tracing::info!(signal = "SIGINT", "shutdown signal received"),
    }
    Ok(())
}

#[cfg(not(unix))]
async fn wait_for_platform_shutdown_signal() -> anyhow::Result<()> {
    tokio::signal::ctrl_c()
        .await
        .context("install ctrl-c handler")?;
    tracing::info!(signal = "ctrl-c", "shutdown signal received");
    Ok(())
}

#[cfg(test)]
mod tests;
