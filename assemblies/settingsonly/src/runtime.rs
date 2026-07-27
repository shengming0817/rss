//! Single private handoff from a prepared settings assembly to runtimeexec.

use std::future::Future;
#[cfg(feature = "test-support")]
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use diport::{DynManagedResource, ManagedResource, ShutdownError};

use crate::listeners;

const TOTAL_DRAIN_BUDGET: Duration =
    Duration::from_secs(crate::deployment_facts::TOTAL_DRAIN_SECONDS);
const DEPLOYMENT_GRACE_PERIOD: Duration = Duration::from_secs(30);
const EXIT_BUFFER: Duration = Duration::from_secs(5);
const READINESS_POLL_INTERVAL: Duration = Duration::from_millis(100);

pub(crate) fn total_drain_budget() -> anyhow::Result<runtimeexec::TotalDrainBudget> {
    runtimeexec::TotalDrainBudget::new(TOTAL_DRAIN_BUDGET, DEPLOYMENT_GRACE_PERIOD, EXIT_BUFFER)
}

pub(crate) type ReadyFuture = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>;
pub(crate) type ReadyHook = Box<dyn FnOnce(listeners::ListenerInventory) -> ReadyFuture + Send>;

pub(crate) struct ProductionStartup {
    captured: crate::config::CapturedConfig,
}

impl ProductionStartup {
    pub(crate) fn new(captured: crate::config::CapturedConfig) -> Self {
        Self { captured }
    }
}

impl runtimeexec::StartupAdapter for ProductionStartup {
    type Adapter = listeners::LaunchAdapter;
    type ProbeReceipt = listeners::FinalizedProbeReceipt;
    type ReadyHook = crate::runtime::ReadyHook;
    type Ready = crate::runtime::ReadyFuture;

    async fn prepare(
        self,
        transaction: &mut runtimeexec::StartupTransaction<'_>,
    ) -> anyhow::Result<
        runtimeexec::PreparedLaunch<Self::Adapter, Self::ProbeReceipt, Self::ReadyHook>,
    > {
        let compiled_plan = crate::plan::SettingsOnlyPlan::bundled()?;
        let (config, secrets, build_identity, frontend) = self.captured.into_runtime_inputs();
        let completed = crate::providers::build(
            compiled_plan.provider_build()?,
            config,
            secrets,
            transaction,
        )
        .await?;
        let (providers, listeners_config, support_probe, provider_bindings) =
            completed.into_parts();
        let inventory_seed =
            compiled_plan.into_inventory_seed(build_identity, provider_bindings)?;
        let (support_name, support_probe) = support_probe.into_parts();
        transaction
            .provider_output_mut()
            .probes
            .push((support_name, support_probe));
        let deps = crate::SharedRuntimeDeps::production(
            providers.pg,
            providers.vault,
            providers.settings_key,
            providers.vault_readiness,
        );
        let bindings = crate::wire_domains(&deps).await?;
        let (primary, admin, health, request_budget) = listeners_config.into_listener_inputs();
        prepare_assembly(
            AssemblyStartupInputs::new(
                bindings,
                providers.verifier,
                providers.audit_sink,
                providers.limiter,
                providers.metrics,
                primary,
                admin,
                health,
                request_budget,
                inventory_seed,
                ReadyAction::Log,
            )
            .with_frontend(frontend),
            transaction,
        )
        .await
    }
}

pub(crate) struct AssemblyStartupInputs {
    bindings: Vec<bootstrap::DomainBinding>,
    verifier: crate::auth_bridge::FederatedVerifier,
    audit_sink: httpserve::AuditSinkHandle,
    limiter: Arc<ratelimit::GovernorLimiter>,
    metrics: Arc<dyn diport::MetricsExporter>,
    primary: std::net::SocketAddr,
    admin: std::net::SocketAddr,
    health: std::net::SocketAddr,
    request_budget: Duration,
    ready: ReadyAction,
    inventory_seed: runtimeexec::inventory::RuntimeInventorySeed,
    frontend: Option<crate::config::ServingFrontendConfig>,
    #[cfg(feature = "test-support")]
    activation_gate: Option<SocketAddr>,
}

impl AssemblyStartupInputs {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        bindings: Vec<bootstrap::DomainBinding>,
        verifier: crate::auth_bridge::FederatedVerifier,
        audit_sink: httpserve::AuditSinkHandle,
        limiter: Arc<ratelimit::GovernorLimiter>,
        metrics: Arc<dyn diport::MetricsExporter>,
        primary: std::net::SocketAddr,
        admin: std::net::SocketAddr,
        health: std::net::SocketAddr,
        request_budget: Duration,
        inventory_seed: runtimeexec::inventory::RuntimeInventorySeed,
        ready: ReadyAction,
    ) -> Self {
        Self {
            bindings,
            verifier,
            audit_sink,
            limiter,
            metrics,
            primary,
            admin,
            health,
            request_budget,
            ready,
            inventory_seed,
            frontend: None,
            #[cfg(feature = "test-support")]
            activation_gate: None,
        }
    }

    fn with_frontend(mut self, frontend: crate::config::ServingFrontendConfig) -> Self {
        self.frontend = Some(frontend);
        self
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn with_activation_gate(mut self, address: SocketAddr) -> Self {
        self.activation_gate = Some(address);
        self
    }
}

pub(crate) async fn prepare_assembly(
    mut inputs: AssemblyStartupInputs,
    transaction: &mut runtimeexec::StartupTransaction<'_>,
) -> anyhow::Result<
    runtimeexec::PreparedLaunch<
        listeners::LaunchAdapter,
        listeners::FinalizedProbeReceipt,
        ReadyHook,
    >,
> {
    let (mut registry, domain_output) = match bootstrap::compose_bindings(&mut inputs.bindings) {
        Ok(composed) => composed,
        Err(error) => {
            transaction.stage_domain_output(bootstrap::drain_binding_outputs(&mut inputs.bindings));
            return Err(error.into());
        }
    };
    transaction.stage_domain_output(domain_output);
    crate::validate_nonactivated_settings_subscriber(&mut registry)?;
    let (provider_output, domain_output) = transaction.outputs_mut();
    register_probes(&mut registry, provider_output)?;
    register_probes(&mut registry, domain_output)?;
    let reporter = Arc::new(registry.take_health_reporter());
    let (inventory_publisher, inventory_reader) =
        runtimeexec::inventory::inventory_channel(inputs.inventory_seed, Arc::clone(&reporter));
    let framework_routes = crate::inventory::InventoryFrameworkRoutes::new(inventory_reader);
    let (finalized, receipt) = listeners::finalize(
        &mut registry,
        inputs.verifier,
        inputs.limiter,
        inputs.metrics,
        inputs.audit_sink,
        reporter,
        &framework_routes,
    )?;
    let adapter = listeners::LaunchAdapter::new(
        finalized,
        inputs.primary,
        inputs.admin,
        inputs.health,
        inputs.request_budget,
        inventory_publisher,
        inputs.frontend,
    )?;
    #[cfg(feature = "test-support")]
    let adapter = match inputs.activation_gate {
        Some(address) => adapter.with_activation_gate(address),
        None => adapter,
    };
    let readiness = receipt.readiness();
    let ready: ReadyHook =
        Box::new(move |inventory| Box::pin(inputs.ready.publish(inventory, readiness)));
    Ok(runtimeexec::PreparedLaunch::new(
        adapter, receipt, ready, None,
    ))
}

pub(crate) async fn launch<Startup>(startup: Startup) -> anyhow::Result<()>
where
    Startup: runtimeexec::StartupAdapter,
{
    let plan = runtimeexec::StartupPlan::new(startup, total_drain_budget()?);
    let _completed = runtimeexec::launch_startup(plan).await?;
    Ok(())
}

pub(crate) async fn launch_captured(captured: crate::config::CapturedConfig) -> anyhow::Result<()> {
    launch(ProductionStartup::new(captured)).await
}

pub(crate) struct SharedManagedResource<T> {
    inner: Arc<T>,
    name: &'static str,
}

impl<T> SharedManagedResource<T> {
    pub(crate) fn new(inner: Arc<T>, name: &'static str) -> Self {
        Self { inner, name }
    }

    pub(crate) fn boxed(inner: Arc<T>, name: &'static str) -> Box<DynManagedResource<'static>>
    where
        T: ManagedResource + Sync + 'static,
    {
        DynManagedResource::new_box(Self::new(inner, name))
    }
}

impl<T> ManagedResource for SharedManagedResource<T>
where
    T: ManagedResource + Sync,
{
    fn name(&self) -> &str {
        self.name
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.inner.shutdown().await
    }
}

pub(crate) fn register_probes(
    registry: &mut bootstrap::Registry,
    output: &mut bootstrap::DomainModuleResult,
) -> anyhow::Result<()> {
    for (name, probe) in output.probes.drain(..) {
        registry
            .probe(name, probe)
            .context("register settingsonly lifecycle probe")?;
    }
    Ok(())
}

pub(crate) enum ReadyAction {
    Log,
    #[cfg(feature = "test-support")]
    Notify(SocketAddr),
}

impl ReadyAction {
    async fn publish(
        self,
        inventory: listeners::ListenerInventory,
        reporter: Arc<bootstrap::HealthReporter>,
    ) -> anyhow::Result<()> {
        log_listeners_activated(&inventory);
        wait_until_healthy(&reporter).await;
        log_assembly_ready(&inventory);
        #[cfg(feature = "test-support")]
        self.notify()?;
        #[cfg(not(feature = "test-support"))]
        let Self::Log = self;
        Ok(())
    }

    #[cfg(feature = "test-support")]
    fn notify(self) -> anyhow::Result<()> {
        if let Self::Notify(address) = self {
            let _socket = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(2))
                .context("notify settingsonly readiness")?;
        }
        Ok(())
    }
}

fn log_listeners_activated(inventory: &listeners::ListenerInventory) {
    tracing::info!(
        primary = %inventory.primary,
        admin = %inventory.admin,
        health = %inventory.health,
        state = "listeners_activated",
        "settingsonly listeners activated"
    );
}

fn log_assembly_ready(inventory: &listeners::ListenerInventory) {
    tracing::info!(
        primary = %inventory.primary,
        admin = %inventory.admin,
        health = %inventory.health,
        state = "ready",
        "settingsonly assembly ready"
    );
}

async fn wait_until_healthy(reporter: &bootstrap::HealthReporter) {
    while reporter.report().overall() != primitives::HealthStatus::Healthy {
        tokio::time::sleep(READINESS_POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    struct ToggleProbe {
        name: primitives::ProbeName,
        ready: Arc<AtomicBool>,
    }

    impl bootstrap::HealthProbe for ToggleProbe {
        fn check(&self) -> primitives::HealthCheck {
            let status = if self.ready.load(Ordering::SeqCst) {
                primitives::HealthStatus::Healthy
            } else {
                primitives::HealthStatus::Unhealthy
            };
            primitives::HealthCheck::new(self.name.clone(), status, "test readiness")
        }
    }

    #[tokio::test]
    async fn ready_action_waits_for_first_healthy_aggregate() {
        let healthy = Arc::new(AtomicBool::new(false));
        let probe_name =
            primitives::ProbeName::parse("toggle-ready").expect("valid readiness probe name");
        let mut registry = bootstrap::Registry::new();
        registry
            .probe(
                probe_name.clone(),
                Box::new(ToggleProbe {
                    name: probe_name,
                    ready: Arc::clone(&healthy),
                }),
            )
            .expect("register readiness probe");
        let reporter = Arc::new(registry.take_health_reporter());
        let inventory = listeners::ListenerInventory {
            primary: "127.0.0.1:1".parse().expect("primary address"),
            admin: "127.0.0.1:3".parse().expect("admin address"),
            health: "127.0.0.1:2".parse().expect("health address"),
        };
        let mut ready = tokio::spawn(ReadyAction::Log.publish(inventory, reporter));

        assert!(
            tokio::time::timeout(Duration::from_millis(30), &mut ready)
                .await
                .is_err(),
            "listener activation must not claim aggregate readiness"
        );
        healthy.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_millis(500), ready)
            .await
            .expect("healthy aggregate must complete readiness publication")
            .expect("readiness task must not panic")
            .expect("readiness publication must succeed");
    }
}
