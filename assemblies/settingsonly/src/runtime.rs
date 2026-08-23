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

const TOTAL_DRAIN_BUDGET: Duration = Duration::from_secs(60);
const READINESS_POLL_INTERVAL: Duration = Duration::from_millis(100);

pub(crate) fn total_drain_budget() -> anyhow::Result<runtimeexec::TotalDrainBudget> {
    runtimeexec::TotalDrainBudget::new(TOTAL_DRAIN_BUDGET)
}

pub(crate) const fn total_drain_duration() -> Duration {
    TOTAL_DRAIN_BUDGET
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
    type ProbeReceipt = Arc<bootstrap::HealthReporter>;
    type ReadyHook = crate::runtime::ReadyHook;
    type Ready = crate::runtime::ReadyFuture;

    async fn prepare(
        self,
        transaction: &mut runtimeexec::StartupTransaction<'_>,
    ) -> anyhow::Result<
        runtimeexec::PreparedLaunch<Self::Adapter, Self::ProbeReceipt, Self::ReadyHook>,
    > {
        let compiled_plan = crate::plan::SettingsOnlyPlan::bundled()?;
        transaction.expect_workers(compiled_plan.expected_workers()?)?;
        let (config, secrets, build_metadata, frontend) = self.captured.into_runtime_inputs();
        let completed = crate::providers::build(
            compiled_plan.provider_build()?,
            compiled_plan.projection_capture(),
            config,
            secrets,
            frontend.rate_limit_quota,
            transaction,
        )
        .await?;
        let (providers, listeners_config) = completed.into_parts();
        anyhow::ensure!(
            compiled_plan.projection_is_active(),
            "bundled SettingsOnly plan must activate Settings v3"
        );
        let projection_runner = eventexec::ProjectionRunnerConfig::new(
            1_u32
                .try_into()
                .context("bind Settings projection batch size 1")?,
            std::time::Duration::from_secs(1),
            eventexec::ProjectionPoisonPolicy::Isolate,
        )
        .context("bind Settings projection runner policy")?;
        let projection_worker = postgres::PgProjectionWorkerDeps::connect(
            &providers.projection_worker_config,
            providers.eventing.projection_payload_protector(),
            Arc::new(crate::SystemClock),
        )
        .await
        .context("connect settings active projection worker capability")?;
        let projection_serving = settings_composition::settings_projection_query_service(
            &providers.pg.for_domain::<postgres::caps::Settings>(),
        );
        let mut compiled_plan = compiled_plan.bind_projection(
            move |binding| {
                projection_worker.into_settings_worker_runtime(
                    binding,
                    projection_runner,
                    Arc::new(eventexec::MetricsProjectionMetrics),
                )
            },
            projection_serving,
        )?;
        let lifecycle = crate::projection::ProjectionLifecycleBatch::from_runtime_plan(
            compiled_plan.workflow_runtime(),
            &providers.eventing.write_admission(),
        )?;
        transaction.stage_domain_output(lifecycle.into_output());
        #[allow(clippy::disallowed_methods)]
        // reason: assembly-root boot identity is captured before event workers are constructed.
        let instance_id = uuid::Uuid::parse_str(
            &std::env::var("RSS_RUNTIME_INSTANCE_ID")
                .context("RSS_RUNTIME_INSTANCE_ID is required")?,
        )
        .context("RSS_RUNTIME_INSTANCE_ID must be a UUID")?;
        #[allow(clippy::disallowed_methods)]
        // reason: assembly-root optional post-restore startup fence.
        let required_admission_epoch = std::env::var("RSS_DR_REQUIRED_ADMISSION_EPOCH_ID")
            .ok()
            .map(|raw| primitives::AdmissionEpochId::parse(&raw))
            .transpose()
            .context("RSS_DR_REQUIRED_ADMISSION_EPOCH_ID must be a canonical UUID")?;
        let admission_identity = eventexec::DrAdmissionProcessIdentity::new(
            "settingsonly",
            compiled_plan.runtime_plan_fingerprint(),
            instance_id,
            uuid::Uuid::new_v4(),
            required_admission_epoch,
        )?;
        let eventing = providers
            .eventing
            .bind_admission_identity(admission_identity)?;
        let settings_v3_serving = compiled_plan.take_settings_v3_serving()?;
        let module_inputs =
            crate::domains::DomainModuleInputs::active_settings(settings_v3_serving);
        let deps = crate::SharedRuntimeDeps::production(
            providers.pg,
            providers.vault,
            providers.settings_key,
            providers.settings_readiness,
        );
        let bindings = crate::wire_domains(&deps, module_inputs).await?;
        let (primary, admin, health, request_budget) = listeners_config.into_listener_inputs();
        prepare_assembly(
            AssemblyStartupInputs::production(
                bindings,
                eventing,
                providers.role_closer,
                compiled_plan,
                build_metadata,
                providers.verifier,
                providers.audit_sink,
                providers.limiter,
                providers.metrics,
                primary,
                admin,
                health,
                request_budget,
                providers.readiness_startup_timeout,
                ReadyAction::Log,
            )
            .with_frontend(frontend)?,
            transaction,
        )
        .await
    }
}

pub(crate) struct AssemblyStartupInputs<S> {
    bindings: Vec<bootstrap::DomainBinding>,
    provider_activation: ProviderActivation,
    verifier: crate::auth_bridge::FederatedVerifier,
    audit_sink: httpserve::AuditSinkHandle,
    limiter: Arc<S>,
    trusted_proxy_config: httpserve::TrustedProxyConfig,
    metrics: Arc<dyn diport::MetricsExporter>,
    primary: std::net::SocketAddr,
    admin: std::net::SocketAddr,
    health: std::net::SocketAddr,
    request_budget: Duration,
    ready: ReadyAction,
    readiness_startup_timeout: Duration,
    frontend: Option<crate::config::ServingFrontendConfig>,
    #[cfg(feature = "test-support")]
    activation_gate: Option<SocketAddr>,
}

#[allow(
    clippy::large_enum_variant,
    reason = "move-only production capabilities stay inline; boxing would weaken the closed activation handoff solely for test-support size"
)]
enum ProviderActivation {
    Production {
        eventing: crate::eventing::EventingInputs,
        role_closer: crate::providers::ProviderRoleCloser,
        plan: crate::plan::BoundSettingsOnlyPlan,
        build_metadata: Option<runtimeexec::inventory::BuildMetadata>,
    },
    #[cfg(feature = "test-support")]
    Fixture(runtimeexec::inventory::RuntimeInventorySeed),
}

impl AssemblyStartupInputs<redis::RedisRateLimiter> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn production(
        bindings: Vec<bootstrap::DomainBinding>,
        eventing: crate::eventing::EventingInputs,
        role_closer: crate::providers::ProviderRoleCloser,
        plan: crate::plan::BoundSettingsOnlyPlan,
        build_metadata: Option<runtimeexec::inventory::BuildMetadata>,
        verifier: crate::auth_bridge::FederatedVerifier,
        audit_sink: httpserve::AuditSinkHandle,
        limiter: Arc<redis::RedisRateLimiter>,
        metrics: Arc<dyn diport::MetricsExporter>,
        primary: std::net::SocketAddr,
        admin: std::net::SocketAddr,
        health: std::net::SocketAddr,
        request_budget: Duration,
        readiness_startup_timeout: Duration,
        ready: ReadyAction,
    ) -> Self {
        Self {
            bindings,
            provider_activation: ProviderActivation::Production {
                eventing,
                role_closer,
                plan,
                build_metadata,
            },
            verifier,
            audit_sink,
            limiter,
            trusted_proxy_config: httpserve::TrustedProxyConfig::disabled(),
            metrics,
            primary,
            admin,
            health,
            request_budget,
            ready,
            readiness_startup_timeout,
            frontend: None,
            #[cfg(feature = "test-support")]
            activation_gate: None,
        }
    }
}

#[cfg(feature = "test-support")]
impl AssemblyStartupInputs<ratelimit::GovernorLimiter> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn fixture(
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
            provider_activation: ProviderActivation::Fixture(inventory_seed),
            verifier,
            audit_sink,
            limiter,
            trusted_proxy_config: httpserve::TrustedProxyConfig::disabled(),
            metrics,
            primary,
            admin,
            health,
            request_budget,
            ready,
            readiness_startup_timeout: Duration::from_secs(30),
            frontend: None,
            activation_gate: None,
        }
    }
}

impl<S> AssemblyStartupInputs<S> {
    fn with_frontend(
        mut self,
        frontend: crate::config::ServingFrontendConfig,
    ) -> anyhow::Result<Self> {
        self.trusted_proxy_config = frontend.trusted_proxy_config.clone();
        self.frontend = Some(frontend);
        Ok(self)
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn with_activation_gate(mut self, address: SocketAddr) -> Self {
        self.activation_gate = Some(address);
        self
    }
}

pub(crate) async fn prepare_assembly<S>(
    mut inputs: AssemblyStartupInputs<S>,
    transaction: &mut runtimeexec::StartupTransaction<'_>,
) -> anyhow::Result<
    runtimeexec::PreparedLaunch<
        listeners::LaunchAdapter,
        Arc<bootstrap::HealthReporter>,
        ReadyHook,
    >,
>
where
    S: diport::RateLimiter + Send + Sync + 'static,
{
    let (mut registry, domain_output) = match bootstrap::compose_bindings(&mut inputs.bindings) {
        Ok(composed) => composed,
        Err(error) => {
            transaction.stage_domain_output(bootstrap::drain_binding_outputs(&mut inputs.bindings));
            return Err(error.into());
        }
    };
    transaction.stage_domain_output(domain_output);
    let (inventory_seed, mut registry) = match inputs.provider_activation {
        ProviderActivation::Production {
            eventing,
            role_closer,
            plan,
            build_metadata,
        } => {
            let write_admission = eventing.write_admission();
            let outputs = crate::eventing::wire(eventing, registry.drain_subscribers()).await?;
            let completed_roles = role_closer.finish(outputs, transaction.provider_output_mut())?;
            let seed = plan.into_inventory_seed(completed_roles)?;
            let seed = match build_metadata {
                Some(metadata) => seed.with_build_metadata(metadata),
                None => seed,
            };
            (seed, registry.admit_writes(write_admission))
        }
        #[cfg(feature = "test-support")]
        ProviderActivation::Fixture(seed) => {
            transaction.expect_workers(bootstrap::ExpectedWorkerInventory::closed([])?)?;
            let (admission_control, _, _, write_admission) =
                primitives::prepare_dr_admission_controls().into_parts();
            admission_control
                .start_running()
                .context("start settingsonly fixture write admission")?;
            (seed, registry.admit_writes(write_admission))
        }
    };
    let (provider_output, domain_output) = transaction.outputs_mut();
    register_probes(&mut registry, provider_output)?;
    register_probes(&mut registry, domain_output)?;
    let listener_probe = runtimeexec::ListenerLifecycleRegistration::install(&mut registry)?;
    let reporter = Arc::clone(listener_probe.assembly_receipt());
    let (inventory_publisher, inventory_reader) =
        runtimeexec::inventory::inventory_channel(inventory_seed, Arc::clone(&reporter));
    let framework_routes = crate::inventory::InventoryFrameworkRoutes::new(inventory_reader);
    let (finalized, receipt) = listeners::finalize(
        &mut registry,
        listeners::FinalizeInputs {
            verifier: inputs.verifier,
            limiter: inputs.limiter,
            trusted_proxy_config: inputs.trusted_proxy_config,
            metrics: inputs.metrics,
            audit_sink: inputs.audit_sink,
            audit_clock: Arc::new(crate::SystemClock),
            reporter,
        },
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
    let readiness_startup_timeout = inputs.readiness_startup_timeout;
    let ready: ReadyHook = Box::new(move |inventory| {
        Box::pin(
            inputs
                .ready
                .publish(inventory, readiness, readiness_startup_timeout),
        )
    });
    Ok(runtimeexec::PreparedLaunch::new(
        adapter,
        listener_probe,
        ready,
        None,
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
    let mut retained = bootstrap::DomainModuleResult::default();
    for lifecycle in output.drain_outputs() {
        match lifecycle {
            bootstrap::DomainLifecycleOutput::Probe(name, probe) => {
                registry
                    .probe(name, probe)
                    .context("register settingsonly lifecycle probe")?;
            }
            bootstrap::DomainLifecycleOutput::Resource(resource) => {
                retained.push_resource(resource);
            }
            bootstrap::DomainLifecycleOutput::Worker(worker) => retained.push_worker(worker),
        }
    }
    *output = retained;
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
        startup_timeout: Duration,
    ) -> anyhow::Result<()> {
        log_listeners_activated(&inventory);
        if tokio::time::timeout(startup_timeout, wait_until_healthy(&reporter))
            .await
            .is_err()
        {
            let report = reporter.report();
            for check in report
                .checks()
                .iter()
                .filter(|check| check.status() != primitives::HealthStatus::Healthy)
            {
                tracing::error!(
                    event = "settingsonly.readiness",
                    component = "settingsonly",
                    probe = check.name().as_str(),
                    outcome = check.status().as_label(),
                    reason = check.detail(),
                    error_type = "startup_timeout",
                    "settingsonly readiness probe blocked startup"
                );
            }
            anyhow::bail!("settingsonly readiness startup timed out");
        }
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
        let mut ready =
            tokio::spawn(ReadyAction::Log.publish(inventory, reporter, Duration::from_secs(2)));

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

    #[tokio::test]
    async fn ready_action_fails_closed_with_the_stable_timeout() {
        let ready = Arc::new(AtomicBool::new(false));
        let probe_name =
            primitives::ProbeName::parse("blocked-ready").expect("valid readiness probe name");
        let mut registry = bootstrap::Registry::new();
        registry
            .probe(
                probe_name.clone(),
                Box::new(ToggleProbe {
                    name: probe_name,
                    ready,
                }),
            )
            .expect("register blocked readiness probe");
        let error = ReadyAction::Log
            .publish(
                listeners::ListenerInventory {
                    primary: "127.0.0.1:1".parse().expect("primary address"),
                    admin: "127.0.0.1:3".parse().expect("admin address"),
                    health: "127.0.0.1:2".parse().expect("health address"),
                },
                Arc::new(registry.take_health_reporter()),
                Duration::from_millis(5),
            )
            .await
            .expect_err("blocked required probe must fail startup");
        assert_eq!(
            error.to_string(),
            "settingsonly readiness startup timed out"
        );
    }
}
