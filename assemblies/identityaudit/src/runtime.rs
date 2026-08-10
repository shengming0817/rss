//! Single private handoff from the sealed identityaudit assembly to runtimeexec.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use diport::{DynManagedResource, ManagedResource, ShutdownError};

use crate::listeners;

const TOTAL_DRAIN_BUDGET: Duration = Duration::from_secs(50);
const READINESS_POLL_INTERVAL: Duration = Duration::from_millis(100);

type ReadyFuture = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>;
type ReadyHook = Box<dyn FnOnce(listeners::ListenerInventory) -> ReadyFuture + Send>;

pub(crate) async fn launch_captured(captured: crate::config::CapturedConfig) -> anyhow::Result<()> {
    let startup = ProductionStartup { captured };
    let plan = runtimeexec::StartupPlan::new(startup, total_drain_budget()?);
    let _completed = runtimeexec::launch_startup(plan).await?;
    Ok(())
}

pub(crate) fn total_drain_budget() -> anyhow::Result<runtimeexec::TotalDrainBudget> {
    runtimeexec::TotalDrainBudget::new(TOTAL_DRAIN_BUDGET)
}

struct ProductionStartup {
    captured: crate::config::CapturedConfig,
}

impl runtimeexec::StartupAdapter for ProductionStartup {
    type Adapter = listeners::LaunchAdapter;
    type ProbeReceipt = listeners::FinalizedProbeReceipt;
    type ReadyHook = ReadyHook;
    type Ready = ReadyFuture;

    async fn prepare(
        self,
        transaction: &mut runtimeexec::StartupTransaction<'_>,
    ) -> anyhow::Result<
        runtimeexec::PreparedLaunch<Self::Adapter, Self::ProbeReceipt, Self::ReadyHook>,
    > {
        let plan = crate::plan::IdentityAuditPlan::bundled()?;
        let (config, secrets, build_metadata, frontend) = self.captured.into_runtime_inputs();
        let build = crate::providers::build(
            plan.provider_build()?,
            plan.workflow_runtime().projection_capture(),
            config,
            secrets,
            frontend.rate_limit_quota,
            transaction,
        )
        .await?;
        let crate::providers::BuildResult {
            providers,
            listeners: listeners_config,
            amqp_url,
            roles,
        } = build;
        let crate::providers::ProviderBundle {
            pg,
            redis,
            signer,
            verifier,
            audit_sink,
            metrics,
            limiter,
            audit_chain_key,
            identity_pseudonym_keys,
            tenant_authority,
            dlx_payload_protector,
            identity,
        } = providers;
        let deps = crate::SharedRuntimeDeps::production(
            pg.clone(),
            Arc::clone(&signer),
            audit_chain_key.clone(),
            identity_pseudonym_keys,
            identity.runtime_config,
            identity.blocklist,
        );
        let mut bindings = crate::wire_domains(&deps).await?;
        let (mut registry, domain_output) = match bootstrap::compose_bindings(&mut bindings) {
            Ok(composed) => composed,
            Err(error) => {
                transaction.stage_domain_output(bootstrap::drain_binding_outputs(&mut bindings));
                return Err(error.into());
            }
        };
        transaction.stage_domain_output(domain_output);

        let event_outputs = crate::eventing::wire(
            &pg,
            &redis,
            registry.drain_subscribers(),
            &amqp_url,
            &audit_chain_key,
            tenant_authority,
            dlx_payload_protector,
        )
        .await?;
        let completed_roles = roles.finish(event_outputs, transaction.provider_output_mut())?;
        let inventory_seed = plan.inventory_seed(completed_roles)?;
        let inventory_seed = match build_metadata {
            Some(metadata) => inventory_seed.with_build_metadata(metadata),
            None => inventory_seed,
        };

        let (provider_output, domain_output) = transaction.outputs_mut();
        register_probes(&mut registry, provider_output)?;
        register_probes(&mut registry, domain_output)?;
        let reporter = Arc::new(registry.take_health_reporter());
        let (inventory_publisher, inventory_reader) =
            runtimeexec::inventory::inventory_channel(inventory_seed, Arc::clone(&reporter));
        crate::modules_gen::register_framework_routes(
            &crate::framework_routes::IdentityAuditFrameworkRoutes::new(inventory_reader),
            &mut registry,
        )
        .context("register identityaudit framework routes")?;
        let (finalized, receipt) = listeners::finalize(
            &mut registry,
            listeners::FinalizeInputs {
                verifier,
                limiter,
                trusted_proxy_config: frontend.trusted_proxy_config.clone(),
                metrics,
                audit_sink,
                audit_clock: Arc::new(crate::SystemClock),
                reporter,
            },
        )?;
        let (primary, admin, health, request_budget) = listeners_config.into_listener_inputs();
        let adapter = listeners::LaunchAdapter::new(
            finalized,
            primary,
            admin,
            health,
            request_budget,
            inventory_publisher,
            Some(frontend),
        )?;
        let readiness = receipt.readiness();
        let ready: ReadyHook = Box::new(move |inventory| {
            Box::pin(async move {
                log_listeners_activated(&inventory);
                wait_until_healthy(&readiness).await;
                log_assembly_ready(&inventory);
                Ok(())
            })
        });
        Ok(runtimeexec::PreparedLaunch::new(
            adapter, receipt, ready, None,
        ))
    }
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

fn register_probes(
    registry: &mut bootstrap::Registry,
    output: &mut bootstrap::DomainModuleResult,
) -> anyhow::Result<()> {
    for (name, probe) in output.probes.drain(..) {
        registry
            .probe(name, probe)
            .context("register identityaudit lifecycle probe")?;
    }
    Ok(())
}

fn log_listeners_activated(inventory: &listeners::ListenerInventory) {
    tracing::info!(
        primary = %inventory.primary,
        admin = %inventory.admin,
        health = %inventory.health,
        state = "listeners_activated",
        "identityaudit listeners activated"
    );
}

fn log_assembly_ready(inventory: &listeners::ListenerInventory) {
    tracing::info!(
        primary = %inventory.primary,
        admin = %inventory.admin,
        health = %inventory.health,
        state = "ready",
        "identityaudit assembly ready"
    );
}

async fn wait_until_healthy(reporter: &bootstrap::HealthReporter) {
    while reporter.report().overall() != primitives::HealthStatus::Healthy {
        tokio::time::sleep(READINESS_POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct CountingResource(Arc<AtomicUsize>);

    impl ManagedResource for CountingResource {
        fn name(&self) -> &str {
            "counting-inner"
        }

        async fn shutdown(&self) -> Result<(), ShutdownError> {
            self.0.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    struct ToggleProbe {
        name: primitives::ProbeName,
        healthy: Arc<AtomicBool>,
    }

    impl bootstrap::HealthProbe for ToggleProbe {
        fn check(&self) -> primitives::HealthCheck {
            let healthy = self.healthy.load(Ordering::Acquire);
            primitives::HealthCheck::new(
                self.name.clone(),
                if healthy {
                    primitives::HealthStatus::Healthy
                } else {
                    primitives::HealthStatus::Unhealthy
                },
                if healthy { "ready" } else { "starting" },
            )
        }
    }

    #[test]
    fn drain_budget_covers_declared_worker_shutdown_bounds() {
        assert!(TOTAL_DRAIN_BUDGET >= Duration::from_secs(45));
        assert!(total_drain_budget().is_ok());
    }

    #[tokio::test]
    async fn shared_resource_delegates_name_and_shutdown_once_per_call() {
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let wrapper = SharedManagedResource::new(
            Arc::new(CountingResource(Arc::clone(&shutdowns))),
            "identityaudit-shared-test",
        );
        assert_eq!(wrapper.name(), "identityaudit-shared-test");
        assert!(wrapper.shutdown().await.is_ok());
        assert_eq!(shutdowns.load(Ordering::Acquire), 1);

        let boxed = SharedManagedResource::boxed(
            Arc::new(CountingResource(Arc::clone(&shutdowns))),
            "identityaudit-shared-boxed-test",
        );
        assert_eq!(boxed.name(), "identityaudit-shared-boxed-test");
        assert!(boxed.shutdown().await.is_ok());
        assert_eq!(shutdowns.load(Ordering::Acquire), 2);
    }

    #[test]
    fn probe_registration_drains_outputs_and_rejects_duplicates() -> anyhow::Result<()> {
        let mut registry = bootstrap::compose(&[])?;
        let healthy = Arc::new(AtomicBool::new(true));
        let name = primitives::ProbeName::parse("identityaudit-runtime-probe")?;
        let probe = || {
            Box::new(ToggleProbe {
                name: name.clone(),
                healthy: Arc::clone(&healthy),
            }) as Box<dyn bootstrap::HealthProbe>
        };
        let mut output = bootstrap::DomainModuleResult {
            probes: vec![(name.clone(), probe())],
            ..Default::default()
        };
        register_probes(&mut registry, &mut output)?;
        assert!(output.probes.is_empty());

        let mut duplicate = bootstrap::DomainModuleResult {
            probes: vec![(name.clone(), probe()), (name.clone(), probe())],
            ..Default::default()
        };
        assert!(register_probes(&mut registry, &mut duplicate).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn readiness_waits_for_all_registered_probes() -> anyhow::Result<()> {
        let mut registry = bootstrap::compose(&[])?;
        let healthy = Arc::new(AtomicBool::new(false));
        let name = primitives::ProbeName::parse("identityaudit-readiness-test")?;
        registry.probe(
            name.clone(),
            Box::new(ToggleProbe {
                name,
                healthy: Arc::clone(&healthy),
            }),
        )?;
        let reporter = registry.take_health_reporter();
        let wait = wait_until_healthy(&reporter);
        tokio::pin!(wait);
        assert!(
            tokio::time::timeout(Duration::from_millis(1), &mut wait)
                .await
                .is_err()
        );
        healthy.store(true, Ordering::Release);
        wait.await;

        let inventory = listeners::ListenerInventory {
            primary: "127.0.0.1:18080".parse()?,
            admin: "127.0.0.1:18081".parse()?,
            health: "127.0.0.1:18082".parse()?,
        };
        log_listeners_activated(&inventory);
        log_assembly_ready(&inventory);
        Ok(())
    }
}
