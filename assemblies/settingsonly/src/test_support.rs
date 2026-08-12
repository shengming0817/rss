//! Default-off façade for the real settingsonly prepare/launch funnel.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;

use crate::{auth_bridge, listeners, runtime};

/// Exact production readiness closure used by artifact acceptance.
#[must_use]
pub const fn production_required_probe_names() -> [&'static str; 17] {
    crate::readiness::PRODUCTION_REQUIRED_PROBES
}

pub struct FixtureConfig {
    primary: SocketAddr,
    health: SocketAddr,
    ready_notify: SocketAddr,
    activation_gate: SocketAddr,
}

impl FixtureConfig {
    #[must_use]
    pub fn new(
        primary: SocketAddr,
        health: SocketAddr,
        ready_notify: SocketAddr,
        activation_gate: SocketAddr,
    ) -> Self {
        Self {
            primary,
            health,
            ready_notify,
            activation_gate,
        }
    }
}

struct FixturePdp;

impl diport::Pdp for FixturePdp {
    async fn verify(
        &self,
        _raw: &diport::RawCredential,
    ) -> Result<diport::VerifiedClaims, diport::PdpError> {
        let tenant = vocab::TenantId::parse("00000000-0000-4000-8000-000000000179")
            .map_err(|_| diport::PdpError::InvalidSignature)?;
        diport::VerifiedClaims::federated_access(
            "settingsonly-fixture",
            Some(tenant),
            vocab::PrincipalKind::User,
            diport::VerifiedFederatedPermissions::new([vocab::GrantPermission::route(
                vocab::RoutePermissionId::SettingsConfigPublish,
            )])
            .map_err(|_| diport::PdpError::InvalidSignature)?,
        )
        .map_err(|_| diport::PdpError::InvalidSignature)
    }
}

struct FixtureMetrics;

impl diport::MetricsExporter for FixtureMetrics {
    fn render(&self) -> String {
        "# settingsonly fixture metrics\n".to_owned()
    }
}

struct FixtureAuditSink;

impl diport::AuditSink for FixtureAuditSink {
    async fn record(&self, _event: diport::AuditEvent) -> Result<(), diport::AuditSinkError> {
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), diport::AuditSinkError> {
        Ok(())
    }
}

struct HealthyProbe {
    name: primitives::ProbeName,
}

impl bootstrap::HealthProbe for HealthyProbe {
    fn check(&self) -> primitives::HealthCheck {
        primitives::HealthCheck::new(
            self.name.clone(),
            primitives::HealthStatus::Healthy,
            "ready",
        )
    }
}

/// A structurally valid token accepted only by the fixture PDP.
#[must_use]
pub fn valid_federated_token() -> String {
    "e30.eyJzdWIiOiJzZXR0aW5nc29ubHktZml4dHVyZSJ9.c2ln".to_owned()
}

struct FixtureStartup {
    config: FixtureConfig,
}

impl runtimeexec::StartupAdapter for FixtureStartup {
    type Adapter = listeners::LaunchAdapter;
    type ProbeReceipt = listeners::FinalizedProbeReceipt;
    type ReadyHook = runtime::ReadyHook;
    type Ready = runtime::ReadyFuture;

    async fn prepare(
        self,
        transaction: &mut runtimeexec::StartupTransaction<'_>,
    ) -> anyhow::Result<
        runtimeexec::PreparedLaunch<Self::Adapter, Self::ProbeReceipt, Self::ReadyHook>,
    > {
        let FixtureConfig {
            primary,
            health,
            ready_notify,
            activation_gate,
        } = self.config;
        let mut provider_output = bootstrap::DomainModuleResult::default();
        for name in [
            settings_composition::CONFIGS_READY_PROBE_NAME,
            settings_composition::KEYPROVIDER_READY_PROBE_NAME,
            settings_composition::SECRET_RESOLVER_READY_PROBE_NAME,
            crate::readiness::FEDERATED_JWKS,
        ] {
            let name = primitives::ProbeName::parse(name)
                .context("build fixture provider readiness probe name")?;
            provider_output
                .probes
                .push((name.clone(), Box::new(HealthyProbe { name })));
        }
        transaction.stage_provider_output(provider_output);
        let bindings = vec![
            settings_composition::test_support::binding()
                .await
                .context("build settings test binding")?,
        ];
        let verifier = auth_bridge::FederatedVerifier::test(diport::DynPdp::new_arc(FixturePdp));
        let admin = "127.0.0.1:8082"
            .parse()
            .context("build fixture Admin bind")?;
        runtime::prepare_assembly(
            runtime::AssemblyStartupInputs::fixture(
                bindings,
                verifier,
                httpserve::AuditSinkHandle::new(FixtureAuditSink),
                listeners::rate_limiter(),
                Arc::new(FixtureMetrics),
                primary,
                admin,
                health,
                Duration::from_secs(2),
                fixture_inventory_seed()?,
                runtime::ReadyAction::Notify(ready_notify),
            )
            .with_activation_gate(activation_gate),
            transaction,
        )
        .await
    }
}

fn fixture_inventory_seed() -> anyhow::Result<runtimeexec::inventory::RuntimeInventorySeed> {
    let plan = crate::plan::SettingsOnlyPlan::bundled()?;
    let bindings = crate::providers_gen::PROVIDER_CATALOG
        .iter()
        .map(|provider| {
            runtimeexec::inventory::ProviderProbeBinding::from_probe_receipt(
                provider.role().as_str(),
                Vec::new(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    plan.into_inventory_seed_fixture(bindings)
}

pub async fn run_fixture(config: FixtureConfig) -> anyhow::Result<()> {
    runtime::launch(FixtureStartup { config }).await
}

/// Build the exact assembly-owned projection worker/probe batch without starting the worker.
///
/// The bundled active activation is consumed through the same sealed binding path as production;
/// this helper substitutes only the worker implementation for component-level lifecycle evidence.
pub fn projection_lifecycle_output() -> anyhow::Result<bootstrap::DomainModuleResult> {
    let plan = crate::plan::SettingsOnlyPlan::bundled()?.bind_fixture_projection()?;
    let (_control, _relay, _consumer, write_admission) =
        primitives::prepare_dr_admission_controls().into_parts();
    crate::projection::ProjectionLifecycleBatch::from_runtime_plan(
        plan.workflow_runtime(),
        &write_admission,
    )
    .map(crate::projection::ProjectionLifecycleBatch::into_output)
}
