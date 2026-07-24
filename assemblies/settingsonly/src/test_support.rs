//! Default-off façade for the real settingsonly prepare/launch funnel.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;

use crate::{auth_bridge, listeners, runtime};

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
        let jwks_name = primitives::ProbeName::parse("federated_access_token_jwks_ready")
            .context("build fixture JWKS probe name")?;
        let mut provider_output = bootstrap::DomainModuleResult::default();
        provider_output.probes.push((
            jwks_name.clone(),
            Box::new(HealthyProbe { name: jwks_name }),
        ));
        transaction.stage_provider_output(provider_output);
        let bindings = vec![
            settings_composition::test_support::binding()
                .await
                .context("build settings test binding")?,
        ];
        let verifier = auth_bridge::FederatedVerifier::test(diport::DynPdp::new_arc(FixturePdp));
        runtime::prepare_assembly(
            runtime::AssemblyStartupInputs::new(
                bindings,
                verifier,
                listeners::rate_limiter(),
                Arc::new(FixtureMetrics),
                primary,
                health,
                Duration::from_secs(2),
                runtime::ReadyAction::Notify(ready_notify),
            )
            .with_activation_gate(activation_gate),
            transaction,
        )
        .await
    }
}

pub async fn run_fixture(config: FixtureConfig) -> anyhow::Result<()> {
    runtime::launch(FixtureStartup { config }).await
}
