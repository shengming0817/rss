//! Typed provider transaction for the production candidate.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Context as _;
use diport::{DynManagedResource, ShutdownError};

type ProductionArtifactSource =
    identity_composition::ExternalPkiArtifactSource<httpd::SpiffeMtlsExternalCsrResolver>;
type ProviderLifecycleOutput = bootstrap::DomainModuleResult;

/// Value-bearing proof that the exact production artifact source crossed the generated provider
/// constructor before the domain lifecycle consumed a clone of the same Arc-backed capability.
pub(crate) struct DeviceProductionArtifactSourceCapability(ProductionArtifactSource);

impl DeviceProductionArtifactSourceCapability {
    pub(crate) fn new(source: &ProductionArtifactSource) -> Self {
        Self(source.clone())
    }

    pub(crate) fn into_output(self) -> bootstrap::DomainModuleResult {
        drop(self.0);
        bootstrap::DomainModuleResult::default()
    }
}

pub(crate) struct ProviderRoleCloser {
    roles: crate::providers_gen::ProviderRoleBatches,
    auth_audit_sink: Option<crate::providers_gen::AuthAuditSinkConstructor>,
    device_certificate_store: Option<crate::providers_gen::DeviceCertificateStoreConstructor>,
    device_command_store: Option<crate::providers_gen::DeviceCommandStoreConstructor>,
    device_mqtt_session: Option<crate::providers_gen::DeviceMqttSessionConstructor>,
    device_production_artifact_source:
        Option<crate::providers_gen::DeviceProductionArtifactSourceConstructor>,
    device_revocation_store: Option<crate::providers_gen::DeviceRevocationStoreConstructor>,
    external_csr_resolver: Option<crate::providers_gen::ExternalCsrResolverConstructor>,
    listener_pdp: Option<crate::providers_gen::ListenerPdpConstructor>,
    listener_rate_limiter: Option<crate::providers_gen::ListenerRateLimiterConstructor>,
    vault_external_pki: Option<crate::providers_gen::VaultExternalPkiConstructor>,
    receipts: ProviderReceipts,
}

#[derive(Default)]
struct ProviderReceipts {
    auth_audit_sink: Option<crate::providers_gen::AuthAuditSinkReceipt>,
    device_certificate_store: Option<crate::providers_gen::DeviceCertificateStoreReceipt>,
    device_command_store: Option<crate::providers_gen::DeviceCommandStoreReceipt>,
    device_mqtt_session: Option<crate::providers_gen::DeviceMqttSessionReceipt>,
    device_production_artifact_source:
        Option<crate::providers_gen::DeviceProductionArtifactSourceReceipt>,
    device_revocation_store: Option<crate::providers_gen::DeviceRevocationStoreReceipt>,
    external_csr_resolver: Option<crate::providers_gen::ExternalCsrResolverReceipt>,
    listener_pdp: Option<crate::providers_gen::ListenerPdpReceipt>,
    listener_rate_limiter: Option<crate::providers_gen::ListenerRateLimiterReceipt>,
    vault_external_pki: Option<crate::providers_gen::VaultExternalPkiReceipt>,
}

macro_rules! stage_provider_role {
    ($method:ident, $constructor:ident, $receipt:ident, $input:ty) => {
        pub(crate) fn $method(
            &mut self,
            output: $input,
            inventory: &mut ProviderLifecycleOutput,
        ) -> anyhow::Result<()> {
            let constructor = self.$constructor.take().context(concat!(
                stringify!($constructor),
                " constructor already consumed"
            ))?;
            let receipt = constructor.finish(output)?.transfer(inventory);
            anyhow::ensure!(
                self.receipts.$receipt.replace(receipt).is_none(),
                concat!(stringify!($receipt), " receipt already staged")
            );
            Ok(())
        }
    };
}

impl ProviderRoleCloser {
    pub(crate) fn new(
        mut roles: crate::providers_gen::ProviderRoleBatches,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            auth_audit_sink: Some(roles.auth_audit_sink()?),
            device_certificate_store: Some(roles.device_certificate_store()?),
            device_command_store: Some(roles.device_command_store()?),
            device_mqtt_session: Some(roles.device_mqtt_session()?),
            device_production_artifact_source: Some(roles.device_production_artifact_source()?),
            device_revocation_store: Some(roles.device_revocation_store()?),
            external_csr_resolver: Some(roles.external_csr_resolver()?),
            listener_pdp: Some(roles.listener_pdp()?),
            listener_rate_limiter: Some(roles.listener_rate_limiter()?),
            vault_external_pki: Some(roles.vault_external_pki()?),
            roles,
            receipts: ProviderReceipts::default(),
        })
    }

    stage_provider_role!(
        stage_auth_audit_sink,
        auth_audit_sink,
        auth_audit_sink,
        ProviderLifecycleOutput
    );
    stage_provider_role!(
        stage_device_certificate_store,
        device_certificate_store,
        device_certificate_store,
        ProviderLifecycleOutput
    );
    stage_provider_role!(
        stage_device_command_store,
        device_command_store,
        device_command_store,
        ProviderLifecycleOutput
    );
    stage_provider_role!(
        stage_device_mqtt_session,
        device_mqtt_session,
        device_mqtt_session,
        ProviderLifecycleOutput
    );
    stage_provider_role!(
        stage_device_production_artifact_source,
        device_production_artifact_source,
        device_production_artifact_source,
        DeviceProductionArtifactSourceCapability
    );
    stage_provider_role!(
        stage_device_revocation_store,
        device_revocation_store,
        device_revocation_store,
        ProviderLifecycleOutput
    );
    stage_provider_role!(
        stage_external_csr_resolver,
        external_csr_resolver,
        external_csr_resolver,
        ProviderLifecycleOutput
    );
    stage_provider_role!(
        stage_listener_pdp,
        listener_pdp,
        listener_pdp,
        crate::providers_gen::ListenerPdpJwksLifecycle
    );
    stage_provider_role!(
        stage_vault_external_pki,
        vault_external_pki,
        vault_external_pki,
        ProviderLifecycleOutput
    );

    pub(crate) fn stage_listener_rate_limiter(
        &mut self,
        output: redis::RedisRateLimiterCapability,
        inventory: &mut bootstrap::DomainModuleResult,
    ) -> anyhow::Result<redis::RedisRateLimiter> {
        let constructor: crate::providers_gen::ListenerRateLimiterConstructor = self
            .listener_rate_limiter
            .take()
            .context("listener_rate_limiter constructor already consumed")?;
        let (receipt, limiter) = constructor.finish(output)?.transfer(inventory);
        anyhow::ensure!(
            self.receipts
                .listener_rate_limiter
                .replace(receipt)
                .is_none(),
            "listener_rate_limiter receipt already staged"
        );
        Ok(limiter)
    }

    pub(crate) fn finish(
        self,
        inventory: &bootstrap::DomainModuleResult,
    ) -> anyhow::Result<crate::providers_gen::CompletedProviderRoles> {
        let mut receipts = self.receipts;
        self.roles.finish(
            inventory,
            receipts
                .auth_audit_sink
                .take()
                .context("auth_audit_sink not staged")?,
            receipts
                .device_certificate_store
                .take()
                .context("device_certificate_store not staged")?,
            receipts
                .device_command_store
                .take()
                .context("device_command_store not staged")?,
            receipts
                .device_mqtt_session
                .take()
                .context("device_mqtt_session not staged")?,
            receipts
                .device_production_artifact_source
                .take()
                .context("device_production_artifact_source not staged")?,
            receipts
                .device_revocation_store
                .take()
                .context("device_revocation_store not staged")?,
            receipts
                .external_csr_resolver
                .take()
                .context("external_csr_resolver not staged")?,
            receipts
                .listener_pdp
                .take()
                .context("listener_pdp not staged")?,
            receipts
                .listener_rate_limiter
                .take()
                .context("listener_rate_limiter not staged")?,
            receipts
                .vault_external_pki
                .take()
                .context("vault_external_pki not staged")?,
        )
    }
}

pub(crate) struct FederatedProvider {
    provider: Arc<oidc::OidcProvider<diport::FederatedAccessProfile>>,
    readiness: oidc::JwksReadinessHandle,
    probe_name: primitives::ProbeName,
}

impl FederatedProvider {
    pub(crate) fn provider(&self) -> Arc<oidc::OidcProvider<diport::FederatedAccessProfile>> {
        Arc::clone(&self.provider)
    }

    pub(crate) fn managed_resource(&self) -> Box<DynManagedResource<'static>> {
        SharedManagedResource::boxed(Arc::clone(&self.provider))
    }
}

pub(crate) fn build_federated_access_provider(
    issuer: String,
    audience: String,
    jwks_path: std::path::PathBuf,
    refresh: Duration,
    token: tokio_util::sync::CancellationToken,
) -> anyhow::Result<FederatedProvider> {
    let source = oidc::JwksKeySource::load_and_watch(
        "deviceidentity-federated-access",
        jwks_path,
        refresh,
        token,
    )
    .context("load deviceidentity federated JWKS")?;
    let readiness = source.readiness_handle();
    let permissions = oidc::FederatedPermissionUniverse::try_new([
        vocab::GrantPermission::route(
            vocab::RoutePermissionId::IdentityDeviceCertificatePolicyWrite,
        ),
        vocab::GrantPermission::route(
            vocab::RoutePermissionId::IdentityDeviceCertificateStatusRead,
        ),
    ])
    .context("build deviceidentity federated permission universe")?;
    let provider = Arc::new(oidc::OidcProvider::new(
        oidc::VerifierConfigBuilder::<diport::FederatedAccessProfile>::new(
            issuer,
            audience,
            permissions,
        )
        .keys_jwks(source)
        .trust_kind("user")
        .build()
        .context("build deviceidentity federated verifier")?,
        Box::new(SystemClock),
    ));
    let probe_name = primitives::ProbeName::parse("deviceidentity_federated_jwks_ready")
        .context("build deviceidentity JWKS readiness probe name")?;
    Ok(FederatedProvider {
        provider,
        readiness,
        probe_name,
    })
}

pub(crate) fn listener_pdp_lifecycle(
    provider: &FederatedProvider,
) -> crate::providers_gen::ListenerPdpJwksLifecycle {
    crate::providers_gen::ListenerPdpJwksLifecycle::single(
        (
            provider.probe_name.clone(),
            Box::new(AccessTokenJwksReadyProbe::federated_access(
                provider.probe_name.clone(),
                provider.readiness.clone(),
            )),
        ),
        provider.managed_resource(),
    )
}

struct AccessTokenJwksReadyProbe {
    name: primitives::ProbeName,
    readiness: oidc::JwksReadinessHandle,
}

impl AccessTokenJwksReadyProbe {
    fn federated_access(name: primitives::ProbeName, readiness: oidc::JwksReadinessHandle) -> Self {
        Self { name, readiness }
    }
}

impl bootstrap::HealthProbe for AccessTokenJwksReadyProbe {
    fn check(&self) -> primitives::HealthCheck {
        let (status, detail) = if self.readiness.is_ready() {
            (primitives::HealthStatus::Healthy, "ready")
        } else {
            (primitives::HealthStatus::Degraded, "last-good")
        };
        primitives::HealthCheck::new(self.name.clone(), status, detail)
    }
}

struct SharedManagedResource<T> {
    inner: Arc<T>,
}

impl<T> SharedManagedResource<T> {
    fn boxed(inner: Arc<T>) -> Box<DynManagedResource<'static>>
    where
        T: diport::ManagedResource + Sync + 'static,
    {
        DynManagedResource::new_box(Self { inner })
    }
}

pub(crate) fn shared_managed_resource<T>(inner: Arc<T>) -> Box<DynManagedResource<'static>>
where
    T: diport::ManagedResource + Sync + 'static,
{
    SharedManagedResource::boxed(inner)
}

impl<T> diport::ManagedResource for SharedManagedResource<T>
where
    T: diport::ManagedResource + Sync,
{
    fn name(&self) -> &str {
        "deviceidentity-federated-verifier"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.inner.shutdown().await
    }
}

struct SystemClock;

impl diport::Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}
