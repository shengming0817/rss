//! Reusable settings assembly composition.
//!
//! This crate owns the complete settings domain wiring while assembly crates retain ownership of
//! concrete infrastructure bundles. All production inputs are mandatory constructor arguments;
//! there is no service bag, optional provider, or fallback path.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context as _;
use bootstrap::{DomainBinding, DomainModuleResult, WorkerSpec};
use diport::key_provider::KeyProviderErrorKind;
use diport::{
    Clock, DynKeyProvider, DynManagedResource, DynSecretResolver, KeyName, KeyProvider as _,
    ManagedResource, SecretResolver as _, SecretResolverError, ShutdownError,
};
use postgres::{ConfigValueProtections, PgDbReadiness, PgDomainDeps, PoolReadiness, caps};
use primitives::{HealthCheck, HealthStatus, ProbeName};
use secure::{Plaintext, ProtectionContext};
use settings::ports::{DynSecretRepo, DynSecretUnitOfWork};
use settings::{SettingsDomain, SettingsService, empty_flag_store};
use tokio_util::sync::CancellationToken;
use vault::{SecretResolverReadinessTarget, VaultDomainDeps, caps as vault_caps};

const DOMAIN_NAME: &str = "settings";
const KEYPROVIDER_READINESS_TENANT: &str = "00000000-0000-4000-8000-000000000147";
const KEYPROVIDER_READINESS_MISMATCH_TENANT: &str = "00000000-0000-4000-8000-000000000148";
const KEYPROVIDER_READINESS_CONFIG_KEY: &str = "readiness.probe";
const KEYPROVIDER_CONFIG_FIELD: &str = "settings.config.value";
const KEYPROVIDER_CONFIG_SCHEME: u32 = 1;
const KEYPROVIDER_READINESS_VALUE: &[u8] = b"rss-keyprovider-ready";
/// Stable readiness probe name for the settings database dependency.
pub const CONFIGS_READY_PROBE_NAME: &str = "configs_ready";
/// Stable readiness probe name for the settings key-provider dependency.
pub const KEYPROVIDER_READY_PROBE_NAME: &str = "keyprovider_ready";
/// Stable readiness probe name for the live Vault KV capability.
pub const SECRET_RESOLVER_READY_PROBE_NAME: &str = "vault_secret_resolver_ready";

/// Validated key-provider readiness sampling period.
///
/// The private field keeps zero and runaway intervals outside the settings composition boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyProviderReadinessInterval(Duration);

impl KeyProviderReadinessInterval {
    const MIN: Duration = Duration::from_secs(1);
    const MAX: Duration = Duration::from_secs(30);

    /// Validate a readiness sampling period.
    ///
    /// # Errors
    ///
    /// Returns an error unless `value` is between one and thirty seconds, inclusive.
    pub fn try_new(value: Duration) -> anyhow::Result<Self> {
        anyhow::ensure!(
            (Self::MIN..=Self::MAX).contains(&value),
            "key-provider readiness interval must be between 1s and 30s"
        );
        Ok(Self(value))
    }

    /// Return the validated duration.
    #[must_use]
    pub const fn get(self) -> Duration {
        self.0
    }
}

impl Default for KeyProviderReadinessInterval {
    fn default() -> Self {
        Self(Duration::from_secs(5))
    }
}

/// Complete, typed inputs for settings assembly wiring.
///
/// Fields are private, and the production constructor accepts one sealed Vault capability. The
/// three provider roles and their readiness lifecycle are derived internally from that capability,
/// so callers cannot self-report healthy while using a different provider for durable reads or
/// writes. Consuming `self` prevents the resulting handles from being reused by another wiring
/// path.
pub struct SettingsModuleDeps {
    pg: PgDomainDeps<caps::Settings>,
    secret_resolver: Box<DynSecretResolver<'static>>,
    read_key_provider: Box<DynKeyProvider<'static>>,
    write_key_provider: Box<DynKeyProvider<'static>>,
    key_name: KeyName,
    clock: Arc<dyn Clock>,
    readiness: SettingsReadinessDeps,
    http_surface: SettingsHttpSurface,
    projection_serving: SettingsProjectionServing,
}

#[derive(Clone, Copy)]
enum SettingsHttpSurface {
    Full,
    ConfigCud,
}

#[derive(Clone)]
enum SettingsProjectionServing {
    Disabled,
    ActiveSettingsOnly(Arc<settings::SettingsProjectionQueryService>),
}

/// Construct the Settings-owned v3 query service from the adapter's two domain-shaped ports.
///
/// The adapter exports only resolver/repository implementations; the composition root remains the
/// sole owner that can assemble them into a domain service. The returned exact `Arc` is then used
/// both as active-workflow evidence and as the explicit Settings module input.
#[must_use]
pub fn settings_projection_query_service(
    pg: &PgDomainDeps<caps::Settings>,
) -> Arc<settings::SettingsProjectionQueryService> {
    let (resolver, repository) = pg.settings_projection_query_parts();
    Arc::new(settings::SettingsProjectionQueryService::new(
        resolver, repository,
    ))
}

/// Non-optional readiness handles derived together with the three provider lifecycle outputs.
#[derive(Clone)]
pub struct SettingsReadinessDeps {
    postgres: Arc<PgDbReadiness>,
    key_provider: Arc<AtomicBool>,
    secret_resolver: Arc<AtomicBool>,
}

/// Typed, non-interchangeable Postgres readiness probe output.
pub struct SettingsPostgresReadinessOutput(DomainModuleResult);

/// Typed, non-interchangeable Vault key-provider readiness output.
pub struct SettingsKeyProviderReadinessOutput(DomainModuleResult);

/// Typed, non-interchangeable Vault secret-resolver readiness output.
pub struct SettingsSecretResolverReadinessOutput(DomainModuleResult);

/// One construction generation for Settings PG/Vault readiness and its exact provider outputs.
pub struct SettingsProviderReadiness {
    pending: SettingsProviderReadinessAwaitingPostgres,
    key_provider: SettingsKeyProviderReadinessOutput,
    secret_resolver: SettingsSecretResolverReadinessOutput,
}

/// The same Settings Vault readiness generation awaiting the live PG readiness snapshot.
pub struct SettingsProviderReadinessAwaitingPostgres {
    key_provider: Arc<AtomicBool>,
    secret_resolver: Arc<AtomicBool>,
}

impl SettingsProviderReadiness {
    /// Derive all readiness handles and lifecycle outputs from the same provider capabilities.
    pub async fn new(
        vault: &VaultDomainDeps<vault_caps::Settings>,
        key_name: KeyName,
        interval: KeyProviderReadinessInterval,
    ) -> anyhow::Result<Self> {
        verify_keyprovider_ready(&vault.key_provider(), key_name.clone())
            .await
            .context("verify settings config value key provider")?;
        let key_provider = Arc::new(AtomicBool::new(true));
        let secret_resolver = Arc::new(AtomicBool::new(false));
        let key_worker = keyprovider_readiness_worker(
            vault.key_provider(),
            key_name,
            interval.get(),
            Arc::clone(&key_provider),
        );
        let resolver_worker = secret_resolver_readiness_worker(
            vault.secret_resolver(),
            vault.secret_resolver_readiness_targets(),
            interval.get(),
            Arc::clone(&secret_resolver),
        );
        Self::from_workers(key_provider, secret_resolver, key_worker, resolver_worker)
    }

    fn from_workers(
        key_provider: Arc<AtomicBool>,
        secret_resolver: Arc<AtomicBool>,
        key_worker: WorkerSpec,
        resolver_worker: WorkerSpec,
    ) -> anyhow::Result<Self> {
        let key_name = ProbeName::parse(KEYPROVIDER_READY_PROBE_NAME)
            .context("keyprovider_ready probe name is invalid")?;
        let resolver_name = ProbeName::parse(SECRET_RESOLVER_READY_PROBE_NAME)
            .context("vault secret resolver probe name is invalid")?;
        Ok(Self {
            pending: SettingsProviderReadinessAwaitingPostgres {
                key_provider: Arc::clone(&key_provider),
                secret_resolver: Arc::clone(&secret_resolver),
            },
            key_provider: SettingsKeyProviderReadinessOutput(DomainModuleResult {
                probes: vec![(key_name, Box::new(KeyProviderReadyProbe::new(key_provider)))],
                workers: vec![key_worker],
                ..Default::default()
            }),
            secret_resolver: SettingsSecretResolverReadinessOutput(DomainModuleResult {
                probes: vec![(
                    resolver_name,
                    Box::new(SecretResolverReadyProbe::new(secret_resolver)),
                )],
                workers: vec![resolver_worker],
                ..Default::default()
            }),
        })
    }

    /// Consume the construction generation into domain handles and exact provider outputs.
    pub fn into_vault_parts(
        self,
    ) -> (
        SettingsProviderReadinessAwaitingPostgres,
        SettingsKeyProviderReadinessOutput,
        SettingsSecretResolverReadinessOutput,
    ) {
        (self.pending, self.key_provider, self.secret_resolver)
    }
}

impl SettingsProviderReadinessAwaitingPostgres {
    /// Bind the live PG snapshot and complete the non-optional domain readiness receipt.
    pub fn bind_postgres(
        self,
        postgres: Arc<PgDbReadiness>,
    ) -> anyhow::Result<(SettingsReadinessDeps, SettingsPostgresReadinessOutput)> {
        let name = ProbeName::parse(CONFIGS_READY_PROBE_NAME)
            .context("configs_ready probe name is invalid")?;
        Ok((
            SettingsReadinessDeps {
                postgres: Arc::clone(&postgres),
                key_provider: self.key_provider,
                secret_resolver: self.secret_resolver,
            },
            SettingsPostgresReadinessOutput(DomainModuleResult {
                probes: vec![(name, Box::new(ConfigsReadyProbe::new(postgres)))],
                ..Default::default()
            }),
        ))
    }
}

impl SettingsPostgresReadinessOutput {
    /// Consume the typed output into the assembly lifecycle carrier.
    pub fn into_output(self) -> DomainModuleResult {
        self.0
    }
}

impl SettingsKeyProviderReadinessOutput {
    /// Consume the typed output into the assembly lifecycle carrier.
    pub fn into_output(self) -> DomainModuleResult {
        self.0
    }
}

impl SettingsSecretResolverReadinessOutput {
    /// Consume the typed output into the assembly lifecycle carrier.
    pub fn into_output(self) -> DomainModuleResult {
        self.0
    }
}

impl SettingsModuleDeps {
    /// Construct settings from capabilities whose readiness lifecycle was already claimed by the
    /// assembly's provider transaction.
    #[must_use]
    pub fn new(
        pg: PgDomainDeps<caps::Settings>,
        vault: VaultDomainDeps<vault_caps::Settings>,
        key_name: KeyName,
        clock: Arc<dyn Clock>,
        readiness: SettingsReadinessDeps,
    ) -> Self {
        Self {
            pg,
            secret_resolver: vault.secret_resolver(),
            read_key_provider: vault.key_provider(),
            write_key_provider: vault.key_provider(),
            key_name,
            clock,
            readiness,
            http_surface: SettingsHttpSurface::Full,
            projection_serving: SettingsProjectionServing::Disabled,
        }
    }

    /// Select the closed settingsonly HTTP surface without exposing a route allowlist.
    #[must_use]
    pub fn config_cud_only(mut self) -> Self {
        self.http_surface = SettingsHttpSurface::ConfigCud;
        self
    }

    /// Select the settings-only route surface and consume its exact active v3 query capability in
    /// one closed choice. Callers cannot declare active serving without supplying the callable
    /// service instance retained by the sealed assembly plan.
    #[must_use]
    pub fn config_cud_only_with_projection_serving(
        mut self,
        serving: Arc<settings::SettingsProjectionQueryService>,
    ) -> Self {
        self.http_surface = SettingsHttpSurface::ConfigCud;
        self.projection_serving = SettingsProjectionServing::ActiveSettingsOnly(serving);
        self
    }

    #[cfg(any(test, feature = "test-support"))]
    #[allow(clippy::too_many_arguments)]
    fn for_test(
        pg: PgDomainDeps<caps::Settings>,
        secret_resolver: Box<DynSecretResolver<'static>>,
        read_key_provider: Box<DynKeyProvider<'static>>,
        write_key_provider: Box<DynKeyProvider<'static>>,
        key_name: KeyName,
        clock: Arc<dyn Clock>,
        readiness: SettingsReadinessDeps,
    ) -> Self {
        Self {
            pg,
            secret_resolver,
            read_key_provider,
            write_key_provider,
            key_name,
            clock,
            readiness,
            http_surface: SettingsHttpSurface::Full,
            projection_serving: SettingsProjectionServing::Disabled,
        }
    }
}

struct SharedClock(Arc<dyn Clock>);

impl Clock for SharedClock {
    fn now(&self) -> std::time::SystemTime {
        self.0.now()
    }
}

/// Build the settings domain as one owned binding.
///
/// Startup performs a real encrypt/decrypt/AAD-mismatch self-check before constructing durable
/// repositories. Provider readiness lifecycle is not copied into the domain binding output: the
/// same construction generation already returned it through [`SettingsPostgresReadinessOutput`],
/// [`SettingsKeyProviderReadinessOutput`], and [`SettingsSecretResolverReadinessOutput`].
///
/// # Errors
///
/// Returns an error when the key provider self-check fails or a stable probe name is invalid.
pub async fn wire(deps: SettingsModuleDeps) -> anyhow::Result<DomainBinding> {
    let SettingsModuleDeps {
        pg,
        secret_resolver,
        read_key_provider,
        write_key_provider,
        key_name,
        clock,
        readiness,
        http_surface,
        projection_serving,
    } = deps;
    let SettingsReadinessDeps {
        postgres: readiness_postgres,
        key_provider: readiness_key_provider,
        secret_resolver: readiness_secret_resolver,
    } = readiness;
    drop((
        readiness_postgres,
        readiness_key_provider,
        readiness_secret_resolver,
    ));
    let output = DomainModuleResult::default();

    let service_clock = Arc::clone(&clock);
    let (configs, writer, secrets, secret_writer) = pg
        .settings_bundle(
            clock,
            ConfigValueProtections::new(read_key_provider, write_key_provider, key_name),
        )
        .into_parts();
    let config_svc = SettingsService::with_postgres(
        configs,
        writer,
        empty_flag_store(),
        Box::new(SharedClock(Arc::clone(&service_clock))),
    );
    let secret_repo: Arc<DynSecretRepo<'static>> = Arc::from(secrets);
    let secret_uow: Arc<DynSecretUnitOfWork<'static>> = Arc::from(secret_writer);
    let secret_svc = Arc::new(settings::SecretResolveService::new(
        Arc::clone(&secret_repo),
        secret_resolver,
    ));
    let domain = SettingsDomain::new(Arc::new(config_svc), secret_repo, secret_uow, secret_svc);
    let mounted_domain: Box<dyn bootstrap::Domain> = match projection_serving {
        SettingsProjectionServing::Disabled => match http_surface {
            SettingsHttpSurface::Full => Box::new(domain),
            SettingsHttpSurface::ConfigCud => Box::new(domain.config_cud_only()),
        },
        SettingsProjectionServing::ActiveSettingsOnly(serving) => {
            anyhow::ensure!(
                matches!(http_surface, SettingsHttpSurface::ConfigCud),
                "active Settings v3 serving requires the sealed settings-only surface"
            );
            Box::new(settings::SettingsProjectionServingDomain::new(
                domain.config_cud_only(),
                serving,
            ))
        }
    };
    Ok(DomainBinding::new(DOMAIN_NAME, mounted_domain, output))
}

/// Build a key-provider readiness worker tied to the supplied shared readiness snapshot.
#[must_use]
fn keyprovider_readiness_worker(
    provider: Box<DynKeyProvider<'static>>,
    key_name: KeyName,
    period: Duration,
    ready: Arc<AtomicBool>,
) -> WorkerSpec {
    WorkerSpec::phase_one(move |token| {
        DynManagedResource::new_box(spawn_keyprovider_readiness_sampler(
            provider, key_name, period, token, ready,
        ))
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResolverReadinessSample {
    Ready,
    Down,
}

async fn sample_secret_resolver_readiness(
    resolver: &DynSecretResolver<'static>,
    targets: &[SecretResolverReadinessTarget],
) -> ResolverReadinessSample {
    for target in targets {
        match resolver.resolve(target.tenant(), target.coordinate()).await {
            Ok(_) => {}
            Err(SecretResolverError::Forbidden) => return ResolverReadinessSample::Down,
            Err(
                SecretResolverError::StoreUnreachable { .. }
                | SecretResolverError::Timeout
                | SecretResolverError::NotFound
                | SecretResolverError::VersionNotFound,
            ) => return ResolverReadinessSample::Down,
            Err(_) => return ResolverReadinessSample::Down,
        }
    }
    ResolverReadinessSample::Ready
}

fn apply_secret_resolver_readiness_sample(ready: &AtomicBool, sample: ResolverReadinessSample) {
    match sample {
        ResolverReadinessSample::Ready => ready.store(true, Ordering::Release),
        ResolverReadinessSample::Down => ready.store(false, Ordering::Release),
    }
}

fn secret_resolver_readiness_worker(
    resolver: Box<DynSecretResolver<'static>>,
    targets: Vec<SecretResolverReadinessTarget>,
    period: Duration,
    ready: Arc<AtomicBool>,
) -> WorkerSpec {
    WorkerSpec::phase_one(move |token| {
        DynManagedResource::new_box(spawn_secret_resolver_readiness_sampler(
            resolver, targets, period, token, ready,
        ))
    })
}

/// DB readiness probe backed by the shared, non-blocking postgres snapshot.
pub struct ConfigsReadyProbe {
    health: Arc<PgDbReadiness>,
    name: ProbeName,
}

impl ConfigsReadyProbe {
    /// Construct the settings database readiness probe.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn new(health: Arc<PgDbReadiness>) -> Self {
        let name = ProbeName::parse(CONFIGS_READY_PROBE_NAME).expect("valid probe name const");
        Self { health, name }
    }
}

impl bootstrap::HealthProbe for ConfigsReadyProbe {
    fn check(&self) -> HealthCheck {
        let (status, detail) = readiness_to_health(self.health.snapshot());
        HealthCheck::new(self.name.clone(), status, detail)
    }
}

/// Key-provider probe backed by the sampler's shared readiness snapshot.
pub struct KeyProviderReadyProbe {
    ready: Arc<AtomicBool>,
    name: ProbeName,
}

/// Vault KV capability probe backed by the resolver canary sampler.
pub struct SecretResolverReadyProbe {
    ready: Arc<AtomicBool>,
    name: ProbeName,
}

impl SecretResolverReadyProbe {
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn new(ready: Arc<AtomicBool>) -> Self {
        let name =
            ProbeName::parse(SECRET_RESOLVER_READY_PROBE_NAME).expect("valid probe name const");
        Self { ready, name }
    }
}

impl bootstrap::HealthProbe for SecretResolverReadyProbe {
    fn check(&self) -> HealthCheck {
        let (status, detail) = if self.ready.load(Ordering::Acquire) {
            (HealthStatus::Healthy, "ready")
        } else {
            (HealthStatus::Unhealthy, "down")
        };
        HealthCheck::new(self.name.clone(), status, detail)
    }
}

impl KeyProviderReadyProbe {
    /// Construct the key-provider readiness probe.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn new(ready: Arc<AtomicBool>) -> Self {
        let name = ProbeName::parse(KEYPROVIDER_READY_PROBE_NAME).expect("valid probe name const");
        Self { ready, name }
    }
}

impl bootstrap::HealthProbe for KeyProviderReadyProbe {
    fn check(&self) -> HealthCheck {
        let (status, detail) = if self.ready.load(Ordering::Acquire) {
            (HealthStatus::Healthy, "ready")
        } else {
            (HealthStatus::Unhealthy, "down")
        };
        HealthCheck::new(self.name.clone(), status, detail)
    }
}

fn readiness_to_health(readiness: PoolReadiness) -> (HealthStatus, &'static str) {
    match readiness {
        PoolReadiness::Ready => (HealthStatus::Healthy, "ready"),
        PoolReadiness::Saturated => (HealthStatus::Unhealthy, "saturated"),
        PoolReadiness::Down => (HealthStatus::Unhealthy, "down"),
        _ => (HealthStatus::Unhealthy, "unknown"),
    }
}

fn keyprovider_readiness_aad(tenant: &str) -> anyhow::Result<secure::DerivedAad> {
    let tenant = vocab::TenantId::parse(tenant)
        .context("keyprovider readiness tenant constant is invalid")?;
    ProtectionContext::authenticated_request(
        tenant,
        KEYPROVIDER_READINESS_CONFIG_KEY,
        KEYPROVIDER_CONFIG_FIELD,
        KEYPROVIDER_CONFIG_SCHEME,
    )
    .map(|context| context.derive())
    .context("keyprovider readiness aad")
}

async fn verify_keyprovider_ready(
    provider: &DynKeyProvider<'static>,
    key_name: KeyName,
) -> anyhow::Result<()> {
    let aad = keyprovider_readiness_aad(KEYPROVIDER_READINESS_TENANT)?;
    let encrypted = provider
        .encrypt(
            key_name,
            Plaintext::new(KEYPROVIDER_READINESS_VALUE.to_vec()),
            aad.clone(),
        )
        .await
        .context("key provider readiness encrypt")?;
    let key_ref = encrypted.key().clone();
    let plaintext = provider
        .decrypt(
            diport::RedactedBytes::new(encrypted.ciphertext().to_vec()),
            key_ref.clone(),
            aad,
        )
        .await
        .context("key provider readiness decrypt")?;
    anyhow::ensure!(
        plaintext.expose() == KEYPROVIDER_READINESS_VALUE,
        "key provider readiness plaintext mismatch"
    );

    let mismatch_aad = keyprovider_readiness_aad(KEYPROVIDER_READINESS_MISMATCH_TENANT)?;
    match provider
        .decrypt(
            diport::RedactedBytes::new(encrypted.ciphertext().to_vec()),
            key_ref,
            mismatch_aad,
        )
        .await
    {
        Ok(_) => anyhow::bail!("key provider accepted mismatched readiness aad"),
        Err(error) if error.kind() == KeyProviderErrorKind::Rejected => Ok(()),
        Err(error) => Err(error).context("key provider readiness mismatched aad decrypt"),
    }
}

struct KeyProviderReadinessSampler {
    handle: tokio::sync::Mutex<Option<diport::OwnedTask<()>>>,
    token: CancellationToken,
}

impl ManagedResource for KeyProviderReadinessSampler {
    fn name(&self) -> &str {
        "keyprovider-readiness-sampler"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.token.cancel();
        let mut handle = self.handle.lock().await;
        if let Some(handle) = handle.take() {
            handle
                .join()
                .await
                .map_err(ShutdownError::from_join_error)?;
        }
        Ok(())
    }
}

fn spawn_keyprovider_readiness_sampler(
    provider: Box<DynKeyProvider<'static>>,
    key_name: KeyName,
    period: Duration,
    token: CancellationToken,
    ready: Arc<AtomicBool>,
) -> KeyProviderReadinessSampler {
    let child = token.child_token();
    let worker_token = child.clone();
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                () = worker_token.cancelled() => break,
                () = tokio::time::sleep(period) => {
                    let is_ready = verify_keyprovider_ready(&provider, key_name.clone()).await.is_ok();
                    ready.store(is_ready, Ordering::Release);
                }
            }
        }
    });
    KeyProviderReadinessSampler {
        handle: tokio::sync::Mutex::new(Some(diport::OwnedTask::new(handle))),
        token: child,
    }
}

struct SecretResolverReadinessSampler {
    handle: tokio::sync::Mutex<Option<diport::OwnedTask<()>>>,
    token: CancellationToken,
}

impl ManagedResource for SecretResolverReadinessSampler {
    fn name(&self) -> &str {
        "vault-secret-resolver-readiness-sampler"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.token.cancel();
        let mut handle = self.handle.lock().await;
        if let Some(handle) = handle.take() {
            handle
                .join()
                .await
                .map_err(ShutdownError::from_join_error)?;
        }
        Ok(())
    }
}

fn spawn_secret_resolver_readiness_sampler(
    resolver: Box<DynSecretResolver<'static>>,
    targets: Vec<SecretResolverReadinessTarget>,
    period: Duration,
    token: CancellationToken,
    ready: Arc<AtomicBool>,
) -> SecretResolverReadinessSampler {
    let child = token.child_token();
    let worker_token = child.clone();
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                () = worker_token.cancelled() => break,
                () = tokio::time::sleep(period) => {
                    let sample = sample_secret_resolver_readiness(&resolver, &targets).await;
                    apply_secret_resolver_readiness_sample(&ready, sample);
                }
            }
        }
    });
    SecretResolverReadinessSampler {
        handle: tokio::sync::Mutex::new(Some(diport::OwnedTask::new(handle))),
        token: child,
    }
}

/// Hermetic settings binding for generated assembly tests.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::*;
    use diport::{
        EncryptOutput, KeyProvider, KeyProviderError, KeyRef, KeyVersion, RedactedBytes,
        SecretCoordinate, SecretMaterial, SecretResolver,
    };
    use secure::{DerivedAad, Plaintext};

    #[derive(Default)]
    struct TestKeyProvider {
        decrypt_count: AtomicBool,
    }

    impl KeyProvider for TestKeyProvider {
        async fn encrypt(
            &self,
            key: KeyName,
            _plaintext: Plaintext,
            _aad: DerivedAad,
        ) -> Result<EncryptOutput, KeyProviderError> {
            Ok(EncryptOutput::new(
                b"module-test-ciphertext".to_vec(),
                KeyRef::new(key, KeyVersion::new(1)),
            ))
        }

        async fn decrypt(
            &self,
            _ciphertext: RedactedBytes,
            _key: KeyRef,
            _aad: DerivedAad,
        ) -> Result<Plaintext, KeyProviderError> {
            if !self.decrypt_count.swap(true, Ordering::Relaxed) {
                Ok(Plaintext::new(KEYPROVIDER_READINESS_VALUE.to_vec()))
            } else {
                Err(KeyProviderError::new(
                    KeyProviderErrorKind::Rejected,
                    std::io::Error::other("module test aad mismatch"),
                ))
            }
        }

        async fn rewrap(
            &self,
            _ciphertext: RedactedBytes,
            key: KeyRef,
            _aad: DerivedAad,
        ) -> Result<EncryptOutput, KeyProviderError> {
            Ok(EncryptOutput::new(b"module-test-rewrapped".to_vec(), key))
        }

        async fn shutdown(&self) -> Result<(), KeyProviderError> {
            Ok(())
        }
    }

    struct EpochClock;

    impl Clock for EpochClock {
        fn now(&self) -> std::time::SystemTime {
            std::time::SystemTime::UNIX_EPOCH
        }
    }

    fn provider() -> Box<DynKeyProvider<'static>> {
        DynKeyProvider::new_box(TestKeyProvider::default())
    }

    struct TestSecretResolver;

    /// Mint healthy readiness handles for hermetic assembly tests only.
    pub fn readiness(postgres: Arc<PgDbReadiness>) -> SettingsReadinessDeps {
        SettingsReadinessDeps {
            postgres,
            key_provider: Arc::new(AtomicBool::new(true)),
            secret_resolver: Arc::new(AtomicBool::new(true)),
        }
    }

    impl SecretResolver for TestSecretResolver {
        async fn resolve(
            &self,
            _tenant: vocab::TenantId,
            _coordinate: &SecretCoordinate,
        ) -> Result<SecretMaterial, SecretResolverError> {
            Err(SecretResolverError::NotFound)
        }
    }

    /// Build a deterministic settings binding without network or database I/O.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixed test key or settings composition cannot be constructed.
    pub async fn binding() -> anyhow::Result<DomainBinding> {
        let pg = postgres::PgRuntimeHandle::for_ready_module_test();
        let key_name = KeyName::try_new("settings-config")?;
        wire(SettingsModuleDeps::for_test(
            pg.for_domain(),
            DynSecretResolver::new_box(TestSecretResolver),
            provider(),
            provider(),
            key_name,
            Arc::new(EpochClock),
            readiness(pg.readiness_handle()),
        ))
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::AtomicU8;

    use bootstrap::{HealthProbe as _, compose_bindings};
    use diport::{
        EncryptOutput, KeyProvider, KeyProviderError, KeyRef, KeyVersion, RedactedBytes,
        SecretCoordinate, SecretMaterial, SecretResolver,
    };
    use secure::DerivedAad;
    use vault::{
        StoreBinding, TenantStoreAllowlist, VaultKeyProvider, VaultRuntimeDeps, VaultSecretResolver,
    };

    #[tokio::test]
    #[allow(clippy::expect_used, clippy::panic)]
    async fn readiness_samplers_propagate_closed_join_failure_kinds() {
        let key_provider = KeyProviderReadinessSampler {
            handle: tokio::sync::Mutex::new(Some(diport::OwnedTask::new(tokio::spawn(async {
                panic!("settings-readiness-plain-panic-secret");
            })))),
            token: CancellationToken::new(),
        };
        let error = key_provider
            .shutdown()
            .await
            .expect_err("panic must propagate");
        assert_eq!(error.kind(), diport::ShutdownErrorKind::TaskPanicked);
        assert!(!format!("{error:?}").contains("plain-panic-secret"));

        let handle = tokio::spawn(std::future::pending::<()>());
        handle.abort();
        let secret_resolver = SecretResolverReadinessSampler {
            handle: tokio::sync::Mutex::new(Some(diport::OwnedTask::new(handle))),
            token: CancellationToken::new(),
        };
        let error = secret_resolver
            .shutdown()
            .await
            .expect_err("cancellation must propagate");
        assert_eq!(error.kind(), diport::ShutdownErrorKind::TaskCancelled);
    }

    struct ReadinessTestWorker;

    impl ManagedResource for ReadinessTestWorker {
        fn name(&self) -> &str {
            "settings-readiness-test-worker"
        }

        async fn shutdown(&self) -> Result<(), ShutdownError> {
            Ok(())
        }
    }

    fn readiness_test_worker() -> WorkerSpec {
        WorkerSpec::phase_one(|_| DynManagedResource::new_box(ReadinessTestWorker))
    }

    struct FailingKeyProvider;

    impl KeyProvider for FailingKeyProvider {
        async fn encrypt(
            &self,
            _key: KeyName,
            _plaintext: Plaintext,
            _aad: DerivedAad,
        ) -> Result<EncryptOutput, KeyProviderError> {
            Err(keyprovider_unavailable())
        }

        async fn decrypt(
            &self,
            _ciphertext: RedactedBytes,
            _key: KeyRef,
            _aad: DerivedAad,
        ) -> Result<Plaintext, KeyProviderError> {
            Err(keyprovider_unavailable())
        }

        async fn rewrap(
            &self,
            _ciphertext: RedactedBytes,
            _key: KeyRef,
            _aad: DerivedAad,
        ) -> Result<EncryptOutput, KeyProviderError> {
            Err(keyprovider_unavailable())
        }

        async fn shutdown(&self) -> Result<(), KeyProviderError> {
            Ok(())
        }
    }

    struct AadBlindKeyProvider;

    impl KeyProvider for AadBlindKeyProvider {
        async fn encrypt(
            &self,
            key: KeyName,
            _plaintext: Plaintext,
            _aad: DerivedAad,
        ) -> Result<EncryptOutput, KeyProviderError> {
            Ok(EncryptOutput::new(
                b"vault:v1:test".to_vec(),
                KeyRef::new(key, KeyVersion::new(1)),
            ))
        }

        async fn decrypt(
            &self,
            _ciphertext: RedactedBytes,
            _key: KeyRef,
            _aad: DerivedAad,
        ) -> Result<Plaintext, KeyProviderError> {
            Ok(Plaintext::new(KEYPROVIDER_READINESS_VALUE.to_vec()))
        }

        async fn rewrap(
            &self,
            _ciphertext: RedactedBytes,
            _key: KeyRef,
            _aad: DerivedAad,
        ) -> Result<EncryptOutput, KeyProviderError> {
            Err(keyprovider_unavailable())
        }

        async fn shutdown(&self) -> Result<(), KeyProviderError> {
            Ok(())
        }
    }

    fn keyprovider_unavailable() -> KeyProviderError {
        KeyProviderError::new(
            KeyProviderErrorKind::Unavailable,
            std::io::Error::other("test keyprovider unavailable"),
        )
    }

    struct ScriptedSecretResolver {
        mode: Arc<AtomicU8>,
    }

    impl SecretResolver for ScriptedSecretResolver {
        async fn resolve(
            &self,
            _tenant: vocab::TenantId,
            _coordinate: &SecretCoordinate,
        ) -> Result<SecretMaterial, SecretResolverError> {
            match self.mode.load(Ordering::Acquire) {
                0 => Ok(SecretMaterial::new(b"ready".to_vec())),
                1 => Err(SecretResolverError::Forbidden),
                2 => Err(SecretResolverError::store_unreachable(
                    std::io::Error::other("scripted provider failure"),
                )),
                3 => Err(SecretResolverError::Timeout),
                _ => Err(SecretResolverError::NotFound),
            }
        }
    }

    #[allow(clippy::expect_used)]
    fn resolver_readiness_targets() -> Vec<SecretResolverReadinessTarget> {
        let tenant = vocab::TenantId::parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
            .expect("canonical readiness fixture tenant");
        let stores = TenantStoreAllowlist::new([(
            (tenant, "vault".to_owned()),
            StoreBinding {
                mount: "secret".to_owned(),
                kv_path_prefix: "tenants/a".to_owned(),
            },
        )])
        .expect("valid readiness fixture allowlist");
        VaultSecretResolver::new(
            reqwest::Client::new(),
            "https://vault.example:8200",
            "s.testtoken",
            Duration::from_secs(5),
            stores,
        )
        .expect("valid readiness fixture resolver")
        .readiness_targets()
    }

    #[test]
    fn readiness_mapping_is_fail_closed() {
        assert_eq!(
            readiness_to_health(PoolReadiness::Ready),
            (HealthStatus::Healthy, "ready")
        );
        assert_eq!(
            readiness_to_health(PoolReadiness::Saturated),
            (HealthStatus::Unhealthy, "saturated")
        );
        assert_eq!(
            readiness_to_health(PoolReadiness::Down),
            (HealthStatus::Unhealthy, "down")
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn production_constructor_derives_all_roles_from_one_sealed_vault_capability() {
        let tenant = vocab::TenantId::parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
            .expect("canonical unused fixture tenant");
        let stores = TenantStoreAllowlist::new([(
            (tenant, "vault".to_owned()),
            StoreBinding {
                mount: "secret".to_owned(),
                kv_path_prefix: "tenants/a".to_owned(),
            },
        )])
        .expect("valid unused fixture allowlist");
        let vault = VaultRuntimeDeps::new(
            VaultSecretResolver::new(
                reqwest::Client::new(),
                "https://vault.example:8200",
                "s.testtoken",
                Duration::from_secs(5),
                stores,
            )
            .expect("valid resolver"),
            VaultKeyProvider::new(
                reqwest::Client::new(),
                "https://vault.example:8200",
                "s.testtoken",
                "transit",
                Duration::from_secs(5),
            )
            .expect("valid key provider"),
        );

        let readiness = SettingsProviderReadiness::new(
            &vault.for_domain::<vault_caps::Settings>(),
            KeyName::try_new("settings-config").expect("valid key name"),
            KeyProviderReadinessInterval::try_new(Duration::from_secs(7))
                .expect("valid readiness interval"),
        )
        .await;
        assert!(
            readiness.is_err(),
            "unreachable Vault must fail startup verification"
        );
    }

    #[test]
    fn keyprovider_readiness_interval_rejects_hot_loop_and_runaway_values() {
        assert!(KeyProviderReadinessInterval::try_new(Duration::ZERO).is_err());
        assert!(KeyProviderReadinessInterval::try_new(Duration::from_millis(999)).is_err());
        assert!(KeyProviderReadinessInterval::try_new(Duration::from_secs(1)).is_ok());
        assert!(KeyProviderReadinessInterval::try_new(Duration::from_secs(30)).is_ok());
        assert!(KeyProviderReadinessInterval::try_new(Duration::from_secs(31)).is_err());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn keyprovider_probe_observes_shared_snapshot() {
        let ready = Arc::new(AtomicBool::new(true));
        let probe = KeyProviderReadyProbe::new(Arc::clone(&ready));
        assert_eq!(probe.check().status(), HealthStatus::Healthy);
        ready.store(false, Ordering::Release);
        assert_eq!(probe.check().status(), HealthStatus::Unhealthy);
    }

    #[tokio::test]
    async fn secret_resolver_readiness_fails_closed_and_recovers() {
        let mode = Arc::new(AtomicU8::new(0));
        let resolver = DynSecretResolver::new_box(ScriptedSecretResolver {
            mode: Arc::clone(&mode),
        });
        let targets = resolver_readiness_targets();
        let ready = AtomicBool::new(false);

        let sample = sample_secret_resolver_readiness(&resolver, &targets).await;
        assert_eq!(sample, ResolverReadinessSample::Ready);
        apply_secret_resolver_readiness_sample(&ready, sample);
        assert!(ready.load(Ordering::Acquire), "success recovers readiness");

        mode.store(2, Ordering::Release);
        let sample = sample_secret_resolver_readiness(&resolver, &targets).await;
        assert_eq!(sample, ResolverReadinessSample::Down);
        apply_secret_resolver_readiness_sample(&ready, sample);
        assert!(
            !ready.load(Ordering::Acquire),
            "provider failure marks down"
        );

        mode.store(0, Ordering::Release);
        let sample = sample_secret_resolver_readiness(&resolver, &targets).await;
        apply_secret_resolver_readiness_sample(&ready, sample);
        assert!(
            ready.load(Ordering::Acquire),
            "later success recovers readiness"
        );

        mode.store(1, Ordering::Release);
        let sample = sample_secret_resolver_readiness(&resolver, &targets).await;
        assert_eq!(sample, ResolverReadinessSample::Down);
        apply_secret_resolver_readiness_sample(&ready, sample);
        assert!(
            !ready.load(Ordering::Acquire),
            "Forbidden must fail readiness closed"
        );

        mode.store(0, Ordering::Release);
        let sample = sample_secret_resolver_readiness(&resolver, &targets).await;
        apply_secret_resolver_readiness_sample(&ready, sample);
        assert!(
            ready.load(Ordering::Acquire),
            "success recovers after Forbidden"
        );

        mode.store(3, Ordering::Release);
        let sample = sample_secret_resolver_readiness(&resolver, &targets).await;
        assert_eq!(sample, ResolverReadinessSample::Down);
        apply_secret_resolver_readiness_sample(&ready, sample);
        assert!(!ready.load(Ordering::Acquire), "timeout marks down");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn hermetic_binding_composes_with_stable_output_order() {
        let mut bindings = vec![
            test_support::binding()
                .await
                .expect("hermetic settings binding builds"),
        ];
        assert_eq!(bindings[0].name(), DOMAIN_NAME);
        let (_, output) = compose_bindings(&mut bindings).expect("settings binding composes");
        assert!(bindings.is_empty());
        assert!(
            output.probes.is_empty(),
            "provider probes must not be duplicated by domain wiring"
        );
        assert!(output.resources.is_empty());
        assert!(
            output.workers.is_empty(),
            "provider samplers must not be duplicated by domain wiring"
        );
    }

    #[tokio::test]
    async fn typed_provider_readiness_outputs_are_non_interchangeable_and_exact()
    -> anyhow::Result<()> {
        let readiness = SettingsProviderReadiness::from_workers(
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicBool::new(true)),
            readiness_test_worker(),
            readiness_test_worker(),
        )?;
        let (pending, key, resolver) = readiness.into_vault_parts();
        let pg = postgres::PgRuntimeHandle::for_ready_module_test();
        let (_deps, postgres) = pending.bind_postgres(pg.readiness_handle())?;
        let postgres = postgres.into_output();
        let key = key.into_output();
        let resolver = resolver.into_output();
        assert_eq!((postgres.probes.len(), postgres.workers.len()), (1, 0));
        assert_eq!(postgres.probes[0].0.as_str(), CONFIGS_READY_PROBE_NAME);
        assert!(postgres.resources.is_empty());
        assert_eq!((key.probes.len(), key.workers.len()), (1, 1));
        assert_eq!(key.probes[0].0.as_str(), KEYPROVIDER_READY_PROBE_NAME);
        assert!(key.resources.is_empty());
        assert_eq!((resolver.probes.len(), resolver.workers.len()), (1, 1));
        assert_eq!(
            resolver.probes[0].0.as_str(),
            SECRET_RESOLVER_READY_PROBE_NAME
        );
        assert!(resolver.resources.is_empty());
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn startup_self_check_preserves_provider_failure_context() {
        let provider = DynKeyProvider::new_box(FailingKeyProvider);
        let key = KeyName::try_new("settings-config").expect("valid key");
        let error = verify_keyprovider_ready(&provider, key)
            .await
            .expect_err("failing provider must fail readiness self-check");
        assert!(
            format!("{error:#}").contains("key provider readiness encrypt"),
            "startup error should retain operation context: {error:#}"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn startup_self_check_rejects_aad_blind_provider() {
        let provider = DynKeyProvider::new_box(AadBlindKeyProvider);
        let key = KeyName::try_new("settings-config").expect("valid key");
        let error = verify_keyprovider_ready(&provider, key)
            .await
            .expect_err("AAD-blind provider must fail readiness self-check");
        assert!(
            format!("{error:#}").contains("accepted mismatched readiness aad"),
            "self-check must prove mismatched AAD fails closed: {error:#}"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn readiness_worker_updates_snapshot_and_drains() {
        let ready = Arc::new(AtomicBool::new(true));
        let worker = keyprovider_readiness_worker(
            DynKeyProvider::new_box(FailingKeyProvider),
            KeyName::try_new("settings-config").expect("valid key"),
            Duration::from_millis(1),
            Arc::clone(&ready),
        );
        let resource = match worker {
            WorkerSpec::PhaseOne(make) | WorkerSpec::Deferred(make) => {
                make(CancellationToken::new())
            }
        };

        tokio::time::timeout(Duration::from_secs(1), async {
            while ready.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("sampler updates readiness within timeout");
        resource.shutdown().await.expect("sampler drains cleanly");
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::expect_used)]
    async fn readiness_worker_waits_for_the_exact_injected_interval() {
        let ready = Arc::new(AtomicBool::new(true));
        let worker = keyprovider_readiness_worker(
            DynKeyProvider::new_box(FailingKeyProvider),
            KeyName::try_new("settings-config").expect("valid key"),
            Duration::from_secs(7),
            Arc::clone(&ready),
        );
        let resource = match worker {
            WorkerSpec::PhaseOne(make) | WorkerSpec::Deferred(make) => {
                make(CancellationToken::new())
            }
        };
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(6)).await;
        tokio::task::yield_now().await;
        assert!(ready.load(Ordering::Acquire));

        tokio::time::advance(Duration::from_secs(1)).await;
        for _ in 0..16 {
            if !ready.load(Ordering::Acquire) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(!ready.load(Ordering::Acquire));
        resource.shutdown().await.expect("sampler drains cleanly");
    }
}
