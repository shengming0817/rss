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
    Clock, DynKeyProvider, DynManagedResource, KeyName, KeyProvider as _, ManagedResource,
    ShutdownError,
};
use postgres::{ConfigValueProtections, PgDbReadiness, PgDomainDeps, PoolReadiness, caps};
use primitives::{HealthCheck, HealthStatus, ProbeName};
use secure::{Plaintext, ProtectionContext};
use settings::ports::{DynSecretRepo, DynSecretUnitOfWork};
use settings::{SettingsDomain, SettingsService, empty_flag_store};
use tokio_util::sync::CancellationToken;
use vault::{VaultDomainDeps, caps as vault_caps};

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
    pg_readiness: Arc<PgDbReadiness>,
    readiness_key_provider: Box<DynKeyProvider<'static>>,
    read_key_provider: Box<DynKeyProvider<'static>>,
    write_key_provider: Box<DynKeyProvider<'static>>,
    key_name: KeyName,
    clock: Arc<dyn Clock>,
    keyprovider_ready: Arc<AtomicBool>,
    readiness_worker: WorkerSpec,
}

impl SettingsModuleDeps {
    /// Construct the settings composition inputs from one sealed settings Vault capability.
    #[must_use]
    pub fn new(
        pg: PgDomainDeps<caps::Settings>,
        pg_readiness: Arc<PgDbReadiness>,
        vault: VaultDomainDeps<vault_caps::Settings>,
        key_name: KeyName,
        clock: Arc<dyn Clock>,
        keyprovider_readiness_interval: KeyProviderReadinessInterval,
    ) -> Self {
        let keyprovider_ready = Arc::new(AtomicBool::new(true));
        let readiness_worker = keyprovider_readiness_worker(
            vault.key_provider(),
            key_name.clone(),
            keyprovider_readiness_interval.get(),
            Arc::clone(&keyprovider_ready),
        );
        Self {
            pg,
            pg_readiness,
            readiness_key_provider: vault.key_provider(),
            read_key_provider: vault.key_provider(),
            write_key_provider: vault.key_provider(),
            key_name,
            clock,
            keyprovider_ready,
            readiness_worker,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[allow(clippy::too_many_arguments)]
    fn for_test(
        pg: PgDomainDeps<caps::Settings>,
        pg_readiness: Arc<PgDbReadiness>,
        readiness_key_provider: Box<DynKeyProvider<'static>>,
        read_key_provider: Box<DynKeyProvider<'static>>,
        write_key_provider: Box<DynKeyProvider<'static>>,
        key_name: KeyName,
        clock: Arc<dyn Clock>,
        keyprovider_ready: Arc<AtomicBool>,
        readiness_worker: WorkerSpec,
    ) -> Self {
        Self {
            pg,
            pg_readiness,
            readiness_key_provider,
            read_key_provider,
            write_key_provider,
            key_name,
            clock,
            keyprovider_ready,
            readiness_worker,
        }
    }
}

struct SharedClock(Arc<dyn Clock>);

impl Clock for SharedClock {
    fn now(&self) -> std::time::SystemTime {
        self.0.now()
    }
}

/// Build the settings domain and its lifecycle output as one owned binding.
///
/// Startup performs a real encrypt/decrypt/AAD-mismatch self-check before constructing durable
/// repositories. Probe/resource/worker ordering is stable: `configs_ready`,
/// `keyprovider_ready`, no detached resources, then the single readiness worker.
///
/// # Errors
///
/// Returns an error when the key provider self-check fails or a stable probe name is invalid.
pub async fn wire(deps: SettingsModuleDeps) -> anyhow::Result<DomainBinding> {
    let SettingsModuleDeps {
        pg,
        pg_readiness,
        readiness_key_provider,
        read_key_provider,
        write_key_provider,
        key_name,
        clock,
        keyprovider_ready,
        readiness_worker,
    } = deps;

    verify_keyprovider_ready(&readiness_key_provider, key_name.clone())
        .await
        .context("verify settings config value key provider")?;

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
        Box::new(SharedClock(service_clock)),
    );
    let secret_repo: Arc<DynSecretRepo<'static>> = Arc::from(secrets);
    let secret_uow: Arc<DynSecretUnitOfWork<'static>> = Arc::from(secret_writer);
    let domain = SettingsDomain::new(Arc::new(config_svc), secret_repo, secret_uow);
    let output = module_result(pg_readiness, keyprovider_ready, readiness_worker)?;

    Ok(DomainBinding::new(DOMAIN_NAME, Box::new(domain), output))
}

/// Build a key-provider readiness worker tied to the supplied shared readiness snapshot.
#[must_use]
fn keyprovider_readiness_worker(
    provider: Box<DynKeyProvider<'static>>,
    key_name: KeyName,
    period: Duration,
    ready: Arc<AtomicBool>,
) -> WorkerSpec {
    Box::new(move |token| {
        DynManagedResource::new_box(spawn_keyprovider_readiness_sampler(
            provider, key_name, period, token, ready,
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
        PoolReadiness::Saturated => (HealthStatus::Degraded, "saturated"),
        PoolReadiness::Down => (HealthStatus::Unhealthy, "down"),
        _ => (HealthStatus::Unhealthy, "unknown"),
    }
}

fn module_result(
    pg_readiness: Arc<PgDbReadiness>,
    keyprovider_ready: Arc<AtomicBool>,
    readiness_worker: WorkerSpec,
) -> anyhow::Result<DomainModuleResult> {
    let configs_name = ProbeName::parse(CONFIGS_READY_PROBE_NAME)
        .context("configs_ready probe name is invalid")?;
    let keyprovider_name = ProbeName::parse(KEYPROVIDER_READY_PROBE_NAME)
        .context("keyprovider_ready probe name is invalid")?;
    Ok(DomainModuleResult {
        probes: vec![
            (configs_name, Box::new(ConfigsReadyProbe::new(pg_readiness))),
            (
                keyprovider_name,
                Box::new(KeyProviderReadyProbe::new(keyprovider_ready)),
            ),
        ],
        resources: Vec::new(),
        workers: vec![readiness_worker],
    })
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
    handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    token: CancellationToken,
}

impl ManagedResource for KeyProviderReadinessSampler {
    fn name(&self) -> &str {
        "keyprovider-readiness-sampler"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.token.cancel();
        let mut handle = self.handle.lock().await;
        if let Some(handle) = handle.take()
            && let Err(error) = handle.await
        {
            tracing::warn!(error = %error, "keyprovider readiness sampler join failed");
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
        handle: tokio::sync::Mutex::new(Some(handle)),
        token: child,
    }
}

/// Hermetic settings binding for generated assembly tests.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::*;
    use diport::{EncryptOutput, KeyProvider, KeyProviderError, KeyRef, KeyVersion, RedactedBytes};
    use secure::{DerivedAad, Plaintext};

    struct NoopResource;

    impl ManagedResource for NoopResource {
        fn name(&self) -> &str {
            "settings-test-worker"
        }

        async fn shutdown(&self) -> Result<(), ShutdownError> {
            Ok(())
        }
    }

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

    /// Build a deterministic settings binding without network or database I/O.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixed test key or settings composition cannot be constructed.
    pub async fn binding() -> anyhow::Result<DomainBinding> {
        let pg = postgres::PgRuntimeHandle::for_module_test();
        let key_name = KeyName::try_new("settings-config")?;
        let ready = Arc::new(AtomicBool::new(true));
        let worker: WorkerSpec = Box::new(|_| DynManagedResource::new_box(NoopResource));
        wire(SettingsModuleDeps::for_test(
            pg.for_domain(),
            pg.readiness_handle(),
            provider(),
            provider(),
            provider(),
            key_name,
            Arc::new(EpochClock),
            ready,
            worker,
        ))
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bootstrap::{HealthProbe as _, compose_bindings};
    use diport::{EncryptOutput, KeyProvider, KeyProviderError, KeyRef, KeyVersion, RedactedBytes};
    use secure::DerivedAad;
    use vault::{TenantStoreAllowlist, VaultKeyProvider, VaultRuntimeDeps, VaultSecretResolver};

    struct TestClock;

    impl Clock for TestClock {
        fn now(&self) -> std::time::SystemTime {
            std::time::SystemTime::UNIX_EPOCH
        }
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

    #[test]
    fn readiness_mapping_is_fail_closed() {
        assert_eq!(
            readiness_to_health(PoolReadiness::Ready),
            (HealthStatus::Healthy, "ready")
        );
        assert_eq!(
            readiness_to_health(PoolReadiness::Saturated),
            (HealthStatus::Degraded, "saturated")
        );
        assert_eq!(
            readiness_to_health(PoolReadiness::Down),
            (HealthStatus::Unhealthy, "down")
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn production_constructor_derives_all_roles_from_one_sealed_vault_capability() {
        let pg = postgres::PgRuntimeHandle::for_module_test();
        let stores = TenantStoreAllowlist::new(std::iter::empty()).expect("empty allowlist");
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

        let _deps = SettingsModuleDeps::new(
            pg.for_domain(),
            pg.readiness_handle(),
            vault.for_domain::<vault_caps::Settings>(),
            KeyName::try_new("settings-config").expect("valid key name"),
            Arc::new(TestClock),
            KeyProviderReadinessInterval::try_new(Duration::from_secs(7))
                .expect("valid readiness interval"),
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
        assert_eq!(output.probes.len(), 2);
        assert_eq!(output.probes[0].0.as_str(), CONFIGS_READY_PROBE_NAME);
        assert_eq!(output.probes[1].0.as_str(), KEYPROVIDER_READY_PROBE_NAME);
        assert!(output.resources.is_empty());
        assert_eq!(output.workers.len(), 1);
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
        let resource = worker(CancellationToken::new());

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
        let resource = worker(CancellationToken::new());
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
