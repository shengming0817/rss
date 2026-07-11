//! Settings domain wiring.

use std::sync::Arc;

use anyhow::Context as _;
use bootstrap::{Domain, DomainBinding, DomainModuleResult};
use diport::{DynKeyProvider, DynManagedResource, KeyName};
use postgres::{ConfigValueProtections, PgDbReadiness, PgDomainDeps, PoolReadiness, caps};
use primitives::{HealthCheck, HealthStatus, ProbeName};
use settings::ports::DynSecretRepo;
use settings::{SettingsDomain, SettingsService, empty_flag_store};
use vault::caps as vault_caps;

use crate::infra::vault::{
    KEYPROVIDER_READY_PROBE_NAME, KeyProviderReadyProbe, build_keyprovider_readiness_interval,
    spawn_keyprovider_readiness_sampler, verify_keyprovider_ready,
};
use crate::{SharedRuntimeDeps, SystemClock};

const DOMAIN_NAME: &str = "settings";

mod sealed {
    pub trait Sealed {}
}

/// Typed provider seam for the settings module factory.
///
/// The trait is sealed: production uses [`SharedRuntimeDeps`], while this crate's tests provide
/// lazy postgres and an in-memory key provider to execute the same public [`module`] entrypoint
/// without external services.
#[doc(hidden)]
pub trait SettingsModuleSource: sealed::Sealed {
    fn settings_pg(&self) -> PgDomainDeps<caps::Settings>;
    fn pg_readiness(&self) -> Arc<PgDbReadiness>;
    fn key_name(&self) -> KeyName;
    fn key_provider(&self) -> Box<DynKeyProvider<'static>>;
    fn readiness_worker(
        &self,
        key_name: KeyName,
        ready: Arc<std::sync::atomic::AtomicBool>,
    ) -> bootstrap::WorkerSpec;
}

impl sealed::Sealed for SharedRuntimeDeps {}

impl SettingsModuleSource for SharedRuntimeDeps {
    fn settings_pg(&self) -> PgDomainDeps<caps::Settings> {
        self.pg.for_domain()
    }

    fn pg_readiness(&self) -> Arc<PgDbReadiness> {
        self.pg.readiness_handle()
    }

    fn key_name(&self) -> KeyName {
        self.settings_config_value_key_name.clone()
    }

    fn key_provider(&self) -> Box<DynKeyProvider<'static>> {
        self.vault
            .for_domain::<vault_caps::Settings>()
            .key_provider()
    }

    fn readiness_worker(
        &self,
        key_name: KeyName,
        ready: Arc<std::sync::atomic::AtomicBool>,
    ) -> bootstrap::WorkerSpec {
        let vault = self.vault.clone();
        Box::new(move |token| {
            DynManagedResource::new_box(spawn_keyprovider_readiness_sampler(
                vault.clone(),
                key_name.clone(),
                build_keyprovider_readiness_interval(),
                token,
                Arc::clone(&ready),
            ))
        })
    }
}

/// Stable readiness probe name for the settings database dependency.
///
/// The public constant is shared with end-to-end tests so a rename is caught at compile time.
pub const CONFIGS_READY_PROBE_NAME: &str = "configs_ready";

/// DB readiness probe backed by the shared, non-blocking postgres readiness snapshot.
///
/// [`bootstrap::HealthProbe::check`] performs no I/O. `Ready` maps to healthy, `Saturated` to
/// degraded, `Down` to unhealthy, and unknown future states fail closed as unhealthy. Details are
/// fixed static strings and cannot carry runtime-sensitive data.
pub struct ConfigsReadyProbe {
    health: Arc<PgDbReadiness>,
    /// Self-reported name retained for health snapshots and registry diagnostics.
    name: ProbeName,
}

impl ConfigsReadyProbe {
    /// Construct the settings database readiness probe from a shared sampling snapshot.
    #[allow(clippy::expect_used)]
    pub fn new(health: Arc<PgDbReadiness>) -> Self {
        // reason: the constant is a source literal validated by this constructor and unit tests.
        let name = ProbeName::parse(CONFIGS_READY_PROBE_NAME).expect("valid probe name const");
        Self { health, name }
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

impl bootstrap::HealthProbe for ConfigsReadyProbe {
    fn check(&self) -> HealthCheck {
        let (status, detail) = readiness_to_health(self.health.snapshot());
        HealthCheck::new(self.name.clone(), status, detail)
    }
}

fn bind<D>(domain: D, output: DomainModuleResult) -> DomainBinding
where
    D: Domain,
{
    DomainBinding::new(DOMAIN_NAME, Box::new(domain), output)
}

/// Build the settings domain as a single-owned runtime binding.
///
/// # Errors
///
/// Returns an error when key-provider readiness fails or stable probe names cannot be constructed.
pub async fn module(source: &impl SettingsModuleSource) -> anyhow::Result<DomainBinding> {
    let (domain, output) = wire_settings_from(source).await?;
    Ok(bind(domain, output))
}

/// Wire the typed settings domain and its lifecycle output.
///
/// The postgres capability projection supplies config read/write and secret repositories from one
/// pool. Startup performs a real key-provider encrypt/decrypt/AAD-mismatch self-check before the
/// domain can become ready. The output contains `configs_ready` and `keyprovider_ready` probes plus
/// one periodic key-provider readiness worker; it contains no detached resources.
///
/// `empty_flag_store()` is intentionally fail-closed until the production flag store lands.
/// Provider resources remain owned by the runtime bundle and are registered separately.
///
/// # Errors
///
/// Returns an error when key-provider readiness fails or stable probe names cannot be constructed.
#[cfg(any(test, feature = "integration"))]
pub(crate) async fn wire_settings(
    deps: &SharedRuntimeDeps,
) -> anyhow::Result<(SettingsDomain, DomainModuleResult)> {
    wire_settings_from(deps).await
}

async fn wire_settings_from(
    source: &impl SettingsModuleSource,
) -> anyhow::Result<(SettingsDomain, DomainModuleResult)> {
    let key_name = source.key_name();
    let probe_provider = source.key_provider();
    verify_keyprovider_ready(&probe_provider, key_name.clone())
        .await
        .context("verify settings config value key provider")?;

    let (configs, writer, secrets) = source
        .settings_pg()
        .settings_bundle(
            Arc::new(SystemClock),
            ConfigValueProtections::new(
                source.key_provider(),
                source.key_provider(),
                key_name.clone(),
            ),
        )
        .into_parts();

    let config_svc =
        SettingsService::with_postgres(configs, writer, empty_flag_store(), Box::new(SystemClock));
    let secret_repo: Arc<DynSecretRepo<'static>> = Arc::from(secrets);

    let keyprovider_ready = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let worker = source.readiness_worker(key_name, Arc::clone(&keyprovider_ready));
    let output = settings_module_result(source.pg_readiness(), keyprovider_ready, worker)?;

    Ok((
        SettingsDomain::new(Arc::new(config_svc), secret_repo),
        output,
    ))
}

fn settings_module_result(
    readiness: Arc<PgDbReadiness>,
    keyprovider_ready: Arc<std::sync::atomic::AtomicBool>,
    worker: bootstrap::WorkerSpec,
) -> anyhow::Result<DomainModuleResult> {
    let probe_name = ProbeName::parse(CONFIGS_READY_PROBE_NAME)
        .context("configs_ready probe name is invalid")?;
    let keyprovider_probe_name = ProbeName::parse(KEYPROVIDER_READY_PROBE_NAME)
        .context("keyprovider_ready probe name is invalid")?;
    Ok(DomainModuleResult {
        probes: vec![
            (probe_name, Box::new(ConfigsReadyProbe::new(readiness))),
            (
                keyprovider_probe_name,
                Box::new(KeyProviderReadyProbe::new(keyprovider_ready)),
            ),
        ],
        resources: Vec::new(),
        workers: vec![worker],
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use base64::Engine as _;
    use bootstrap::compose_bindings;
    use deadpool_redis::{Config as RedisConfig, Runtime as RedisRuntime};
    use diport::key_provider::KeyProviderErrorKind;
    use diport::{
        EncryptOutput, KeyProvider, KeyProviderError, KeyRef, KeyVersion, ManagedResource,
        RedactedBytes, ShutdownError,
    };
    use secure::{DerivedAad, Plaintext};
    use vault::{TenantStoreAllowlist, VaultKeyProvider, VaultRuntimeDeps, VaultSecretResolver};
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    struct NoopResource;

    impl ManagedResource for NoopResource {
        fn name(&self) -> &str {
            "settings-test-worker"
        }

        async fn shutdown(&self) -> Result<(), ShutdownError> {
            Ok(())
        }
    }

    struct NoopDomainTransport;

    impl distributed::DomainTransport for NoopDomainTransport {
        fn dispatch(
            &self,
            _request: distributed::DomainRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            distributed::DomainResponse,
                            distributed::DomainTransportError,
                        >,
                    > + Send
                    + '_,
            >,
        > {
            Box::pin(async {
                Ok(distributed::DomainResponse::new(
                    204,
                    Vec::new(),
                    Vec::new(),
                ))
            })
        }
    }

    #[derive(Default)]
    struct TestKeyProvider {
        decrypt_count: std::sync::atomic::AtomicUsize,
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
            if self
                .decrypt_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                == 0
            {
                Ok(Plaintext::new(b"rss-keyprovider-ready".to_vec()))
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

    struct TestModuleSource {
        pg: postgres::PgRuntimeDeps,
    }

    impl sealed::Sealed for TestModuleSource {}

    impl SettingsModuleSource for TestModuleSource {
        fn settings_pg(&self) -> PgDomainDeps<caps::Settings> {
            self.pg.for_domain()
        }

        fn pg_readiness(&self) -> Arc<PgDbReadiness> {
            self.pg.readiness_handle()
        }

        #[allow(clippy::expect_used)]
        fn key_name(&self) -> KeyName {
            KeyName::try_new("settings-config").expect("valid module test key")
        }

        fn key_provider(&self) -> Box<DynKeyProvider<'static>> {
            DynKeyProvider::new_box(TestKeyProvider::default())
        }

        fn readiness_worker(
            &self,
            _key_name: KeyName,
            _ready: Arc<std::sync::atomic::AtomicBool>,
        ) -> bootstrap::WorkerSpec {
            Box::new(|_| DynManagedResource::new_box(NoopResource))
        }
    }

    pub(crate) async fn test_binding() -> anyhow::Result<DomainBinding> {
        let source = TestModuleSource {
            pg: postgres::PgRuntimeDeps::for_module_test(),
        };
        module(&source).await
    }

    #[allow(clippy::expect_used)]
    fn readiness_context_b64(tenant: &str) -> String {
        let tenant = vocab::TenantId::parse(tenant).expect("canonical readiness tenant");
        let aad = secure::ProtectionContext::authenticated_request(
            tenant,
            "readiness.probe",
            "settings.config.value",
            1,
        )
        .expect("valid readiness aad")
        .derive();
        base64::engine::general_purpose::STANDARD.encode(aad.as_canonical_bytes())
    }

    async fn mount_keyprovider_mocks(server: &MockServer) {
        let ready_context = readiness_context_b64("00000000-0000-4000-8000-000000000147");
        let mismatch_context = readiness_context_b64("00000000-0000-4000-8000-000000000148");
        Mock::given(method("POST"))
            .and(path("/v1/transit/encrypt/settings-config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "ciphertext": "vault:v1:cnNzLWtleXByb3ZpZGVyLXJlYWR5",
                    "key_version": 1
                }
            })))
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/settings-config"))
            .and(body_partial_json(
                serde_json::json!({ "context": ready_context }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "plaintext": base64::engine::general_purpose::STANDARD
                        .encode(b"rss-keyprovider-ready")
                }
            })))
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/transit/decrypt/settings-config"))
            .and(body_partial_json(
                serde_json::json!({ "context": mismatch_context }),
            ))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({ "errors": ["aad mismatch"] })),
            )
            .mount(server)
            .await;
    }

    #[allow(clippy::expect_used)]
    fn s3_deps() -> s3::S3RuntimeDeps {
        crate::build_s3_runtime_deps_from(|name| match name {
            "RSS_S3_ENDPOINT_URL" => Some("http://127.0.0.1:1".to_string()),
            "RSS_S3_ALLOW_PLAINTEXT" => Some("true".to_string()),
            "RSS_S3_BUCKET" => Some("rss-module-test".to_string()),
            "RSS_S3_ACCESS_KEY_ID" => Some("module-test-access".to_string()),
            "RSS_S3_SECRET_ACCESS_KEY" => Some("module-test-secret".to_string()),
            "RSS_S3_FORCE_PATH_STYLE" => Some("true".to_string()),
            _ => None,
        })
        .expect("hermetic S3 deps build")
    }

    #[allow(clippy::expect_used)]
    fn redis_deps() -> redis::RedisRuntimeDeps {
        let pool = RedisConfig::from_url("redis://127.0.0.1:1")
            .create_pool(Some(RedisRuntime::Tokio1))
            .expect("lazy redis pool builds");
        redis::RedisRuntimeDeps::setup(pool)
    }

    #[allow(clippy::expect_used)]
    fn vault_deps(server: &MockServer) -> VaultRuntimeDeps {
        let client = reqwest::Client::new();
        let addr = server.uri();
        VaultRuntimeDeps::new(
            VaultSecretResolver::new_allow_http(
                client.clone(),
                addr.clone(),
                "module-test-token",
                std::time::Duration::from_secs(5),
                TenantStoreAllowlist::new(std::iter::empty())
                    .expect("empty test allowlist is valid"),
            )
            .expect("hermetic vault resolver builds"),
            VaultKeyProvider::new_allow_http(
                client,
                addr,
                "module-test-token",
                "transit",
                std::time::Duration::from_secs(5),
            )
            .expect("hermetic vault key provider builds"),
        )
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn production_source_and_typed_wire_execute_with_hermetic_providers() {
        let server = MockServer::start().await;
        mount_keyprovider_mocks(&server).await;
        let deps = SharedRuntimeDeps {
            pg: postgres::PgRuntimeDeps::for_module_test(),
            redis: redis_deps(),
            s3: s3_deps(),
            vault: vault_deps(&server),
            settings_config_value_key_name: KeyName::try_new("settings-config")
                .expect("valid settings key"),
            domain_transport: Arc::new(NoopDomainTransport),
        };

        let binding = module(&deps)
            .await
            .expect("production source module builds");
        assert_eq!(binding.name(), DOMAIN_NAME);

        let (_, output) = wire_settings(&deps)
            .await
            .expect("typed production wiring builds");
        assert_eq!(output.probes.len(), 2);
        assert!(output.resources.is_empty());
        assert_eq!(output.workers.len(), 1);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn module_executes_hermetic_source_and_has_stable_two_zero_one_output() {
        let mut bindings = vec![test_binding().await.expect("settings module builds")];
        assert_eq!(bindings[0].name(), DOMAIN_NAME);

        let (_, output) = compose_bindings(&mut bindings).expect("settings domain composes");
        assert!(bindings.is_empty());
        assert_eq!(output.probes.len(), 2);
        assert_eq!(output.probes[0].0.as_str(), CONFIGS_READY_PROBE_NAME);
        assert_eq!(output.probes[1].0.as_str(), KEYPROVIDER_READY_PROBE_NAME);
        assert!(output.resources.is_empty());
        assert_eq!(output.workers.len(), 1);
    }

    #[test]
    fn configs_ready_maps_all_known_states() {
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

    #[test]
    #[allow(clippy::expect_used)]
    fn keyprovider_probe_observes_the_shared_sampler_handle() {
        let ready = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let worker: bootstrap::WorkerSpec =
            Box::new(|_| diport::DynManagedResource::new_box(NoopResource));
        let output =
            settings_module_result(Arc::new(PgDbReadiness::new()), Arc::clone(&ready), worker)
                .expect("valid settings output constants");

        assert_eq!(output.probes[1].1.check().status(), HealthStatus::Healthy);
        ready.store(false, std::sync::atomic::Ordering::Release);
        assert_eq!(output.probes[1].1.check().status(), HealthStatus::Unhealthy);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn configs_ready_registers_and_is_unique() {
        let name_a = ProbeName::parse(CONFIGS_READY_PROBE_NAME).expect("valid probe name const");
        let name_b = ProbeName::parse(CONFIGS_READY_PROBE_NAME).expect("valid probe name const");
        let mut registry = bootstrap::compose(&[]).expect("empty compose");
        let readiness = Arc::new(PgDbReadiness::new());

        registry
            .probe(
                name_a,
                Box::new(ConfigsReadyProbe::new(Arc::clone(&readiness))),
            )
            .expect("first register ok");
        assert!(
            registry
                .probe(name_b, Box::new(ConfigsReadyProbe::new(readiness)))
                .is_err()
        );
    }
}
