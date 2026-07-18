//! Process-lifetime runtime configuration capture.
//!
//! Configuration owned by this funnel crosses exactly one `source -> snapshot` boundary. The
//! source is consumed by value, every closed-catalog key is read once, and the snapshot adapter can
//! only borrow captured values. `SnapshotConfig` seals the listener/auth/tracing/serving-OIDC
//! consumers migrated by #1783, every PostgreSQL/Redis serving or maintenance consumer migrated by
//! #1784, the Vault/S3 serving plus settings-maintenance consumers migrated by #1785, and the
//! event/domain/DLX/worker serving inputs migrated by #1786. `RUNTIME-ENV-FUNNEL-01` enforces
//! crate-wide reader exclusivity: this module owns the sole snapshot capture, while exactly four
//! named maintenance grant sources remain outside the catalog. CI/Forge credentials, the AWS
//! default credential chain, and SPIFFE rotation material are not runtime-crate readers.

use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};

use secure::SecretText;

pub(super) const DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV: &str =
    "RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS";
const DOMAIN_TRANSPORT_URL_ENV_SUFFIX: &str = "DOMAIN_TRANSPORT_URL";
const DOMAIN_TRANSPORT_MTLS_SPIFFE_ALLOW_SET_ENV_SUFFIX: &str =
    "DOMAIN_TRANSPORT_MTLS_SPIFFE_ALLOW_SET";

/// Closed set of non-domain-specific process keys used by the serving runtime.
///
/// Maintenance grants, CI/Forge credentials, AWS dynamic credentials, and SPIFFE rotation
/// material must not be added here. Generated AMQP and configured domain-transport keys are added
/// through the two explicit families below, never by enumerating the process environment.
const FIXED_SERVING_KEYS: &[&str] = &[
    "RUST_LOG",
    "SPIFFE_ENDPOINT_SOCKET",
    "RSS_ADMIN_LISTEN_ADDR",
    "RSS_AMQP_ALLOW_PLAINTEXT",
    "RSS_AMQP_URL",
    "RSS_AUDIT_CHAIN_KEY_B64URL",
    "RSS_COMMAND_IDEMPOTENCY_KEYS_JSON",
    "RSS_DLX_ARCHIVE_KEY_NAME",
    "RSS_DLX_ARCHIVE_S3_BUCKET",
    "RSS_DLX_ARCHIVE_VAULT_TOKEN",
    "RSS_DLX_HOT_VAULT_TOKEN",
    "RSS_DLX_PAYLOAD_KEY_NAME",
    "RSS_DOMAIN_TRANSPORT_MTLS_LOCAL_SPIFFE_ID",
    "RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS",
    "RSS_DOMAIN_TRANSPORT_URL",
    "RSS_HEALTH_LISTEN_ADDR",
    "RSS_HTTP_SERVER_REQUEST_BUDGET_MS",
    "RSS_IDENTITY_SESSION_TTL_SECS",
    "RSS_INTERNAL_AUTH_SCHEME",
    "RSS_INTERNAL_LISTEN_ADDR",
    "RSS_INTERNAL_MTLS_SPIFFE_ALLOW_SET",
    "RSS_JWT_ACCESS_TTL_SECS",
    "RSS_JWT_AUDIENCE",
    "RSS_JWT_ES256_KEY_ID",
    "RSS_JWT_ISSUER",
    "RSS_KEYPROVIDER_READINESS_SAMPLE_INTERVAL_SECS",
    "RSS_LISTENER_ALLOW_PLAINTEXT",
    "RSS_OIDC_AUDIENCE",
    "RSS_OIDC_ES256_SEC1_B64URL",
    "RSS_OIDC_HS256_KID",
    "RSS_OIDC_HS256_SECRET_B64URL",
    "RSS_OIDC_ISSUER",
    "RSS_OIDC_JWKS_PATH",
    "RSS_OIDC_JWKS_REFRESH_INTERVAL_SECS",
    "RSS_OIDC_TRUSTED_KINDS",
    "RSS_OTEL_ENDPOINT",
    "RSS_OUTBOX_RETAIN_SECONDS",
    "RSS_OUTBOX_SWEEP_INTERVAL_MS",
    "RSS_PASSWORD_BLOCKLIST_PATH",
    "RSS_PG_AUDIT_ADMIN_PASSWORD",
    "RSS_PG_AUDIT_ADMIN_USERNAME",
    "RSS_PG_DATABASE",
    "RSS_PG_DLX_ARCHIVER_PASSWORD",
    "RSS_PG_DLX_ARCHIVER_USERNAME",
    "RSS_PG_DLX_PURGER_PASSWORD",
    "RSS_PG_DLX_PURGER_USERNAME",
    "RSS_PG_DLX_VERIFIER_PASSWORD",
    "RSS_PG_DLX_VERIFIER_USERNAME",
    "RSS_PG_HOST",
    "RSS_PG_MAX_CONNECTIONS",
    "RSS_PG_MIGRATOR_PASSWORD",
    "RSS_PG_MIGRATOR_USERNAME",
    "RSS_PG_PASSWORD",
    "RSS_PG_PORT",
    "RSS_PG_READ_MAX_CONNECTIONS",
    "RSS_PG_READ_PASSWORD",
    "RSS_PG_READ_USERNAME",
    "RSS_PG_READINESS_SAMPLE_INTERVAL_SECS",
    "RSS_PG_SSL_MODE",
    "RSS_PG_SSL_ROOT_CERT_PATH",
    "RSS_PG_USERNAME",
    "RSS_PRIMARY_LISTEN_ADDR",
    "RSS_REDIS_ALLOW_PLAINTEXT",
    "RSS_REDIS_READINESS_SAMPLE_INTERVAL_SECS",
    "RSS_REDIS_URL",
    "RSS_REFRESH_TTL_SECS",
    "RSS_RELAY_LEASE_TTL_MS",
    "RSS_RELAY_MAX_IN_FLIGHT",
    "RSS_RELAY_POLL_INTERVAL_MS",
    "RSS_RELAY_PUBLISH_TIMEOUT_MS",
    "RSS_RELAY_SAFETY_MARGIN_MS",
    "RSS_RELAY_SAMPLE_INTERVAL_MS",
    "RSS_RELAY_SETTLE_TIMEOUT_MS",
    "RSS_S3_ACCESS_KEY_ID",
    "RSS_S3_ALLOW_PLAINTEXT",
    "RSS_S3_BUCKET",
    "RSS_S3_CANARY_INTERVAL_SECS",
    "RSS_S3_CANARY_KEY_PREFIX",
    "RSS_S3_CANARY_TIMEOUT_SECS",
    "RSS_S3_ENDPOINT_URL",
    "RSS_S3_FORCE_PATH_STYLE",
    "RSS_S3_REGION",
    "RSS_S3_SECRET_ACCESS_KEY",
    "RSS_S3_SESSION_TOKEN",
    "RSS_SESSION_SWEEP_INTERVAL_MS",
    "RSS_SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES",
    "RSS_SETTINGS_CONFIG_VALUE_KEY_NAME",
    "RSS_TENANT_AUTHORITY_CLOCK_SKEW_SECS",
    "RSS_TENANT_AUTHORITY_HMAC_KEY_B64URL",
    "RSS_TENANT_AUTHORITY_TTL_SECS",
    "RSS_TOPOLOGY",
    "RSS_VAULT_ADDR",
    "RSS_VAULT_CA_CERT_PEM_PATH",
    "RSS_VAULT_TOKEN",
    "RSS_VAULT_TRANSIT_MOUNT",
];

/// Opaque catalog key passed to configuration sources.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RuntimeConfigKey(String);

impl RuntimeConfigKey {
    fn from_static(value: &'static str) -> Self {
        Self(value.to_owned())
    }

    fn from_dynamic(value: String) -> Self {
        Self(value)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for RuntimeConfigKey {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

/// Result of one configuration-source read. Non-Unicode bytes are deliberately discarded.
pub(crate) enum CapturedConfigValue {
    Missing,
    NonUnicode,
    Present(SecretText),
}

/// Single-read configuration source boundary.
pub(crate) trait RuntimeConfigSource {
    fn read(&mut self, key: &RuntimeConfigKey) -> CapturedConfigValue;
}

/// Production environment source. It reads only the key supplied by the closed catalog.
struct EnvConfigSource;

impl RuntimeConfigSource for EnvConfigSource {
    fn read(&mut self, key: &RuntimeConfigKey) -> CapturedConfigValue {
        match std::env::var_os(key.as_str()) {
            None => CapturedConfigValue::Missing,
            Some(value) => match value.into_string() {
                Ok(value) => CapturedConfigValue::Present(SecretText::from_string(value)),
                Err(_) => CapturedConfigValue::NonUnicode,
            },
        }
    }
}

#[cfg(test)]
struct TestConfigSource(BTreeMap<String, String>);

#[cfg(test)]
impl RuntimeConfigSource for TestConfigSource {
    fn read(&mut self, key: &RuntimeConfigKey) -> CapturedConfigValue {
        self.0
            .remove(key.as_str())
            .map_or(CapturedConfigValue::Missing, |value| {
                CapturedConfigValue::Present(SecretText::from_string(value))
            })
    }
}

/// Capture a test generation from explicit UTF-8 values without duplicating source fakes.
///
/// Read-count and non-Unicode tests keep their purpose-built sources in `config_tests`.
#[cfg(test)]
pub(crate) fn test_snapshot(
    entries: &[(&str, &str)],
) -> Result<RuntimeConfigSnapshot, RuntimeConfigCaptureError> {
    RuntimeConfigSnapshot::capture(TestConfigSource(
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect(),
    ))
}

/// Closed, secret-safe capture failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum RuntimeConfigCaptureError {
    #[error("runtime serving configuration catalog contains a duplicate fixed key")]
    DuplicateFixedKey,
}

/// Immutable process-lifetime configuration generation.
///
/// INVARIANT: RUNTIME-CONFIG-SNAPSHOT-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" } -- private storage, by-value source consumption, mutually exclusive owned serving/operator inputs, the sole `RuntimeServingConfig` aggregate mapper, exact generated-domain inputs, and private-field `SnapshotConfig` signatures make snapshot omission and capability forgery unrepresentable for migrated serving, event/domain/DLX/worker, PostgreSQL maintenance, OIDC JWKS export, and Vault-backed settings-maintenance consumers.
///
/// The Medium `RUNTIME-CONFIG-SNAPSHOT-LIVE-01` carrier in `runtime-baseline` guards the production
/// capture-to-consumer flow; the independent `RUNTIME-ENV-FUNNEL-01` gate enforces the complete
/// runtime-crate direct-reader inventory.
pub(crate) struct RuntimeConfigSnapshot {
    values: BTreeMap<RuntimeConfigKey, CapturedConfigValue>,
}

/// Borrowed authority to read one immutable serving-configuration generation.
///
/// Only [`RuntimeConfigSnapshot::view`] can mint this capability. Production consumers that
/// require snapshot-backed configuration accept this type directly, so an ambient environment
/// reader cannot be substituted accidentally.
#[derive(Clone, Copy)]
pub(crate) struct SnapshotConfig<'a> {
    snapshot: &'a RuntimeConfigSnapshot,
}

impl<'a> SnapshotConfig<'a> {
    /// Borrow a captured UTF-8 value without cloning or exposing the snapshot's secret carrier.
    /// Missing, non-Unicode, and unknown keys have the same `None` decision as
    /// `std::env::var(name).ok()`; there is no source fallback.
    pub(crate) fn value(self, name: &str) -> Option<&'a str> {
        self.snapshot.get(name).map(SecretText::expose)
    }
}

pub(crate) struct ServingConfigMapper<'a> {
    config: SnapshotConfig<'a>,
}

impl<'a> ServingConfigMapper<'a> {
    fn new(config: SnapshotConfig<'a>) -> Self {
        Self { config }
    }

    pub(crate) const fn config(&self) -> SnapshotConfig<'a> {
        self.config
    }

    #[cfg(test)]
    pub(crate) fn for_test(config: SnapshotConfig<'a>) -> Self {
        Self::new(config)
    }
}

pub(crate) struct WorkerRuntimeConfig {
    event: crate::event_transport::EventWorkerConfig,
    dlx: crate::event_transport::DlxWorkerConfig,
    distributed: crate::distributed_runtime::DistributedWorkerConfig,
    session_sweep_interval: std::time::Duration,
    keyprovider_readiness_interval: settings_composition::KeyProviderReadinessInterval,
}

impl WorkerRuntimeConfig {
    pub(crate) fn from_mapper(mapper: &ServingConfigMapper<'_>) -> anyhow::Result<Self> {
        let config = mapper.config();
        Ok(Self {
            event: crate::event_transport::EventWorkerConfig::from_mapper(mapper)?,
            dlx: crate::event_transport::DlxWorkerConfig::canonical(),
            distributed: crate::distributed_runtime::DistributedWorkerConfig::canonical(),
            session_sweep_interval: session_sweep_interval_from_value(
                config.value("RSS_SESSION_SWEEP_INTERVAL_MS"),
            ),
            keyprovider_readiness_interval: keyprovider_readiness_interval_from_value(
                config.value("RSS_KEYPROVIDER_READINESS_SAMPLE_INTERVAL_SECS"),
            ),
        })
    }

    #[cfg(test)]
    pub(crate) fn into_test_parts(
        self,
    ) -> (
        crate::event_transport::EventWorkerConfig,
        std::time::Duration,
        settings_composition::KeyProviderReadinessInterval,
    ) {
        (
            self.event,
            self.session_sweep_interval,
            self.keyprovider_readiness_interval,
        )
    }
}

pub(crate) struct RuntimeServingConfig {
    event_transport: crate::event_transport::EventTransportConfig,
    event_worker: crate::event_transport::EventWorkerConfig,
    dlx_worker: crate::event_transport::DlxWorkerConfig,
    distributed_worker: crate::distributed_runtime::DistributedWorkerConfig,
    domain_transport: crate::DomainTransportConfig,
    domain_modules: crate::domains::DomainModuleInputs,
    audit_consumer_key: primitives::MacKey,
    session_sweep_interval: std::time::Duration,
}

pub(crate) struct RuntimeServingConfigParts {
    pub(crate) event_transport: crate::event_transport::EventTransportConfig,
    pub(crate) event_worker: crate::event_transport::EventWorkerConfig,
    pub(crate) dlx_worker: crate::event_transport::DlxWorkerConfig,
    pub(crate) distributed_worker: crate::distributed_runtime::DistributedWorkerConfig,
    pub(crate) domain_transport: crate::DomainTransportConfig,
    pub(crate) domain_modules: crate::domains::DomainModuleInputs,
    pub(crate) audit_consumer_key: primitives::MacKey,
    pub(crate) session_sweep_interval: std::time::Duration,
}

impl RuntimeServingConfig {
    pub(crate) fn from_snapshot(config: SnapshotConfig<'_>) -> anyhow::Result<Self> {
        let mapper = ServingConfigMapper::new(config);
        let event_transport = crate::event_transport::EventTransportConfig::from_mapper(&mapper)?;
        let topology = event_transport.topology();
        let WorkerRuntimeConfig {
            event,
            dlx,
            distributed,
            session_sweep_interval,
            keyprovider_readiness_interval,
        } = WorkerRuntimeConfig::from_mapper(&mapper)?;
        let domain_transport = crate::DomainTransportConfig::from_mapper(topology, &mapper)?;
        let domain_modules = crate::domains::DomainModuleInputs::from_snapshot(
            &mapper,
            keyprovider_readiness_interval,
        )?;
        let audit_consumer_key = domain_modules.audit_consumer_key();
        Ok(Self {
            event_transport,
            event_worker: event,
            dlx_worker: dlx,
            distributed_worker: distributed,
            domain_transport,
            domain_modules,
            audit_consumer_key,
            session_sweep_interval,
        })
    }

    pub(crate) fn into_parts(self) -> RuntimeServingConfigParts {
        RuntimeServingConfigParts {
            event_transport: self.event_transport,
            event_worker: self.event_worker,
            dlx_worker: self.dlx_worker,
            distributed_worker: self.distributed_worker,
            domain_transport: self.domain_transport,
            domain_modules: self.domain_modules,
            audit_consumer_key: self.audit_consumer_key,
            session_sweep_interval: self.session_sweep_interval,
        }
    }
}

const DEFAULT_SESSION_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);
const MIN_SESSION_SWEEP_INTERVAL_MS: u64 = 1_000;
fn session_sweep_interval_from_value(raw: Option<&str>) -> std::time::Duration {
    match raw {
        None => DEFAULT_SESSION_SWEEP_INTERVAL,
        Some(raw) => match raw.trim().parse::<u64>() {
            Ok(milliseconds) if milliseconds >= MIN_SESSION_SWEEP_INTERVAL_MS => {
                std::time::Duration::from_millis(milliseconds)
            }
            _ => {
                tracing::warn!(
                    env = "RSS_SESSION_SWEEP_INTERVAL_MS",
                    default_ms = DEFAULT_SESSION_SWEEP_INTERVAL.as_millis(),
                    min_ms = MIN_SESSION_SWEEP_INTERVAL_MS,
                    "invalid session sweep interval (expected u64 ms >= 1000); using default"
                );
                DEFAULT_SESSION_SWEEP_INTERVAL
            }
        },
    }
}

fn keyprovider_readiness_interval_from_value(
    raw: Option<&str>,
) -> settings_composition::KeyProviderReadinessInterval {
    match raw {
        None => settings_composition::KeyProviderReadinessInterval::default(),
        Some(raw) => match raw
            .parse::<u64>()
            .map(std::time::Duration::from_secs)
            .ok()
            .and_then(|value| {
                settings_composition::KeyProviderReadinessInterval::try_new(value).ok()
            }) {
            Some(interval) => interval,
            _ => {
                tracing::warn!(
                    env = "RSS_KEYPROVIDER_READINESS_SAMPLE_INTERVAL_SECS",
                    "invalid keyprovider readiness sample interval (need 1..=30s); using default 5s"
                );
                settings_composition::KeyProviderReadinessInterval::default()
            }
        },
    }
}

impl RuntimeConfigSnapshot {
    /// Capture the process-lifetime configuration generation from the closed environment source.
    ///
    /// This is the only production source-minting surface. The generic capture primitive and the
    /// concrete environment source stay private to this module so sibling modules cannot express a
    /// second or alternate production capture.
    pub(crate) fn capture_process_snapshot() -> Result<Self, RuntimeConfigCaptureError> {
        Self::capture(EnvConfigSource)
    }

    /// Test-only generic capture surface for purpose-built source fakes.
    #[cfg(test)]
    pub(crate) fn capture_test(
        source: impl RuntimeConfigSource,
    ) -> Result<Self, RuntimeConfigCaptureError> {
        Self::capture(source)
    }

    /// Consume a source and capture each unique serving key exactly once.
    fn capture(mut source: impl RuntimeConfigSource) -> Result<Self, RuntimeConfigCaptureError> {
        let mut catalog = fixed_catalog()?;
        add_generated_event_keys(&mut catalog);

        let mut values = BTreeMap::new();
        for key in catalog {
            let value = source.read(&key);
            values.insert(key, value);
        }

        let dynamic_domains = values
            .get(DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV)
            .and_then(present_text)
            .and_then(|raw| domain_transport_required_domains_from_value(raw.expose()).ok())
            .unwrap_or_default();
        for domain in dynamic_domains {
            for key in [
                domain_transport_url_env(&domain),
                domain_transport_mtls_allow_set_env(&domain),
            ] {
                if values.contains_key(key.as_str()) {
                    continue;
                }
                let key = RuntimeConfigKey::from_dynamic(key);
                let value = source.read(&key);
                values.insert(key, value);
            }
        }

        Ok(Self { values })
    }

    /// Mint the only configuration capability accepted by serving-runtime consumers.
    pub(crate) fn view(&self) -> SnapshotConfig<'_> {
        SnapshotConfig { snapshot: self }
    }

    /// Borrow a captured UTF-8 value. Missing, non-Unicode, and unknown keys all match
    /// `std::env::var(name).ok()` and return `None`; no source fallback exists.
    fn get(&self, name: &str) -> Option<&SecretText> {
        self.values.get(name).and_then(present_text)
    }
}

impl std::fmt::Debug for RuntimeConfigSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RuntimeConfigSnapshot(<redacted>)")
    }
}

fn present_text(value: &CapturedConfigValue) -> Option<&SecretText> {
    match value {
        CapturedConfigValue::Present(value) => Some(value),
        CapturedConfigValue::Missing | CapturedConfigValue::NonUnicode => None,
    }
}

fn fixed_catalog() -> Result<BTreeSet<RuntimeConfigKey>, RuntimeConfigCaptureError> {
    let mut catalog = BTreeSet::new();
    for key in FIXED_SERVING_KEYS {
        if !catalog.insert(RuntimeConfigKey::from_static(key)) {
            return Err(RuntimeConfigCaptureError::DuplicateFixedKey);
        }
    }
    Ok(catalog)
}

fn add_generated_event_keys(catalog: &mut BTreeSet<RuntimeConfigKey>) {
    for domain in generated::event::PRODUCER_DOMAINS {
        catalog.insert(RuntimeConfigKey::from_dynamic(format!(
            "RSS_{}_AMQP_URL",
            domain.as_str().to_ascii_uppercase()
        )));
    }
}

pub(super) fn domain_transport_required_domains_from(
    get: &impl Fn(&str) -> Option<String>,
) -> anyhow::Result<Vec<String>> {
    let raw = get(DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV).ok_or_else(|| {
        anyhow::anyhow!("missing required env var: {DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV}")
    })?;
    domain_transport_required_domains_from_value(&raw)
}

fn domain_transport_required_domains_from_value(raw: &str) -> anyhow::Result<Vec<String>> {
    let mut domains = Vec::new();
    for part in raw.split(',') {
        let domain = part.trim();
        anyhow::ensure!(
            !domain.is_empty(),
            "{DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV} must not contain empty entries"
        );
        anyhow::ensure!(
            !domain.chars().any(char::is_control) && !domain.chars().any(char::is_whitespace),
            "{DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV} entries must not contain whitespace or control characters"
        );
        domains.push(domain.to_uppercase());
    }
    anyhow::ensure!(
        !domains.is_empty(),
        "{DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV} must list at least one domain"
    );
    domains.sort();
    domains.dedup();
    Ok(domains)
}

pub(super) fn domain_transport_url_env(domain: &str) -> String {
    format!(
        "RSS_{}_{}",
        domain.to_ascii_uppercase(),
        DOMAIN_TRANSPORT_URL_ENV_SUFFIX
    )
}

pub(super) fn domain_transport_mtls_allow_set_env(domain: &str) -> String {
    format!(
        "RSS_{}_{}",
        domain.to_ascii_uppercase(),
        DOMAIN_TRANSPORT_MTLS_SPIFFE_ALLOW_SET_ENV_SUFFIX
    )
}
