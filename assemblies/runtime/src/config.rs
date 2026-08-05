//! Process-lifetime runtime configuration capture.
//!
//! Configuration owned by this funnel crosses exactly one `source -> snapshot` boundary. The
//! source is consumed by value, every closed-catalog key is read once, and the snapshot adapter can
//! only borrow captured values. `SnapshotConfig` seals the listener/auth/tracing/serving-OIDC
//! consumers migrated by #1783, every PostgreSQL/Redis serving or maintenance consumer migrated by
//! #1784, the Vault/S3 serving plus settings-maintenance consumers migrated by #1785, and the
//! event/domain/DLX/worker serving inputs migrated by #1786. `RUNTIME-ENV-FUNNEL-01` enforces
//! crate-wide reader exclusivity: this module owns the closed snapshot captures, while exactly three
//! named maintenance grant sources remain outside the catalog. CI/Forge credentials, the AWS
//! default credential chain, and SPIFFE rotation material are not runtime-crate readers.

use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use runtimeexec::config::{SecretDocument, SecretValue};
use secure::SecretText;
use serde::Deserialize;

const SERVING_SECRET_BUNDLE_PATH: &str = "/var/run/rss/secrets/serving-secret-bundle";
const PROJECTION_OPERATOR_SECRET_BUNDLE_PATH: &str =
    "/var/run/rss/secrets/projection-operator-secret-bundle";
pub(crate) const BUILD_SOURCE_REVISION_ENV: &str = "RSS_BUILD_SOURCE_REVISION";
pub(crate) const DECLARED_IMAGE_DIGEST_ENV: &str = "RSS_DECLARED_IMAGE_DIGEST";
pub(crate) const BUNDLE_PG_PASSWORD: &str = "RSS_INTERNAL_BUNDLE_PG_PASSWORD";
pub(crate) const BUNDLE_PG_READ_PASSWORD: &str = "RSS_INTERNAL_BUNDLE_PG_READ_PASSWORD";
pub(crate) const BUNDLE_PG_AUDIT_ADMIN_PASSWORD: &str =
    "RSS_INTERNAL_BUNDLE_PG_AUDIT_ADMIN_PASSWORD";
pub(crate) const BUNDLE_PG_DLX_ARCHIVER_PASSWORD: &str =
    "RSS_INTERNAL_BUNDLE_PG_DLX_ARCHIVER_PASSWORD";
pub(crate) const BUNDLE_PG_DLX_VERIFIER_PASSWORD: &str =
    "RSS_INTERNAL_BUNDLE_PG_DLX_VERIFIER_PASSWORD";
pub(crate) const BUNDLE_PG_DLX_PURGER_PASSWORD: &str = "RSS_INTERNAL_BUNDLE_PG_DLX_PURGER_PASSWORD";

const DOMAIN_TRANSPORT_URL_ENV_SUFFIX: &str = "DOMAIN_TRANSPORT_URL";
const DOMAIN_TRANSPORT_MTLS_SPIFFE_ALLOW_SET_ENV_SUFFIX: &str =
    "DOMAIN_TRANSPORT_MTLS_SPIFFE_ALLOW_SET";

/// Shared remote domain transport endpoint fallback (`durable-shared` only).
pub(crate) const DOMAIN_TRANSPORT_SHARED_URL_ENV: &str = "RSS_DOMAIN_TRANSPORT_URL";

/// Assembly domains that always capture per-domain transport URL / allow-set keys.
const ASSEMBLY_DOMAIN_TRANSPORT_DOMAINS: &[&str] = &["settings", "identity", "audit"];

pub(crate) const SETTINGS_DOMAIN_PLACEMENT_WORKLOAD_ENV: &str =
    "RSS_SETTINGS_DOMAIN_PLACEMENT_WORKLOAD";
pub(crate) const IDENTITY_DOMAIN_PLACEMENT_WORKLOAD_ENV: &str =
    "RSS_IDENTITY_DOMAIN_PLACEMENT_WORKLOAD";
pub(crate) const AUDIT_DOMAIN_PLACEMENT_WORKLOAD_ENV: &str = "RSS_AUDIT_DOMAIN_PLACEMENT_WORKLOAD";

/// RSS access-token signing / rotation env keys (single source for parse + error copy).
pub(crate) const RSS_ACCESS_TOKEN_SIGNING_ACTIVE_KEY_ID_ENV: &str =
    "RSS_ACCESS_TOKEN_SIGNING_ACTIVE_KEY_ID";
pub(crate) const RSS_ACCESS_TOKEN_SIGNING_NEXT_KEY_ID_ENV: &str =
    "RSS_ACCESS_TOKEN_SIGNING_NEXT_KEY_ID";
pub(crate) const RSS_ACCESS_TOKEN_SIGNING_RETIRING_ENV: &str = "RSS_ACCESS_TOKEN_SIGNING_RETIRING";
pub(crate) const RSS_ACCESS_TOKEN_SIGNING_ROTATED_AT_ENV: &str =
    "RSS_ACCESS_TOKEN_SIGNING_ROTATED_AT";
pub(crate) const RSS_ACCESS_TOKEN_ROTATION_MODE_ENV: &str = "RSS_ACCESS_TOKEN_ROTATION_MODE";
const RSS_ACCESS_TOKEN_ROTATION_CLOCK_SKEW_SECS_ENV: &str =
    "RSS_ACCESS_TOKEN_ROTATION_CLOCK_SKEW_SECS";
const RSS_ACCESS_TOKEN_ROTATION_JWKS_PROPAGATION_SLO_SECS_ENV: &str =
    "RSS_ACCESS_TOKEN_ROTATION_JWKS_PROPAGATION_SLO_SECS";
const RSS_ACCESS_TOKEN_ROTATION_MARGIN_SECS_ENV: &str = "RSS_ACCESS_TOKEN_ROTATION_MARGIN_SECS";

/// Removed serving keys that must fail closed instead of disappearing from the closed catalog.
const FORBIDDEN_SERVING_KEYS: &[&str] = &[
    "RSS_ACCESS_TOKEN_TRUSTED_KINDS",
    // Production egress TLS downgrade knobs (#1710): residual process values fail capture.
    "RSS_AMQP_ALLOW_PLAINTEXT",
    "RSS_REDIS_ALLOW_PLAINTEXT",
    "RSS_S3_ALLOW_PLAINTEXT",
    "RSS_PG_SSL_MODE",
];

/// Closed set of non-domain-specific process keys used by the serving runtime.
///
/// Purpose-bound grants consumed through the closed snapshot are listed explicitly; ambient
/// maintenance grants, CI/Forge credentials, AWS dynamic credentials, and SPIFFE rotation material
/// must not be added here. Generated AMQP and configured domain-transport keys are added through
/// the two explicit families below, never by enumerating the process environment.
const FIXED_SERVING_KEYS: &[&str] = &[
    BUNDLE_PG_PASSWORD,
    BUNDLE_PG_READ_PASSWORD,
    BUNDLE_PG_AUDIT_ADMIN_PASSWORD,
    BUNDLE_PG_DLX_ARCHIVER_PASSWORD,
    BUNDLE_PG_DLX_VERIFIER_PASSWORD,
    BUNDLE_PG_DLX_PURGER_PASSWORD,
    "RUST_LOG",
    "SPIFFE_ENDPOINT_SOCKET",
    "RSS_ADMIN_LISTEN_ADDR",
    "RSS_AMQP_CA_CERT_PEM_PATH",
    "RSS_AMQP_URL",
    "RSS_AUDIT_CHAIN_KEY_B64URL",
    BUILD_SOURCE_REVISION_ENV,
    "RSS_COMMAND_IDEMPOTENCY_KEYS_JSON",
    "RSS_DLX_ARCHIVE_KEY_NAME",
    "RSS_DLX_ARCHIVE_S3_BUCKET",
    "RSS_DLX_ARCHIVE_VAULT_TOKEN",
    "RSS_DLX_HOT_VAULT_TOKEN",
    "RSS_DLX_PAYLOAD_KEY_NAME",
    DECLARED_IMAGE_DIGEST_ENV,
    "RSS_DOMAIN_TRANSPORT_MTLS_LOCAL_SPIFFE_ID",
    DOMAIN_TRANSPORT_SHARED_URL_ENV,
    "RSS_HEALTH_LISTEN_ADDR",
    "RSS_HTTP_SERVER_REQUEST_BUDGET_MS",
    "RSS_IDENTITY_AUTH_GRANT_TTL_SECS",
    "RSS_IDENTITY_PSEUDONYM_KEY_B64URL",
    IDENTITY_DOMAIN_PLACEMENT_WORKLOAD_ENV,
    SETTINGS_DOMAIN_PLACEMENT_WORKLOAD_ENV,
    AUDIT_DOMAIN_PLACEMENT_WORKLOAD_ENV,
    "RSS_ADMIN_TOKEN_PROFILE",
    "RSS_ACCESS_TOKEN_AUDIENCE",
    "RSS_ACCESS_TOKEN_ISSUER",
    "RSS_ACCESS_TOKEN_JWKS_PATH",
    "RSS_ACCESS_TOKEN_JWKS_REFRESH_INTERVAL_SECS",
    RSS_ACCESS_TOKEN_ROTATION_CLOCK_SKEW_SECS_ENV,
    RSS_ACCESS_TOKEN_ROTATION_JWKS_PROPAGATION_SLO_SECS_ENV,
    RSS_ACCESS_TOKEN_ROTATION_MARGIN_SECS_ENV,
    RSS_ACCESS_TOKEN_ROTATION_MODE_ENV,
    RSS_ACCESS_TOKEN_SIGNING_ACTIVE_KEY_ID_ENV,
    RSS_ACCESS_TOKEN_SIGNING_NEXT_KEY_ID_ENV,
    RSS_ACCESS_TOKEN_SIGNING_RETIRING_ENV,
    RSS_ACCESS_TOKEN_SIGNING_ROTATED_AT_ENV,
    "RSS_ACCESS_TOKEN_TTL_SECS",
    "RSS_FEDERATED_ACCESS_TOKEN_AUDIENCE",
    "RSS_FEDERATED_ACCESS_TOKEN_ISSUER",
    "RSS_FEDERATED_ACCESS_TOKEN_JWKS_PATH",
    "RSS_FEDERATED_ACCESS_TOKEN_JWKS_REFRESH_INTERVAL_SECS",
    "RSS_FEDERATED_ACCESS_TOKEN_TRUSTED_KINDS",
    "RSS_INTERNAL_AUTH_SCHEME",
    "RSS_INTERNAL_LISTEN_ADDR",
    "RSS_INTERNAL_MTLS_SPIFFE_ALLOW_SET",
    "RSS_KEYPROVIDER_READINESS_SAMPLE_INTERVAL_SECS",
    "RSS_L2_DR_RECOVERY_OPERATOR_GRANTS",
    "RSS_LISTENER_ALLOW_PLAINTEXT",
    "RSS_OTEL_ENDPOINT",
    "RSS_OUTBOX_RETAIN_SECONDS",
    "RSS_OUTBOX_SWEEP_INTERVAL_MS",
    "RSS_PASSWORD_BLOCKLIST_PATH",
    "RSS_PG_AUDIT_ADMIN_PASSWORD",
    "RSS_PG_AUDIT_ADMIN_PASSWORD_FILE",
    "RSS_PG_AUDIT_ADMIN_USERNAME",
    "RSS_PG_DATABASE",
    "RSS_PG_DLX_ARCHIVER_PASSWORD",
    "RSS_PG_DLX_ARCHIVER_PASSWORD_FILE",
    "RSS_PG_DLX_ARCHIVER_MAX_CONNECTIONS",
    "RSS_PG_DLX_ARCHIVER_USERNAME",
    "RSS_PG_DLX_PURGER_PASSWORD",
    "RSS_PG_DLX_PURGER_PASSWORD_FILE",
    "RSS_PG_DLX_PURGER_MAX_CONNECTIONS",
    "RSS_PG_DLX_PURGER_USERNAME",
    "RSS_PG_DLX_VERIFIER_PASSWORD",
    "RSS_PG_DLX_VERIFIER_PASSWORD_FILE",
    "RSS_PG_DLX_VERIFIER_MAX_CONNECTIONS",
    "RSS_PG_DLX_VERIFIER_USERNAME",
    "RSS_PG_HOST",
    "RSS_PG_L2_DR_RECOVERY_AUDITOR_USERNAME",
    "RSS_PG_L2_DR_RECOVERY_EXECUTOR_USERNAME",
    "RSS_PG_MAX_CONNECTIONS",
    "RSS_PG_MIGRATOR_PASSWORD",
    "RSS_PG_MIGRATOR_PASSWORD_FILE",
    "RSS_PG_MIGRATOR_USERNAME",
    "RSS_PG_PASSWORD",
    "RSS_PG_PASSWORD_FILE",
    "RSS_PG_PORT",
    "RSS_PG_READ_MAX_CONNECTIONS",
    "RSS_PG_READ_PASSWORD",
    "RSS_PG_READ_PASSWORD_FILE",
    "RSS_PG_READ_USERNAME",
    "RSS_PG_READINESS_SAMPLE_INTERVAL_SECS",
    "RSS_PG_SAGA_OPERATOR_PASSWORD",
    "RSS_PG_SAGA_OPERATOR_PASSWORD_FILE",
    "RSS_PG_SAGA_OPERATOR_USERNAME",
    "RSS_PG_SSL_ROOT_CERT_PATH",
    "RSS_PG_USERNAME",
    "RSS_PRIMARY_TOKEN_PROFILE",
    "RSS_PRIMARY_LISTEN_ADDR",
    "RSS_REDIS_CA_CERT_PEM_PATH",
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
    "RSS_S3_BUCKET",
    "RSS_S3_CA_CERT_PEM_PATH",
    "RSS_S3_CANARY_INTERVAL_SECS",
    "RSS_S3_CANARY_KEY_PREFIX",
    "RSS_S3_CANARY_TIMEOUT_SECS",
    "RSS_S3_ENDPOINT_URL",
    "RSS_S3_FORCE_PATH_STYLE",
    "RSS_S3_REGION",
    "RSS_S3_SECRET_ACCESS_KEY",
    "RSS_S3_SESSION_TOKEN",
    "RSS_AUTH_GRANT_SWEEP_INTERVAL_MS",
    "RSS_SERVICE_TOKEN_AUDIENCE",
    "RSS_SERVICE_TOKEN_HS256_KID",
    "RSS_SERVICE_TOKEN_HS256_SECRET_B64URL",
    "RSS_SERVICE_TOKEN_ISSUER",
    "RSS_SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES",
    "RSS_SETTINGS_CONFIG_VALUE_KEY_NAME",
    "RSS_TENANT_AUTHORITY_CLOCK_SKEW_SECS",
    "RSS_TENANT_AUTHORITY_HMAC_KEY_B64URL",
    "RSS_TENANT_AUTHORITY_TTL_SECS",
    "RSS_TOPOLOGY",
    "RSS_VAULT_ADDR",
    "RSS_VAULT_CA_CERT_PEM_PATH",
    "RSS_VAULT_TENANT_STORE_ALLOWLIST_JSON",
    "RSS_VAULT_TOKEN",
    "RSS_VAULT_TRANSIT_MOUNT",
];

/// Closed set visible to `rss projections ...`.
///
/// Secret values and password-file locations are installed only from the dedicated bundle. The
/// environment contributes the command's non-secret provider and sealed-plan configuration.
const FIXED_PROJECTION_OPERATOR_KEYS: &[&str] = &[
    "RUST_LOG",
    "RSS_OTEL_ENDPOINT",
    "RSS_PG_HOST",
    "RSS_PG_PORT",
    "RSS_PG_DATABASE",
    "RSS_PG_SSL_ROOT_CERT_PATH",
    "RSS_PG_PROJECTION_READER_USERNAME",
    "RSS_PG_PROJECTION_READER_PASSWORD_FILE",
    "RSS_PG_PROJECTION_OPERATOR_USERNAME",
    "RSS_PG_PROJECTION_OPERATOR_PASSWORD_FILE",
    "RSS_PROJECTION_OPERATOR_TOKEN_ISSUER",
    "RSS_PROJECTION_OPERATOR_TOKEN_AUDIENCE",
    "RSS_PROJECTION_OPERATOR_TOKEN_JWKS_PATH",
    "RSS_PROJECTION_OPERATOR_TOKEN_JWKS_REFRESH_INTERVAL_SECS",
    "RSS_PROJECTION_MAINTENANCE_OPERATOR_GRANTS",
    "RSS_DLX_PAYLOAD_KEY_NAME",
    "RSS_DLX_HOT_VAULT_TOKEN",
    "RSS_VAULT_ADDR",
    "RSS_VAULT_CA_CERT_PEM_PATH",
    "RSS_VAULT_TRANSIT_MOUNT",
    "RSS_PRIMARY_TOKEN_PROFILE",
    "RSS_ADMIN_TOKEN_PROFILE",
    "RSS_INTERNAL_AUTH_SCHEME",
    SETTINGS_DOMAIN_PLACEMENT_WORKLOAD_ENV,
    IDENTITY_DOMAIN_PLACEMENT_WORKLOAD_ENV,
    AUDIT_DOMAIN_PLACEMENT_WORKLOAD_ENV,
];

const FORBIDDEN_PROJECTION_OPERATOR_ENVIRONMENT_KEYS: &[&str] = &[
    "RSS_PG_PROJECTION_READER_PASSWORD",
    "RSS_PG_PROJECTION_READER_PASSWORD_FILE",
    "RSS_PG_PROJECTION_OPERATOR_PASSWORD",
    "RSS_PG_PROJECTION_OPERATOR_PASSWORD_FILE",
];

/// Closed set visible to `rss l2-dr-recovery ...`.
///
/// Password-file paths are read from the operator environment on this dedicated path only. Serving
/// capture rejects both plaintext passwords and password-file secret paths so the serving snapshot
/// cannot hold L2 DR lane credentials.
#[cfg(feature = "operator-cli")]
const FIXED_L2_DR_OPERATOR_KEYS: &[&str] = &[
    "RUST_LOG",
    "RSS_OTEL_ENDPOINT",
    "RSS_PG_HOST",
    "RSS_PG_PORT",
    "RSS_PG_DATABASE",
    "RSS_PG_SSL_ROOT_CERT_PATH",
    "RSS_L2_DR_RECOVERY_OPERATOR_GRANTS",
    "RSS_PG_L2_DR_RECOVERY_AUDITOR_USERNAME",
    "RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE",
    "RSS_PG_L2_DR_RECOVERY_EXECUTOR_USERNAME",
    "RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE",
];

/// Serving must reject these L2 DR secret channels; password-file paths belong only to the L2
/// operator snapshot, never the serving generation.
const FORBIDDEN_L2_DR_SERVING_SECRET_KEYS: &[&str] = &[
    "RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD",
    "RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD_FILE",
    "RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD",
    "RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD_FILE",
];

/// L2 DR operator capture rejects plaintext password environment channels only.
#[cfg(feature = "operator-cli")]
const FORBIDDEN_L2_DR_OPERATOR_PLAINTEXT_KEYS: &[&str] = &[
    "RSS_PG_L2_DR_RECOVERY_AUDITOR_PASSWORD",
    "RSS_PG_L2_DR_RECOVERY_EXECUTOR_PASSWORD",
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
struct ServingSecretBundle {
    secrets: BTreeMap<String, SecretText>,
}

struct ProjectionOperatorSecretBundle {
    secrets: BTreeMap<String, SecretText>,
}

struct EnvConfigSource;

const LEGACY_SECRET_ENVIRONMENT_KEYS: &[&str] = &[
    BUNDLE_PG_PASSWORD,
    BUNDLE_PG_READ_PASSWORD,
    BUNDLE_PG_AUDIT_ADMIN_PASSWORD,
    BUNDLE_PG_DLX_ARCHIVER_PASSWORD,
    BUNDLE_PG_DLX_VERIFIER_PASSWORD,
    BUNDLE_PG_DLX_PURGER_PASSWORD,
    "RSS_AMQP_URL",
    "RSS_SETTINGS_AMQP_URL",
    "RSS_IDENTITY_AMQP_URL",
    "RSS_AUDIT_AMQP_URL",
    "RSS_AUDIT_CHAIN_KEY_B64URL",
    "RSS_IDENTITY_PSEUDONYM_KEY_B64URL",
    "RSS_COMMAND_IDEMPOTENCY_KEYS_JSON",
    "RSS_DLX_ARCHIVE_VAULT_TOKEN",
    "RSS_DLX_HOT_VAULT_TOKEN",
    "RSS_PG_PASSWORD",
    "RSS_PG_PASSWORD_FILE",
    "RSS_PG_READ_PASSWORD",
    "RSS_PG_READ_PASSWORD_FILE",
    "RSS_PG_AUDIT_ADMIN_PASSWORD",
    "RSS_PG_AUDIT_ADMIN_PASSWORD_FILE",
    "RSS_PG_DLX_ARCHIVER_PASSWORD",
    "RSS_PG_DLX_ARCHIVER_PASSWORD_FILE",
    "RSS_PG_DLX_VERIFIER_PASSWORD",
    "RSS_PG_DLX_VERIFIER_PASSWORD_FILE",
    "RSS_PG_DLX_PURGER_PASSWORD",
    "RSS_PG_DLX_PURGER_PASSWORD_FILE",
    "RSS_REDIS_URL",
    "RSS_S3_ACCESS_KEY_ID",
    "RSS_S3_SECRET_ACCESS_KEY",
    "RSS_S3_SESSION_TOKEN",
    "RSS_SERVICE_TOKEN_HS256_SECRET_B64URL",
    "RSS_TENANT_AUTHORITY_HMAC_KEY_B64URL",
    "RSS_VAULT_TOKEN",
];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeServingSecretBundle {
    amqp_url: Option<SecretValue>,
    settings_amqp_url: Option<SecretValue>,
    identity_amqp_url: Option<SecretValue>,
    audit_amqp_url: Option<SecretValue>,
    audit_chain_key: Option<SecretValue>,
    identity_pseudonym_key: Option<SecretValue>,
    command_idempotency_keys: Option<SecretValue>,
    dlx_archive_vault_token: Option<SecretValue>,
    dlx_hot_vault_token: Option<SecretValue>,
    pg_password: Option<SecretValue>,
    pg_read_password: Option<SecretValue>,
    pg_audit_admin_password: Option<SecretValue>,
    pg_dlx_archiver_password: Option<SecretValue>,
    pg_dlx_verifier_password: Option<SecretValue>,
    pg_dlx_purger_password: Option<SecretValue>,
    redis_url: Option<SecretValue>,
    s3_access_key_id: Option<SecretValue>,
    s3_secret_access_key: Option<SecretValue>,
    s3_session_token: Option<SecretValue>,
    service_token_secret: Option<SecretValue>,
    tenant_authority_key: Option<SecretValue>,
    vault_token: Option<SecretValue>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeProjectionOperatorSecretBundle {
    pg_projection_reader_password_file: SecretValue,
    pg_projection_operator_password_file: SecretValue,
    replay_vault_token: SecretValue,
}

impl ServingSecretBundle {
    fn capture() -> Result<Self, RuntimeConfigCaptureError> {
        let document =
            runtimeexec::config::read_secret_document(Path::new(SERVING_SECRET_BUNDLE_PATH))
                .map_err(|_| RuntimeConfigCaptureError::SecretBundleRead)?;
        Self::from_secret_document(&document)
    }

    #[cfg(test)]
    fn from_document(document: &str) -> Result<Self, RuntimeConfigCaptureError> {
        let document = SecretDocument::new(zeroize::Zeroizing::new(document.to_owned()));
        Self::from_secret_document(&document)
    }

    fn from_secret_document(document: &SecretDocument) -> Result<Self, RuntimeConfigCaptureError> {
        let bundle: RuntimeServingSecretBundle = document
            .parse()
            .map_err(|_| RuntimeConfigCaptureError::InvalidSecretBundle)?;
        let mut secrets = BTreeMap::new();
        let entries = [
            ("RSS_AMQP_URL", bundle.amqp_url),
            ("RSS_SETTINGS_AMQP_URL", bundle.settings_amqp_url),
            ("RSS_IDENTITY_AMQP_URL", bundle.identity_amqp_url),
            ("RSS_AUDIT_AMQP_URL", bundle.audit_amqp_url),
            ("RSS_AUDIT_CHAIN_KEY_B64URL", bundle.audit_chain_key),
            (
                "RSS_IDENTITY_PSEUDONYM_KEY_B64URL",
                bundle.identity_pseudonym_key,
            ),
            (
                "RSS_COMMAND_IDEMPOTENCY_KEYS_JSON",
                bundle.command_idempotency_keys,
            ),
            (
                "RSS_DLX_ARCHIVE_VAULT_TOKEN",
                bundle.dlx_archive_vault_token,
            ),
            ("RSS_DLX_HOT_VAULT_TOKEN", bundle.dlx_hot_vault_token),
            (BUNDLE_PG_PASSWORD, bundle.pg_password),
            (BUNDLE_PG_READ_PASSWORD, bundle.pg_read_password),
            (
                BUNDLE_PG_AUDIT_ADMIN_PASSWORD,
                bundle.pg_audit_admin_password,
            ),
            (
                BUNDLE_PG_DLX_ARCHIVER_PASSWORD,
                bundle.pg_dlx_archiver_password,
            ),
            (
                BUNDLE_PG_DLX_VERIFIER_PASSWORD,
                bundle.pg_dlx_verifier_password,
            ),
            (BUNDLE_PG_DLX_PURGER_PASSWORD, bundle.pg_dlx_purger_password),
            ("RSS_REDIS_URL", bundle.redis_url),
            ("RSS_S3_ACCESS_KEY_ID", bundle.s3_access_key_id),
            ("RSS_S3_SECRET_ACCESS_KEY", bundle.s3_secret_access_key),
            ("RSS_S3_SESSION_TOKEN", bundle.s3_session_token),
            (
                "RSS_SERVICE_TOKEN_HS256_SECRET_B64URL",
                bundle.service_token_secret,
            ),
            (
                "RSS_TENANT_AUTHORITY_HMAC_KEY_B64URL",
                bundle.tenant_authority_key,
            ),
            ("RSS_VAULT_TOKEN", bundle.vault_token),
        ];
        for (name, value) in entries {
            if let Some(value) = value {
                if value.is_empty() {
                    return Err(RuntimeConfigCaptureError::InvalidSecretBundle);
                }
                secrets.insert(name.to_owned(), value.into_secret_text());
            }
        }
        Ok(Self { secrets })
    }
}

impl ProjectionOperatorSecretBundle {
    fn capture() -> Result<Self, RuntimeConfigCaptureError> {
        let document = runtimeexec::config::read_secret_document(Path::new(
            PROJECTION_OPERATOR_SECRET_BUNDLE_PATH,
        ))
        .map_err(|_| RuntimeConfigCaptureError::ProjectionSecretBundleRead)?;
        Self::from_secret_document(&document)
    }

    #[cfg(test)]
    fn from_document(document: &str) -> Result<Self, RuntimeConfigCaptureError> {
        let document = SecretDocument::new(zeroize::Zeroizing::new(document.to_owned()));
        Self::from_secret_document(&document)
    }

    fn from_secret_document(document: &SecretDocument) -> Result<Self, RuntimeConfigCaptureError> {
        let bundle: RuntimeProjectionOperatorSecretBundle = document
            .parse()
            .map_err(|_| RuntimeConfigCaptureError::InvalidProjectionSecretBundle)?;
        let entries = [
            (
                "RSS_PG_PROJECTION_READER_PASSWORD_FILE",
                bundle.pg_projection_reader_password_file,
            ),
            (
                "RSS_PG_PROJECTION_OPERATOR_PASSWORD_FILE",
                bundle.pg_projection_operator_password_file,
            ),
            ("RSS_DLX_HOT_VAULT_TOKEN", bundle.replay_vault_token),
        ];
        let mut secrets = BTreeMap::new();
        for (name, value) in entries {
            if value.is_empty() {
                return Err(RuntimeConfigCaptureError::InvalidProjectionSecretBundle);
            }
            secrets.insert(name.to_owned(), value.into_secret_text());
        }
        Ok(Self { secrets })
    }
}

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
    // Test fixtures may explicitly seed legacy secret slots; production still rejects ambient
    // secret environment channels via capture_process_snapshot + ServingSecretBundle.
    RuntimeConfigSnapshot::capture_test(TestConfigSource(
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
    #[error("removed runtime serving configuration key must not be set: {0}")]
    ForbiddenServingKey(&'static str),
    #[error("runtime serving secret bundle could not be read")]
    SecretBundleRead,
    #[error("runtime serving secret bundle is invalid")]
    InvalidSecretBundle,
    #[error("runtime projection operator secret bundle could not be read")]
    ProjectionSecretBundleRead,
    #[error("runtime projection operator secret bundle is invalid")]
    InvalidProjectionSecretBundle,
    #[error("runtime secret environment channel is forbidden: {0}")]
    ForbiddenSecretEnvironment(&'static str),
}

/// Immutable process-lifetime configuration generation.
///
/// INVARIANT: RUNTIME-CONFIG-SNAPSHOT-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" } -- private storage, by-value source consumption, mutually exclusive owned serving/operator/Projection inputs, the sole `RuntimeServingConfig` aggregate mapper, exact generated-domain inputs, and private-field `SnapshotConfig` signatures make snapshot omission and capability forgery unrepresentable for migrated serving, event/domain/DLX/worker, PostgreSQL maintenance, OIDC JWKS export, Projection control, and Vault-backed settings-maintenance consumers.
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

    fn is_configured(self, name: &str) -> bool {
        self.snapshot
            .values
            .get(name)
            .is_some_and(|value| !matches!(value, CapturedConfigValue::Missing))
    }
}

pub(crate) fn build_metadata(
    config: SnapshotConfig<'_>,
) -> anyhow::Result<Option<runtimeexec::inventory::BuildMetadata>> {
    runtimeexec::inventory::BuildMetadata::from_optional(
        config.value(BUILD_SOURCE_REVISION_ENV),
        config.value(DECLARED_IMAGE_DIGEST_ENV),
    )
    .map_err(anyhow::Error::from)
}

const PRIMARY_TOKEN_PROFILE_ENV: &str = "RSS_PRIMARY_TOKEN_PROFILE";
const ADMIN_TOKEN_PROFILE_ENV: &str = "RSS_ADMIN_TOKEN_PROFILE";
const INTERNAL_AUTH_SCHEME_ENV: &str = "RSS_INTERNAL_AUTH_SCHEME";

const RSS_ACCESS_TOKEN_ENV: [&str; 13] = [
    "RSS_ACCESS_TOKEN_ISSUER",
    "RSS_ACCESS_TOKEN_AUDIENCE",
    RSS_ACCESS_TOKEN_SIGNING_ACTIVE_KEY_ID_ENV,
    RSS_ACCESS_TOKEN_SIGNING_NEXT_KEY_ID_ENV,
    RSS_ACCESS_TOKEN_SIGNING_RETIRING_ENV,
    RSS_ACCESS_TOKEN_SIGNING_ROTATED_AT_ENV,
    "RSS_ACCESS_TOKEN_TTL_SECS",
    "RSS_ACCESS_TOKEN_JWKS_PATH",
    "RSS_ACCESS_TOKEN_JWKS_REFRESH_INTERVAL_SECS",
    RSS_ACCESS_TOKEN_ROTATION_CLOCK_SKEW_SECS_ENV,
    RSS_ACCESS_TOKEN_ROTATION_JWKS_PROPAGATION_SLO_SECS_ENV,
    RSS_ACCESS_TOKEN_ROTATION_MARGIN_SECS_ENV,
    RSS_ACCESS_TOKEN_ROTATION_MODE_ENV,
];

const DEFAULT_ROTATION_CLOCK_SKEW_SECS: u64 = 60;
const DEFAULT_ROTATION_JWKS_PROPAGATION_SLO_SECS: u64 = 300;
const DEFAULT_ROTATION_MARGIN_SECS: u64 = 60;
const MAX_ROTATION_POLICY_SECS: u64 = 86_400;
const FEDERATED_ACCESS_TOKEN_ENV: [&str; 5] = [
    "RSS_FEDERATED_ACCESS_TOKEN_ISSUER",
    "RSS_FEDERATED_ACCESS_TOKEN_AUDIENCE",
    "RSS_FEDERATED_ACCESS_TOKEN_TRUSTED_KINDS",
    "RSS_FEDERATED_ACCESS_TOKEN_JWKS_PATH",
    "RSS_FEDERATED_ACCESS_TOKEN_JWKS_REFRESH_INTERVAL_SECS",
];
const SERVICE_TOKEN_ENV: [&str; 4] = [
    "RSS_SERVICE_TOKEN_ISSUER",
    "RSS_SERVICE_TOKEN_AUDIENCE",
    "RSS_SERVICE_TOKEN_HS256_KID",
    "RSS_SERVICE_TOKEN_HS256_SECRET_B64URL",
];

const MIN_JWKS_REFRESH_INTERVAL_SECS: u64 = 5;
const MAX_JWKS_REFRESH_INTERVAL_SECS: u64 = 3_600;
const MIN_HS256_KEY_BYTES: usize = 32;
const MAX_HS256_KEY_BYTES: usize = 128;

/// Token profile selected for one external listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccessTokenProfileSelection {
    RssAccess,
    FederatedAccess,
}

impl AccessTokenProfileSelection {
    fn parse(config: SnapshotConfig<'_>, name: &'static str) -> anyhow::Result<Self> {
        match required_scalar(config, name)? {
            "rss-access" => Ok(Self::RssAccess),
            "federated-access" => Ok(Self::FederatedAccess),
            _ => anyhow::bail!("{name} must be exactly rss-access or federated-access"),
        }
    }
}

/// Authentication selected for the Internal listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InternalAuthSelection {
    Mtls,
    ServiceToken,
}

impl InternalAuthSelection {
    pub(crate) fn parse(config: SnapshotConfig<'_>) -> anyhow::Result<Self> {
        match required_scalar(config, INTERNAL_AUTH_SCHEME_ENV)? {
            "mtls" => Ok(Self::Mtls),
            "service-token" => Ok(Self::ServiceToken),
            _ => anyhow::bail!("{INTERNAL_AUTH_SCHEME_ENV} must be exactly mtls or service-token"),
        }
    }
}

/// Principal kinds that an access-token profile may assert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AccessPrincipalKind {
    User,
    Device,
    Admin,
    SuperAdmin,
}

impl AccessPrincipalKind {
    fn parse(value: &str, name: &'static str) -> anyhow::Result<Self> {
        match value {
            "user" => Ok(Self::User),
            "device" => Ok(Self::Device),
            "admin" => Ok(Self::Admin),
            "superAdmin" => Ok(Self::SuperAdmin),
            _ => anyhow::bail!("{name} entries must be exactly user, device, admin, or superAdmin"),
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Device => "device",
            Self::Admin => "admin",
            Self::SuperAdmin => "superAdmin",
        }
    }
}

struct AccessJwksLocation {
    watch_path: PathBuf,
    startup_identity: PathBuf,
}

impl AccessJwksLocation {
    fn parse(config: SnapshotConfig<'_>, name: &'static str) -> anyhow::Result<Self> {
        let watch_path = PathBuf::from(required_scalar(config, name)?);
        let startup_identity = std::fs::canonicalize(&watch_path).map_err(|_| {
            anyhow::anyhow!("{name} must reference an existing canonicalizable path")
        })?;
        Ok(Self {
            watch_path,
            startup_identity,
        })
    }

    fn watch_path(&self) -> &Path {
        &self.watch_path
    }

    fn same_startup_identity(&self, other: &Self) -> bool {
        self.startup_identity == other.startup_identity
    }
}

struct AccessVerifierConfigCore {
    issuer: String,
    audience: String,
    jwks_location: AccessJwksLocation,
    jwks_refresh_interval: Duration,
}

impl AccessVerifierConfigCore {
    fn parse(
        config: SnapshotConfig<'_>,
        issuer_env: &'static str,
        audience_env: &'static str,
        jwks_path_env: &'static str,
        refresh_interval_env: &'static str,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            issuer: required_scalar(config, issuer_env)?.to_owned(),
            audience: required_scalar(config, audience_env)?.to_owned(),
            jwks_location: AccessJwksLocation::parse(config, jwks_path_env)?,
            jwks_refresh_interval: required_duration_secs(
                config,
                refresh_interval_env,
                MIN_JWKS_REFRESH_INTERVAL_SECS,
                MAX_JWKS_REFRESH_INTERVAL_SECS,
            )?,
        })
    }

    fn same_jwks_startup_identity(&self, other: &Self) -> bool {
        self.jwks_location
            .same_startup_identity(&other.jwks_location)
    }
}

/// Closed RSS access-token configuration.
pub(crate) struct RssAccessTokenConfig {
    verifier: AccessVerifierConfigCore,
    signing_key_ring: authn::SigningKeyRing,
    rotation_mode: authn::RotationMode,
    ttl: Duration,
}

impl RssAccessTokenConfig {
    fn parse(config: SnapshotConfig<'_>) -> anyhow::Result<Self> {
        let verifier = AccessVerifierConfigCore::parse(
            config,
            "RSS_ACCESS_TOKEN_ISSUER",
            "RSS_ACCESS_TOKEN_AUDIENCE",
            "RSS_ACCESS_TOKEN_JWKS_PATH",
            "RSS_ACCESS_TOKEN_JWKS_REFRESH_INTERVAL_SECS",
        )?;
        let ttl = required_duration_secs(
            config,
            "RSS_ACCESS_TOKEN_TTL_SECS",
            1,
            diport::TokenProfile::RssAccess
                .policy()
                .maximum_lifetime()
                .as_secs(),
        )?;
        let (signing_key_ring, rotation_mode) = parse_rss_signing_rotation(config, ttl)?;
        Ok(Self {
            verifier,
            signing_key_ring,
            rotation_mode,
            ttl,
        })
    }

    pub(crate) fn issuer(&self) -> &str {
        &self.verifier.issuer
    }

    pub(crate) fn audience(&self) -> &str {
        &self.verifier.audience
    }

    pub(crate) fn jwks_path(&self) -> &Path {
        self.verifier.jwks_location.watch_path()
    }

    pub(crate) const fn jwks_refresh_interval(&self) -> Duration {
        self.verifier.jwks_refresh_interval
    }

    /// Signing key ring for mint / rotation probe wiring.
    pub(crate) fn signing_key_ring(&self) -> &authn::SigningKeyRing {
        &self.signing_key_ring
    }

    /// Retirement deadlines derived from the signing key ring (single source).
    #[allow(clippy::expect_used)]
    pub(crate) fn retirement_schedule(&self) -> oidc::RetirementSchedule {
        oidc::RetirementSchedule::from_entries(
            self.signing_key_ring
                .retiring()
                .iter()
                .map(|(kid, until)| (kid.as_str().to_owned(), *until)),
        )
        .expect("SigningKeyRing retiring entries are already validated")
    }

    /// Planned vs emergency rotation mode.
    pub(crate) const fn rotation_mode(&self) -> authn::RotationMode {
        self.rotation_mode
    }

    #[cfg(test)]
    pub(crate) const fn ttl(&self) -> Duration {
        self.ttl
    }

    fn issuer_config(&self) -> authn::JwtIssuerConfig<diport::RssAccessProfile> {
        authn::JwtIssuerConfig::rss_access(
            self.signing_key_ring.clone(),
            diport::SigningPurpose::new("auth.rss-access"),
            self.issuer(),
            self.audience(),
            self.ttl,
        )
    }
}

fn parse_rss_signing_rotation(
    config: SnapshotConfig<'_>,
    max_access_ttl: Duration,
) -> anyhow::Result<(authn::SigningKeyRing, authn::RotationMode)> {
    let active = required_scalar(config, RSS_ACCESS_TOKEN_SIGNING_ACTIVE_KEY_ID_ENV)?;
    let next = optional_scalar(config, RSS_ACCESS_TOKEN_SIGNING_NEXT_KEY_ID_ENV)?;
    let retiring = parse_signing_retiring(config)?;
    let rotated_at = optional_i64(config, RSS_ACCESS_TOKEN_SIGNING_ROTATED_AT_ENV)?;
    let rotation_mode = parse_rotation_mode(config)?;
    let policy = authn::RotationOverlapPolicy {
        max_access_ttl,
        clock_skew: optional_duration_secs_with_default(
            config,
            RSS_ACCESS_TOKEN_ROTATION_CLOCK_SKEW_SECS_ENV,
            DEFAULT_ROTATION_CLOCK_SKEW_SECS,
            0,
            MAX_ROTATION_POLICY_SECS,
        )?,
        jwks_propagation_slo: optional_duration_secs_with_default(
            config,
            RSS_ACCESS_TOKEN_ROTATION_JWKS_PROPAGATION_SLO_SECS_ENV,
            DEFAULT_ROTATION_JWKS_PROPAGATION_SLO_SECS,
            0,
            MAX_ROTATION_POLICY_SECS,
        )?,
        margin: optional_duration_secs_with_default(
            config,
            RSS_ACCESS_TOKEN_ROTATION_MARGIN_SECS_ENV,
            DEFAULT_ROTATION_MARGIN_SECS,
            0,
            MAX_ROTATION_POLICY_SECS,
        )?,
    };

    if !retiring.is_empty() {
        let rotated_at = rotated_at.ok_or_else(|| {
            anyhow::anyhow!(
                "{RSS_ACCESS_TOKEN_SIGNING_ROTATED_AT_ENV} is required when {RSS_ACCESS_TOKEN_SIGNING_RETIRING_ENV} is set"
            )
        })?;
        for (_, verify_until) in &retiring {
            policy
                .validate_overlap(rotated_at, *verify_until, rotation_mode)
                .map_err(|error| {
                    map_rotation_overlap_error(error, &policy, rotated_at, *verify_until)
                })?;
        }
    }

    let ring = authn::SigningKeyRing::with_rotation(
        diport::KeyId::new(active.to_owned()),
        next.map(|kid| diport::KeyId::new(kid.to_owned())),
        retiring
            .into_iter()
            .map(|(kid, until)| (diport::KeyId::new(kid), until))
            .collect(),
    )
    .map_err(signing_key_ring_error)?;

    Ok((ring, rotation_mode))
}

fn parse_signing_retiring(config: SnapshotConfig<'_>) -> anyhow::Result<Vec<(String, i64)>> {
    let Some(raw) = optional_scalar(config, RSS_ACCESS_TOKEN_SIGNING_RETIRING_ENV)? else {
        return Ok(Vec::new());
    };
    parse_signing_retiring_raw(raw)
}

/// Parse `kid=unixSeconds` comma-separated retiring entries (shared with JWKS export).
pub(crate) fn parse_signing_retiring_raw(raw: &str) -> anyhow::Result<Vec<(String, i64)>> {
    let mut entries = Vec::new();
    for part in raw.split(',') {
        anyhow::ensure!(
            !part.is_empty(),
            "{RSS_ACCESS_TOKEN_SIGNING_RETIRING_ENV} must not contain empty entries"
        );
        let (kid, until_raw) = part.split_once('=').ok_or_else(|| {
            anyhow::anyhow!(
                "{RSS_ACCESS_TOKEN_SIGNING_RETIRING_ENV} entries must be kid=unixSeconds"
            )
        })?;
        anyhow::ensure!(
            !kid.is_empty(),
            "{RSS_ACCESS_TOKEN_SIGNING_RETIRING_ENV} key id must not be empty"
        );
        let verify_until = until_raw.parse::<i64>().map_err(|_| {
            anyhow::anyhow!(
                "{RSS_ACCESS_TOKEN_SIGNING_RETIRING_ENV} verify-until must be unix seconds"
            )
        })?;
        entries.push((kid.to_owned(), verify_until));
    }
    anyhow::ensure!(
        !entries.is_empty(),
        "{RSS_ACCESS_TOKEN_SIGNING_RETIRING_ENV} must list at least one entry when set"
    );
    Ok(entries)
}

fn parse_rotation_mode(config: SnapshotConfig<'_>) -> anyhow::Result<authn::RotationMode> {
    match optional_scalar(config, RSS_ACCESS_TOKEN_ROTATION_MODE_ENV)? {
        None | Some("planned") => Ok(authn::RotationMode::Planned),
        Some("emergency") => {
            tracing::warn!(
                reason = "RSS_ACCESS_TOKEN_ROTATION_MODE=emergency",
                "signing-key rotation running in emergency mode; planned overlap checks are skipped"
            );
            Ok(authn::RotationMode::Emergency)
        }
        Some(_) => {
            anyhow::bail!(
                "{RSS_ACCESS_TOKEN_ROTATION_MODE_ENV} must be exactly planned or emergency"
            )
        }
    }
}

fn signing_key_ring_error(error: authn::KeyRingError) -> anyhow::Error {
    anyhow::anyhow!("{error}")
}

fn map_rotation_overlap_error(
    error: authn::KeyRingError,
    policy: &authn::RotationOverlapPolicy,
    rotated_at: i64,
    verify_until: i64,
) -> anyhow::Error {
    match error {
        authn::KeyRingError::InsufficientOverlap => {
            let need = policy.min_overlap().as_secs();
            let have = verify_until.saturating_sub(rotated_at);
            anyhow::anyhow!(
                "rotation verify overlap is insufficient: need {need}s have {have}s \
                 (knobs: RSS_ACCESS_TOKEN_TTL_SECS, RSS_ACCESS_TOKEN_ROTATION_CLOCK_SKEW_SECS, \
                 RSS_ACCESS_TOKEN_ROTATION_JWKS_PROPAGATION_SLO_SECS, \
                 RSS_ACCESS_TOKEN_ROTATION_MARGIN_SECS)"
            )
        }
        other => signing_key_ring_error(other),
    }
}

/// Closed federated access-token configuration.
pub(crate) struct FederatedAccessTokenConfig {
    verifier: AccessVerifierConfigCore,
    trusted_kinds: Vec<AccessPrincipalKind>,
}

impl FederatedAccessTokenConfig {
    fn parse(config: SnapshotConfig<'_>) -> anyhow::Result<Self> {
        Ok(Self {
            verifier: AccessVerifierConfigCore::parse(
                config,
                "RSS_FEDERATED_ACCESS_TOKEN_ISSUER",
                "RSS_FEDERATED_ACCESS_TOKEN_AUDIENCE",
                "RSS_FEDERATED_ACCESS_TOKEN_JWKS_PATH",
                "RSS_FEDERATED_ACCESS_TOKEN_JWKS_REFRESH_INTERVAL_SECS",
            )?,
            trusted_kinds: trusted_access_kinds(
                config,
                "RSS_FEDERATED_ACCESS_TOKEN_TRUSTED_KINDS",
            )?,
        })
    }

    pub(crate) fn issuer(&self) -> &str {
        &self.verifier.issuer
    }

    pub(crate) fn audience(&self) -> &str {
        &self.verifier.audience
    }

    pub(crate) fn trusted_kinds(&self) -> &[AccessPrincipalKind] {
        &self.trusted_kinds
    }

    pub(crate) fn jwks_path(&self) -> &Path {
        self.verifier.jwks_location.watch_path()
    }

    pub(crate) const fn jwks_refresh_interval(&self) -> Duration {
        self.verifier.jwks_refresh_interval
    }
}

/// Dedicated verifier-only Projection operator token configuration.
pub(crate) struct ProjectionOperatorTokenConfig {
    verifier: AccessVerifierConfigCore,
}

impl ProjectionOperatorTokenConfig {
    pub(crate) fn from_snapshot(config: SnapshotConfig<'_>) -> anyhow::Result<Self> {
        Ok(Self {
            verifier: AccessVerifierConfigCore::parse(
                config,
                "RSS_PROJECTION_OPERATOR_TOKEN_ISSUER",
                "RSS_PROJECTION_OPERATOR_TOKEN_AUDIENCE",
                "RSS_PROJECTION_OPERATOR_TOKEN_JWKS_PATH",
                "RSS_PROJECTION_OPERATOR_TOKEN_JWKS_REFRESH_INTERVAL_SECS",
            )?,
        })
    }

    pub(crate) fn issuer(&self) -> &str {
        &self.verifier.issuer
    }

    pub(crate) fn audience(&self) -> &str {
        &self.verifier.audience
    }

    pub(crate) fn jwks_path(&self) -> &Path {
        self.verifier.jwks_location.watch_path()
    }

    pub(crate) const fn jwks_refresh_interval(&self) -> Duration {
        self.verifier.jwks_refresh_interval
    }
}

/// Closed Service Token configuration.
pub(crate) struct ServiceTokenConfig {
    issuer: String,
    audience: String,
    hs256_kid: String,
    hs256_secret: diport::SecretMaterial,
}

impl ServiceTokenConfig {
    pub(crate) fn from_snapshot(config: SnapshotConfig<'_>) -> anyhow::Result<Self> {
        Self::parse(config)
    }

    fn parse(config: SnapshotConfig<'_>) -> anyhow::Result<Self> {
        let secret = required_scalar(config, "RSS_SERVICE_TOKEN_HS256_SECRET_B64URL")?;
        let mut decoded = [0_u8; MAX_HS256_KEY_BYTES];
        let hs256_secret = (|| {
            let decoded_len = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode_slice(secret, &mut decoded)
                .map_err(|_| {
                    anyhow::anyhow!(
                        "RSS_SERVICE_TOKEN_HS256_SECRET_B64URL must encode {MIN_HS256_KEY_BYTES}..={MAX_HS256_KEY_BYTES} bytes as unpadded base64url"
                    )
                })?;
            anyhow::ensure!(
                (MIN_HS256_KEY_BYTES..=MAX_HS256_KEY_BYTES).contains(&decoded_len),
                "RSS_SERVICE_TOKEN_HS256_SECRET_B64URL must encode {MIN_HS256_KEY_BYTES}..={MAX_HS256_KEY_BYTES} bytes"
            );
            Ok::<_, anyhow::Error>(diport::SecretMaterial::new(decoded[..decoded_len].to_vec()))
        })();
        decoded.fill(0);
        let hs256_secret = hs256_secret?;
        Ok(Self {
            issuer: required_scalar(config, "RSS_SERVICE_TOKEN_ISSUER")?.to_owned(),
            audience: required_scalar(config, "RSS_SERVICE_TOKEN_AUDIENCE")?.to_owned(),
            hs256_kid: required_scalar(config, "RSS_SERVICE_TOKEN_HS256_KID")?.to_owned(),
            hs256_secret,
        })
    }

    pub(crate) fn issuer(&self) -> &str {
        &self.issuer
    }

    pub(crate) fn audience(&self) -> &str {
        &self.audience
    }

    pub(crate) fn hs256_kid(&self) -> &str {
        &self.hs256_kid
    }

    pub(crate) fn hs256_secret(&self) -> &[u8] {
        self.hs256_secret.expose()
    }
}

/// One process-wide, mutually exclusive token-profile configuration generation.
pub(crate) struct TokenProfilesConfig {
    primary: AccessTokenProfileSelection,
    rss_access: Option<RssAccessTokenConfig>,
    federated_access: Option<FederatedAccessTokenConfig>,
    service_token: Option<ServiceTokenConfig>,
}

impl TokenProfilesConfig {
    pub(crate) fn listener_selections(
        config: SnapshotConfig<'_>,
    ) -> anyhow::Result<(
        AccessTokenProfileSelection,
        AccessTokenProfileSelection,
        InternalAuthSelection,
    )> {
        let primary = AccessTokenProfileSelection::parse(config, PRIMARY_TOKEN_PROFILE_ENV)?;
        let admin = AccessTokenProfileSelection::parse(config, ADMIN_TOKEN_PROFILE_ENV)?;
        let internal = InternalAuthSelection::parse(config)?;
        anyhow::ensure!(
            !matches!(
                (primary, admin),
                (
                    AccessTokenProfileSelection::FederatedAccess,
                    AccessTokenProfileSelection::RssAccess
                )
            ),
            "federated Primary requires federated Admin"
        );
        Ok((primary, admin, internal))
    }

    pub(crate) fn from_snapshot(config: SnapshotConfig<'_>) -> anyhow::Result<Self> {
        let (primary, admin, internal) = Self::listener_selections(config)?;

        let rss_active = matches!(primary, AccessTokenProfileSelection::RssAccess)
            || matches!(admin, AccessTokenProfileSelection::RssAccess);
        let federated_active = matches!(primary, AccessTokenProfileSelection::FederatedAccess)
            || matches!(admin, AccessTokenProfileSelection::FederatedAccess);
        let service_active = matches!(internal, InternalAuthSelection::ServiceToken);

        let rss_access = parse_active_namespace(
            config,
            rss_active,
            "RSS_ACCESS_TOKEN_*",
            &RSS_ACCESS_TOKEN_ENV,
            RssAccessTokenConfig::parse,
        )?;
        let federated_access = parse_active_namespace(
            config,
            federated_active,
            "RSS_FEDERATED_ACCESS_TOKEN_*",
            &FEDERATED_ACCESS_TOKEN_ENV,
            FederatedAccessTokenConfig::parse,
        )?;
        let service_token = parse_active_namespace(
            config,
            service_active,
            "RSS_SERVICE_TOKEN_*",
            &SERVICE_TOKEN_ENV,
            ServiceTokenConfig::parse,
        )?;

        ensure_profile_trust_isolation(
            rss_access.as_ref(),
            federated_access.as_ref(),
            service_token.as_ref(),
        )?;

        Ok(Self {
            primary,
            rss_access,
            federated_access,
            service_token,
        })
    }

    pub(crate) fn rss_access(&self) -> Option<&RssAccessTokenConfig> {
        self.rss_access.as_ref()
    }

    pub(crate) fn federated_access(&self) -> Option<&FederatedAccessTokenConfig> {
        self.federated_access.as_ref()
    }

    pub(crate) fn service_token(&self) -> Option<&ServiceTokenConfig> {
        self.service_token.as_ref()
    }

    fn primary_identity_profile(
        &self,
    ) -> anyhow::Result<crate::domains::identity::IdentityTokenProfileInput> {
        match self.primary {
            AccessTokenProfileSelection::RssAccess => self
                .rss_access
                .as_ref()
                .map(|config| {
                    crate::domains::identity::IdentityTokenProfileInput::rss_access(
                        config.issuer_config(),
                    )
                })
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "RSS Primary token profile is missing its typed issuer configuration"
                    )
                }),
            AccessTokenProfileSelection::FederatedAccess => {
                Ok(crate::domains::identity::IdentityTokenProfileInput::federated_access())
            }
        }
    }
}

impl std::fmt::Debug for TokenProfilesConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TokenProfilesConfig(<redacted>)")
    }
}

fn required_scalar<'a>(config: SnapshotConfig<'a>, name: &'static str) -> anyhow::Result<&'a str> {
    let value = config
        .value(name)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {name}"))?;
    anyhow::ensure!(!value.is_empty(), "{name} must not be empty");
    anyhow::ensure!(
        value.trim() == value
            && !value.chars().any(char::is_control)
            && !value.chars().any(char::is_whitespace),
        "{name} must not contain leading, trailing, whitespace, or control characters"
    );
    Ok(value)
}

fn optional_scalar<'a>(
    config: SnapshotConfig<'a>,
    name: &'static str,
) -> anyhow::Result<Option<&'a str>> {
    match config.value(name) {
        None => Ok(None),
        Some(_) => required_scalar(config, name).map(Some),
    }
}

fn optional_i64(config: SnapshotConfig<'_>, name: &'static str) -> anyhow::Result<Option<i64>> {
    match optional_scalar(config, name)? {
        None => Ok(None),
        Some(raw) => raw
            .parse::<i64>()
            .map(Some)
            .map_err(|_| anyhow::anyhow!("{name} must be unix seconds")),
    }
}

fn optional_duration_secs_with_default(
    config: SnapshotConfig<'_>,
    name: &'static str,
    default: u64,
    min: u64,
    max: u64,
) -> anyhow::Result<Duration> {
    match optional_scalar(config, name)? {
        None => Ok(Duration::from_secs(default)),
        Some(_) => required_duration_secs(config, name, min, max),
    }
}

fn required_duration_secs(
    config: SnapshotConfig<'_>,
    name: &'static str,
    min: u64,
    max: u64,
) -> anyhow::Result<Duration> {
    let raw = required_scalar(config, name)?;
    let seconds = raw
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("{name} must be seconds in {min}..={max}"))?;
    anyhow::ensure!(
        (min..=max).contains(&seconds),
        "{name} must be seconds in {min}..={max}"
    );
    Ok(Duration::from_secs(seconds))
}

fn trusted_access_kinds(
    config: SnapshotConfig<'_>,
    name: &'static str,
) -> anyhow::Result<Vec<AccessPrincipalKind>> {
    let raw = required_scalar(config, name)?;
    let mut kinds = BTreeSet::new();
    for value in raw.split(',') {
        anyhow::ensure!(!value.is_empty(), "{name} must not contain empty entries");
        let kind = AccessPrincipalKind::parse(value, name)?;
        anyhow::ensure!(kinds.insert(kind), "{name} must not contain duplicates");
    }
    anyhow::ensure!(!kinds.is_empty(), "{name} must list at least one kind");
    Ok(kinds.into_iter().collect())
}

fn parse_active_namespace<T>(
    config: SnapshotConfig<'_>,
    active: bool,
    namespace: &'static str,
    keys: &[&str],
    parse: impl FnOnce(SnapshotConfig<'_>) -> anyhow::Result<T>,
) -> anyhow::Result<Option<T>> {
    if active {
        return parse(config).map(Some);
    }
    anyhow::ensure!(
        !keys.iter().any(|name| config.is_configured(name)),
        "orphan token profile configuration: {namespace} is configured but no listener selects it"
    );
    Ok(None)
}

fn ensure_profile_trust_isolation(
    rss: Option<&RssAccessTokenConfig>,
    federated: Option<&FederatedAccessTokenConfig>,
    service: Option<&ServiceTokenConfig>,
) -> anyhow::Result<()> {
    if let (Some(rss), Some(federated)) = (rss, federated) {
        anyhow::ensure!(
            rss.issuer() != federated.issuer(),
            "RSS and federated access token issuers must be distinct"
        );
        anyhow::ensure!(
            rss.audience() != federated.audience(),
            "RSS and federated access token audiences must be distinct"
        );
        anyhow::ensure!(
            !rss.verifier.same_jwks_startup_identity(&federated.verifier),
            "RSS and federated access token canonical JWKS paths must be distinct"
        );
    }
    if let Some(service) = service {
        for (name, issuer, audience) in [
            (
                "RSS access",
                rss.map(RssAccessTokenConfig::issuer),
                rss.map(RssAccessTokenConfig::audience),
            ),
            (
                "federated access",
                federated.map(FederatedAccessTokenConfig::issuer),
                federated.map(FederatedAccessTokenConfig::audience),
            ),
        ] {
            if let Some(issuer) = issuer {
                anyhow::ensure!(
                    service.issuer() != issuer,
                    "Service Token issuer must be distinct from the active {name} issuer"
                );
            }
            if let Some(audience) = audience {
                anyhow::ensure!(
                    service.audience() != audience,
                    "Service Token audience must be distinct from the active {name} audience"
                );
            }
        }
    }
    Ok(())
}

pub(crate) struct ServingConfigMapper<'a> {
    config: SnapshotConfig<'a>,
}

impl<'a> ServingConfigMapper<'a> {
    pub(crate) fn new(config: SnapshotConfig<'a>) -> Self {
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
    auth_grant_sweep_interval: std::time::Duration,
    keyprovider_readiness_interval: settings_composition::KeyProviderReadinessInterval,
}

impl WorkerRuntimeConfig {
    pub(crate) fn from_mapper(mapper: &ServingConfigMapper<'_>) -> anyhow::Result<Self> {
        let config = mapper.config();
        Ok(Self {
            event: crate::event_transport::EventWorkerConfig::from_mapper(mapper)?,
            dlx: crate::event_transport::DlxWorkerConfig::canonical(),
            distributed: crate::distributed_runtime::DistributedWorkerConfig::canonical(),
            auth_grant_sweep_interval: auth_grant_sweep_interval_from_value(
                config.value("RSS_AUTH_GRANT_SWEEP_INTERVAL_MS"),
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
            self.auth_grant_sweep_interval,
            self.keyprovider_readiness_interval,
        )
    }
}

pub(crate) struct RuntimeServingConfig {
    token_profiles: TokenProfilesConfig,
    event_transport: crate::event_transport::EventTransportConfig,
    event_worker: crate::event_transport::EventWorkerConfig,
    dlx_worker: crate::event_transport::DlxWorkerConfig,
    distributed_worker: crate::distributed_runtime::DistributedWorkerConfig,
    domain_modules: crate::domains::DomainModuleInputs,
    audit_consumer_key: primitives::MacKey,
    auth_grant_sweep_interval: std::time::Duration,
}

pub(crate) struct RuntimeServingConfigParts {
    pub(crate) token_profiles: TokenProfilesConfig,
    pub(crate) event_transport: crate::event_transport::EventTransportConfig,
    pub(crate) event_worker: crate::event_transport::EventWorkerConfig,
    pub(crate) dlx_worker: crate::event_transport::DlxWorkerConfig,
    pub(crate) distributed_worker: crate::distributed_runtime::DistributedWorkerConfig,
    pub(crate) domain_modules: crate::domains::DomainModuleInputs,
    pub(crate) audit_consumer_key: primitives::MacKey,
    pub(crate) auth_grant_sweep_interval: std::time::Duration,
}

impl RuntimeServingConfig {
    pub(crate) fn from_snapshot(config: SnapshotConfig<'_>) -> anyhow::Result<Self> {
        let mapper = ServingConfigMapper::new(config);
        let token_profiles = TokenProfilesConfig::from_snapshot(config)?;
        let identity_token_profile = token_profiles.primary_identity_profile()?;
        let event_transport = crate::event_transport::EventTransportConfig::from_mapper(&mapper)?;
        let WorkerRuntimeConfig {
            event,
            dlx,
            distributed,
            auth_grant_sweep_interval,
            keyprovider_readiness_interval,
        } = WorkerRuntimeConfig::from_mapper(&mapper)?;
        let domain_modules = crate::domains::DomainModuleInputs::from_snapshot(
            &mapper,
            keyprovider_readiness_interval,
            identity_token_profile,
        )?;
        let audit_consumer_key = domain_modules.audit_consumer_key();
        Ok(Self {
            token_profiles,
            event_transport,
            event_worker: event,
            dlx_worker: dlx,
            distributed_worker: distributed,
            domain_modules,
            audit_consumer_key,
            auth_grant_sweep_interval,
        })
    }

    pub(crate) fn into_parts(self) -> RuntimeServingConfigParts {
        RuntimeServingConfigParts {
            token_profiles: self.token_profiles,
            event_transport: self.event_transport,
            event_worker: self.event_worker,
            dlx_worker: self.dlx_worker,
            distributed_worker: self.distributed_worker,
            domain_modules: self.domain_modules,
            audit_consumer_key: self.audit_consumer_key,
            auth_grant_sweep_interval: self.auth_grant_sweep_interval,
        }
    }
}

const DEFAULT_AUTH_GRANT_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);
const MIN_AUTH_GRANT_SWEEP_INTERVAL_MS: u64 = 1_000;
fn auth_grant_sweep_interval_from_value(raw: Option<&str>) -> std::time::Duration {
    match raw {
        None => DEFAULT_AUTH_GRANT_SWEEP_INTERVAL,
        Some(raw) => match raw.trim().parse::<u64>() {
            Ok(milliseconds) if milliseconds >= MIN_AUTH_GRANT_SWEEP_INTERVAL_MS => {
                std::time::Duration::from_millis(milliseconds)
            }
            _ => {
                tracing::warn!(
                    env = "RSS_AUTH_GRANT_SWEEP_INTERVAL_MS",
                    default_ms = DEFAULT_AUTH_GRANT_SWEEP_INTERVAL.as_millis(),
                    min_ms = MIN_AUTH_GRANT_SWEEP_INTERVAL_MS,
                    "invalid AuthGrant sweep interval (expected u64 ms >= 1000); using default"
                );
                DEFAULT_AUTH_GRANT_SWEEP_INTERVAL
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
        let bundle = ServingSecretBundle::capture()?;
        let mut snapshot = Self::capture_with_forbidden_check(EnvConfigSource)?;
        snapshot.install_secret_bundle(bundle)?;
        Ok(snapshot)
    }

    /// Capture the Projection CLI's independent closed generation.
    ///
    /// The serving bundle is neither opened nor represented in this path. Secret environment
    /// channels are rejected before the dedicated bundle is read, and bundle fields are installed
    /// into predeclared slots without an environment fallback.
    pub(crate) fn capture_projection_operator_process_snapshot()
    -> Result<Self, RuntimeConfigCaptureError> {
        let mut snapshot = Self::capture_projection_operator(EnvConfigSource)?;
        snapshot.reject_projection_operator_secret_environment()?;
        let bundle = ProjectionOperatorSecretBundle::capture()?;
        snapshot.install_projection_operator_secret_bundle(bundle)?;
        Ok(snapshot)
    }

    /// Capture the L2 DR operator CLI's independent closed generation.
    ///
    /// Serving secret channels are neither opened nor represented here. Plaintext L2 DR passwords
    /// are rejected; password-file paths are read only through this dedicated catalog.
    #[cfg(feature = "operator-cli")]
    pub(crate) fn capture_l2_dr_operator_process_snapshot()
    -> Result<Self, RuntimeConfigCaptureError> {
        let snapshot = Self::capture_l2_dr_operator(EnvConfigSource)?;
        snapshot.reject_l2_dr_operator_plaintext_environment()?;
        Ok(snapshot)
    }

    /// Test-only generic capture surface for purpose-built source fakes.
    #[cfg(test)]
    pub(crate) fn capture_test(
        source: impl RuntimeConfigSource,
    ) -> Result<Self, RuntimeConfigCaptureError> {
        Self::capture(source)
    }

    #[cfg(test)]
    pub(crate) fn capture_serving_test(
        source: impl RuntimeConfigSource,
    ) -> Result<Self, RuntimeConfigCaptureError> {
        Self::capture_with_forbidden_check(source)
    }

    #[cfg(test)]
    pub(crate) fn capture_projection_operator_test(
        source: impl RuntimeConfigSource,
        bundle_document: &str,
    ) -> Result<Self, RuntimeConfigCaptureError> {
        let mut snapshot = Self::capture_projection_operator(source)?;
        snapshot.reject_projection_operator_secret_environment()?;
        let bundle = ProjectionOperatorSecretBundle::from_document(bundle_document)?;
        snapshot.install_projection_operator_secret_bundle(bundle)?;
        Ok(snapshot)
    }

    #[cfg(all(test, feature = "operator-cli"))]
    pub(crate) fn capture_l2_dr_operator_test(
        source: impl RuntimeConfigSource,
    ) -> Result<Self, RuntimeConfigCaptureError> {
        let snapshot = Self::capture_l2_dr_operator(source)?;
        snapshot.reject_l2_dr_operator_plaintext_environment()?;
        Ok(snapshot)
    }

    fn capture_with_forbidden_check(
        mut source: impl RuntimeConfigSource,
    ) -> Result<Self, RuntimeConfigCaptureError> {
        reject_forbidden_serving_keys(&mut source)?;
        let snapshot = Self::capture(source)?;
        snapshot.reject_legacy_secret_environment()?;
        Ok(snapshot)
    }

    /// Consume a source and capture each unique serving key exactly once.
    fn capture(mut source: impl RuntimeConfigSource) -> Result<Self, RuntimeConfigCaptureError> {
        let mut catalog = fixed_catalog()?;
        add_generated_event_keys(&mut catalog);
        for key in LEGACY_SECRET_ENVIRONMENT_KEYS
            .iter()
            .chain(FORBIDDEN_PROJECTION_OPERATOR_ENVIRONMENT_KEYS)
            .chain(FORBIDDEN_L2_DR_SERVING_SECRET_KEYS)
        {
            catalog.insert(RuntimeConfigKey::from_static(key));
        }

        let mut values = BTreeMap::new();
        for key in catalog {
            let value = source.read(&key);
            values.insert(key, value);
        }

        for domain in ASSEMBLY_DOMAIN_TRANSPORT_DOMAINS {
            for key in [
                domain_transport_url_env(domain),
                domain_transport_mtls_allow_set_env(domain),
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

    fn capture_projection_operator(
        mut source: impl RuntimeConfigSource,
    ) -> Result<Self, RuntimeConfigCaptureError> {
        reject_forbidden_serving_keys(&mut source)?;
        let mut values = BTreeMap::new();
        for name in FIXED_PROJECTION_OPERATOR_KEYS
            .iter()
            .chain(LEGACY_SECRET_ENVIRONMENT_KEYS)
            .chain(FORBIDDEN_PROJECTION_OPERATOR_ENVIRONMENT_KEYS)
        {
            let key = RuntimeConfigKey::from_static(name);
            if values.contains_key(&key) {
                continue;
            }
            let value = source.read(&key);
            values.insert(key, value);
        }
        Ok(Self { values })
    }

    #[cfg(feature = "operator-cli")]
    fn capture_l2_dr_operator(
        mut source: impl RuntimeConfigSource,
    ) -> Result<Self, RuntimeConfigCaptureError> {
        reject_forbidden_serving_keys(&mut source)?;
        let mut values = BTreeMap::new();
        for name in FIXED_L2_DR_OPERATOR_KEYS
            .iter()
            .chain(FORBIDDEN_L2_DR_OPERATOR_PLAINTEXT_KEYS)
            .chain(LEGACY_SECRET_ENVIRONMENT_KEYS)
        {
            let key = RuntimeConfigKey::from_static(name);
            if values.contains_key(&key) {
                continue;
            }
            let value = source.read(&key);
            values.insert(key, value);
        }
        Ok(Self { values })
    }

    fn reject_legacy_secret_environment(&self) -> Result<(), RuntimeConfigCaptureError> {
        for name in LEGACY_SECRET_ENVIRONMENT_KEYS
            .iter()
            .chain(FORBIDDEN_PROJECTION_OPERATOR_ENVIRONMENT_KEYS)
            .chain(FORBIDDEN_L2_DR_SERVING_SECRET_KEYS)
        {
            if self
                .values
                .get(*name)
                .is_some_and(|value| !matches!(value, CapturedConfigValue::Missing))
            {
                return Err(RuntimeConfigCaptureError::ForbiddenSecretEnvironment(name));
            }
        }
        Ok(())
    }

    fn reject_projection_operator_secret_environment(
        &self,
    ) -> Result<(), RuntimeConfigCaptureError> {
        for name in FORBIDDEN_PROJECTION_OPERATOR_ENVIRONMENT_KEYS {
            if self
                .values
                .get(*name)
                .is_some_and(|value| !matches!(value, CapturedConfigValue::Missing))
            {
                return Err(RuntimeConfigCaptureError::ForbiddenSecretEnvironment(name));
            }
        }
        for name in LEGACY_SECRET_ENVIRONMENT_KEYS {
            if self
                .values
                .get(*name)
                .is_some_and(|value| !matches!(value, CapturedConfigValue::Missing))
            {
                return Err(RuntimeConfigCaptureError::ForbiddenSecretEnvironment(name));
            }
        }
        Ok(())
    }

    #[cfg(feature = "operator-cli")]
    fn reject_l2_dr_operator_plaintext_environment(&self) -> Result<(), RuntimeConfigCaptureError> {
        for name in FORBIDDEN_L2_DR_OPERATOR_PLAINTEXT_KEYS
            .iter()
            .chain(LEGACY_SECRET_ENVIRONMENT_KEYS)
        {
            if self
                .values
                .get(*name)
                .is_some_and(|value| !matches!(value, CapturedConfigValue::Missing))
            {
                return Err(RuntimeConfigCaptureError::ForbiddenSecretEnvironment(name));
            }
        }
        Ok(())
    }

    fn install_secret_bundle(
        &mut self,
        bundle: ServingSecretBundle,
    ) -> Result<(), RuntimeConfigCaptureError> {
        for (name, value) in bundle.secrets {
            let Some(slot) = self.values.get_mut(name.as_str()) else {
                return Err(RuntimeConfigCaptureError::InvalidSecretBundle);
            };
            if !matches!(slot, CapturedConfigValue::Missing) {
                return Err(RuntimeConfigCaptureError::ForbiddenSecretEnvironment(
                    "internal bundle target",
                ));
            }
            *slot = CapturedConfigValue::Present(value);
        }
        Ok(())
    }

    fn install_projection_operator_secret_bundle(
        &mut self,
        bundle: ProjectionOperatorSecretBundle,
    ) -> Result<(), RuntimeConfigCaptureError> {
        for (name, value) in bundle.secrets {
            let Some(slot) = self.values.get_mut(name.as_str()) else {
                return Err(RuntimeConfigCaptureError::InvalidProjectionSecretBundle);
            };
            if !matches!(slot, CapturedConfigValue::Missing) {
                return Err(RuntimeConfigCaptureError::ForbiddenSecretEnvironment(
                    "projection operator bundle target",
                ));
            }
            *slot = CapturedConfigValue::Present(value);
        }
        Ok(())
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

fn reject_forbidden_serving_keys(
    source: &mut impl RuntimeConfigSource,
) -> Result<(), RuntimeConfigCaptureError> {
    for name in FORBIDDEN_SERVING_KEYS {
        let key = RuntimeConfigKey::from_static(name);
        if !matches!(source.read(&key), CapturedConfigValue::Missing) {
            return Err(RuntimeConfigCaptureError::ForbiddenServingKey(name));
        }
    }
    Ok(())
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

pub(crate) fn domain_transport_url_env(domain: &str) -> String {
    format!(
        "RSS_{}_{}",
        domain.to_ascii_uppercase(),
        DOMAIN_TRANSPORT_URL_ENV_SUFFIX
    )
}

pub(crate) fn domain_transport_mtls_allow_set_env(domain: &str) -> String {
    format!(
        "RSS_{}_{}",
        domain.to_ascii_uppercase(),
        DOMAIN_TRANSPORT_MTLS_SPIFFE_ALLOW_SET_ENV_SUFFIX
    )
}

#[cfg(test)]
mod build_metadata_tests {
    use super::*;

    #[allow(clippy::expect_used)]
    #[test]
    fn build_metadata_capture_is_optional_but_atomic() {
        let empty = test_snapshot(&[]).expect("empty snapshot");
        assert!(
            build_metadata(empty.view())
                .expect("optional metadata")
                .is_none()
        );

        let complete = test_snapshot(&[
            (
                BUILD_SOURCE_REVISION_ENV,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                DECLARED_IMAGE_DIGEST_ENV,
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
        ])
        .expect("complete snapshot");
        let metadata = build_metadata(complete.view())
            .expect("valid metadata")
            .expect("present metadata");
        assert_eq!(metadata.source_revision(), "a".repeat(40));

        for (key, value) in [
            (BUILD_SOURCE_REVISION_ENV, "a".repeat(40)),
            (
                DECLARED_IMAGE_DIGEST_ENV,
                format!("sha256:{}", "b".repeat(64)),
            ),
        ] {
            let partial = test_snapshot(&[(key, value.as_str())]).expect("partial snapshot");
            assert!(build_metadata(partial.view()).is_err());
        }
    }
}

#[cfg(test)]
mod forbidden_serving_key_tests {
    use super::*;

    const REMOVED_VALUE_BAIT: &str = "removed-kind-config-secret-bait";

    fn complete_rss_profile_values() -> BTreeMap<String, String> {
        [
            (PRIMARY_TOKEN_PROFILE_ENV, "rss-access"),
            (ADMIN_TOKEN_PROFILE_ENV, "rss-access"),
            (INTERNAL_AUTH_SCHEME_ENV, "mtls"),
            ("RSS_ACCESS_TOKEN_ISSUER", "https://issuer.test"),
            ("RSS_ACCESS_TOKEN_AUDIENCE", "rss"),
            (RSS_ACCESS_TOKEN_SIGNING_ACTIVE_KEY_ID_ENV, "active-es256"),
            ("RSS_ACCESS_TOKEN_TTL_SECS", "900"),
            (
                "RSS_ACCESS_TOKEN_JWKS_PATH",
                concat!(env!("CARGO_MANIFEST_DIR"), "/src/config.rs"),
            ),
            ("RSS_ACCESS_TOKEN_JWKS_REFRESH_INTERVAL_SECS", "60"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
    }

    #[allow(clippy::expect_used)]
    #[test]
    fn complete_new_rss_config_with_removed_trusted_kinds_fails_without_value_leak() {
        let values = complete_rss_profile_values();
        let snapshot =
            RuntimeConfigSnapshot::capture_with_forbidden_check(TestConfigSource(values.clone()))
                .expect("complete new RSS profile configuration must capture");
        TokenProfilesConfig::from_snapshot(snapshot.view())
            .expect("complete new RSS profile configuration must parse");

        let mut values_with_removed_key = values;
        values_with_removed_key.insert(
            FORBIDDEN_SERVING_KEYS[0].to_owned(),
            REMOVED_VALUE_BAIT.to_owned(),
        );
        let error = RuntimeConfigSnapshot::capture_with_forbidden_check(TestConfigSource(
            values_with_removed_key,
        ))
        .err()
        .unwrap_or_else(|| {
            unreachable!("removed RSS trusted-kinds key must fail snapshot capture")
        });

        assert_eq!(
            error,
            RuntimeConfigCaptureError::ForbiddenServingKey(FORBIDDEN_SERVING_KEYS[0])
        );
        let rendered = format!("{error:?}: {error}");
        assert!(rendered.contains(FORBIDDEN_SERVING_KEYS[0]), "{rendered}");
        assert!(!rendered.contains(REMOVED_VALUE_BAIT), "{rendered}");
    }

    /// Production egress TLS downgrade knobs (#1710): any residual process value fails capture.
    #[test]
    fn banned_egress_tls_downgrade_keys_fail_capture_without_value_leak() {
        const BANNED: &[&str] = &[
            "RSS_AMQP_ALLOW_PLAINTEXT",
            "RSS_REDIS_ALLOW_PLAINTEXT",
            "RSS_S3_ALLOW_PLAINTEXT",
            "RSS_PG_SSL_MODE",
        ];
        for key in BANNED {
            assert!(
                FORBIDDEN_SERVING_KEYS.contains(key),
                "{key} must be in FORBIDDEN_SERVING_KEYS"
            );
            assert!(
                !FIXED_SERVING_KEYS.contains(key),
                "{key} must be deleted from FIXED_SERVING_KEYS"
            );
            let mut values = complete_rss_profile_values();
            values.insert((*key).to_owned(), REMOVED_VALUE_BAIT.to_owned());
            let error =
                RuntimeConfigSnapshot::capture_with_forbidden_check(TestConfigSource(values))
                    .err()
                    .unwrap_or_else(|| unreachable!("{key} must fail snapshot capture when set"));
            assert_eq!(error, RuntimeConfigCaptureError::ForbiddenServingKey(key));
            let rendered = format!("{error:?}: {error}");
            assert!(rendered.contains(key), "{rendered}");
            assert!(!rendered.contains(REMOVED_VALUE_BAIT), "{rendered}");
        }
        assert!(
            FIXED_SERVING_KEYS.contains(&"RSS_LISTENER_ALLOW_PLAINTEXT"),
            "ingress plaintext opt-in stays in the serving catalog"
        );
    }
}

#[cfg(test)]
mod serving_secret_bundle_tests {
    use super::*;

    #[allow(clippy::expect_used)]
    #[test]
    fn closed_bundle_maps_secrets_without_exposing_values() {
        let mut bundle = ServingSecretBundle::from_document(
            r#"{
                "pgPassword":"writer-bait",
                "pgReadPassword":"reader-bait",
                "amqpUrl":"amqp-bait"
            }"#,
        )
        .expect("valid closed bundle");

        for key in [BUNDLE_PG_PASSWORD, BUNDLE_PG_READ_PASSWORD, "RSS_AMQP_URL"] {
            assert!(bundle.secrets.remove(key).is_some());
        }
    }

    #[test]
    fn bundle_rejects_unknown_and_empty_fields_without_value_diagnostics() {
        for document in [
            r#"{"legacyPassword":"unknown-bait"}"#,
            r#"{"pgPassword":""}"#,
        ] {
            let error = ServingSecretBundle::from_document(document)
                .err()
                .unwrap_or_else(|| unreachable!("invalid secret bundle must fail closed"));
            let rendered = format!("{error:?}: {error}");
            assert_eq!(error, RuntimeConfigCaptureError::InvalidSecretBundle);
            assert!(!rendered.contains("unknown-bait"), "{rendered}");
        }
    }
}

#[cfg(test)]
mod projection_operator_secret_bundle_tests {
    use super::*;

    const COMPLETE_BUNDLE: &str = r#"{
        "pgProjectionReaderPasswordFile":"/run/secrets/projection-reader",
        "pgProjectionOperatorPasswordFile":"/run/secrets/projection-operator",
        "replayVaultToken":"replay-vault-bait"
    }"#;

    #[allow(clippy::expect_used)]
    #[test]
    fn closed_bundle_maps_only_projection_command_secrets() {
        let mut bundle = ProjectionOperatorSecretBundle::from_document(COMPLETE_BUNDLE)
            .expect("valid projection operator bundle");
        let expected = [
            "RSS_PG_PROJECTION_READER_PASSWORD_FILE",
            "RSS_PG_PROJECTION_OPERATOR_PASSWORD_FILE",
            "RSS_DLX_HOT_VAULT_TOKEN",
        ];
        assert_eq!(bundle.secrets.len(), expected.len());
        for key in expected {
            assert!(bundle.secrets.remove(key).is_some(), "missing {key}");
        }
    }

    #[test]
    fn bundle_rejects_missing_unknown_and_empty_fields_without_value_diagnostics() {
        for document in [
            r#"{
                "pgProjectionReaderPasswordFile":"/run/secrets/projection-reader",
                "pgProjectionOperatorPasswordFile":"/run/secrets/projection-operator"
            }"#,
            r#"{
                "pgProjectionReaderPasswordFile":"/run/secrets/projection-reader",
                "pgProjectionOperatorPasswordFile":"/run/secrets/projection-operator",
                "replayVaultToken":"replay-vault-bait",
                "servingVaultToken":"forbidden-serving-bait"
            }"#,
            r#"{
                "pgProjectionReaderPasswordFile":"",
                "pgProjectionOperatorPasswordFile":"/run/secrets/projection-operator",
                "replayVaultToken":"replay-vault-bait"
            }"#,
            r#"{
                "pgProjectionReaderPasswordFile":"/run/secrets/projection-reader",
                "pgProjectionOperatorPasswordFile":"/run/secrets/projection-operator",
                "serviceTokenSecret":"removed-compatibility-bait",
                "replayVaultToken":"replay-vault-bait"
            }"#,
        ] {
            let error = ProjectionOperatorSecretBundle::from_document(document)
                .err()
                .unwrap_or_else(|| unreachable!("invalid projection bundle must fail closed"));
            let rendered = format!("{error:?}: {error}");
            assert_eq!(
                error,
                RuntimeConfigCaptureError::InvalidProjectionSecretBundle
            );
            for secret in [
                "removed-compatibility-bait",
                "replay-vault-bait",
                "forbidden-serving-bait",
            ] {
                assert!(!rendered.contains(secret), "{rendered}");
            }
        }
    }
}
