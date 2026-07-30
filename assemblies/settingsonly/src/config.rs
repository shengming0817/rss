//! Closed, versioned configuration capture for the settings-only executable assembly.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use schemars::JsonSchema;
use serde::Deserialize;
use zeroize::Zeroizing;

const SERVING_SECRET_BUNDLE_PATH: &str = "/var/run/rss/secrets/serving-secret-bundle";
const SECRET_BUNDLE_FIELDS: &[&str] = &[
    "pgWriterPassword",
    "pgReaderPassword",
    "pgDlxArchiverPassword",
    "pgDlxVerifierPassword",
    "pgDlxPurgerPassword",
    "vaultToken",
    "settingsAmqpPublisherUrl",
    "settingsAmqpSubscriberUrl",
    "redisUrl",
    "tenantAuthorityKey",
    "dlxHotVaultToken",
    "dlxArchiveVaultToken",
    "s3AccessKeyId",
    "s3SecretAccessKey",
];
const BUILD_SOURCE_REVISION_ENV: &str = "RSS_BUILD_SOURCE_REVISION";
const DECLARED_IMAGE_DIGEST_ENV: &str = "RSS_DECLARED_IMAGE_DIGEST";
#[cfg(test)]
use runtimeexec::config::{
    ADMIN_PORT_ENV, HEALTH_PORT_ENV, MTLS_ALLOW_SET_ENV, POD_IP_ENV, PRIMARY_PORT_ENV,
    SPIFFE_ENDPOINT_ENV,
};
use runtimeexec::config::{FrontendConfigError, SecretValue};
#[cfg(test)]
const PG_WRITER_PASSWORD_ENV: &str = "RSS_SETTINGSONLY_PG_WRITER_PASSWORD";
#[cfg(test)]
const PG_READER_PASSWORD_ENV: &str = "RSS_SETTINGSONLY_PG_READER_PASSWORD";
#[cfg(test)]
const PG_DLX_ARCHIVER_PASSWORD_ENV: &str = "RSS_SETTINGSONLY_PG_DLX_ARCHIVER_PASSWORD";
#[cfg(test)]
const PG_DLX_VERIFIER_PASSWORD_ENV: &str = "RSS_SETTINGSONLY_PG_DLX_VERIFIER_PASSWORD";
#[cfg(test)]
const PG_DLX_PURGER_PASSWORD_ENV: &str = "RSS_SETTINGSONLY_PG_DLX_PURGER_PASSWORD";
#[cfg(test)]
const VAULT_TOKEN_ENV: &str = "RSS_SETTINGSONLY_VAULT_TOKEN";
#[cfg(test)]
const SETTINGS_AMQP_PUBLISHER_URL_ENV: &str = "RSS_SETTINGSONLY_AMQP_PUBLISHER_URL";
#[cfg(test)]
const SETTINGS_AMQP_SUBSCRIBER_URL_ENV: &str = "RSS_SETTINGSONLY_AMQP_SUBSCRIBER_URL";
#[cfg(test)]
const REDIS_URL_ENV: &str = "RSS_SETTINGSONLY_REDIS_URL";
#[cfg(test)]
const TENANT_AUTHORITY_KEY_ENV: &str = "RSS_SETTINGSONLY_TENANT_AUTHORITY_KEY";
#[cfg(test)]
const DLX_HOT_VAULT_TOKEN_ENV: &str = "RSS_SETTINGSONLY_DLX_HOT_VAULT_TOKEN";
#[cfg(test)]
const DLX_ARCHIVE_VAULT_TOKEN_ENV: &str = "RSS_SETTINGSONLY_DLX_ARCHIVE_VAULT_TOKEN";
#[cfg(test)]
const S3_ACCESS_KEY_ID_ENV: &str = "RSS_SETTINGSONLY_S3_ACCESS_KEY_ID";
#[cfg(test)]
const S3_SECRET_ACCESS_KEY_ENV: &str = "RSS_SETTINGSONLY_S3_SECRET_ACCESS_KEY";
const FORBIDDEN_SHARED_AMQP_URL_ENV: &str = "RSS_AMQP_URL";

/// Capture, parse, validate, and resolve one immutable settings-only configuration generation.
///
/// The document is read exactly once and parsed exactly once. Each closed environment reference
/// is resolved exactly once after the non-secret document has passed validation.
pub(crate) fn capture(path: &Path) -> Result<CapturedConfig, ConfigError> {
    capture_from(path, &mut ProcessConfigSource)
}

fn capture_from(
    path: &Path,
    source: &mut impl ConfigSource,
) -> Result<CapturedConfig, ConfigError> {
    let document = source
        .read_document(path)
        .map_err(|error| ConfigError::DocumentRead(ReadFailure::from(error.kind())))?;
    let config = parse_document(&document)?;
    config.validate()?;

    if source
        .read_environment(FORBIDDEN_SHARED_AMQP_URL_ENV)
        .is_some()
    {
        return Err(ConfigError::ForbiddenEnvironment(
            FORBIDDEN_SHARED_AMQP_URL_ENV,
        ));
    }

    let document = source
        .read_secret_bundle(Path::new(SERVING_SECRET_BUNDLE_PATH))
        .map_err(|error| ConfigError::SecretBundleRead(ReadFailure::from(error.kind())))?;
    let bundle: ServingSecretBundle = parse_secret_bundle(&document)?;
    let secrets = bundle.try_into()?;
    let build_metadata = capture_build_metadata(source)?;
    let frontend =
        runtimeexec::config::capture_serving_frontend(|name| source.read_environment(name))
            .map_err(frontend_error)?;
    Ok(CapturedConfig {
        config,
        secrets,
        build_metadata,
        frontend,
    })
}

fn capture_build_metadata(
    source: &mut impl ConfigSource,
) -> Result<Option<runtimeexec::inventory::BuildMetadata>, ConfigError> {
    let source_revision = source
        .read_environment(BUILD_SOURCE_REVISION_ENV)
        .map(|value| {
            value
                .into_string()
                .map_err(|_| ConfigError::NonUnicodeEnvironment(BUILD_SOURCE_REVISION_ENV))
        })
        .transpose()?;
    let image_digest = source
        .read_environment(DECLARED_IMAGE_DIGEST_ENV)
        .map(|value| {
            value
                .into_string()
                .map_err(|_| ConfigError::NonUnicodeEnvironment(DECLARED_IMAGE_DIGEST_ENV))
        })
        .transpose()?;
    runtimeexec::inventory::BuildMetadata::from_optional(
        source_revision.as_deref(),
        image_digest.as_deref(),
    )
    .map_err(|_| ConfigError::InvalidValue("buildMetadata"))
}

trait ConfigSource {
    fn read_document(&mut self, path: &Path) -> std::io::Result<String>;
    fn read_secret_bundle(&mut self, path: &Path) -> std::io::Result<Zeroizing<String>>;
    fn read_environment(&mut self, name: &'static str) -> Option<OsString>;
}

struct ProcessConfigSource;

impl ConfigSource for ProcessConfigSource {
    fn read_document(&mut self, path: &Path) -> std::io::Result<String> {
        std::fs::read_to_string(path)
    }

    fn read_secret_bundle(&mut self, path: &Path) -> std::io::Result<Zeroizing<String>> {
        std::fs::read_to_string(path).map(Zeroizing::new)
    }

    fn read_environment(&mut self, name: &'static str) -> Option<OsString> {
        std::env::var_os(name)
    }
}

fn parse_secret_bundle(document: &str) -> Result<ServingSecretBundle, ConfigError> {
    serde_json::from_str(document).map_err(|error| {
        let message = error.to_string();
        let reported_field = message
            .split_once('`')
            .and_then(|(_, tail)| tail.split_once('`'))
            .map(|(field, _)| field);
        let field = reported_field
            .and_then(|reported| {
                SECRET_BUNDLE_FIELDS
                    .iter()
                    .copied()
                    .find(|field| *field == reported)
            })
            .unwrap_or("<document>");
        let category = if message.starts_with("missing field") {
            DocumentIssue::MissingField
        } else if message.starts_with("unknown field") {
            DocumentIssue::UnknownField
        } else if error.is_syntax() || error.is_eof() {
            DocumentIssue::Syntax
        } else {
            DocumentIssue::WrongType
        };
        ConfigError::InvalidSecretBundle { category, field }
    })
}

fn parse_document(document: &str) -> Result<SettingsOnlyConfig, ConfigError> {
    toml::from_str(document).map_err(|error| invalid_document(document, &error))
}

fn invalid_document(document: &str, error: &toml::de::Error) -> ConfigError {
    let rendered = error.to_string();
    let category = if rendered.contains("unknown field") {
        DocumentIssue::UnknownField
    } else if rendered.contains("missing field") {
        DocumentIssue::MissingField
    } else if rendered.contains("duplicate field") || rendered.contains("duplicate key") {
        DocumentIssue::DuplicateField
    } else if rendered.contains("invalid type") {
        DocumentIssue::WrongType
    } else {
        DocumentIssue::Syntax
    };
    let (line, column) = error
        .span()
        .map(|span| line_column(document, span.start))
        .unwrap_or((0, 0));
    ConfigError::InvalidDocument {
        category,
        line,
        column,
    }
}

fn line_column(document: &str, offset: usize) -> (u32, u32) {
    let prefix = &document[..offset.min(document.len())];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix.chars().count() + 1, |(_, tail)| {
            tail.chars().count() + 1
        });
    (
        u32::try_from(line).unwrap_or(u32::MAX),
        u32::try_from(column).unwrap_or(u32::MAX),
    )
}

/// Static, redacted failures for the configuration boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConfigError {
    DocumentRead(ReadFailure),
    InvalidDocument {
        category: DocumentIssue,
        line: u32,
        column: u32,
    },
    InvalidValue(&'static str),
    SecretBundleRead(ReadFailure),
    InvalidSecretBundle {
        category: DocumentIssue,
        field: &'static str,
    },
    MissingEnvironment(&'static str),
    NonUnicodeEnvironment(&'static str),
    EmptyEnvironment(&'static str),
    ForbiddenEnvironment(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadFailure {
    NotFound,
    PermissionDenied,
    Other,
}

impl From<std::io::ErrorKind> for ReadFailure {
    fn from(value: std::io::ErrorKind) -> Self {
        match value {
            std::io::ErrorKind::NotFound => Self::NotFound,
            std::io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DocumentIssue {
    Syntax,
    UnknownField,
    MissingField,
    DuplicateField,
    WrongType,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DocumentRead(kind) => {
                write!(
                    formatter,
                    "settings-only config could not be read: {kind:?}"
                )
            }
            Self::InvalidDocument {
                category,
                line,
                column,
            } => write!(
                formatter,
                "settings-only config is invalid: {category:?} at line {line}, column {column}"
            ),
            Self::InvalidValue(field) => {
                write!(formatter, "settings-only config field is invalid: {field}")
            }
            Self::SecretBundleRead(kind) => {
                write!(
                    formatter,
                    "settings-only secret bundle could not be read: {kind:?}"
                )
            }
            Self::InvalidSecretBundle { category, field } => write!(
                formatter,
                "settings-only secret bundle is invalid: {category:?} at {field}"
            ),
            Self::MissingEnvironment(name) => {
                write!(
                    formatter,
                    "settings-only secret environment is missing: {name}"
                )
            }
            Self::NonUnicodeEnvironment(name) => write!(
                formatter,
                "settings-only secret environment is not valid Unicode: {name}"
            ),
            Self::EmptyEnvironment(name) => {
                write!(
                    formatter,
                    "settings-only secret environment is empty: {name}"
                )
            }
            Self::ForbiddenEnvironment(name) => {
                write!(formatter, "settings-only environment is forbidden: {name}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// One captured document and its separately owned, zeroizing secret material.
pub(crate) struct CapturedConfig {
    config: SettingsOnlyConfig,
    secrets: ResolvedSecrets,
    build_metadata: Option<runtimeexec::inventory::BuildMetadata>,
    frontend: ServingFrontendConfig,
}

impl CapturedConfig {
    pub(crate) fn into_runtime_inputs(
        self,
    ) -> (
        SettingsOnlyConfig,
        ResolvedSecrets,
        Option<runtimeexec::inventory::BuildMetadata>,
        ServingFrontendConfig,
    ) {
        (
            self.config,
            self.secrets,
            self.build_metadata,
            self.frontend,
        )
    }
}

pub(crate) type ServingFrontendConfig = runtimeexec::config::ServingFrontendConfig;

fn frontend_error(error: FrontendConfigError) -> ConfigError {
    match error {
        FrontendConfigError::Missing(name) => ConfigError::MissingEnvironment(name),
        FrontendConfigError::NonUnicode(name) => ConfigError::NonUnicodeEnvironment(name),
        FrontendConfigError::Empty(name) => ConfigError::EmptyEnvironment(name),
        FrontendConfigError::Invalid(name) => ConfigError::InvalidValue(name),
    }
}

impl fmt::Debug for CapturedConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CapturedConfig(<validated>, <redacted>)")
    }
}

/// Closed production secret bundle; every allocation is erased when its final owner is dropped.
pub(crate) struct ResolvedSecrets {
    pg_writer_password: Zeroizing<String>,
    pg_reader_password: Zeroizing<String>,
    pg_dlx_archiver_password: Zeroizing<String>,
    pg_dlx_verifier_password: Zeroizing<String>,
    pg_dlx_purger_password: Zeroizing<String>,
    vault_token: Zeroizing<String>,
    settings_amqp_publisher_url: Zeroizing<String>,
    settings_amqp_subscriber_url: Zeroizing<String>,
    redis_url: Zeroizing<String>,
    tenant_authority_key: Zeroizing<String>,
    dlx_hot_vault_token: Zeroizing<String>,
    dlx_archive_vault_token: Zeroizing<String>,
    s3_access_key_id: Zeroizing<String>,
    s3_secret_access_key: Zeroizing<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServingSecretBundle {
    pg_writer_password: SecretValue,
    pg_reader_password: SecretValue,
    pg_dlx_archiver_password: SecretValue,
    pg_dlx_verifier_password: SecretValue,
    pg_dlx_purger_password: SecretValue,
    vault_token: SecretValue,
    settings_amqp_publisher_url: SecretValue,
    settings_amqp_subscriber_url: SecretValue,
    redis_url: SecretValue,
    tenant_authority_key: SecretValue,
    dlx_hot_vault_token: SecretValue,
    dlx_archive_vault_token: SecretValue,
    s3_access_key_id: SecretValue,
    s3_secret_access_key: SecretValue,
}

impl TryFrom<ServingSecretBundle> for ResolvedSecrets {
    type Error = ConfigError;

    fn try_from(value: ServingSecretBundle) -> Result<Self, Self::Error> {
        for (field, secret) in [
            ("pgWriterPassword", value.pg_writer_password.as_str()),
            ("pgReaderPassword", value.pg_reader_password.as_str()),
            (
                "pgDlxArchiverPassword",
                value.pg_dlx_archiver_password.as_str(),
            ),
            (
                "pgDlxVerifierPassword",
                value.pg_dlx_verifier_password.as_str(),
            ),
            ("pgDlxPurgerPassword", value.pg_dlx_purger_password.as_str()),
            ("vaultToken", value.vault_token.as_str()),
            (
                "settingsAmqpPublisherUrl",
                value.settings_amqp_publisher_url.as_str(),
            ),
            (
                "settingsAmqpSubscriberUrl",
                value.settings_amqp_subscriber_url.as_str(),
            ),
            ("redisUrl", value.redis_url.as_str()),
            ("tenantAuthorityKey", value.tenant_authority_key.as_str()),
            ("dlxHotVaultToken", value.dlx_hot_vault_token.as_str()),
            (
                "dlxArchiveVaultToken",
                value.dlx_archive_vault_token.as_str(),
            ),
            ("s3AccessKeyId", value.s3_access_key_id.as_str()),
            ("s3SecretAccessKey", value.s3_secret_access_key.as_str()),
        ] {
            if secret.is_empty() {
                return Err(ConfigError::InvalidSecretBundle {
                    category: DocumentIssue::MissingField,
                    field,
                });
            }
        }
        let secrets = Self {
            pg_writer_password: value.pg_writer_password.into_zeroizing(),
            pg_reader_password: value.pg_reader_password.into_zeroizing(),
            pg_dlx_archiver_password: value.pg_dlx_archiver_password.into_zeroizing(),
            pg_dlx_verifier_password: value.pg_dlx_verifier_password.into_zeroizing(),
            pg_dlx_purger_password: value.pg_dlx_purger_password.into_zeroizing(),
            vault_token: value.vault_token.into_zeroizing(),
            settings_amqp_publisher_url: value.settings_amqp_publisher_url.into_zeroizing(),
            settings_amqp_subscriber_url: value.settings_amqp_subscriber_url.into_zeroizing(),
            redis_url: value.redis_url.into_zeroizing(),
            tenant_authority_key: value.tenant_authority_key.into_zeroizing(),
            dlx_hot_vault_token: value.dlx_hot_vault_token.into_zeroizing(),
            dlx_archive_vault_token: value.dlx_archive_vault_token.into_zeroizing(),
            s3_access_key_id: value.s3_access_key_id.into_zeroizing(),
            s3_secret_access_key: value.s3_secret_access_key.into_zeroizing(),
        };
        secrets.validate()?;
        Ok(secrets)
    }
}

impl ResolvedSecrets {
    fn validate(&self) -> Result<(), ConfigError> {
        let postgres_passwords = [
            self.pg_writer_password.as_str(),
            self.pg_reader_password.as_str(),
            self.pg_dlx_archiver_password.as_str(),
            self.pg_dlx_verifier_password.as_str(),
            self.pg_dlx_purger_password.as_str(),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        if postgres_passwords.len() != 5 {
            return Err(ConfigError::InvalidValue("postgres.rolePasswords"));
        }
        validate_tls_endpoint(
            &self.settings_amqp_publisher_url,
            "amqps://",
            "eventing.settingsAmqpPublisherUrl",
        )?;
        validate_tls_endpoint(
            &self.settings_amqp_subscriber_url,
            "amqps://",
            "eventing.settingsAmqpSubscriberUrl",
        )?;
        if self.settings_amqp_publisher_url == self.settings_amqp_subscriber_url {
            return Err(ConfigError::InvalidValue("eventing.amqpRoleUrls"));
        }
        validate_tls_endpoint(&self.redis_url, "rediss://", "redis.url")?;
        if self.tenant_authority_key.len() < 32 {
            return Err(ConfigError::InvalidValue("tenantAuthority.key"));
        }
        if self.vault_token == self.dlx_hot_vault_token
            || self.vault_token == self.dlx_archive_vault_token
            || self.dlx_hot_vault_token == self.dlx_archive_vault_token
        {
            return Err(ConfigError::InvalidValue("vault.workloadTokens"));
        }
        Ok(())
    }

    pub(crate) fn into_secret_material(self) -> ProductionSecretMaterial {
        let Self {
            pg_writer_password,
            pg_reader_password,
            pg_dlx_archiver_password,
            pg_dlx_verifier_password,
            pg_dlx_purger_password,
            vault_token,
            settings_amqp_publisher_url,
            settings_amqp_subscriber_url,
            redis_url,
            tenant_authority_key,
            dlx_hot_vault_token,
            dlx_archive_vault_token,
            s3_access_key_id,
            s3_secret_access_key,
        } = self;
        ProductionSecretMaterial {
            pg_writer_password,
            pg_reader_password,
            pg_dlx_archiver_password,
            pg_dlx_verifier_password,
            pg_dlx_purger_password,
            vault_token,
            settings_amqp_publisher_url,
            settings_amqp_subscriber_url,
            redis_url,
            tenant_authority_key,
            dlx_hot_vault_token,
            dlx_archive_vault_token,
            s3_access_key_id,
            s3_secret_access_key,
        }
    }
}

pub(crate) struct ProductionSecretMaterial {
    pub(crate) pg_writer_password: Zeroizing<String>,
    pub(crate) pg_reader_password: Zeroizing<String>,
    pub(crate) pg_dlx_archiver_password: Zeroizing<String>,
    pub(crate) pg_dlx_verifier_password: Zeroizing<String>,
    pub(crate) pg_dlx_purger_password: Zeroizing<String>,
    pub(crate) vault_token: Zeroizing<String>,
    pub(crate) settings_amqp_publisher_url: Zeroizing<String>,
    pub(crate) settings_amqp_subscriber_url: Zeroizing<String>,
    pub(crate) redis_url: Zeroizing<String>,
    pub(crate) tenant_authority_key: Zeroizing<String>,
    pub(crate) dlx_hot_vault_token: Zeroizing<String>,
    pub(crate) dlx_archive_vault_token: Zeroizing<String>,
    pub(crate) s3_access_key_id: Zeroizing<String>,
    pub(crate) s3_secret_access_key: Zeroizing<String>,
}

impl fmt::Debug for ResolvedSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResolvedSecrets(<redacted>)")
    }
}

struct SchemaVersionV2;

impl JsonSchema for SchemaVersionV2 {
    fn is_referenceable() -> bool {
        false
    }

    fn schema_name() -> String {
        "SettingsOnlySchemaVersionV2".to_owned()
    }

    fn json_schema(_generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::Schema::Object(schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::Integer.into()),
            const_value: Some(serde_json::json!(2)),
            ..schemars::schema::SchemaObject::default()
        })
    }
}

#[derive(Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
enum ProductionProfile {
    Production,
}

#[derive(Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
enum DurableTopology {
    DurableIsolated,
}

/// The complete version-two production document. Every field is mandatory.
#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SettingsOnlyConfig {
    #[schemars(with = "SchemaVersionV2")]
    schema_version: u32,
    profile: ProductionProfile,
    topology: DurableTopology,
    listeners: ListenersConfig,
    federated: FederatedConfig,
    postgres: PostgresConfig,
    vault: VaultConfig,
    eventing: EventingConfig,
    redis: RedisConfig,
    tenant_authority: TenantAuthorityConfig,
    dlx: DlxConfig,
    s3: S3Config,
    readiness: ReadinessConfig,
    drain: DrainConfig,
}

impl SettingsOnlyConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != 2 {
            return Err(ConfigError::InvalidValue("schemaVersion"));
        }
        let ProductionProfile::Production = self.profile;
        let DurableTopology::DurableIsolated = self.topology;
        self.listeners.validate()?;
        self.federated.validate()?;
        self.postgres.validate()?;
        self.vault.validate()?;
        self.eventing.validate()?;
        self.redis.validate()?;
        self.tenant_authority.validate()?;
        self.dlx.validate()?;
        self.s3.validate()?;
        self.readiness.validate()?;
        self.drain.validate()
    }

    pub(crate) fn into_sections(self) -> SettingsOnlyConfigSections {
        SettingsOnlyConfigSections {
            listeners: self.listeners,
            federated: self.federated,
            postgres: self.postgres,
            vault: self.vault,
            production_infra: ProductionInfraConfig {
                eventing: self.eventing,
                redis: self.redis,
                tenant_authority: self.tenant_authority,
                dlx: self.dlx,
                s3: self.s3,
                readiness: self.readiness,
                drain: self.drain,
            },
        }
    }
}

pub(crate) struct SettingsOnlyConfigSections {
    pub(crate) listeners: ListenersConfig,
    pub(crate) federated: FederatedConfig,
    pub(crate) postgres: PostgresConfig,
    pub(crate) vault: VaultConfig,
    pub(crate) production_infra: ProductionInfraConfig,
}

pub(crate) struct ProductionInfraConfig {
    pub(crate) eventing: EventingConfig,
    pub(crate) redis: RedisConfig,
    pub(crate) tenant_authority: TenantAuthorityConfig,
    pub(crate) dlx: DlxConfig,
    pub(crate) s3: S3Config,
    pub(crate) readiness: ReadinessConfig,
    pub(crate) drain: DrainConfig,
}

/// A socket that is statically confined to canonical loopback plaintext transport.
///
/// settingsonly has no TLS listener capability. Keeping this type private makes non-loopback
/// plaintext binds unrepresentable after configuration capture; an ingress must terminate TLS and
/// share the process network namespace when external access is required.
#[derive(Clone, Copy)]
struct PlaintextLoopbackAddress(SocketAddr);

impl PlaintextLoopbackAddress {
    fn get(self) -> SocketAddr {
        self.0
    }
}

impl<'de> Deserialize<'de> for PlaintextLoopbackAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        let address: SocketAddr = raw
            .parse()
            .map_err(|_| serde::de::Error::custom("invalid socket address"))?;
        if address.port() == 0 {
            return Err(serde::de::Error::custom("socket port must be non-zero"));
        }
        if !address.ip().is_loopback() || address.to_string() != raw {
            return Err(serde::de::Error::custom(
                "plaintext listener must use a canonical loopback address",
            ));
        }
        Ok(Self(address))
    }
}

impl JsonSchema for PlaintextLoopbackAddress {
    fn schema_name() -> String {
        "PlaintextLoopbackAddress".to_owned()
    }

    fn json_schema(_generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            string: Some(Box::new(schemars::schema::StringValidation {
                min_length: Some(1),
                pattern: Some(
                    r"^(?:127\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])|\[::1\]):(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$"
                        .to_owned(),
                ),
                ..schemars::schema::StringValidation::default()
            })),
            ..schemars::schema::SchemaObject::default()
        }
        .into()
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ListenersConfig {
    primary: ListenerEndpoint,
    admin: ListenerEndpoint,
    health: ListenerEndpoint,
    #[schemars(range(min = 1, max = 20_000))]
    request_budget_ms: u64,
}

impl ListenersConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !(1..=20_000).contains(&self.request_budget_ms) {
            return Err(ConfigError::InvalidValue("listeners.requestBudgetMs"));
        }
        let addresses = [self.primary.bind.0, self.admin.bind.0, self.health.bind.0];
        if addresses[0] == addresses[1]
            || addresses[0] == addresses[2]
            || addresses[1] == addresses[2]
        {
            return Err(ConfigError::InvalidValue("listeners.bind"));
        }
        Ok(())
    }

    pub(crate) fn into_listener_inputs(self) -> (SocketAddr, SocketAddr, SocketAddr, Duration) {
        (
            self.primary.bind.get(),
            self.admin.bind.get(),
            self.health.bind.get(),
            Duration::from_millis(self.request_budget_ms),
        )
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ListenerEndpoint {
    bind: PlaintextLoopbackAddress,
}

/// Principal kinds accepted from the one federated verifier profile.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub(crate) enum TrustedKind {
    User,
    Device,
    Admin,
    SuperAdmin,
}

impl TrustedKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Device => "device",
            Self::Admin => "admin",
            Self::SuperAdmin => "superAdmin",
        }
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FederatedConfig {
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    issuer: String,
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    audience: String,
    #[schemars(length(min = 1))]
    jwks_path: PathBuf,
    #[schemars(range(min = 1, max = 300))]
    refresh_seconds: u64,
    #[schemars(schema_with = "unique_trusted_kinds_schema")]
    trusted_kinds: Vec<TrustedKind>,
}

fn unique_trusted_kinds_schema(
    generator: &mut schemars::r#gen::SchemaGenerator,
) -> schemars::schema::Schema {
    let mut schema: schemars::schema::SchemaObject =
        <Vec<TrustedKind>>::json_schema(generator).into();
    let array = schema.array.get_or_insert_with(Default::default);
    array.min_items = Some(1);
    array.unique_items = Some(true);
    schema.into()
}

impl FederatedConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_tls_endpoint(&self.issuer, "https://", "federated.issuer")?;
        non_blank(&self.audience, "federated.audience")?;
        non_empty_path(&self.jwks_path, "federated.jwksPath")?;
        if !(1..=300).contains(&self.refresh_seconds) {
            return Err(ConfigError::InvalidValue("federated.refreshSeconds"));
        }
        if self.trusted_kinds.is_empty()
            || self
                .trusted_kinds
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != self.trusted_kinds.len()
        {
            return Err(ConfigError::InvalidValue("federated.trustedKinds"));
        }
        Ok(())
    }

    pub(crate) fn into_oidc_inputs(self) -> (String, String, PathBuf, Duration, Vec<TrustedKind>) {
        (
            self.issuer,
            self.audience,
            self.jwks_path,
            Duration::from_secs(self.refresh_seconds),
            self.trusted_kinds,
        )
    }
}

/// Closed PostgreSQL TLS policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum PgSslMode {
    VerifyFull,
}

impl JsonSchema for PgSslMode {
    fn is_referenceable() -> bool {
        false
    }

    fn schema_name() -> String {
        "SettingsOnlyPgVerifyFull".to_owned()
    }

    fn json_schema(_generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::Schema::Object(schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            const_value: Some(serde_json::json!("verifyFull")),
            ..schemars::schema::SchemaObject::default()
        })
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(transparent)]
struct RequiredCaPath(PathBuf);

impl RequiredCaPath {
    fn validate(&self, field: &'static str) -> Result<(), ConfigError> {
        non_empty_path(&self.0, field)
    }

    fn into_optional(self) -> Option<PathBuf> {
        Some(self.0)
    }

    fn into_path(self) -> PathBuf {
        self.0
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PostgresConfig {
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    host: String,
    #[schemars(range(min = 1))]
    port: u16,
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    database: String,
    ssl_mode: PgSslMode,
    ssl_root_cert_path: RequiredCaPath,
    writer: PgWriterRoleConfig,
    reader: PgReaderRoleConfig,
    dlx_archiver: PgDlxArchiverRoleConfig,
    dlx_verifier: PgDlxVerifierRoleConfig,
    dlx_purger: PgDlxPurgerRoleConfig,
    #[schemars(range(min = 1, max = 300))]
    readiness_seconds: u64,
}

impl PostgresConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        non_blank(&self.host, "postgres.host")?;
        non_blank(&self.database, "postgres.database")?;
        if self.port == 0 {
            return Err(ConfigError::InvalidValue("postgres.port"));
        }
        self.ssl_root_cert_path
            .validate("postgres.sslRootCertPath")?;
        self.writer.validate()?;
        self.reader.validate()?;
        self.dlx_archiver.validate()?;
        self.dlx_verifier.validate()?;
        self.dlx_purger.validate()?;
        if !(1..=300).contains(&self.readiness_seconds) {
            return Err(ConfigError::InvalidValue("postgres.readinessSeconds"));
        }
        Ok(())
    }

    pub(crate) fn into_postgres_inputs(self) -> PostgresInputs {
        PostgresInputs {
            connection: PgConnectionConfig {
                host: self.host,
                port: self.port,
                database: self.database,
                ssl_mode: self.ssl_mode,
                ssl_root_cert_path: self.ssl_root_cert_path.into_optional(),
            },
            writer: self.writer,
            reader: self.reader,
            dlx_archiver: self.dlx_archiver,
            dlx_verifier: self.dlx_verifier,
            dlx_purger: self.dlx_purger,
            readiness_interval: Duration::from_secs(self.readiness_seconds),
        }
    }
}

pub(crate) struct PostgresInputs {
    pub(crate) connection: PgConnectionConfig,
    pub(crate) writer: PgWriterRoleConfig,
    pub(crate) reader: PgReaderRoleConfig,
    pub(crate) dlx_archiver: PgDlxArchiverRoleConfig,
    pub(crate) dlx_verifier: PgDlxVerifierRoleConfig,
    pub(crate) dlx_purger: PgDlxPurgerRoleConfig,
    pub(crate) readiness_interval: Duration,
}

pub(crate) struct PgConnectionConfig {
    host: String,
    port: u16,
    database: String,
    ssl_mode: PgSslMode,
    ssl_root_cert_path: Option<PathBuf>,
}

impl PgConnectionConfig {
    pub(crate) fn into_connect_options(self) -> (String, u16, String, PgSslMode, Option<PathBuf>) {
        (
            self.host,
            self.port,
            self.database,
            self.ssl_mode,
            self.ssl_root_cert_path,
        )
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PgWriterRoleConfig {
    #[schemars(range(min = 1, max = 100))]
    max_connections: u32,
}

impl PgWriterRoleConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.max_connections == 0 || self.max_connections > 100 {
            return Err(ConfigError::InvalidValue("postgres.writer.maxConnections"));
        }
        Ok(())
    }

    pub(crate) fn into_writer_pool(self) -> (String, u32) {
        ("rss_app".to_owned(), self.max_connections)
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PgReaderRoleConfig {
    #[schemars(range(min = 1, max = 100))]
    max_connections: u32,
}

impl PgReaderRoleConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.max_connections == 0 || self.max_connections > 100 {
            return Err(ConfigError::InvalidValue("postgres.reader.maxConnections"));
        }
        Ok(())
    }

    pub(crate) fn into_reader_pool(self) -> (String, u32) {
        ("rss_app_read".to_owned(), self.max_connections)
    }
}

macro_rules! dlx_postgres_role {
    ($type:ident, $field:literal, $username:literal, $getter:ident) => {
        #[derive(Deserialize, JsonSchema)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub(crate) struct $type {
            #[schemars(range(min = 1, max = 20))]
            max_connections: u32,
        }

        impl $type {
            fn validate(&self) -> Result<(), ConfigError> {
                bounded(
                    u64::from(self.max_connections),
                    1,
                    20,
                    concat!($field, ".maxConnections"),
                )
            }

            pub(crate) fn $getter(self) -> (String, u32) {
                ($username.to_owned(), self.max_connections)
            }
        }
    };
}

dlx_postgres_role!(
    PgDlxArchiverRoleConfig,
    "postgres.dlxArchiver",
    "rss_dlx_archiver",
    into_dlx_archiver_pool
);
dlx_postgres_role!(
    PgDlxVerifierRoleConfig,
    "postgres.dlxVerifier",
    "rss_dlx_verifier",
    into_dlx_verifier_pool
);
dlx_postgres_role!(
    PgDlxPurgerRoleConfig,
    "postgres.dlxPurger",
    "rss_dlx_purger",
    into_dlx_purger_pool
);

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct VaultConfig {
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    addr: String,
    ca_cert_pem_path: RequiredCaPath,
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    transit_mount: String,
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    settings_key_name: String,
    #[schemars(schema_with = "unique_vault_bindings_schema")]
    tenant_store_allowlist: Vec<VaultStoreBindingConfig>,
    #[schemars(range(min = 1, max = 30))]
    readiness_seconds: u64,
}

fn unique_vault_bindings_schema(
    generator: &mut schemars::r#gen::SchemaGenerator,
) -> schemars::schema::Schema {
    let mut schema: schemars::schema::SchemaObject =
        <Vec<VaultStoreBindingConfig>>::json_schema(generator).into();
    let array = schema.array.get_or_insert_with(Default::default);
    array.min_items = Some(1);
    array.unique_items = Some(true);
    schema.into()
}

impl VaultConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_tls_endpoint(&self.addr, "https://", "vault.addr")?;
        self.ca_cert_pem_path.validate("vault.caCertPemPath")?;
        non_blank(&self.transit_mount, "vault.transitMount")?;
        non_blank(&self.settings_key_name, "vault.settingsKeyName")?;
        if self.tenant_store_allowlist.is_empty() {
            return Err(ConfigError::InvalidValue("vault.tenantStoreAllowlist"));
        }
        let mut coordinates = BTreeSet::new();
        for binding in &self.tenant_store_allowlist {
            binding.validate()?;
            if !coordinates.insert((&binding.tenant_id, &binding.store_id)) {
                return Err(ConfigError::InvalidValue("vault.tenantStoreAllowlist"));
            }
        }
        if !(1..=30).contains(&self.readiness_seconds) {
            return Err(ConfigError::InvalidValue("vault.readinessSeconds"));
        }
        Ok(())
    }

    pub(crate) fn into_vault_inputs(
        self,
    ) -> (
        String,
        Option<PathBuf>,
        String,
        String,
        Vec<VaultStoreBindingConfig>,
        Duration,
    ) {
        (
            self.addr,
            self.ca_cert_pem_path.into_optional(),
            self.transit_mount,
            self.settings_key_name,
            self.tenant_store_allowlist,
            Duration::from_secs(self.readiness_seconds),
        )
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct VaultStoreBindingConfig {
    #[schemars(schema_with = "tenant_id_schema")]
    tenant_id: String,
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    store_id: String,
    #[schemars(schema_with = "non_empty_vault_path_schema")]
    mount: String,
    #[schemars(schema_with = "optional_vault_path_schema")]
    kv_path_prefix: String,
}

fn tenant_id_schema(_generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
    let nil = schemars::schema::SchemaObject {
        const_value: Some(serde_json::json!("00000000-0000-0000-0000-000000000000")),
        ..schemars::schema::SchemaObject::default()
    };
    schemars::schema::SchemaObject {
        instance_type: Some(schemars::schema::InstanceType::String.into()),
        format: Some("uuid".to_owned()),
        subschemas: Some(Box::new(schemars::schema::SubschemaValidation {
            not: Some(Box::new(nil.into())),
            ..schemars::schema::SubschemaValidation::default()
        })),
        string: Some(Box::new(schemars::schema::StringValidation {
            min_length: Some(1),
            pattern: Some(
                "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$".to_owned(),
            ),
            ..schemars::schema::StringValidation::default()
        })),
        ..schemars::schema::SchemaObject::default()
    }
    .into()
}

fn non_empty_vault_path_schema(
    _generator: &mut schemars::r#gen::SchemaGenerator,
) -> schemars::schema::Schema {
    vault_path_schema(false)
}

fn optional_vault_path_schema(
    _generator: &mut schemars::r#gen::SchemaGenerator,
) -> schemars::schema::Schema {
    vault_path_schema(true)
}

fn vault_path_schema(allow_empty: bool) -> schemars::schema::Schema {
    let dot_segment = schemars::schema::SchemaObject {
        instance_type: Some(schemars::schema::InstanceType::String.into()),
        string: Some(Box::new(schemars::schema::StringValidation {
            pattern: Some(r"(?:^|/)(?:\.|\.\.)(?:/|$)".to_owned()),
            ..schemars::schema::StringValidation::default()
        })),
        ..schemars::schema::SchemaObject::default()
    };
    schemars::schema::SchemaObject {
        instance_type: Some(schemars::schema::InstanceType::String.into()),
        subschemas: Some(Box::new(schemars::schema::SubschemaValidation {
            not: Some(Box::new(dot_segment.into())),
            ..schemars::schema::SubschemaValidation::default()
        })),
        string: Some(Box::new(schemars::schema::StringValidation {
            min_length: (!allow_empty).then_some(1),
            pattern: Some(if allow_empty {
                r"^(?:[^/]+(?:/[^/]+)*)?$".to_owned()
            } else {
                r"^[^/]+(?:/[^/]+)*$".to_owned()
            }),
            ..schemars::schema::StringValidation::default()
        })),
        ..schemars::schema::SchemaObject::default()
    }
    .into()
}

impl VaultStoreBindingConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        vocab::TenantId::parse(&self.tenant_id)
            .map_err(|_| ConfigError::InvalidValue("vault.tenantStoreAllowlist.tenantId"))?;
        non_blank(&self.store_id, "vault.tenantStoreAllowlist.storeId")?;
        validate_vault_path(&self.mount, false, "vault.tenantStoreAllowlist.mount")?;
        validate_vault_path(
            &self.kv_path_prefix,
            true,
            "vault.tenantStoreAllowlist.kvPathPrefix",
        )
    }

    pub(crate) fn into_store_binding(self) -> (String, String, String, String) {
        (
            self.tenant_id,
            self.store_id,
            self.mount,
            self.kv_path_prefix,
        )
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EventingConfig {
    amqp_ca_cert_pem_path: RequiredCaPath,
    #[schemars(range(min = 1, max = 60_000))]
    publisher_confirm_timeout_ms: u64,
}

impl EventingConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        self.amqp_ca_cert_pem_path
            .validate("eventing.amqpCaCertPemPath")?;
        bounded(
            self.publisher_confirm_timeout_ms,
            1,
            60_000,
            "eventing.publisherConfirmTimeoutMs",
        )
    }

    pub(crate) fn into_eventing_inputs(self) -> EventingInputs {
        EventingInputs {
            amqp_ca_cert_pem_path: self.amqp_ca_cert_pem_path.into_path(),
            publisher_confirm_timeout: Duration::from_millis(self.publisher_confirm_timeout_ms),
        }
    }
}

pub(crate) struct EventingInputs {
    pub(crate) amqp_ca_cert_pem_path: PathBuf,
    pub(crate) publisher_confirm_timeout: Duration,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RedisConfig {
    ca_cert_pem_path: RequiredCaPath,
    #[schemars(range(min = 1, max = 30))]
    readiness_seconds: u64,
}

impl RedisConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        self.ca_cert_pem_path.validate("redis.caCertPemPath")?;
        bounded(self.readiness_seconds, 1, 30, "redis.readinessSeconds")
    }

    pub(crate) fn into_redis_inputs(self) -> RedisInputs {
        RedisInputs {
            ca_cert_pem_path: self.ca_cert_pem_path.into_path(),
            readiness: Duration::from_secs(self.readiness_seconds),
        }
    }
}

pub(crate) struct RedisInputs {
    pub(crate) ca_cert_pem_path: PathBuf,
    pub(crate) readiness: Duration,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TenantAuthorityConfig {
    #[schemars(range(min = 3600, max = 86_400))]
    ttl_seconds: u64,
    #[schemars(range(min = 0, max = 300))]
    clock_skew_seconds: u64,
}

impl TenantAuthorityConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        bounded(
            self.ttl_seconds,
            3_600,
            86_400,
            "tenantAuthority.ttlSeconds",
        )?;
        bounded(
            self.clock_skew_seconds,
            0,
            300,
            "tenantAuthority.clockSkewSeconds",
        )
    }

    pub(crate) fn into_tenant_authority_inputs(self) -> (Duration, Duration) {
        (
            Duration::from_secs(self.ttl_seconds),
            Duration::from_secs(self.clock_skew_seconds),
        )
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DlxConfig {
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    hot_key_name: String,
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    archive_key_name: String,
    #[schemars(range(min = 1, max = 30))]
    readiness_seconds: u64,
}

impl DlxConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        non_blank(&self.hot_key_name, "dlx.hotKeyName")?;
        non_blank(&self.archive_key_name, "dlx.archiveKeyName")?;
        if self.hot_key_name == self.archive_key_name {
            return Err(ConfigError::InvalidValue("dlx.keyNames"));
        }
        bounded(self.readiness_seconds, 1, 30, "dlx.readinessSeconds")
    }

    pub(crate) fn into_dlx_inputs(self) -> DlxInputs {
        DlxInputs {
            hot_key_name: self.hot_key_name,
            archive_key_name: self.archive_key_name,
            readiness_interval: Duration::from_secs(self.readiness_seconds),
        }
    }
}

pub(crate) struct DlxInputs {
    pub(crate) hot_key_name: String,
    pub(crate) archive_key_name: String,
    pub(crate) readiness_interval: Duration,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct S3Config {
    #[schemars(length(min = 1), regex(pattern = "^https://.+$"))]
    endpoint: String,
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    region: String,
    #[schemars(
        length(min = 3, max = 63),
        regex(pattern = "^[a-z0-9][a-z0-9.-]*[a-z0-9]$")
    )]
    archive_bucket: String,
    force_path_style: bool,
    ca_cert_pem_path: RequiredCaPath,
    #[schemars(range(min = 1, max = 30))]
    readiness_seconds: u64,
}

impl S3Config {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_tls_endpoint(&self.endpoint, "https://", "s3.endpoint")?;
        non_blank(&self.region, "s3.region")?;
        validate_s3_bucket(&self.archive_bucket)?;
        let _ = self.force_path_style;
        self.ca_cert_pem_path.validate("s3.caCertPemPath")?;
        bounded(self.readiness_seconds, 1, 30, "s3.readinessSeconds")
    }

    pub(crate) fn into_s3_inputs(self) -> S3Inputs {
        S3Inputs {
            endpoint: self.endpoint,
            region: self.region,
            archive_bucket: self.archive_bucket,
            force_path_style: self.force_path_style,
            ca_cert_pem_path: self.ca_cert_pem_path.into_path(),
            readiness_interval: Duration::from_secs(self.readiness_seconds),
        }
    }
}

pub(crate) struct S3Inputs {
    pub(crate) endpoint: String,
    pub(crate) region: String,
    pub(crate) archive_bucket: String,
    pub(crate) force_path_style: bool,
    pub(crate) ca_cert_pem_path: PathBuf,
    pub(crate) readiness_interval: Duration,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReadinessConfig {
    #[schemars(range(min = 1, max = 300))]
    startup_timeout_seconds: u64,
}

impl ReadinessConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        bounded(
            self.startup_timeout_seconds,
            1,
            300,
            "readiness.startupTimeoutSeconds",
        )
    }

    pub(crate) fn into_startup_timeout(self) -> Duration {
        Duration::from_secs(self.startup_timeout_seconds)
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(transparent)]
struct DrainSeconds60(u64);

impl JsonSchema for DrainSeconds60 {
    fn is_referenceable() -> bool {
        false
    }

    fn schema_name() -> String {
        "SettingsOnlyDrainSeconds60".to_owned()
    }

    fn json_schema(_generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::Schema::Object(schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::Integer.into()),
            const_value: Some(serde_json::json!(60)),
            ..schemars::schema::SchemaObject::default()
        })
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DrainConfig {
    total_seconds: DrainSeconds60,
}

impl DrainConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        (self.total_seconds.0 == 60)
            .then_some(())
            .ok_or(ConfigError::InvalidValue("drain.totalSeconds"))
    }

    pub(crate) fn into_total_budget(self) -> Duration {
        Duration::from_secs(self.total_seconds.0)
    }
}

fn non_blank(value: &str, field: &'static str) -> Result<(), ConfigError> {
    if value.trim().is_empty() {
        return Err(ConfigError::InvalidValue(field));
    }
    Ok(())
}

fn bounded(value: u64, minimum: u64, maximum: u64, field: &'static str) -> Result<(), ConfigError> {
    if !(minimum..=maximum).contains(&value) {
        return Err(ConfigError::InvalidValue(field));
    }
    Ok(())
}

fn validate_tls_endpoint(
    value: &str,
    required_prefix: &str,
    field: &'static str,
) -> Result<(), ConfigError> {
    let authority = value
        .strip_prefix(required_prefix)
        .ok_or(ConfigError::InvalidValue(field))?;
    if authority.is_empty()
        || authority.starts_with('/')
        || authority.chars().any(char::is_whitespace)
    {
        return Err(ConfigError::InvalidValue(field));
    }
    Ok(())
}

fn validate_s3_bucket(value: &str) -> Result<(), ConfigError> {
    let valid = (3..=63).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte)
        })
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && !value.contains("..")
        && !value.contains(".-")
        && !value.contains("-.")
        && value.parse::<std::net::Ipv4Addr>().is_err();
    valid
        .then_some(())
        .ok_or(ConfigError::InvalidValue("s3.archiveBucket"))
}

fn non_empty_path(path: &Path, field: &'static str) -> Result<(), ConfigError> {
    if path.as_os_str().is_empty() {
        return Err(ConfigError::InvalidValue(field));
    }
    Ok(())
}

fn validate_vault_path(
    value: &str,
    allow_empty: bool,
    field: &'static str,
) -> Result<(), ConfigError> {
    if value.is_empty() {
        return allow_empty
            .then_some(())
            .ok_or(ConfigError::InvalidValue(field));
    }
    if value
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(ConfigError::InvalidValue(field));
    }
    Ok(())
}

#[cfg(test)]
fn schema_bytes() -> Vec<u8> {
    let schema = schemars::r#gen::SchemaSettings::draft07()
        .into_generator()
        .into_root_schema_for::<SettingsOnlyConfig>();
    let Ok(mut bytes) = serde_json::to_vec_pretty(&schema) else {
        unreachable!("schemars RootSchema serialization is infallible")
    };
    bytes.push(b'\n');
    bytes
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    const SECRET_SENTINEL: &str = "do-not-leak-settingsonly-secret";
    const VALID_CONFIG: &str = r#"
schemaVersion = 2
profile = "production"
topology = "durable-isolated"

[listeners]
requestBudgetMs = 15000

[listeners.primary]
bind = "127.0.0.1:18080"

[listeners.admin]
bind = "127.0.0.1:18082"

[listeners.health]
bind = "127.0.0.1:18081"

[federated]
issuer = "https://issuer.example.test"
audience = "rss-settingsonly"
jwksPath = "/run/rss/federated.jwks.json"
refreshSeconds = 5
trustedKinds = ["user", "device", "admin", "superAdmin"]

[postgres]
host = "postgres.example.test"
port = 5432
database = "rss"
sslMode = "verifyFull"
sslRootCertPath = "/run/rss/postgres-ca.pem"
readinessSeconds = 5

[postgres.writer]
maxConnections = 5

[postgres.reader]
maxConnections = 5

[postgres.dlxArchiver]
maxConnections = 2

[postgres.dlxVerifier]
maxConnections = 2

[postgres.dlxPurger]
maxConnections = 2

[vault]
addr = "https://vault.example.test:8200"
caCertPemPath = "/run/rss/vault-ca.pem"
transitMount = "transit"
settingsKeyName = "settings-config-value"
readinessSeconds = 5

[[vault.tenantStoreAllowlist]]
tenantId = "00000000-0000-4000-8000-000000000147"
storeId = "vault"
mount = "secret"
kvPathPrefix = "tenants/settings"

[eventing]
amqpCaCertPemPath = "/run/rss/amqp-ca.pem"
publisherConfirmTimeoutMs = 5000

[redis]
caCertPemPath = "/run/rss/redis-ca.pem"
readinessSeconds = 5

[tenantAuthority]
ttlSeconds = 3600
clockSkewSeconds = 60

[dlx]
hotKeyName = "settings-dlx-hot"
archiveKeyName = "settings-dlx-archive"
readinessSeconds = 5

[s3]
endpoint = "https://s3.example.test"
region = "us-east-1"
archiveBucket = "rss-settingsonly-dlx"
forcePathStyle = false
caCertPemPath = "/run/rss/s3-ca.pem"
readinessSeconds = 5

[readiness]
startupTimeoutSeconds = 30

[drain]
totalSeconds = 60
"#;

    struct TestSource {
        document: String,
        secret_document: Option<String>,
        document_reads: usize,
        environments: BTreeMap<&'static str, OsString>,
        environment_reads: BTreeMap<&'static str, usize>,
    }

    impl TestSource {
        fn complete(document: impl Into<String>) -> Self {
            Self {
                document: document.into(),
                secret_document: None,
                document_reads: 0,
                environments: [
                    (
                        PG_WRITER_PASSWORD_ENV,
                        "do-not-leak-settingsonly-secret-writer",
                    ),
                    (
                        PG_READER_PASSWORD_ENV,
                        "do-not-leak-settingsonly-secret-reader",
                    ),
                    (PG_DLX_ARCHIVER_PASSWORD_ENV, "dlx-archiver-password"),
                    (PG_DLX_VERIFIER_PASSWORD_ENV, "dlx-verifier-password"),
                    (PG_DLX_PURGER_PASSWORD_ENV, "dlx-purger-password"),
                    (VAULT_TOKEN_ENV, "settings-vault-token"),
                    (
                        SETTINGS_AMQP_PUBLISHER_URL_ENV,
                        "amqps://settings-publisher:secret@rabbit.example.test/%2fsettings",
                    ),
                    (
                        SETTINGS_AMQP_SUBSCRIBER_URL_ENV,
                        "amqps://settings-subscriber:secret@rabbit.example.test/%2fsettings",
                    ),
                    (REDIS_URL_ENV, "rediss://redis.example.test:6379/0"),
                    (
                        TENANT_AUTHORITY_KEY_ENV,
                        "tenant-authority-key-material-32-bytes",
                    ),
                    (DLX_HOT_VAULT_TOKEN_ENV, "dlx-hot-vault-token"),
                    (DLX_ARCHIVE_VAULT_TOKEN_ENV, "dlx-archive-vault-token"),
                    (S3_ACCESS_KEY_ID_ENV, "settingsonly-s3-access"),
                    (S3_SECRET_ACCESS_KEY_ENV, "settingsonly-s3-secret"),
                ]
                .into_iter()
                .map(|(name, value)| (name, OsString::from(value)))
                .chain([
                    (BUILD_SOURCE_REVISION_ENV, OsString::from("a".repeat(40))),
                    (
                        DECLARED_IMAGE_DIGEST_ENV,
                        OsString::from(format!("sha256:{}", "b".repeat(64))),
                    ),
                    (POD_IP_ENV, OsString::from("127.0.0.2")),
                    (PRIMARY_PORT_ENV, OsString::from("8080")),
                    (ADMIN_PORT_ENV, OsString::from("8082")),
                    (HEALTH_PORT_ENV, OsString::from("8083")),
                    (
                        MTLS_ALLOW_SET_ENV,
                        OsString::from("[\"spiffe://rss.local/ns/rss/sa/ingress-gateway\"]"),
                    ),
                    (
                        SPIFFE_ENDPOINT_ENV,
                        OsString::from("unix:///run/spire/sockets/agent.sock"),
                    ),
                ])
                .collect(),
                environment_reads: BTreeMap::new(),
            }
        }
    }

    impl ConfigSource for TestSource {
        fn read_document(&mut self, _path: &Path) -> std::io::Result<String> {
            self.document_reads += 1;
            Ok(self.document.clone())
        }

        fn read_secret_bundle(&mut self, _path: &Path) -> std::io::Result<Zeroizing<String>> {
            if let Some(document) = self.secret_document.take() {
                return Ok(Zeroizing::new(document));
            }
            let value = |source: &mut Self, name| {
                source
                    .read_environment(name)
                    .and_then(|value| value.into_string().ok())
                    .unwrap_or_default()
            };
            Ok(Zeroizing::new(
                serde_json::json!({
                    "pgWriterPassword": value(self, PG_WRITER_PASSWORD_ENV),
                    "pgReaderPassword": value(self, PG_READER_PASSWORD_ENV),
                    "pgDlxArchiverPassword": value(self, PG_DLX_ARCHIVER_PASSWORD_ENV),
                    "pgDlxVerifierPassword": value(self, PG_DLX_VERIFIER_PASSWORD_ENV),
                    "pgDlxPurgerPassword": value(self, PG_DLX_PURGER_PASSWORD_ENV),
                    "vaultToken": value(self, VAULT_TOKEN_ENV),
                    "settingsAmqpPublisherUrl": value(self, SETTINGS_AMQP_PUBLISHER_URL_ENV),
                    "settingsAmqpSubscriberUrl": value(self, SETTINGS_AMQP_SUBSCRIBER_URL_ENV),
                    "redisUrl": value(self, REDIS_URL_ENV),
                    "tenantAuthorityKey": value(self, TENANT_AUTHORITY_KEY_ENV),
                    "dlxHotVaultToken": value(self, DLX_HOT_VAULT_TOKEN_ENV),
                    "dlxArchiveVaultToken": value(self, DLX_ARCHIVE_VAULT_TOKEN_ENV),
                    "s3AccessKeyId": value(self, S3_ACCESS_KEY_ID_ENV),
                    "s3SecretAccessKey": value(self, S3_SECRET_ACCESS_KEY_ENV),
                })
                .to_string(),
            ))
        }

        fn read_environment(&mut self, name: &'static str) -> Option<OsString> {
            *self.environment_reads.entry(name).or_default() += 1;
            self.environments.get(name).cloned()
        }
    }

    fn parse(document: &str) -> Result<SettingsOnlyConfig, ConfigError> {
        let parsed = parse_document(document)?;
        parsed.validate()?;
        Ok(parsed)
    }

    fn parse_error(document: &str) -> ConfigError {
        match parse(document) {
            Ok(_) => panic!("configuration unexpectedly passed validation"),
            Err(error) => error,
        }
    }

    fn schema_validator() -> jsonschema::Validator {
        let schema: serde_json::Value =
            serde_json::from_slice(&schema_bytes()).expect("generated schema JSON");
        jsonschema::draft7::options()
            .should_validate_formats(true)
            .build(&schema)
            .expect("valid generated Draft-07 schema")
    }

    fn json_value(document: &str) -> serde_json::Value {
        let value: toml::Value = toml::from_str(document).expect("valid TOML fixture syntax");
        serde_json::to_value(value).expect("TOML value maps to JSON")
    }

    #[test]
    fn committed_schema_is_generated_from_the_parser_types() {
        assert_eq!(schema_bytes(), include_bytes!("../config.schema.json"));
    }

    #[test]
    fn valid_document_is_accepted_by_parser_and_schema() {
        parse(VALID_CONFIG).expect("valid closed configuration");
        assert!(schema_validator().is_valid(&json_value(VALID_CONFIG)));
    }

    #[test]
    fn published_sample_is_accepted_by_parser_and_schema() {
        let sample = include_str!("../settingsonly.example.toml");
        parse(sample).expect("valid published sample configuration");
        assert!(schema_validator().is_valid(&json_value(sample)));
    }

    #[test]
    fn parser_and_schema_reject_unknown_fields_recursively() {
        for document in [
            VALID_CONFIG.replace("schemaVersion = 2", "schemaVersion = 2\nlegacy = true"),
            VALID_CONFIG.replace(
                "requestBudgetMs = 15000",
                "requestBudgetMs = 15000\nlegacy = true",
            ),
            VALID_CONFIG.replace("[postgres.writer]", "[postgres.writer]\nlegacy = true"),
            VALID_CONFIG.replace(
                "kvPathPrefix = \"tenants/settings\"",
                "kvPathPrefix = \"tenants/settings\"\nlegacy = true",
            ),
            VALID_CONFIG.replace(
                "publisherConfirmTimeoutMs = 5000",
                "publisherConfirmTimeoutMs = 5000\nlegacy = true",
            ),
            VALID_CONFIG.replace("[redis]", "[redis]\nlegacy = true"),
            VALID_CONFIG.replace("[tenantAuthority]", "[tenantAuthority]\nlegacy = true"),
            VALID_CONFIG.replace("[dlx]", "[dlx]\nlegacy = true"),
            VALID_CONFIG.replace("[s3]", "[s3]\nlegacy = true"),
            VALID_CONFIG.replace("[readiness]", "[readiness]\nlegacy = true"),
            VALID_CONFIG.replace("[drain]", "[drain]\nlegacy = true"),
        ] {
            assert!(matches!(
                parse_error(&document),
                ConfigError::InvalidDocument { .. }
            ));
            assert!(!schema_validator().is_valid(&json_value(&document)));
        }
    }

    #[test]
    fn parser_and_schema_reject_v1_and_unknown_schema_versions() {
        for version in [1, 3] {
            let document =
                VALID_CONFIG.replace("schemaVersion = 2", &format!("schemaVersion = {version}"));
            assert_eq!(
                parse_error(&document),
                ConfigError::InvalidValue("schemaVersion")
            );
            assert!(!schema_validator().is_valid(&json_value(&document)));
        }
    }

    #[test]
    fn production_shape_and_all_durable_sections_are_required() {
        for (header, field) in [
            ("profile = \"production\"\n", "profile"),
            ("topology = \"durable-isolated\"\n", "topology"),
            ("[eventing]", "eventing"),
            ("[redis]", "redis"),
            ("[tenantAuthority]", "tenantAuthority"),
            ("[dlx]", "dlx"),
            ("[s3]", "s3"),
            ("[readiness]", "readiness"),
            ("[drain]", "drain"),
        ] {
            let document = if header.ends_with('\n') {
                VALID_CONFIG.replacen(header, "", 1)
            } else {
                VALID_CONFIG.replacen(header, &format!("[{field}Removed]"), 1)
            };
            assert!(parse(&document).is_err(), "missing {field} passed parser");
            assert!(
                !schema_validator().is_valid(&json_value(&document)),
                "missing {field} passed schema"
            );
        }
    }

    #[test]
    fn explicit_amqp_and_redis_ca_paths_are_required() {
        for (line, field) in [
            (
                "amqpCaCertPemPath = \"/run/rss/amqp-ca.pem\"\n",
                "eventing.amqpCaCertPemPath",
            ),
            (
                "caCertPemPath = \"/run/rss/redis-ca.pem\"\n",
                "redis.caCertPemPath",
            ),
        ] {
            let document = VALID_CONFIG.replacen(line, "", 1);
            assert!(parse(&document).is_err(), "missing {field} passed parser");
            assert!(
                !schema_validator().is_valid(&json_value(&document)),
                "missing {field} passed schema"
            );
        }
    }

    #[test]
    fn profile_topology_and_drain_are_closed_single_values() {
        for (needle, replacement, field) in [
            ("profile = \"production\"", "profile = \"demo\"", "profile"),
            (
                "topology = \"durable-isolated\"",
                "topology = \"demo\"",
                "topology",
            ),
            (
                "totalSeconds = 60",
                "totalSeconds = 59",
                "drain.totalSeconds",
            ),
            (
                "totalSeconds = 60",
                "totalSeconds = 61",
                "drain.totalSeconds",
            ),
        ] {
            let document = VALID_CONFIG.replace(needle, replacement);
            assert!(parse(&document).is_err(), "invalid {field} passed parser");
            assert!(
                !schema_validator().is_valid(&json_value(&document)),
                "invalid {field} passed schema"
            );
        }
    }

    #[test]
    fn parser_and_schema_reject_removed_tracing_input() {
        let document = format!("{VALID_CONFIG}\n[tracing]\nfilter = \"info\"\n");
        assert!(matches!(
            parse_error(&document),
            ConfigError::InvalidDocument { .. }
        ));
        assert!(!schema_validator().is_valid(&json_value(&document)));
    }

    #[test]
    fn parser_and_schema_reject_removed_runtime_noop_fields() {
        for document in [
            VALID_CONFIG.replace(
                "archiveKeyName = \"settings-dlx-archive\"",
                "archiveKeyName = \"settings-dlx-archive\"\narchivePrefix = \"settingsonly/dlx\"",
            ),
            VALID_CONFIG.replace(
                "startupTimeoutSeconds = 30",
                "startupTimeoutSeconds = 30\nprobeTimeoutSeconds = 5",
            ),
        ] {
            assert!(matches!(
                parse_error(&document),
                ConfigError::InvalidDocument {
                    category: DocumentIssue::UnknownField,
                    ..
                }
            ));
            assert!(!schema_validator().is_valid(&json_value(&document)));
        }
    }

    #[test]
    fn plaintext_and_non_closed_secret_references_are_rejected_without_leaking_values() {
        let plaintext = VALID_CONFIG.replace(
            "[postgres.writer]",
            &format!("[postgres.writer]\npassword = \"{SECRET_SENTINEL}\""),
        );
        let wrong_kind = VALID_CONFIG.replace(
            "settingsKeyName = \"settings-config-value\"",
            "settingsKeyName = \"settings-config-value\"\ntoken = { kind = \"fileRef\", path = \"/tmp/token\" }",
        );
        let generic_name = VALID_CONFIG.replace(
            "[postgres.reader]",
            "[postgres.reader]\nsecretEnvironment = \"RSS_ARBITRARY_SECRET\"",
        );

        for document in [&plaintext, &wrong_kind, &generic_name] {
            let error = parse_error(document);
            assert!(matches!(error, ConfigError::InvalidDocument { .. }));
            assert!(!format!("{error:?} {error}").contains(SECRET_SENTINEL));
            assert!(!schema_validator().is_valid(&json_value(document)));
        }
    }

    #[test]
    fn capture_reads_document_and_each_closed_environment_exactly_once() {
        let mut source = TestSource::complete(VALID_CONFIG);
        let captured = capture_from(Path::new("ignored"), &mut source).expect("capture");
        assert_eq!(source.document_reads, 1);
        assert_eq!(source.environment_reads.len(), 23);
        assert!(source.environment_reads.values().all(|reads| *reads == 1));
        assert_eq!(source.environment_reads[FORBIDDEN_SHARED_AMQP_URL_ENV], 1);
        assert!(!format!("{captured:?}").contains(SECRET_SENTINEL));
        let (_, secrets, build_metadata, frontend) = captured.into_runtime_inputs();
        let build_metadata = build_metadata.expect("build metadata");
        assert_eq!(build_metadata.source_revision(), "a".repeat(40));
        assert_eq!(
            build_metadata.image_digest(),
            format!("sha256:{}", "b".repeat(64))
        );
        assert_eq!(frontend.primary_port, 8080);
        assert!(!format!("{secrets:?}").contains(SECRET_SENTINEL));
        assert_secret_material(secrets.into_secret_material());
    }

    #[test]
    fn secret_bundle_catalog_separates_amqp_publisher_and_subscriber_identities() {
        assert!(SECRET_BUNDLE_FIELDS.contains(&"settingsAmqpPublisherUrl"));
        assert!(SECRET_BUNDLE_FIELDS.contains(&"settingsAmqpSubscriberUrl"));
        assert!(!SECRET_BUNDLE_FIELDS.contains(&"settingsAmqpUrl"));
    }

    fn assert_secret_material(secrets: ProductionSecretMaterial) {
        assert_eq!(
            &*secrets.pg_writer_password,
            "do-not-leak-settingsonly-secret-writer"
        );
        assert_eq!(
            &*secrets.pg_reader_password,
            "do-not-leak-settingsonly-secret-reader"
        );
        assert_eq!(&*secrets.pg_dlx_archiver_password, "dlx-archiver-password");
        assert_eq!(&*secrets.pg_dlx_verifier_password, "dlx-verifier-password");
        assert_eq!(&*secrets.pg_dlx_purger_password, "dlx-purger-password");
        assert_eq!(&*secrets.vault_token, "settings-vault-token");
        assert!(secrets.settings_amqp_publisher_url.starts_with("amqps://"));
        assert!(secrets.settings_amqp_subscriber_url.starts_with("amqps://"));
        assert_ne!(
            secrets.settings_amqp_publisher_url,
            secrets.settings_amqp_subscriber_url
        );
        assert!(secrets.redis_url.starts_with("rediss://"));
        assert_eq!(
            &*secrets.tenant_authority_key,
            "tenant-authority-key-material-32-bytes"
        );
        assert_ne!(secrets.dlx_hot_vault_token, secrets.dlx_archive_vault_token);
        assert_eq!(&*secrets.s3_access_key_id, "settingsonly-s3-access");
        assert_eq!(&*secrets.s3_secret_access_key, "settingsonly-s3-secret");
    }

    #[test]
    fn capture_rejects_partial_build_metadata() {
        for missing in [BUILD_SOURCE_REVISION_ENV, DECLARED_IMAGE_DIGEST_ENV] {
            let mut source = TestSource::complete(VALID_CONFIG);
            source.environments.remove(missing);
            assert_eq!(
                capture_from(Path::new("ignored"), &mut source).unwrap_err(),
                ConfigError::InvalidValue("buildMetadata")
            );
        }
    }

    #[test]
    fn frontend_failure_names_the_exact_environment_variable() {
        let mut source = TestSource::complete(VALID_CONFIG);
        source
            .environments
            .insert(PRIMARY_PORT_ENV, OsString::from("not-a-port"));

        let error = capture_from(Path::new("ignored"), &mut source).unwrap_err();

        assert_eq!(error, ConfigError::InvalidValue(PRIMARY_PORT_ENV));
    }

    #[test]
    fn capture_errors_do_not_expose_secret_material() {
        let mut source = TestSource::complete(VALID_CONFIG);
        source.environments.remove(VAULT_TOKEN_ENV);
        let error = capture_from(Path::new("ignored"), &mut source).unwrap_err();
        assert_eq!(
            error,
            ConfigError::InvalidSecretBundle {
                category: DocumentIssue::MissingField,
                field: "vaultToken",
            }
        );
        assert!(!format!("{error:?} {error}").contains(SECRET_SENTINEL));
    }

    #[test]
    fn secret_bundle_diagnostics_are_structural_and_redacted() {
        for (document, category, field) in [
            (
                serde_json::json!({"pgWriterPassword": SECRET_SENTINEL}).to_string(),
                DocumentIssue::MissingField,
                "pgReaderPassword",
            ),
            (
                format!("{{\"unexpectedSecret\":\"{SECRET_SENTINEL}\"}}"),
                DocumentIssue::UnknownField,
                "<document>",
            ),
        ] {
            let mut source = TestSource::complete(VALID_CONFIG);
            source.secret_document = Some(document);
            let error = capture_from(Path::new("ignored"), &mut source).unwrap_err();
            assert_eq!(error, ConfigError::InvalidSecretBundle { category, field });
            assert!(!format!("{error:?} {error}").contains(SECRET_SENTINEL));
        }

        let mut source = TestSource::complete(VALID_CONFIG);
        source.environments.insert(VAULT_TOKEN_ENV, OsString::new());
        let error = capture_from(Path::new("ignored"), &mut source).unwrap_err();
        assert_eq!(
            error,
            ConfigError::InvalidSecretBundle {
                category: DocumentIssue::MissingField,
                field: "vaultToken",
            }
        );
    }

    #[test]
    fn shared_amqp_environment_is_rejected_without_bundle_fallback() {
        let mut source = TestSource::complete(VALID_CONFIG);
        source.environments.insert(
            FORBIDDEN_SHARED_AMQP_URL_ENV,
            OsString::from("amqps://shared.example.test/%2f"),
        );
        assert_eq!(
            capture_from(Path::new("ignored"), &mut source).unwrap_err(),
            ConfigError::ForbiddenEnvironment(FORBIDDEN_SHARED_AMQP_URL_ENV)
        );
        assert_eq!(source.environment_reads.len(), 1);
    }

    #[test]
    fn production_transport_secrets_require_tls_and_distinct_vault_tokens() {
        for (name, value, field) in [
            (
                SETTINGS_AMQP_PUBLISHER_URL_ENV,
                "amqp://rabbit.example.test/%2fsettings",
                "eventing.settingsAmqpPublisherUrl",
            ),
            (
                SETTINGS_AMQP_SUBSCRIBER_URL_ENV,
                "amqp://rabbit.example.test/%2fsettings",
                "eventing.settingsAmqpSubscriberUrl",
            ),
            (
                REDIS_URL_ENV,
                "redis://redis.example.test:6379/0",
                "redis.url",
            ),
            (
                DLX_ARCHIVE_VAULT_TOKEN_ENV,
                "dlx-hot-vault-token",
                "vault.workloadTokens",
            ),
            (
                PG_DLX_PURGER_PASSWORD_ENV,
                "do-not-leak-settingsonly-secret-writer",
                "postgres.rolePasswords",
            ),
            (TENANT_AUTHORITY_KEY_ENV, "too-short", "tenantAuthority.key"),
        ] {
            let mut source = TestSource::complete(VALID_CONFIG);
            source.environments.insert(name, OsString::from(value));
            assert_eq!(
                capture_from(Path::new("ignored"), &mut source).unwrap_err(),
                ConfigError::InvalidValue(field)
            );
        }

        let mut source = TestSource::complete(VALID_CONFIG);
        let publisher_url = source.environments[SETTINGS_AMQP_PUBLISHER_URL_ENV].clone();
        source
            .environments
            .insert(SETTINGS_AMQP_SUBSCRIBER_URL_ENV, publisher_url);
        assert_eq!(
            capture_from(Path::new("ignored"), &mut source).unwrap_err(),
            ConfigError::InvalidValue("eventing.amqpRoleUrls")
        );
    }

    #[test]
    fn semantic_bounds_and_closed_trusted_kinds_fail_closed() {
        for (needle, replacement) in [
            ("requestBudgetMs = 15000", "requestBudgetMs = 0"),
            ("refreshSeconds = 5", "refreshSeconds = 0"),
            (
                "trustedKinds = [\"user\", \"device\", \"admin\", \"superAdmin\"]",
                "trustedKinds = []",
            ),
            (
                "trustedKinds = [\"user\", \"device\", \"admin\", \"superAdmin\"]",
                "trustedKinds = [\"root\"]",
            ),
            ("maxConnections = 5", "maxConnections = 0"),
            ("readinessSeconds = 5", "readinessSeconds = 0"),
            (
                "publisherConfirmTimeoutMs = 5000",
                "publisherConfirmTimeoutMs = 0",
            ),
            ("ttlSeconds = 3600", "ttlSeconds = 3599"),
            ("startupTimeoutSeconds = 30", "startupTimeoutSeconds = 0"),
        ] {
            let document = VALID_CONFIG.replacen(needle, replacement, 1);
            assert!(parse(&document).is_err(), "{replacement}");
            assert!(!schema_validator().is_valid(&json_value(&document)));
        }
    }

    #[test]
    fn parser_and_schema_share_statically_expressible_semantic_constraints() {
        for document in [
            VALID_CONFIG.replace("127.0.0.1:18080", "not-a-socket"),
            VALID_CONFIG.replace("127.0.0.1:18080", "0.0.0.0:18080"),
            VALID_CONFIG.replace("127.0.0.1:18081", "10.0.0.8:18081"),
            VALID_CONFIG.replace(
                "trustedKinds = [\"user\", \"device\", \"admin\", \"superAdmin\"]",
                "trustedKinds = [\"user\", \"user\"]",
            ),
            VALID_CONFIG.replace(
                "issuer = \"https://issuer.example.test\"",
                "issuer = \"   \"",
            ),
            VALID_CONFIG.replace("mount = \"secret\"", "mount = \"secret//nested\""),
            VALID_CONFIG.replace("mount = \"secret\"", "mount = \"secret/../nested\""),
            VALID_CONFIG.replace(
                "kvPathPrefix = \"tenants/settings\"",
                "kvPathPrefix = \"tenants/./settings\"",
            ),
            VALID_CONFIG.replace(
                "tenantId = \"00000000-0000-4000-8000-000000000147\"",
                "tenantId = \"------------------------------------\"",
            ),
            VALID_CONFIG.replace(
                "tenantId = \"00000000-0000-4000-8000-000000000147\"",
                "tenantId = \"00000000-0000-0000-0000-000000000000\"",
            ),
            VALID_CONFIG.replace("sslMode = \"verifyFull\"", "sslMode = \"disable\""),
            VALID_CONFIG.replace("endpoint = \"https://s3.example.test\"", "endpoint = \"http://s3.example.test\""),
            VALID_CONFIG.replacen(
                "[[vault.tenantStoreAllowlist]]",
                "[[vault.tenantStoreAllowlist]]\ntenantId = \"00000000-0000-4000-8000-000000000147\"\nstoreId = \"vault\"\nmount = \"secret\"\nkvPathPrefix = \"tenants/settings\"\n\n[[vault.tenantStoreAllowlist]]",
                1,
            ),
        ] {
            assert!(parse(&document).is_err(), "parser accepted: {document}");
            assert!(
                !schema_validator().is_valid(&json_value(&document)),
                "schema accepted: {document}"
            );
        }
    }

    #[test]
    fn postgres_roles_and_tls_policy_are_closed_at_deserialization() {
        for section in [
            "writer",
            "reader",
            "dlxArchiver",
            "dlxVerifier",
            "dlxPurger",
        ] {
            let document = VALID_CONFIG.replace(
                &format!("[postgres.{section}]"),
                &format!("[postgres.{section}]\nusername = \"legacy_role\""),
            );
            assert!(matches!(
                parse_error(&document),
                ConfigError::InvalidDocument {
                    category: DocumentIssue::UnknownField,
                    ..
                }
            ));
            assert!(!schema_validator().is_valid(&json_value(&document)));
        }

        for mode in ["disable", "prefer", "require", "verifyCa"] {
            let document =
                VALID_CONFIG.replace("sslMode = \"verifyFull\"", &format!("sslMode = \"{mode}\""));
            assert!(matches!(
                parse_error(&document),
                ConfigError::InvalidDocument { .. }
            ));
            assert!(!schema_validator().is_valid(&json_value(&document)));
        }
    }

    #[test]
    fn parser_rejects_cross_field_constraints() {
        let same_bind = VALID_CONFIG.replace("127.0.0.1:18081", "127.0.0.1:18080");
        assert_eq!(
            parse_error(&same_bind),
            ConfigError::InvalidValue("listeners.bind")
        );
        let shared_dlx_key = VALID_CONFIG.replace(
            "hotKeyName = \"settings-dlx-hot\"",
            "hotKeyName = \"settings-dlx-archive\"",
        );
        assert_eq!(
            parse_error(&shared_dlx_key),
            ConfigError::InvalidValue("dlx.keyNames")
        );
    }

    #[test]
    fn document_diagnostics_are_locatable_and_redacted() {
        let document = VALID_CONFIG.replace(
            "[postgres.writer]",
            &format!("[postgres.writer]\nunknownSecret = \"{SECRET_SENTINEL}\""),
        );
        let error = parse_error(&document);
        let rendered = format!("{error:?} {error}");
        assert!(matches!(
            error,
            ConfigError::InvalidDocument {
                category: DocumentIssue::UnknownField,
                line: 1..,
                column: 1..
            }
        ));
        assert!(!rendered.contains(SECRET_SENTINEL));
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn consuming_accessors_preserve_closed_values() {
        let config = parse(VALID_CONFIG).expect("valid config");
        let SettingsOnlyConfigSections {
            listeners,
            federated,
            postgres,
            vault,
            production_infra,
        } = config.into_sections();
        let (primary, admin, health, budget) = listeners.into_listener_inputs();
        assert_eq!(primary, "127.0.0.1:18080".parse().unwrap());
        assert_eq!(admin, "127.0.0.1:18082".parse().unwrap());
        assert_eq!(health, "127.0.0.1:18081".parse().unwrap());
        assert_eq!(budget, Duration::from_secs(15));

        let (_, _, _, refresh, kinds) = federated.into_oidc_inputs();
        assert_eq!(refresh, Duration::from_secs(5));
        assert_eq!(
            kinds
                .into_iter()
                .map(TrustedKind::as_str)
                .collect::<Vec<_>>(),
            ["user", "device", "admin", "superAdmin"]
        );

        let postgres = postgres.into_postgres_inputs();
        assert_eq!(postgres.connection.into_connect_options().1, 5432);
        assert_eq!(
            postgres.writer.into_writer_pool(),
            ("rss_app".to_owned(), 5)
        );
        assert_eq!(
            postgres.reader.into_reader_pool(),
            ("rss_app_read".to_owned(), 5)
        );
        assert_eq!(
            postgres.dlx_archiver.into_dlx_archiver_pool(),
            ("rss_dlx_archiver".to_owned(), 2)
        );
        assert_eq!(
            postgres.dlx_verifier.into_dlx_verifier_pool(),
            ("rss_dlx_verifier".to_owned(), 2)
        );
        assert_eq!(
            postgres.dlx_purger.into_dlx_purger_pool(),
            ("rss_dlx_purger".to_owned(), 2)
        );
        assert_eq!(postgres.readiness_interval, Duration::from_secs(5));

        let (_, _, _, key, allowlist, vault_readiness) = vault.into_vault_inputs();
        assert_eq!(key, "settings-config-value");
        assert_eq!(allowlist.len(), 1);
        assert_eq!(
            allowlist.into_iter().next().unwrap().into_store_binding().1,
            "vault"
        );
        assert_eq!(vault_readiness, Duration::from_secs(5));

        let ProductionInfraConfig {
            eventing,
            redis,
            tenant_authority,
            dlx,
            s3,
            readiness,
            drain,
        } = production_infra;
        let eventing = eventing.into_eventing_inputs();
        assert_eq!(eventing.publisher_confirm_timeout, Duration::from_secs(5));
        assert_eq!(
            eventing.amqp_ca_cert_pem_path,
            PathBuf::from("/run/rss/amqp-ca.pem")
        );
        let redis = redis.into_redis_inputs();
        assert_eq!(redis.readiness, Duration::from_secs(5));
        assert_eq!(
            redis.ca_cert_pem_path,
            PathBuf::from("/run/rss/redis-ca.pem")
        );
        assert_eq!(
            tenant_authority.into_tenant_authority_inputs(),
            (Duration::from_secs(3600), Duration::from_secs(60))
        );
        let dlx = dlx.into_dlx_inputs();
        assert_eq!(dlx.hot_key_name, "settings-dlx-hot");
        assert_eq!(dlx.archive_key_name, "settings-dlx-archive");
        assert_eq!(dlx.readiness_interval, Duration::from_secs(5));
        let s3 = s3.into_s3_inputs();
        assert_eq!(s3.endpoint, "https://s3.example.test");
        assert_eq!(s3.region, "us-east-1");
        assert_eq!(s3.archive_bucket, "rss-settingsonly-dlx");
        assert!(!s3.force_path_style);
        assert_eq!(s3.ca_cert_pem_path, PathBuf::from("/run/rss/s3-ca.pem"));
        assert_eq!(s3.readiness_interval, Duration::from_secs(5));
        assert_eq!(readiness.into_startup_timeout(), Duration::from_secs(30));
        assert_eq!(drain.into_total_budget(), Duration::from_secs(60));
    }
}
