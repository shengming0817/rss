//! Closed, versioned configuration capture for the IdentityAudit executable assembly.

use std::ffi::OsString;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use schemars::JsonSchema;
use serde::Deserialize;
use url::{Host, Url};
use zeroize::Zeroizing;

const SERVING_SECRET_BUNDLE_PATH: &str = "/var/run/rss/secrets/serving-secret-bundle";
#[cfg(feature = "test-support")]
const TEST_SECRET_BUNDLE_PATH_ENV: &str = "RSS_IDENTITYAUDIT_TEST_SECRET_BUNDLE_PATH";
const BUILD_SOURCE_REVISION_ENV: &str = "RSS_BUILD_SOURCE_REVISION";
const DECLARED_IMAGE_DIGEST_ENV: &str = "RSS_DECLARED_IMAGE_DIGEST";
#[cfg(test)]
use runtimeexec::config::{
    ADMIN_PORT_ENV, HEALTH_PORT_ENV, MTLS_ALLOW_SET_ENV, POD_IP_ENV, PRIMARY_PORT_ENV,
    SPIFFE_ENDPOINT_ENV,
};
use runtimeexec::config::{FrontendConfigError, SecretDocument, SecretValue};
const FORBIDDEN_SHARED_AMQP_URL_ENV: &str = "RSS_AMQP_URL";

/// Read, parse, validate, and resolve one immutable configuration generation.
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
    let bundle: ServingSecretBundle = document
        .parse()
        .map_err(|_| ConfigError::InvalidSecretBundle)?;
    let secrets: ResolvedSecrets = bundle.try_into()?;
    secrets.validate()?;
    let build_metadata = capture_build_metadata(source)?;
    let frontend = runtimeexec::config::capture_serving_frontend(
        |name| source.read_environment(name),
        |raw| {
            httpserve::TrustedProxyConfig::try_from_json(raw).map_err(|_| {
                FrontendConfigError::Invalid(runtimeexec::config::TRUSTED_PROXY_CIDRS_ENV)
            })
        },
    )
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
    fn read_secret_bundle(&mut self, path: &Path) -> std::io::Result<SecretDocument>;
    fn read_environment(&mut self, name: &'static str) -> Option<OsString>;
}

struct ProcessConfigSource;

impl ConfigSource for ProcessConfigSource {
    fn read_document(&mut self, path: &Path) -> std::io::Result<String> {
        std::fs::read_to_string(path)
    }

    fn read_secret_bundle(&mut self, path: &Path) -> std::io::Result<SecretDocument> {
        #[cfg(feature = "test-support")]
        {
            let path = std::env::var_os(TEST_SECRET_BUNDLE_PATH_ENV)
                .map(PathBuf::from)
                .unwrap_or_else(|| path.to_owned());
            runtimeexec::config::read_secret_document(&path)
        }
        #[cfg(not(feature = "test-support"))]
        {
            runtimeexec::config::read_secret_document(path)
        }
    }

    fn read_environment(&mut self, name: &'static str) -> Option<OsString> {
        std::env::var_os(name)
    }
}

fn parse_document(document: &str) -> Result<IdentityAuditConfig, ConfigError> {
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
    InvalidSecretBundle,
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
                    "identityaudit config could not be read: {kind:?}"
                )
            }
            Self::InvalidDocument {
                category,
                line,
                column,
            } => write!(
                formatter,
                "identityaudit config is invalid: {category:?} at line {line}, column {column}"
            ),
            Self::InvalidValue(field) => {
                write!(formatter, "identityaudit config field is invalid: {field}")
            }
            Self::SecretBundleRead(kind) => {
                write!(
                    formatter,
                    "identityaudit secret bundle could not be read: {kind:?}"
                )
            }
            Self::InvalidSecretBundle => {
                formatter.write_str("identityaudit secret bundle is invalid")
            }
            Self::MissingEnvironment(name) => {
                write!(
                    formatter,
                    "identityaudit secret environment is missing: {name}"
                )
            }
            Self::NonUnicodeEnvironment(name) => write!(
                formatter,
                "identityaudit secret environment is not valid Unicode: {name}"
            ),
            Self::EmptyEnvironment(name) => {
                write!(
                    formatter,
                    "identityaudit secret environment is empty: {name}"
                )
            }
            Self::ForbiddenEnvironment(name) => {
                write!(
                    formatter,
                    "identityaudit forbidden environment is present: {name}"
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {}

pub(crate) struct CapturedConfig {
    config: IdentityAuditConfig,
    secrets: ResolvedSecrets,
    build_metadata: Option<runtimeexec::inventory::BuildMetadata>,
    frontend: ServingFrontendConfig,
}

impl CapturedConfig {
    pub(crate) fn into_runtime_inputs(
        self,
    ) -> (
        IdentityAuditConfig,
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

pub(crate) type ServingFrontendConfig =
    runtimeexec::config::ServingFrontendConfig<httpserve::TrustedProxyConfig>;

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

pub(crate) struct ResolvedSecrets {
    pg_writer_password: Zeroizing<String>,
    pg_reader_password: Zeroizing<String>,
    pg_audit_admin_password: Zeroizing<String>,
    vault_signer_token: Zeroizing<String>,
    vault_dlx_token: Zeroizing<String>,
    identity_amqp_url: Zeroizing<String>,
    redis_url: Zeroizing<String>,
    audit_chain_key: primitives::MacKey,
    tenant_authority_key: primitives::MacKey,
    identity_pseudonym_key: secure::RedactionHashKey,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServingSecretBundle {
    pg_writer_password: SecretValue,
    pg_reader_password: SecretValue,
    pg_audit_admin_password: SecretValue,
    vault_signer_token: SecretValue,
    vault_dlx_token: SecretValue,
    identity_amqp_url: SecretValue,
    redis_url: SecretValue,
    audit_chain_key: SecretValue,
    tenant_authority_key: SecretValue,
    identity_pseudonym_key: SecretValue,
}

impl TryFrom<ServingSecretBundle> for ResolvedSecrets {
    type Error = ConfigError;

    fn try_from(value: ServingSecretBundle) -> Result<Self, Self::Error> {
        let values = [
            value.pg_writer_password.as_str(),
            value.pg_reader_password.as_str(),
            value.pg_audit_admin_password.as_str(),
            value.vault_signer_token.as_str(),
            value.vault_dlx_token.as_str(),
            value.identity_amqp_url.as_str(),
            value.redis_url.as_str(),
            value.audit_chain_key.as_str(),
            value.tenant_authority_key.as_str(),
            value.identity_pseudonym_key.as_str(),
        ];
        if values.iter().any(|value| value.is_empty()) {
            return Err(ConfigError::InvalidSecretBundle);
        }
        let audit_chain_key = value.audit_chain_key.into_zeroizing();
        let tenant_authority_key = value.tenant_authority_key.into_zeroizing();
        let identity_pseudonym_key = value.identity_pseudonym_key.into_zeroizing();
        let secrets = Self {
            pg_writer_password: value.pg_writer_password.into_zeroizing(),
            pg_reader_password: value.pg_reader_password.into_zeroizing(),
            pg_audit_admin_password: value.pg_audit_admin_password.into_zeroizing(),
            vault_signer_token: value.vault_signer_token.into_zeroizing(),
            vault_dlx_token: value.vault_dlx_token.into_zeroizing(),
            identity_amqp_url: value.identity_amqp_url.into_zeroizing(),
            redis_url: value.redis_url.into_zeroizing(),
            audit_chain_key: decode_mac_key(&audit_chain_key, "eventing.auditChainKey")?,
            tenant_authority_key: decode_mac_key(
                &tenant_authority_key,
                "eventing.tenantAuthorityKey",
            )?,
            identity_pseudonym_key: decode_pseudonym_key(
                &identity_pseudonym_key,
                "identity.pseudonymKey",
            )?,
        };
        secrets.validate()?;
        Ok(secrets)
    }
}

impl ResolvedSecrets {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.vault_signer_token == self.vault_dlx_token {
            return Err(ConfigError::InvalidValue("vault.workloadTokens"));
        }
        validate_required_tls_url(&self.identity_amqp_url, "amqps", "eventing.identityAmqpUrl")?;
        validate_required_tls_url(&self.redis_url, "rediss", "eventing.redisUrl")?;
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn into_secret_material(
        self,
    ) -> (
        Zeroizing<String>,
        Zeroizing<String>,
        Zeroizing<String>,
        Zeroizing<String>,
        Zeroizing<String>,
        Zeroizing<String>,
        Zeroizing<String>,
        primitives::MacKey,
        primitives::MacKey,
        secure::RedactionHashKey,
    ) {
        (
            self.pg_writer_password,
            self.pg_reader_password,
            self.pg_audit_admin_password,
            self.vault_signer_token,
            self.vault_dlx_token,
            self.identity_amqp_url,
            self.redis_url,
            self.audit_chain_key,
            self.tenant_authority_key,
            self.identity_pseudonym_key,
        )
    }
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
        "IdentityAuditSchemaVersionV2".to_owned()
    }

    fn json_schema(_generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::Schema::Object(schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::Integer.into()),
            const_value: Some(serde_json::json!(2)),
            ..schemars::schema::SchemaObject::default()
        })
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct IdentityAuditConfig {
    #[schemars(with = "SchemaVersionV2")]
    schema_version: u32,
    listeners: ListenersConfig,
    identity: IdentityConfig,
    oidc: OidcConfig,
    postgres: PostgresConfig,
    vault: VaultConfig,
    eventing: EventingConfig,
    redis: RedisConfig,
}

impl IdentityAuditConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != 2 {
            return Err(ConfigError::InvalidValue("schemaVersion"));
        }
        self.listeners.validate()?;
        self.identity.validate()?;
        self.oidc.validate()?;
        if self.identity.issuer != self.oidc.issuer {
            return Err(ConfigError::InvalidValue("identity.issuer"));
        }
        if self.identity.audience != self.oidc.audience {
            return Err(ConfigError::InvalidValue("identity.audience"));
        }
        self.postgres.validate()?;
        self.vault.validate()?;
        if self.identity.key_id != self.vault.signing_key_name {
            return Err(ConfigError::InvalidValue("identity.keyId"));
        }
        self.eventing.validate()?;
        self.redis.validate()
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn into_sections(
        self,
    ) -> (
        ListenersConfig,
        IdentityConfig,
        OidcConfig,
        PostgresConfig,
        VaultConfig,
        EventingConfig,
        RedisConfig,
    ) {
        (
            self.listeners,
            self.identity,
            self.oidc,
            self.postgres,
            self.vault,
            self.eventing,
            self.redis,
        )
    }
}

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
    #[schemars(range(min = 1, max = 300_000))]
    request_budget_ms: u64,
}

impl ListenersConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !(1..=300_000).contains(&self.request_budget_ms) {
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

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct IdentityConfig {
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    issuer: String,
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    audience: String,
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    key_id: String,
    #[schemars(range(min = 60, max = 86_400))]
    access_ttl_seconds: u64,
    #[schemars(range(min = 60, max = 2_592_000))]
    auth_grant_ttl_seconds: u64,
    #[schemars(range(min = 60, max = 2_592_000))]
    refresh_ttl_seconds: u64,
    #[schemars(length(min = 1))]
    password_blocklist_path: PathBuf,
}

impl IdentityConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_tls_url(&self.issuer, "https", "http", "identity.issuer")?;
        non_blank(&self.audience, "identity.audience")?;
        non_blank(&self.key_id, "identity.keyId")?;
        bounded(
            self.access_ttl_seconds,
            60,
            86_400,
            "identity.accessTtlSeconds",
        )?;
        bounded(
            self.auth_grant_ttl_seconds,
            60,
            2_592_000,
            "identity.authGrantTtlSeconds",
        )?;
        bounded(
            self.refresh_ttl_seconds,
            60,
            2_592_000,
            "identity.refreshTtlSeconds",
        )?;
        if self.access_ttl_seconds > self.auth_grant_ttl_seconds
            || self.access_ttl_seconds > self.refresh_ttl_seconds
        {
            return Err(ConfigError::InvalidValue("identity.ttl"));
        }
        non_empty_path(
            &self.password_blocklist_path,
            "identity.passwordBlocklistPath",
        )
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn into_identity_inputs(
        self,
    ) -> (
        String,
        String,
        String,
        Duration,
        Duration,
        Duration,
        PathBuf,
    ) {
        (
            self.issuer,
            self.audience,
            self.key_id,
            Duration::from_secs(self.access_ttl_seconds),
            Duration::from_secs(self.auth_grant_ttl_seconds),
            Duration::from_secs(self.refresh_ttl_seconds),
            self.password_blocklist_path,
        )
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OidcConfig {
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    issuer: String,
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    audience: String,
    #[schemars(length(min = 1))]
    jwks_path: PathBuf,
    #[schemars(range(min = 1, max = 300))]
    refresh_seconds: u64,
}

impl OidcConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_tls_url(&self.issuer, "https", "http", "oidc.issuer")?;
        non_blank(&self.audience, "oidc.audience")?;
        non_empty_path(&self.jwks_path, "oidc.jwksPath")?;
        bounded(self.refresh_seconds, 1, 300, "oidc.refreshSeconds")
    }

    pub(crate) fn into_oidc_inputs(self) -> (String, String, PathBuf, Duration) {
        (
            self.issuer,
            self.audience,
            self.jwks_path,
            Duration::from_secs(self.refresh_seconds),
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum PgSslMode {
    Disable,
    VerifyFull,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PostgresConfig {
    connection: PgConnectionConfig,
    writer: PgWriterRoleConfig,
    reader: PgReaderRoleConfig,
    audit_admin: PgAuditAdminRoleConfig,
}

impl PostgresConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        self.connection.validate()?;
        self.writer.validate()?;
        self.reader.validate()?;
        self.audit_admin.validate()
    }

    pub(crate) fn into_postgres_inputs(
        self,
    ) -> (
        PgConnectionConfig,
        PgWriterRoleConfig,
        PgReaderRoleConfig,
        PgAuditAdminRoleConfig,
    ) {
        (self.connection, self.writer, self.reader, self.audit_admin)
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PgConnectionConfig {
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    host: String,
    #[schemars(range(min = 1))]
    port: u16,
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    database: String,
    ssl_mode: PgSslMode,
    ssl_root_cert_path: Option<PathBuf>,
}

impl PgConnectionConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        non_blank(&self.host, "postgres.connection.host")?;
        non_blank(&self.database, "postgres.connection.database")?;
        if self.port == 0 {
            return Err(ConfigError::InvalidValue("postgres.connection.port"));
        }
        if let Some(path) = &self.ssl_root_cert_path {
            non_empty_path(path, "postgres.connection.sslRootCertPath")?;
        }
        let loopback = self
            .host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
        if !loopback
            && (self.ssl_mode != PgSslMode::VerifyFull || self.ssl_root_cert_path.is_none())
        {
            return Err(ConfigError::InvalidValue("postgres.connection.tls"));
        }
        Ok(())
    }

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

macro_rules! postgres_role {
    ($type:ident, $field:literal, $getter:ident) => {
        #[derive(Deserialize, JsonSchema)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub(crate) struct $type {
            #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
            username: String,
            #[schemars(range(min = 1, max = 100))]
            max_connections: u32,
        }

        impl $type {
            fn validate(&self) -> Result<(), ConfigError> {
                non_blank(&self.username, concat!($field, ".username"))?;
                bounded(
                    u64::from(self.max_connections),
                    1,
                    100,
                    concat!($field, ".maxConnections"),
                )?;
                Ok(())
            }

            pub(crate) fn $getter(self) -> (String, u32) {
                (self.username, self.max_connections)
            }
        }
    };
}

postgres_role!(PgWriterRoleConfig, "postgres.writer", into_writer_pool);
postgres_role!(PgReaderRoleConfig, "postgres.reader", into_reader_pool);
postgres_role!(
    PgAuditAdminRoleConfig,
    "postgres.auditAdmin",
    into_audit_admin_pool
);

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct VaultConfig {
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    addr: String,
    #[schemars(length(min = 1))]
    ca_cert_pem_path: PathBuf,
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    transit_mount: String,
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    signing_key_name: String,
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    dlx_payload_key_name: String,
    #[schemars(range(min = 1, max = 30))]
    readiness_seconds: u64,
}

impl VaultConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_tls_url(&self.addr, "https", "http", "vault.addr")?;
        non_empty_path(&self.ca_cert_pem_path, "vault.caCertPemPath")?;
        non_blank(&self.transit_mount, "vault.transitMount")?;
        non_blank(&self.signing_key_name, "vault.signingKeyName")?;
        non_blank(&self.dlx_payload_key_name, "vault.dlxPayloadKeyName")?;
        bounded(self.readiness_seconds, 1, 30, "vault.readinessSeconds")
    }

    pub(crate) fn into_vault_inputs(self) -> (String, PathBuf, String, String, String, Duration) {
        (
            self.addr,
            self.ca_cert_pem_path,
            self.transit_mount,
            self.signing_key_name,
            self.dlx_payload_key_name,
            Duration::from_secs(self.readiness_seconds),
        )
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EventingConfig {
    #[schemars(length(min = 1))]
    amqp_ca_cert_pem_path: PathBuf,
    audit_chain_key_id: AuditChainKeyId,
    #[schemars(range(min = 3600, max = 86_400))]
    tenant_authority_ttl_seconds: u64,
    #[schemars(range(min = 0, max = 300))]
    tenant_authority_clock_skew_seconds: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(transparent)]
pub(crate) struct AuditChainKeyId(u16);

impl JsonSchema for AuditChainKeyId {
    fn is_referenceable() -> bool {
        false
    }

    fn schema_name() -> String {
        "IdentityAuditChainKeyV1".to_owned()
    }

    fn json_schema(_generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::Schema::Object(schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::Integer.into()),
            const_value: Some(serde_json::json!(1)),
            ..schemars::schema::SchemaObject::default()
        })
    }
}

impl AuditChainKeyId {
    pub(crate) const fn get(self) -> u16 {
        self.0
    }
}

pub(crate) struct EventingInputs {
    pub(crate) amqp_ca_cert_pem_path: PathBuf,
    pub(crate) audit_chain_key_id: AuditChainKeyId,
    pub(crate) tenant_authority_ttl: Duration,
    pub(crate) tenant_authority_clock_skew: Duration,
}

impl EventingConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        non_empty_path(&self.amqp_ca_cert_pem_path, "eventing.amqpCaCertPemPath")?;
        if self.audit_chain_key_id.get() != 1 {
            return Err(ConfigError::InvalidValue("eventing.auditChainKeyId"));
        }
        bounded(
            self.tenant_authority_ttl_seconds,
            3600,
            86_400,
            "eventing.tenantAuthorityTtlSeconds",
        )?;
        bounded(
            self.tenant_authority_clock_skew_seconds,
            0,
            300,
            "eventing.tenantAuthorityClockSkewSeconds",
        )?;
        Ok(())
    }

    pub(crate) fn into_eventing_inputs(self) -> EventingInputs {
        EventingInputs {
            amqp_ca_cert_pem_path: self.amqp_ca_cert_pem_path,
            audit_chain_key_id: self.audit_chain_key_id,
            tenant_authority_ttl: Duration::from_secs(self.tenant_authority_ttl_seconds),
            tenant_authority_clock_skew: Duration::from_secs(
                self.tenant_authority_clock_skew_seconds,
            ),
        }
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RedisConfig {
    #[schemars(length(min = 1))]
    ca_cert_pem_path: PathBuf,
}

impl RedisConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        non_empty_path(&self.ca_cert_pem_path, "redis.caCertPemPath")
    }

    pub(crate) fn into_ca_cert_pem_path(self) -> PathBuf {
        self.ca_cert_pem_path
    }
}

fn non_blank(value: &str, field: &'static str) -> Result<(), ConfigError> {
    if value.trim().is_empty() {
        return Err(ConfigError::InvalidValue(field));
    }
    Ok(())
}

fn non_empty_path(path: &Path, field: &'static str) -> Result<(), ConfigError> {
    if path.as_os_str().is_empty() {
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

fn validate_tls_url(
    value: &str,
    tls_scheme: &str,
    plaintext_scheme: &str,
    field: &'static str,
) -> Result<(), ConfigError> {
    let parsed = Url::parse(value).map_err(|_| ConfigError::InvalidValue(field))?;
    if parsed.scheme() == tls_scheme {
        return parsed
            .host()
            .is_some()
            .then_some(())
            .ok_or(ConfigError::InvalidValue(field));
    }
    if parsed.scheme() == plaintext_scheme && url_host_is_loopback(&parsed) {
        return Ok(());
    }
    Err(ConfigError::InvalidValue(field))
}

fn validate_required_tls_url(
    value: &str,
    tls_scheme: &str,
    field: &'static str,
) -> Result<(), ConfigError> {
    let parsed = Url::parse(value).map_err(|_| ConfigError::InvalidValue(field))?;
    (parsed.scheme() == tls_scheme && parsed.host().is_some())
        .then_some(())
        .ok_or(ConfigError::InvalidValue(field))
}

fn url_host_is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(host)) => host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback()),
        None => false,
    }
}

fn decode_mac_key(
    value: &Zeroizing<String>,
    field: &'static str,
) -> Result<primitives::MacKey, ConfigError> {
    let decoded = Zeroizing::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value.as_bytes())
            .map_err(|_| ConfigError::InvalidValue(field))?,
    );
    (decoded.len() >= 32)
        .then(|| primitives::MacKey::from_bytes(decoded.to_vec()))
        .ok_or(ConfigError::InvalidValue(field))
}

fn decode_pseudonym_key(
    value: &Zeroizing<String>,
    field: &'static str,
) -> Result<secure::RedactionHashKey, ConfigError> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| ConfigError::InvalidValue(field))?;
    secure::RedactionHashKey::from_bytes(decoded).map_err(|_| ConfigError::InvalidValue(field))
}

#[cfg(test)]
pub(crate) fn parse_for_test(document: &str) -> Result<IdentityAuditConfig, ConfigError> {
    let config = parse_document(document)?;
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
fn schema_bytes() -> Vec<u8> {
    let schema = schemars::r#gen::SchemaSettings::draft07()
        .into_generator()
        .into_root_schema_for::<IdentityAuditConfig>();
    let Ok(mut bytes) = serde_json::to_vec_pretty(&schema) else {
        unreachable!("schemars RootSchema serialization is infallible")
    };
    bytes.push(b'\n');
    bytes
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use anyhow::Context as _;

    use super::*;

    const SECRET_SENTINEL: &str = "do-not-leak-identityaudit-secret";
    const VALID_KEY: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";
    const VALID_CONFIG: &str = r#"
schemaVersion = 2

[listeners]
requestBudgetMs = 30000
[listeners.primary]
bind = "127.0.0.1:18080"
[listeners.admin]
bind = "127.0.0.1:18081"
[listeners.health]
bind = "127.0.0.1:18083"

[identity]
issuer = "https://identity.example.test"
audience = "rss-identityaudit"
keyId = "identity-access-es256"
accessTtlSeconds = 900
authGrantTtlSeconds = 2592000
refreshTtlSeconds = 2592000
passwordBlocklistPath = "/run/rss/password-blocklist.sha256"

[oidc]
issuer = "https://identity.example.test"
audience = "rss-identityaudit"
jwksPath = "/run/rss/oidc.jwks.json"
refreshSeconds = 30

[postgres.connection]
host = "postgres.example.test"
port = 5432
database = "rss"
sslMode = "verifyFull"
sslRootCertPath = "/run/rss/postgres-ca.pem"
[postgres.writer]
username = "rss_identity_writer"
maxConnections = 10
[postgres.reader]
username = "rss_identity_reader"
maxConnections = 10
[postgres.auditAdmin]
username = "rss_audit_admin"
maxConnections = 5

[vault]
addr = "https://vault.example.test:8200"
caCertPemPath = "/run/rss/vault-ca.pem"
transitMount = "transit"
signingKeyName = "identity-access-es256"
dlxPayloadKeyName = "identityaudit-dlx-payload"
readinessSeconds = 10

[eventing]
amqpCaCertPemPath = "/run/rss/amqp-ca.pem"
auditChainKeyId = 1
tenantAuthorityTtlSeconds = 3600
tenantAuthorityClockSkewSeconds = 60

[redis]
caCertPemPath = "/run/rss/redis-ca.pem"
"#;

    struct TestSource {
        document: String,
        secret_document: Option<String>,
        document_reads: usize,
        environments: BTreeMap<&'static str, Option<OsString>>,
        environment_reads: BTreeMap<&'static str, usize>,
    }

    impl TestSource {
        fn complete(document: impl Into<String>) -> Self {
            let environments = BTreeMap::from([
                (FORBIDDEN_SHARED_AMQP_URL_ENV, None),
                (
                    BUILD_SOURCE_REVISION_ENV,
                    Some(OsString::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
                ),
                (
                    DECLARED_IMAGE_DIGEST_ENV,
                    Some(OsString::from(
                        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    )),
                ),
                (POD_IP_ENV, Some(OsString::from("127.0.0.2"))),
                (PRIMARY_PORT_ENV, Some(OsString::from("8080"))),
                (ADMIN_PORT_ENV, Some(OsString::from("8081"))),
                (HEALTH_PORT_ENV, Some(OsString::from("8083"))),
                (
                    MTLS_ALLOW_SET_ENV,
                    Some(OsString::from(
                        "[\"spiffe://rss.local/ns/rss/sa/ingress-gateway\"]",
                    )),
                ),
                (
                    SPIFFE_ENDPOINT_ENV,
                    Some(OsString::from("unix:///run/spire/sockets/agent.sock")),
                ),
                (runtimeexec::config::TRUSTED_PROXY_CIDRS_ENV, None),
                (runtimeexec::config::RATE_LIMIT_PER_SECOND_ENV, None),
                (runtimeexec::config::RATE_LIMIT_BURST_ENV, None),
            ]);
            Self {
                document: document.into(),
                secret_document: Some(valid_secret_bundle_document()),
                document_reads: 0,
                environments,
                environment_reads: BTreeMap::new(),
            }
        }

        fn set_environment(&mut self, name: &'static str, value: impl Into<OsString>) {
            assert!(self.environments.contains_key(name));
            self.environments.insert(name, Some(value.into()));
        }

        fn clear_environment(&mut self, name: &'static str) {
            assert!(self.environments.contains_key(name));
            self.environments.insert(name, None);
        }

        fn mutate_secret_bundle(
            &mut self,
            mutate: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
        ) {
            let document = self
                .secret_document
                .as_deref()
                .expect("complete source has one secret document");
            let mut value: serde_json::Value =
                serde_json::from_str(document).expect("valid secret fixture JSON");
            mutate(value.as_object_mut().expect("secret fixture is an object"));
            self.secret_document = Some(value.to_string());
        }
    }

    impl ConfigSource for TestSource {
        fn read_document(&mut self, _path: &Path) -> std::io::Result<String> {
            self.document_reads += 1;
            Ok(self.document.clone())
        }

        fn read_secret_bundle(&mut self, _path: &Path) -> std::io::Result<SecretDocument> {
            self.secret_document
                .take()
                .map(|document| SecretDocument::new(Zeroizing::new(document)))
                .ok_or_else(|| std::io::Error::other("secret document was read more than once"))
        }

        fn read_environment(&mut self, name: &'static str) -> Option<OsString> {
            *self.environment_reads.entry(name).or_default() += 1;
            self.environments.get(name).cloned().flatten()
        }
    }

    fn valid_secret_bundle_document() -> String {
        serde_json::json!({
            "pgWriterPassword": SECRET_SENTINEL,
            "pgReaderPassword": SECRET_SENTINEL,
            "pgAuditAdminPassword": SECRET_SENTINEL,
            "vaultSignerToken": SECRET_SENTINEL,
            "vaultDlxToken": "identityaudit-dlx-token-distinct",
            "identityAmqpUrl": "amqps://identity:secret@rabbit.example.test/%2fidentity",
            "redisUrl": "rediss://redis.example.test:6379/0",
            "auditChainKey": VALID_KEY,
            "tenantAuthorityKey": VALID_KEY,
            "identityPseudonymKey": VALID_KEY,
        })
        .to_string()
    }

    fn environment_reads_are_exact(source: &TestSource) -> bool {
        source.environments.keys().copied().collect::<BTreeSet<_>>()
            == source
                .environment_reads
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
            && source.environment_reads.values().all(|reads| *reads == 1)
    }

    fn parse(document: &str) -> Result<IdentityAuditConfig, ConfigError> {
        let config = parse_document(document)?;
        config.validate()?;
        Ok(config)
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
    fn valid_document_and_published_sample_match_parser_and_schema() {
        for document in [VALID_CONFIG, include_str!("../identityaudit.example.toml")] {
            parse(document).expect("valid closed configuration");
            assert!(schema_validator().is_valid(&json_value(document)));
        }
    }

    #[test]
    fn parser_and_schema_reject_unknown_fields_recursively() {
        for document in [
            VALID_CONFIG.replace("schemaVersion = 2", "schemaVersion = 2\nlegacy = true"),
            VALID_CONFIG.replace(
                "requestBudgetMs = 30000",
                "requestBudgetMs = 30000\nlegacy = true",
            ),
            VALID_CONFIG.replace("database = \"rss\"", "database = \"rss\"\nlegacy = true"),
            VALID_CONFIG.replace(
                "username = \"rss_audit_admin\"",
                "username = \"rss_audit_admin\"\nlegacy = true",
            ),
            VALID_CONFIG.replace("[eventing]", "[eventing]\nlegacy = true"),
        ] {
            assert!(matches!(
                parse_error(&document),
                ConfigError::InvalidDocument { .. }
            ));
            assert!(!schema_validator().is_valid(&json_value(&document)));
        }
    }

    #[test]
    fn parser_and_schema_reject_old_or_unknown_schema_versions() {
        for version in [0, 1, 3] {
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
    fn explicit_amqp_and_redis_ca_paths_are_required() {
        let v2 = VALID_CONFIG.to_owned();
        parse(&v2).expect("schema v2 with both private CA paths must be accepted");
        assert!(schema_validator().is_valid(&json_value(&v2)));

        for (field, document) in [
            (
                "eventing.amqpCaCertPemPath",
                v2.replace("amqpCaCertPemPath = \"/run/rss/amqp-ca.pem\"\n", ""),
            ),
            (
                "redis.caCertPemPath",
                v2.replace("caCertPemPath = \"/run/rss/redis-ca.pem\"\n", ""),
            ),
        ] {
            assert!(parse(&document).is_err(), "missing {field} must fail");
            assert!(!schema_validator().is_valid(&json_value(&document)));
        }

        for (field, document) in [
            (
                "eventing.amqpCaCertPemPath",
                v2.replace("/run/rss/amqp-ca.pem", ""),
            ),
            (
                "redis.caCertPemPath",
                v2.replace("/run/rss/redis-ca.pem", ""),
            ),
        ] {
            assert_eq!(parse_error(&document), ConfigError::InvalidValue(field));
        }
    }

    #[test]
    fn plaintext_and_non_closed_secret_references_are_rejected_without_leaking_values() {
        let plaintext = VALID_CONFIG.replace(
            "username = \"rss_identity_writer\"",
            &format!("username = \"rss_identity_writer\"\npassword = \"{SECRET_SENTINEL}\""),
        );
        let wrong_kind = VALID_CONFIG.replace(
            "signingKeyName = \"identity-access-es256\"",
            "signingKeyName = \"identity-access-es256\"\nsignerToken = { kind = \"fileRef\", path = \"/tmp/token\" }",
        );
        let generic_name = VALID_CONFIG.replace(
            "[eventing]",
            "[eventing]\nsecretEnvironment = \"RSS_ARBITRARY_SECRET\"",
        );
        for document in [&plaintext, &wrong_kind, &generic_name] {
            let error = parse_error(document);
            assert!(matches!(error, ConfigError::InvalidDocument { .. }));
            assert!(!format!("{error:?} {error}").contains(SECRET_SENTINEL));
            assert!(!schema_validator().is_valid(&json_value(document)));
        }
    }

    fn assert_capture_source_reads(source: &TestSource) {
        assert_eq!(source.document_reads, 1);
        assert!(
            environment_reads_are_exact(source),
            "environment read closure drift: expected_keys={:?} actual_reads={:?}",
            source.environments.keys().collect::<Vec<_>>(),
            source.environment_reads
        );
    }

    #[test]
    fn environment_read_comparator_rejects_missing_extra_duplicate_and_equal_replacement() {
        let mut source = TestSource::complete(VALID_CONFIG);
        source.environment_reads = source
            .environments
            .keys()
            .copied()
            .map(|key| (key, 1))
            .collect();
        assert!(environment_reads_are_exact(&source));

        source.environment_reads.remove(PRIMARY_PORT_ENV);
        assert!(!environment_reads_are_exact(&source));
        source.environment_reads.insert("RSS_EQUAL_REPLACEMENT", 1);
        assert!(!environment_reads_are_exact(&source));
        source.environment_reads.remove("RSS_EQUAL_REPLACEMENT");
        source.environment_reads.insert(PRIMARY_PORT_ENV, 2);
        assert!(!environment_reads_are_exact(&source));
        source.environment_reads.insert(PRIMARY_PORT_ENV, 1);
        source.environment_reads.insert("RSS_EXTRA", 1);
        assert!(!environment_reads_are_exact(&source));
    }

    fn assert_captured_runtime_inputs(captured: CapturedConfig) -> anyhow::Result<()> {
        assert!(!format!("{captured:?}").contains(SECRET_SENTINEL));
        let (_, secrets, build_metadata, frontend) = captured.into_runtime_inputs();
        let build_metadata = build_metadata.context("identityaudit build metadata is missing")?;
        assert_eq!(
            build_metadata.source_revision(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            build_metadata.image_digest(),
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(frontend.primary_port, 8080);
        assert!(!format!("{secrets:?}").contains(SECRET_SENTINEL));
        let material = secrets.into_secret_material();
        assert_eq!(&*material.0, SECRET_SENTINEL);
        assert_eq!(&*material.3, SECRET_SENTINEL);
        assert_eq!(material.7.as_bytes().len(), 32);
        assert_eq!(material.8.as_bytes().len(), 32);
        Ok(())
    }

    #[test]
    fn capture_reads_document_and_closed_environments_exactly_once() -> anyhow::Result<()> {
        let mut source = TestSource::complete(VALID_CONFIG);
        let captured = capture_from(Path::new("ignored"), &mut source)?;
        assert_capture_source_reads(&source);
        assert_captured_runtime_inputs(captured)
    }

    #[test]
    fn capture_rejects_partial_build_metadata() {
        for missing in [BUILD_SOURCE_REVISION_ENV, DECLARED_IMAGE_DIGEST_ENV] {
            let mut source = TestSource::complete(VALID_CONFIG);
            source.clear_environment(missing);
            assert_eq!(
                capture_from(Path::new("ignored"), &mut source).unwrap_err(),
                ConfigError::InvalidValue("buildMetadata")
            );
        }
    }

    #[test]
    fn frontend_failure_names_the_exact_environment_variable() {
        let mut source = TestSource::complete(VALID_CONFIG);
        source.set_environment(PRIMARY_PORT_ENV, "not-a-port");

        let error = capture_from(Path::new("ignored"), &mut source).unwrap_err();

        assert_eq!(error, ConfigError::InvalidValue(PRIMARY_PORT_ENV));
    }

    #[test]
    fn capture_rejects_shared_amqp_fallback_presence() {
        let mut source = TestSource::complete(VALID_CONFIG);
        source.set_environment(FORBIDDEN_SHARED_AMQP_URL_ENV, SECRET_SENTINEL);
        let error = capture_from(Path::new("ignored"), &mut source).unwrap_err();
        assert_eq!(
            error,
            ConfigError::ForbiddenEnvironment(FORBIDDEN_SHARED_AMQP_URL_ENV)
        );
        assert!(!format!("{error:?} {error}").contains(SECRET_SENTINEL));
    }

    #[test]
    fn capture_errors_and_resolved_transport_validation_are_redacted() {
        let mut missing = TestSource::complete(VALID_CONFIG);
        missing.mutate_secret_bundle(|bundle| {
            bundle.remove("vaultSignerToken");
        });
        let error = capture_from(Path::new("ignored"), &mut missing).unwrap_err();
        assert_eq!(error, ConfigError::InvalidSecretBundle);
        assert!(!format!("{error:?} {error}").contains(SECRET_SENTINEL));

        let mut plaintext_remote = TestSource::complete(VALID_CONFIG);
        plaintext_remote.mutate_secret_bundle(|bundle| {
            bundle.insert(
                "identityAmqpUrl".to_owned(),
                serde_json::Value::String(format!(
                    "amqp://identity:{SECRET_SENTINEL}@rabbit.example.test/%2fidentity"
                )),
            );
        });
        let error = capture_from(Path::new("ignored"), &mut plaintext_remote).unwrap_err();
        assert_eq!(error, ConfigError::InvalidValue("eventing.identityAmqpUrl"));
        assert!(!format!("{error:?} {error}").contains(SECRET_SENTINEL));

        for (name, field) in [
            ("auditChainKey", "eventing.auditChainKey"),
            ("tenantAuthorityKey", "eventing.tenantAuthorityKey"),
            ("identityPseudonymKey", "identity.pseudonymKey"),
        ] {
            for invalid in ["not-base64", "dGlueQ"] {
                let mut source = TestSource::complete(VALID_CONFIG);
                source.mutate_secret_bundle(|bundle| {
                    bundle.insert(
                        name.to_owned(),
                        serde_json::Value::String(invalid.to_owned()),
                    );
                });
                let error = capture_from(Path::new("ignored"), &mut source).unwrap_err();
                assert_eq!(error, ConfigError::InvalidValue(field));
                assert!(!format!("{error:?} {error}").contains(invalid));
            }
        }
    }

    #[test]
    fn parser_and_schema_share_static_bounds_and_loopback_listener_rules() {
        for document in [
            VALID_CONFIG.replace("requestBudgetMs = 30000", "requestBudgetMs = 0"),
            VALID_CONFIG.replace("refreshSeconds = 30", "refreshSeconds = 0"),
            VALID_CONFIG.replace("maxConnections = 10", "maxConnections = 0"),
            VALID_CONFIG.replace("auditChainKeyId = 1", "auditChainKeyId = 2"),
            VALID_CONFIG.replace(
                "tenantAuthorityTtlSeconds = 3600",
                "tenantAuthorityTtlSeconds = 3599",
            ),
            VALID_CONFIG.replace(
                "tenantAuthorityClockSkewSeconds = 60",
                "tenantAuthorityClockSkewSeconds = 301",
            ),
            VALID_CONFIG.replace("127.0.0.1:18080", "0.0.0.0:18080"),
            VALID_CONFIG.replace("127.0.0.1:18081", "not-a-socket"),
        ] {
            assert!(parse(&document).is_err());
            assert!(!schema_validator().is_valid(&json_value(&document)));
        }
    }

    #[test]
    fn parser_rejects_cross_field_and_remote_plaintext_constraints() {
        let cases = [
            VALID_CONFIG.replace("127.0.0.1:18081", "127.0.0.1:18080"),
            VALID_CONFIG.replace(
                "https://identity.example.test",
                "http://issuer.example.test",
            ),
            VALID_CONFIG.replace(
                "https://vault.example.test:8200",
                "http://vault.example.test:8200",
            ),
            VALID_CONFIG.replace("sslMode = \"verifyFull\"", "sslMode = \"disable\""),
            VALID_CONFIG.replace("authGrantTtlSeconds = 2592000", "authGrantTtlSeconds = 60"),
            VALID_CONFIG.replacen(
                "issuer = \"https://identity.example.test\"",
                "issuer = \"https://different-issuer.example.test\"",
                1,
            ),
            VALID_CONFIG.replacen(
                "audience = \"rss-identityaudit\"",
                "audience = \"rss-other\"",
                1,
            ),
            VALID_CONFIG.replace(
                "tenantAuthorityTtlSeconds = 3600",
                "tenantAuthorityTtlSeconds = 3599",
            ),
            VALID_CONFIG.replace(
                "tenantAuthorityClockSkewSeconds = 60",
                "tenantAuthorityClockSkewSeconds = 301",
            ),
            VALID_CONFIG.replace("auditChainKeyId = 1", "auditChainKeyId = 2"),
        ];
        for document in cases {
            assert!(parse(&document).is_err(), "parser accepted: {document}");
        }
    }

    #[test]
    fn capture_rejects_reused_vault_workload_tokens() {
        let mut source = TestSource::complete(VALID_CONFIG);
        source.mutate_secret_bundle(|bundle| {
            bundle.insert(
                "vaultDlxToken".to_owned(),
                serde_json::Value::String(SECRET_SENTINEL.to_owned()),
            );
        });
        let error = capture_from(Path::new("ignored"), &mut source).unwrap_err();
        assert_eq!(error, ConfigError::InvalidValue("vault.workloadTokens"));
        assert!(!format!("{error:?} {error}").contains(SECRET_SENTINEL));
    }

    #[test]
    fn loopback_plaintext_amqp_and_redis_are_rejected() {
        let document = VALID_CONFIG
            .replace("https://identity.example.test", "http://127.0.0.1:19000")
            .replace("https://identity.example.test", "http://127.0.0.1:19000")
            .replace("https://vault.example.test:8200", "http://127.0.0.1:18200")
            .replace("host = \"postgres.example.test\"", "host = \"127.0.0.1\"")
            .replace("sslMode = \"verifyFull\"", "sslMode = \"disable\"");
        parse(&document).expect("explicit loopback plaintext config");

        let mut source = TestSource::complete(&document);
        source.mutate_secret_bundle(|bundle| {
            bundle.insert(
                "identityAmqpUrl".to_owned(),
                serde_json::Value::String("amqp://127.0.0.1:5672/%2fidentity".to_owned()),
            );
            bundle.insert(
                "redisUrl".to_owned(),
                serde_json::Value::String("redis://[::1]:6379/0".to_owned()),
            );
        });
        let error = capture_from(Path::new("ignored"), &mut source).unwrap_err();
        assert_eq!(error, ConfigError::InvalidValue("eventing.identityAmqpUrl"));

        let mut source = TestSource::complete(&document);
        source.mutate_secret_bundle(|bundle| {
            bundle.insert(
                "identityAmqpUrl".to_owned(),
                serde_json::Value::String("amqps://127.0.0.1:5671/%2fidentity".to_owned()),
            );
            bundle.insert(
                "redisUrl".to_owned(),
                serde_json::Value::String("redis://[::1]:6379/0".to_owned()),
            );
        });
        let error = capture_from(Path::new("ignored"), &mut source).unwrap_err();
        assert_eq!(error, ConfigError::InvalidValue("eventing.redisUrl"));
    }

    #[test]
    fn document_diagnostics_are_locatable_and_redacted() {
        let document = VALID_CONFIG.replace(
            "username = \"rss_identity_writer\"",
            &format!("unknownSecret = \"{SECRET_SENTINEL}\""),
        );
        let error = parse_error(&document);
        assert!(matches!(
            error,
            ConfigError::InvalidDocument {
                category: DocumentIssue::UnknownField,
                line: 1..,
                column: 1..
            }
        ));
        assert!(!format!("{error:?} {error}").contains(SECRET_SENTINEL));
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn consuming_accessors_preserve_closed_values() {
        let config = parse(VALID_CONFIG).expect("valid config");
        let (listeners, identity, oidc, postgres, vault, eventing, redis) = config.into_sections();
        let (primary, admin, health, budget) = listeners.into_listener_inputs();
        assert_eq!(primary, "127.0.0.1:18080".parse().unwrap());
        assert_eq!(admin, "127.0.0.1:18081".parse().unwrap());
        assert_eq!(health, "127.0.0.1:18083".parse().unwrap());
        assert_eq!(budget, Duration::from_secs(30));
        assert_eq!(identity.into_identity_inputs().3, Duration::from_secs(900));
        assert_eq!(oidc.into_oidc_inputs().3, Duration::from_secs(30));
        let (connection, writer, reader, audit_admin) = postgres.into_postgres_inputs();
        assert_eq!(connection.into_connect_options().1, 5432);
        assert_eq!(writer.into_writer_pool().1, 10);
        assert_eq!(reader.into_reader_pool().1, 10);
        assert_eq!(audit_admin.into_audit_admin_pool().1, 5);
        assert_eq!(vault.into_vault_inputs().3, "identity-access-es256");
        let eventing = eventing.into_eventing_inputs();
        assert_eq!(eventing.audit_chain_key_id.get(), 1);
        assert_eq!(
            eventing.amqp_ca_cert_pem_path,
            PathBuf::from("/run/rss/amqp-ca.pem")
        );
        assert_eq!(eventing.tenant_authority_ttl, Duration::from_secs(3600));
        assert_eq!(
            eventing.tenant_authority_clock_skew,
            Duration::from_secs(60)
        );
        assert_eq!(
            redis.into_ca_cert_pem_path(),
            PathBuf::from("/run/rss/redis-ca.pem")
        );
    }
}
