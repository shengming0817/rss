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
#[cfg(test)]
use runtimeexec::config::{
    ADMIN_PORT_ENV, HEALTH_PORT_ENV, MTLS_ALLOW_SET_ENV, POD_IP_ENV, PRIMARY_PORT_ENV,
    SPIFFE_ENDPOINT_ENV,
};
use runtimeexec::config::{FrontendConfigError, SecretDocument, SecretValue};
#[cfg(test)]
const PG_WRITER_PASSWORD_ENV: &str = "RSS_SETTINGSONLY_PG_WRITER_PASSWORD";
#[cfg(test)]
const PG_READER_PASSWORD_ENV: &str = "RSS_SETTINGSONLY_PG_READER_PASSWORD";
#[cfg(test)]
const VAULT_TOKEN_ENV: &str = "RSS_SETTINGSONLY_VAULT_TOKEN";
const BUILD_SOURCE_SHA_ENV: &str = "RSS_BUILD_SOURCE_SHA";
const BUILD_IMAGE_DIGEST_ENV: &str = "RSS_BUILD_IMAGE_DIGEST";

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

    let document = source
        .read_secret_bundle(Path::new(SERVING_SECRET_BUNDLE_PATH))
        .map_err(|error| ConfigError::SecretBundleRead(ReadFailure::from(error.kind())))?;
    let bundle: ServingSecretBundle = document
        .parse()
        .map_err(|_| ConfigError::InvalidSecretBundle)?;
    let secrets = bundle.try_into()?;
    let source_sha = resolve_public_environment(source, BUILD_SOURCE_SHA_ENV)?;
    let image_digest = resolve_public_environment(source, BUILD_IMAGE_DIGEST_ENV)?;
    let build_identity = runtimeexec::inventory::BuildIdentity::parse(&source_sha, &image_digest)
        .map_err(|_| ConfigError::InvalidValue("buildIdentity"))?;
    let frontend =
        runtimeexec::config::capture_serving_frontend(|name| source.read_environment(name))
            .map_err(frontend_error)?;
    Ok(CapturedConfig {
        config,
        secrets,
        build_identity,
        frontend,
    })
}

fn resolve_public_environment(
    source: &mut impl ConfigSource,
    name: &'static str,
) -> Result<String, ConfigError> {
    let value = source
        .read_environment(name)
        .ok_or(ConfigError::MissingEnvironment(name))?
        .into_string()
        .map_err(|_| ConfigError::NonUnicodeEnvironment(name))?;
    if value.is_empty() {
        return Err(ConfigError::EmptyEnvironment(name));
    }
    Ok(value)
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
        runtimeexec::config::read_secret_document(path)
    }

    fn read_environment(&mut self, name: &'static str) -> Option<OsString> {
        std::env::var_os(name)
    }
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
    InvalidSecretBundle,
    MissingEnvironment(&'static str),
    NonUnicodeEnvironment(&'static str),
    EmptyEnvironment(&'static str),
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
            Self::InvalidSecretBundle => {
                formatter.write_str("settings-only secret bundle is invalid")
            }
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
        }
    }
}

impl std::error::Error for ConfigError {}

/// One captured document and its separately owned, zeroizing secret material.
pub(crate) struct CapturedConfig {
    config: SettingsOnlyConfig,
    secrets: ResolvedSecrets,
    build_identity: runtimeexec::inventory::BuildIdentity,
    frontend: ServingFrontendConfig,
}

impl CapturedConfig {
    pub(crate) fn into_runtime_inputs(
        self,
    ) -> (
        SettingsOnlyConfig,
        ResolvedSecrets,
        runtimeexec::inventory::BuildIdentity,
        ServingFrontendConfig,
    ) {
        (
            self.config,
            self.secrets,
            self.build_identity,
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

/// Three resolved secret allocations, each erased when its final owner is dropped.
pub(crate) struct ResolvedSecrets {
    pg_writer_password: Zeroizing<String>,
    pg_reader_password: Zeroizing<String>,
    vault_token: Zeroizing<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServingSecretBundle {
    pg_writer_password: SecretValue,
    pg_reader_password: SecretValue,
    vault_token: SecretValue,
}

impl TryFrom<ServingSecretBundle> for ResolvedSecrets {
    type Error = ConfigError;

    fn try_from(value: ServingSecretBundle) -> Result<Self, Self::Error> {
        if [
            value.pg_writer_password.as_str(),
            value.pg_reader_password.as_str(),
            value.vault_token.as_str(),
        ]
        .iter()
        .any(|value| value.is_empty())
        {
            return Err(ConfigError::InvalidSecretBundle);
        }
        Ok(Self {
            pg_writer_password: value.pg_writer_password.into_zeroizing(),
            pg_reader_password: value.pg_reader_password.into_zeroizing(),
            vault_token: value.vault_token.into_zeroizing(),
        })
    }
}

impl ResolvedSecrets {
    pub(crate) fn into_secret_material(
        self,
    ) -> (Zeroizing<String>, Zeroizing<String>, Zeroizing<String>) {
        (
            self.pg_writer_password,
            self.pg_reader_password,
            self.vault_token,
        )
    }
}

impl fmt::Debug for ResolvedSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResolvedSecrets(<redacted>)")
    }
}

struct SchemaVersionV1;

impl JsonSchema for SchemaVersionV1 {
    fn is_referenceable() -> bool {
        false
    }

    fn schema_name() -> String {
        "SettingsOnlySchemaVersionV1".to_owned()
    }

    fn json_schema(_generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::Schema::Object(schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::Integer.into()),
            const_value: Some(serde_json::json!(1)),
            ..schemars::schema::SchemaObject::default()
        })
    }
}

/// The complete version-one document. All fields are mandatory unless represented as `Option`.
#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SettingsOnlyConfig {
    #[schemars(with = "SchemaVersionV1")]
    schema_version: u32,
    listeners: ListenersConfig,
    federated: FederatedConfig,
    postgres: PostgresConfig,
    vault: VaultConfig,
}

impl SettingsOnlyConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != 1 {
            return Err(ConfigError::InvalidValue("schemaVersion"));
        }
        self.listeners.validate()?;
        self.federated.validate()?;
        self.postgres.validate()?;
        self.vault.validate()
    }

    pub(crate) fn into_sections(
        self,
    ) -> (
        ListenersConfig,
        FederatedConfig,
        PostgresConfig,
        VaultConfig,
    ) {
        (self.listeners, self.federated, self.postgres, self.vault)
    }
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
        non_blank(&self.issuer, "federated.issuer")?;
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
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum PgSslMode {
    Disable,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
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
    ssl_root_cert_path: Option<PathBuf>,
    writer: PgWriterRoleConfig,
    reader: PgReaderRoleConfig,
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
        if let Some(path) = &self.ssl_root_cert_path {
            non_empty_path(path, "postgres.sslRootCertPath")?;
        }
        self.writer.validate()?;
        self.reader.validate()?;
        if !(1..=300).contains(&self.readiness_seconds) {
            return Err(ConfigError::InvalidValue("postgres.readinessSeconds"));
        }
        Ok(())
    }

    pub(crate) fn into_postgres_inputs(
        self,
    ) -> (
        PgConnectionConfig,
        PgWriterRoleConfig,
        PgReaderRoleConfig,
        Duration,
    ) {
        (
            PgConnectionConfig {
                host: self.host,
                port: self.port,
                database: self.database,
                ssl_mode: self.ssl_mode,
                ssl_root_cert_path: self.ssl_root_cert_path,
            },
            self.writer,
            self.reader,
            Duration::from_secs(self.readiness_seconds),
        )
    }
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
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    username: String,
    #[schemars(range(min = 1, max = 100))]
    max_connections: u32,
}

impl PgWriterRoleConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        non_blank(&self.username, "postgres.writer.username")?;
        if self.max_connections == 0 || self.max_connections > 100 {
            return Err(ConfigError::InvalidValue("postgres.writer.maxConnections"));
        }
        Ok(())
    }

    pub(crate) fn into_writer_pool(self) -> (String, u32) {
        (self.username, self.max_connections)
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PgReaderRoleConfig {
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    username: String,
    #[schemars(range(min = 1, max = 100))]
    max_connections: u32,
}

impl PgReaderRoleConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        non_blank(&self.username, "postgres.reader.username")?;
        if self.max_connections == 0 || self.max_connections > 100 {
            return Err(ConfigError::InvalidValue("postgres.reader.maxConnections"));
        }
        Ok(())
    }

    pub(crate) fn into_reader_pool(self) -> (String, u32) {
        (self.username, self.max_connections)
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct VaultConfig {
    #[schemars(length(min = 1), regex(pattern = "^.*\\S.*$"))]
    addr: String,
    ca_cert_pem_path: Option<PathBuf>,
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
        non_blank(&self.addr, "vault.addr")?;
        if let Some(path) = &self.ca_cert_pem_path {
            non_empty_path(path, "vault.caCertPemPath")?;
        }
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
            self.ca_cert_pem_path,
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
schemaVersion = 1

[listeners]
requestBudgetMs = 30000

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
username = "rss_settings_writer"
maxConnections = 5

[postgres.reader]
username = "rss_settings_reader"
maxConnections = 5

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
"#;

    struct TestSource {
        document: String,
        document_reads: usize,
        environments: BTreeMap<&'static str, OsString>,
        environment_reads: BTreeMap<&'static str, usize>,
    }

    impl TestSource {
        fn complete(document: impl Into<String>) -> Self {
            Self {
                document: document.into(),
                document_reads: 0,
                environments: [
                    PG_WRITER_PASSWORD_ENV,
                    PG_READER_PASSWORD_ENV,
                    VAULT_TOKEN_ENV,
                ]
                .into_iter()
                .map(|name| (name, OsString::from(SECRET_SENTINEL)))
                .chain([
                    (BUILD_SOURCE_SHA_ENV, OsString::from("a".repeat(40))),
                    (
                        BUILD_IMAGE_DIGEST_ENV,
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

        fn read_secret_bundle(&mut self, _path: &Path) -> std::io::Result<SecretDocument> {
            let value = |source: &mut Self, name| {
                source
                    .read_environment(name)
                    .and_then(|value| value.into_string().ok())
                    .unwrap_or_default()
            };
            Ok(SecretDocument::new(Zeroizing::new(
                serde_json::json!({
                    "pgWriterPassword": value(self, PG_WRITER_PASSWORD_ENV),
                    "pgReaderPassword": value(self, PG_READER_PASSWORD_ENV),
                    "vaultToken": value(self, VAULT_TOKEN_ENV),
                })
                .to_string(),
            )))
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
            VALID_CONFIG.replace("schemaVersion = 1", "schemaVersion = 1\nlegacy = true"),
            VALID_CONFIG.replace(
                "requestBudgetMs = 30000",
                "requestBudgetMs = 30000\nlegacy = true",
            ),
            VALID_CONFIG.replace(
                "username = \"rss_settings_writer\"",
                "username = \"rss_settings_writer\"\nlegacy = true",
            ),
            VALID_CONFIG.replace(
                "kvPathPrefix = \"tenants/settings\"",
                "kvPathPrefix = \"tenants/settings\"\nlegacy = true",
            ),
        ] {
            assert!(matches!(
                parse_error(&document),
                ConfigError::InvalidDocument { .. }
            ));
            assert!(!schema_validator().is_valid(&json_value(&document)));
        }
    }

    #[test]
    fn parser_and_schema_reject_unknown_schema_version() {
        let document = VALID_CONFIG.replace("schemaVersion = 1", "schemaVersion = 2");
        assert_eq!(
            parse_error(&document),
            ConfigError::InvalidValue("schemaVersion")
        );
        assert!(!schema_validator().is_valid(&json_value(&document)));
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
    fn plaintext_and_non_closed_secret_references_are_rejected_without_leaking_values() {
        let plaintext = VALID_CONFIG.replace(
            "username = \"rss_settings_writer\"",
            &format!("username = \"rss_settings_writer\"\npassword = \"{SECRET_SENTINEL}\""),
        );
        let wrong_kind = VALID_CONFIG.replace(
            "settingsKeyName = \"settings-config-value\"",
            "settingsKeyName = \"settings-config-value\"\ntoken = { kind = \"fileRef\", path = \"/tmp/token\" }",
        );
        let generic_name = VALID_CONFIG.replace(
            "username = \"rss_settings_reader\"",
            "username = \"rss_settings_reader\"\nsecretEnvironment = \"RSS_ARBITRARY_SECRET\"",
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
        assert_eq!(source.environment_reads.len(), 11);
        assert!(source.environment_reads.values().all(|reads| *reads == 1));
        assert!(!format!("{captured:?}").contains(SECRET_SENTINEL));
        let (_, secrets, build_identity, frontend) = captured.into_runtime_inputs();
        assert_eq!(build_identity.source_sha(), "a".repeat(40));
        assert_eq!(frontend.primary_port, 8080);
        assert!(!format!("{secrets:?}").contains(SECRET_SENTINEL));
        let (writer, reader, vault) = secrets.into_secret_material();
        assert_eq!(&**writer, SECRET_SENTINEL);
        assert_eq!(&**reader, SECRET_SENTINEL);
        assert_eq!(&**vault, SECRET_SENTINEL);
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
        assert_eq!(error, ConfigError::InvalidSecretBundle);
        assert!(!format!("{error:?} {error}").contains(SECRET_SENTINEL));
    }

    #[test]
    fn semantic_bounds_and_closed_trusted_kinds_fail_closed() {
        for (needle, replacement) in [
            ("requestBudgetMs = 30000", "requestBudgetMs = 0"),
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
    fn parser_rejects_cross_field_constraints() {
        let same_bind = VALID_CONFIG.replace("127.0.0.1:18081", "127.0.0.1:18080");
        assert_eq!(
            parse_error(&same_bind),
            ConfigError::InvalidValue("listeners.bind")
        );
    }

    #[test]
    fn document_diagnostics_are_locatable_and_redacted() {
        let document = VALID_CONFIG.replace(
            "username = \"rss_settings_writer\"",
            &format!("unknownSecret = \"{SECRET_SENTINEL}\""),
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
        let (listeners, federated, postgres, vault) = config.into_sections();
        let (primary, admin, health, budget) = listeners.into_listener_inputs();
        assert_eq!(primary, "127.0.0.1:18080".parse().unwrap());
        assert_eq!(admin, "127.0.0.1:18082".parse().unwrap());
        assert_eq!(health, "127.0.0.1:18081".parse().unwrap());
        assert_eq!(budget, Duration::from_secs(30));

        let (_, _, _, refresh, kinds) = federated.into_oidc_inputs();
        assert_eq!(refresh, Duration::from_secs(5));
        assert_eq!(
            kinds
                .into_iter()
                .map(TrustedKind::as_str)
                .collect::<Vec<_>>(),
            ["user", "device", "admin", "superAdmin"]
        );

        let (connection, writer, reader, readiness) = postgres.into_postgres_inputs();
        assert_eq!(connection.into_connect_options().1, 5432);
        assert_eq!(
            writer.into_writer_pool(),
            ("rss_settings_writer".to_owned(), 5)
        );
        assert_eq!(
            reader.into_reader_pool(),
            ("rss_settings_reader".to_owned(), 5)
        );
        assert_eq!(readiness, Duration::from_secs(5));

        let (_, _, _, key, allowlist, vault_readiness) = vault.into_vault_inputs();
        assert_eq!(key, "settings-config-value");
        assert_eq!(allowlist.len(), 1);
        assert_eq!(
            allowlist.into_iter().next().unwrap().into_store_binding().1,
            "vault"
        );
        assert_eq!(vault_readiness, Duration::from_secs(5));
    }
}
