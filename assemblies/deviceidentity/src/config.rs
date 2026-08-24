//! Closed schemaVersion=2 configuration capture.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use runtimeexec::config::{SecretDocument, SecretValue};
use schemars::JsonSchema;
use serde::Deserialize;

const SERVING_SECRET_BUNDLE_PATH: &str = "/var/run/rss/secrets/serving-secret-bundle";

struct SchemaVersionV2;

impl JsonSchema for SchemaVersionV2 {
    fn is_referenceable() -> bool {
        false
    }

    fn schema_name() -> String {
        "DeviceIdentitySchemaVersionV2".to_owned()
    }

    fn json_schema(_generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::Schema::Object(schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::Integer.into()),
            const_value: Some(serde_json::json!(2)),
            ..schemars::schema::SchemaObject::default()
        })
    }
}

struct LoopbackSocketAddress;

impl JsonSchema for LoopbackSocketAddress {
    fn schema_name() -> String {
        "LoopbackSocketAddress".to_owned()
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
pub(crate) struct DeviceIdentityConfig {
    #[schemars(with = "SchemaVersionV2")]
    schema_version: u8,
    pub(crate) listeners: Listeners,
    pub(crate) oidc: Oidc,
    pub(crate) identity: Identity,
    pub(crate) postgres: Postgres,
    pub(crate) mqtt: Mqtt,
    pub(crate) vault: Vault,
    pub(crate) csr: Csr,
    pub(crate) redis: Redis,
    pub(crate) workers: Workers,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Listeners {
    #[schemars(with = "LoopbackSocketAddress")]
    pub(crate) primary: std::net::SocketAddr,
    #[schemars(with = "LoopbackSocketAddress")]
    pub(crate) internal: std::net::SocketAddr,
    #[schemars(with = "LoopbackSocketAddress")]
    pub(crate) health: std::net::SocketAddr,
    #[schemars(range(min = 1, max = 300_000))]
    pub(crate) request_budget_ms: u64,
    #[schemars(length(min = 1))]
    pub(crate) internal_client_spiffe_allow_set: Vec<String>,
    pub(crate) trusted_proxy_cidrs: Vec<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Oidc {
    #[schemars(regex(pattern = "^https://"))]
    pub(crate) issuer: String,
    #[schemars(length(min = 1))]
    pub(crate) audience: String,
    pub(crate) jwks_path: PathBuf,
    #[schemars(range(min = 1, max = 300))]
    pub(crate) refresh_seconds: u64,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Postgres {
    #[schemars(length(min = 1))]
    pub(crate) host: String,
    #[schemars(range(min = 1))]
    pub(crate) port: u16,
    #[schemars(length(min = 1))]
    pub(crate) database: String,
    pub(crate) verify_mode: VerifyFull,
    pub(crate) ca_pem_path: PathBuf,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Mqtt {
    #[schemars(regex(pattern = "^mqtts://"))]
    pub(crate) url: String,
    pub(crate) ca_pem_path: PathBuf,
    #[schemars(range(min = 1, max = 86_400))]
    pub(crate) session_expiry_seconds: u64,
    #[schemars(regex(pattern = "^[0-9a-f]{64}$"))]
    pub(crate) broker_assertion_public_key_hex: String,
    #[schemars(length(min = 1))]
    pub(crate) scopes: Vec<MqttScope>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MqttScope {
    #[schemars(length(min = 1))]
    pub(crate) tenant: String,
    #[schemars(length(min = 1))]
    pub(crate) device: String,
    #[schemars(range(min = 1))]
    pub(crate) generation: u64,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Identity {
    #[schemars(length(min = 1))]
    pub(crate) tenant: String,
    #[schemars(length(min = 1))]
    pub(crate) holder_id: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Vault {
    #[schemars(regex(pattern = "^https://"))]
    pub(crate) url: String,
    #[schemars(length(min = 1))]
    pub(crate) mount: String,
    #[schemars(length(min = 1))]
    pub(crate) role: String,
    pub(crate) ca_pem_path: PathBuf,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Csr {
    #[schemars(regex(pattern = "^https://.*?/internal/v1/device-csr:resolve$"))]
    pub(crate) url: String,
    #[schemars(regex(pattern = "^spiffe://"))]
    pub(crate) local_spiffe_id: String,
    #[schemars(length(min = 1))]
    pub(crate) remote_spiffe_allow_set: Vec<String>,
    #[schemars(range(min = 65_536, max = 65_536))]
    pub(crate) max_pem_bytes: usize,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Redis {
    #[schemars(regex(pattern = "^rediss://"))]
    pub(crate) url: String,
    pub(crate) ca_pem_path: PathBuf,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Workers {
    #[schemars(range(min = 1, max = 300_000))]
    pub(crate) reconcile_ms: u64,
    #[schemars(range(min = 1, max = 300_000))]
    pub(crate) command_relay_ms: u64,
    #[schemars(range(min = 1, max = 300_000))]
    pub(crate) receipt_relay_ms: u64,
    #[schemars(range(min = 1, max = 300_000))]
    pub(crate) shutdown_ms: u64,
}

#[derive(Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum VerifyFull {
    VerifyFull,
}

pub(crate) struct CapturedConfig {
    pub(crate) config: DeviceIdentityConfig,
    pub(crate) secrets: ServingSecrets,
    pub(crate) build_metadata: Option<runtimeexec::inventory::BuildMetadata>,
}

pub(crate) struct ServingSecrets {
    pub(crate) pg_writer_username: String,
    pub(crate) pg_writer_password: zeroize::Zeroizing<String>,
    pub(crate) pg_reader_username: String,
    pub(crate) pg_reader_password: zeroize::Zeroizing<String>,
    pub(crate) pg_audit_username: String,
    pub(crate) pg_audit_password: zeroize::Zeroizing<String>,
    pub(crate) vault_token: zeroize::Zeroizing<String>,
    pub(crate) mqtt_client_id: String,
    pub(crate) mqtt_certificate_pem: diport::SecretMaterial,
    pub(crate) mqtt_private_key_pem: diport::SecretMaterial,
    pub(crate) command_idempotency_key: zeroize::Zeroizing<Vec<u8>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServingSecretBundle {
    pg_writer_username: SecretValue,
    pg_writer_password: SecretValue,
    pg_reader_username: SecretValue,
    pg_reader_password: SecretValue,
    pg_audit_username: SecretValue,
    pg_audit_password: SecretValue,
    vault_token: SecretValue,
    mqtt_client_id: SecretValue,
    mqtt_certificate_pem: SecretValue,
    mqtt_private_key_pem: SecretValue,
    command_idempotency_key: SecretValue,
}

pub(crate) fn capture(path: &Path) -> anyhow::Result<CapturedConfig> {
    let document =
        std::fs::read_to_string(path).map_err(|_| anyhow::anyhow!("read deviceidentity config"))?;
    let config = parse_document(&document)?;
    reject_provider_secret_environment()?;
    let document: SecretDocument =
        runtimeexec::config::read_secret_document(Path::new(SERVING_SECRET_BUNDLE_PATH))
            .map_err(|_| anyhow::anyhow!("read serving secret bundle"))?;
    let secrets: ServingSecretBundle = document
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid serving secret bundle"))?;
    let source_revision = std::env::var("RSS_BUILD_SOURCE_REVISION").ok();
    let image_digest = std::env::var("RSS_DECLARED_IMAGE_DIGEST").ok();
    let build_metadata = runtimeexec::inventory::BuildMetadata::from_optional(
        source_revision.as_deref(),
        image_digest.as_deref(),
    )
    .map_err(|_| anyhow::anyhow!("build revision and image digest must be a valid pair"))?;
    Ok(CapturedConfig {
        config,
        secrets: secrets.try_into()?,
        build_metadata,
    })
}

fn parse_document(document: &str) -> anyhow::Result<DeviceIdentityConfig> {
    let config: DeviceIdentityConfig = toml::from_str(document).map_err(|error| {
        anyhow::anyhow!(
            "invalid deviceidentity config at byte range {:?}: {}",
            error.span(),
            error.message()
        )
    })?;
    config.validate()?;
    Ok(config)
}

fn reject_provider_secret_environment() -> anyhow::Result<()> {
    const FORBIDDEN: &[&str] = &[
        "DATABASE_URL",
        "PGPASSWORD",
        "VAULT_TOKEN",
        "REDIS_URL",
        "MQTT_PASSWORD",
        "MQTT_PRIVATE_KEY",
        "RSS_DATABASE_URL",
        "RSS_PGPASSWORD",
        "RSS_VAULT_TOKEN",
        "RSS_REDIS_URL",
        "RSS_MQTT_PASSWORD",
        "RSS_MQTT_PRIVATE_KEY",
    ];
    anyhow::ensure!(
        FORBIDDEN
            .iter()
            .all(|name| std::env::var_os(name).is_none()),
        "provider secret environment is forbidden"
    );
    Ok(())
}

impl TryFrom<ServingSecretBundle> for ServingSecrets {
    type Error = anyhow::Error;

    fn try_from(value: ServingSecretBundle) -> Result<Self, Self::Error> {
        let required = [
            value.pg_writer_username.as_str(),
            value.pg_writer_password.as_str(),
            value.pg_reader_username.as_str(),
            value.pg_reader_password.as_str(),
            value.pg_audit_username.as_str(),
            value.pg_audit_password.as_str(),
            value.vault_token.as_str(),
            value.mqtt_client_id.as_str(),
            value.mqtt_certificate_pem.as_str(),
            value.mqtt_private_key_pem.as_str(),
            value.command_idempotency_key.as_str(),
        ];
        anyhow::ensure!(
            required.iter().all(|item| !item.is_empty()),
            "empty serving secret"
        );
        let command_idempotency_key =
            zeroize::Zeroizing::new(value.command_idempotency_key.as_bytes().to_vec());
        anyhow::ensure!(
            command_idempotency_key.len() >= 32,
            "invalid command idempotency key"
        );
        Ok(Self {
            pg_writer_username: value.pg_writer_username.into_zeroizing().to_string(),
            pg_writer_password: value.pg_writer_password.into_zeroizing(),
            pg_reader_username: value.pg_reader_username.into_zeroizing().to_string(),
            pg_reader_password: value.pg_reader_password.into_zeroizing(),
            pg_audit_username: value.pg_audit_username.into_zeroizing().to_string(),
            pg_audit_password: value.pg_audit_password.into_zeroizing(),
            vault_token: value.vault_token.into_zeroizing(),
            mqtt_client_id: value.mqtt_client_id.into_zeroizing().to_string(),
            mqtt_certificate_pem: diport::SecretMaterial::new(
                value.mqtt_certificate_pem.as_bytes().to_vec(),
            ),
            mqtt_private_key_pem: diport::SecretMaterial::new(
                value.mqtt_private_key_pem.as_bytes().to_vec(),
            ),
            command_idempotency_key,
        })
    }
}

impl DeviceIdentityConfig {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.schema_version == 2, "unsupported config schema");
        let VerifyFull::VerifyFull = self.postgres.verify_mode;
        for address in [
            self.listeners.primary,
            self.listeners.internal,
            self.listeners.health,
        ] {
            anyhow::ensure!(
                address.ip().is_loopback() && address.port() != 0,
                "listeners: loopback address with non-zero port required"
            );
        }
        anyhow::ensure!(
            [
                self.listeners.primary,
                self.listeners.internal,
                self.listeners.health
            ]
            .into_iter()
            .collect::<BTreeSet<_>>()
            .len()
                == 3,
            "listeners: addresses must be unique"
        );
        let proxy_json = serde_json::to_string(&self.listeners.trusted_proxy_cidrs)
            .map_err(|_| anyhow::anyhow!("listeners.trustedProxyCidrs: invalid"))?;
        httpserve::TrustedProxyConfig::try_from_json(Some(&proxy_json))
            .map_err(|_| anyhow::anyhow!("listeners.trustedProxyCidrs: invalid"))?;
        anyhow::ensure!(
            !self.listeners.internal_client_spiffe_allow_set.is_empty()
                && self
                    .listeners
                    .internal_client_spiffe_allow_set
                    .iter()
                    .all(|id| id.starts_with("spiffe://"))
                && all_unique(&self.listeners.internal_client_spiffe_allow_set),
            "listeners.internalClientSpiffeAllowSet: invalid"
        );
        anyhow::ensure!(
            rss_request_context::TenantId::parse(&self.identity.tenant).is_ok()
                && !self.identity.holder_id.trim().is_empty()
                && self.mqtt.broker_assertion_public_key_hex.len() == 64
                && !self.mqtt.scopes.is_empty()
                && self
                    .mqtt
                    .broker_assertion_public_key_hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && (1..=86_400).contains(&self.mqtt.session_expiry_seconds)
                && self.mqtt.scopes.iter().all(|scope| {
                    rss_request_context::TenantId::parse(&scope.tenant).is_ok()
                        && ids::DeviceId::parse(&scope.device).is_ok()
                        && scope.generation > 0
                }),
            "identity/mqtt: invalid binding"
        );
        anyhow::ensure!(
            (1..=300_000).contains(&self.listeners.request_budget_ms),
            "listeners.requestBudgetMs: invalid"
        );
        anyhow::ensure!(
            self.oidc.issuer.starts_with("https://")
                && !self.oidc.audience.trim().is_empty()
                && !self.oidc.jwks_path.as_os_str().is_empty()
                && (1..=300).contains(&self.oidc.refresh_seconds),
            "oidc: invalid configuration"
        );
        anyhow::ensure!(
            !self.postgres.host.trim().is_empty()
                && self.postgres.port != 0
                && !self.postgres.database.trim().is_empty()
                && non_empty_path(&self.postgres.ca_pem_path),
            "postgres: invalid configuration"
        );
        mqtt::MqttsEndpoint::parse(&self.mqtt.url)
            .map_err(|_| anyhow::anyhow!("mqtt.url: invalid TLS endpoint"))?;
        secure::DomainHttpEndpoint::parse(&self.vault.url)
            .map_err(|_| anyhow::anyhow!("vault.url: invalid HTTPS endpoint"))?;
        secure::DomainHttpEndpoint::parse(&self.csr.url)
            .map_err(|_| anyhow::anyhow!("csr.url: invalid HTTPS endpoint"))?;
        secure::RedisEndpoint::parse(
            self.redis.url.clone(),
            secure::PlaintextEndpointPolicy::Deny,
        )
        .map_err(|_| anyhow::anyhow!("redis.url: invalid TLS endpoint or userinfo"))?;
        let redis_url = url::Url::parse(&self.redis.url)
            .map_err(|_| anyhow::anyhow!("redis.url: invalid TLS endpoint or userinfo"))?;
        anyhow::ensure!(
            redis_url.username().is_empty() && redis_url.password().is_none(),
            "redis.url: userinfo is forbidden"
        );
        anyhow::ensure!(
            self.csr.url.ends_with("/internal/v1/device-csr:resolve"),
            "csr.url: exact resolve path required"
        );
        anyhow::ensure!(
            non_empty_path(&self.mqtt.ca_pem_path)
                && non_empty_path(&self.vault.ca_pem_path)
                && non_empty_path(&self.redis.ca_pem_path)
                && !self.vault.mount.trim().is_empty()
                && !self.vault.role.trim().is_empty(),
            "provider paths/identities: invalid"
        );
        anyhow::ensure!(
            authn::SpiffeId::parse(&self.csr.local_spiffe_id).is_ok()
                && !self.csr.remote_spiffe_allow_set.is_empty()
                && self
                    .csr
                    .remote_spiffe_allow_set
                    .iter()
                    .all(|id| authn::SpiffeId::parse(id).is_ok())
                && all_unique(&self.csr.remote_spiffe_allow_set),
            "csr SPIFFE policy: invalid"
        );
        anyhow::ensure!(
            self.csr.max_pem_bytes == diport::MAX_PKI_CSR_BYTES,
            "csr.maxPemBytes: closed limit mismatch"
        );
        anyhow::ensure!(
            [
                self.workers.reconcile_ms,
                self.workers.command_relay_ms,
                self.workers.receipt_relay_ms,
                self.workers.shutdown_ms,
            ]
            .into_iter()
            .all(|value| (1..=300_000).contains(&value)),
            "workers: interval/budget out of range"
        );
        Ok(())
    }

    pub(crate) fn oidc_refresh(&self) -> Duration {
        Duration::from_secs(self.oidc.refresh_seconds)
    }

    pub(crate) fn trusted_proxy_config(&self) -> anyhow::Result<httpserve::TrustedProxyConfig> {
        let raw = serde_json::to_string(&self.listeners.trusted_proxy_cidrs)
            .map_err(|_| anyhow::anyhow!("listeners.trustedProxyCidrs: invalid"))?;
        httpserve::TrustedProxyConfig::try_from_json(Some(&raw))
            .map_err(|_| anyhow::anyhow!("listeners.trustedProxyCidrs: invalid"))
    }
}

fn non_empty_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
}

fn all_unique(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

#[cfg(test)]
fn schema_bytes() -> Vec<u8> {
    let schema = schemars::r#gen::SchemaSettings::draft07()
        .into_generator()
        .into_root_schema_for::<DeviceIdentityConfig>();
    let Ok(mut bytes) = serde_json::to_vec_pretty(&schema) else {
        unreachable!("schemars RootSchema serialization is infallible")
    };
    bytes.push(b'\n');
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = include_str!("../deviceidentity.example.toml");

    #[test]
    fn committed_schema_is_generated_from_parser_types() {
        assert_eq!(schema_bytes(), include_bytes!("../config.schema.json"));
    }

    #[test]
    #[ignore = "maintenance helper for refreshing the committed generated schema"]
    fn refresh_committed_schema() {
        std::fs::write(
            concat!(env!("CARGO_MANIFEST_DIR"), "/config.schema.json"),
            schema_bytes(),
        )
        .expect("write generated config schema");
    }

    #[test]
    fn example_is_the_closed_schema_v2_shape() {
        assert!(parse_document(VALID).is_ok());
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../config.schema.json")).expect("schema JSON");
        let validator = jsonschema::draft7::options()
            .build(&schema)
            .expect("schema compiles");
        let value: toml::Value = toml::from_str(VALID).expect("example TOML");
        let value = serde_json::to_value(value).expect("TOML projects to JSON");
        assert!(validator.is_valid(&value));
    }

    #[test]
    fn unknown_duplicate_missing_and_plaintext_inputs_fail_before_bind() {
        assert!(parse_document(&format!("{VALID}\nunknown = true\n")).is_err());
        assert!(
            parse_document(
                &VALID.replace("schemaVersion = 2", "schemaVersion = 2\nschemaVersion = 2",)
            )
            .is_err()
        );
        assert!(parse_document(&VALID.replace("audience = \"rss-deviceidentity\"\n", "")).is_err());
        assert!(
            parse_document(&VALID.replace(
                "https://vault.example.invalid",
                "http://vault.example.invalid",
            ))
            .is_err()
        );
    }

    #[test]
    fn old_schema_and_non_loopback_listener_are_rejected() {
        assert!(parse_document(&VALID.replace("schemaVersion = 2", "schemaVersion = 1")).is_err());
        assert!(parse_document(&VALID.replace("127.0.0.1:8080", "0.0.0.0:8080")).is_err());
        for port in ["65536", "99999"] {
            let document = VALID.replace("127.0.0.1:8080", &format!("127.0.0.1:{port}"));
            assert!(parse_document(&document).is_err());
            let value: toml::Value = toml::from_str(&document).expect("TOML fixture");
            let value = serde_json::to_value(value).expect("TOML projects to JSON");
            let schema: serde_json::Value =
                serde_json::from_slice(&schema_bytes()).expect("generated schema");
            let validator = jsonschema::draft7::options()
                .build(&schema)
                .expect("generated schema compiles");
            assert!(!validator.is_valid(&value));
        }
    }

    #[test]
    fn all_worker_bounds_and_secret_bearing_redis_urls_fail_closed() {
        for field in [
            "reconcileMs",
            "commandRelayMs",
            "receiptRelayMs",
            "shutdownMs",
        ] {
            assert!(
                parse_document(
                    &VALID.replace(&format!("{field} = 30000"), &format!("{field} = 0"))
                )
                .is_err(),
                "{field} accepted zero"
            );
        }
        assert!(
            parse_document(&VALID.replace(
                "rediss://redis.example.invalid:6379",
                "rediss://user:secret@redis.example.invalid:6379",
            ))
            .is_err()
        );
    }
}
