use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context as _;
use base64::Engine as _;
use diport::KeyName;
use vault::{
    TenantStoreAllowlist, VaultKeyProvider, VaultRuntimeDeps, VaultSecretResolver, VaultSigner,
};

use crate::EnvSecret;
use crate::config::SnapshotConfig;

// ── Vault secret resolver wiring ─────────────────────────────────────────────────────────────

/// 固定 Vault 请求超时；当前 runtime 配置目录不提供该值的动态覆盖。
pub(crate) const DEFAULT_VAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// One captured Vault generation. Private fields, a snapshot-only production constructor, and
/// consuming exits keep the endpoint, token, Transit mount, TLS roots, and settings key name from
/// being mixed across captures. Each consuming exit validates its Vault adapter before parsing the
/// settings key name so the actual failing provider boundary owns error classification.
pub(crate) struct VaultRuntimeConfig {
    client: reqwest::Client,
    addr: String,
    token: EnvSecret,
    transit_mount: String,
    settings_key_name: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum VaultRuntimeConfigError {
    #[error("vault client configuration is invalid: {0}")]
    VaultClientConfig(#[source] anyhow::Error),
    #[error("settings config value key name is invalid: {0}")]
    SettingsKeyNameConfig(#[source] anyhow::Error),
}

struct VaultConfigValues<'a> {
    addr: Option<String>,
    token: Option<&'a str>,
    transit_mount: Option<String>,
    ca_cert_pem_path: Option<&'a str>,
    settings_key_name: Option<&'a str>,
}

impl std::fmt::Debug for VaultRuntimeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VaultRuntimeConfig(<redacted>)")
    }
}

impl VaultRuntimeConfig {
    /// Capture the complete Vault/settings generation before constructing any adapter. The CA
    /// bundle is read and parsed here exactly once; both runtime adapters later receive clones of
    /// this single configured client handle.
    pub(crate) fn from_snapshot(
        config: SnapshotConfig<'_>,
    ) -> Result<Self, VaultRuntimeConfigError> {
        Self::from_values(VaultConfigValues {
            addr: config.value(VAULT_ADDR_ENV).map(str::to_owned),
            token: config.value(VAULT_TOKEN_ENV),
            transit_mount: config.value(VAULT_TRANSIT_MOUNT_ENV).map(str::to_owned),
            ca_cert_pem_path: config.value(VAULT_CA_CERT_PEM_PATH_ENV),
            settings_key_name: config.value(SETTINGS_CONFIG_VALUE_KEY_NAME_ENV),
        })
    }

    fn from_values(values: VaultConfigValues<'_>) -> Result<Self, VaultRuntimeConfigError> {
        let addr = required_value(values.addr, VAULT_ADDR_ENV)
            .map_err(VaultRuntimeConfigError::VaultClientConfig)?;
        let token = EnvSecret::required_value(values.token, VAULT_TOKEN_ENV)
            .map_err(VaultRuntimeConfigError::VaultClientConfig)?;
        let transit_mount = required_value(values.transit_mount, VAULT_TRANSIT_MOUNT_ENV)
            .map_err(VaultRuntimeConfigError::VaultClientConfig)?;
        let client = build_vault_tls_client_from_value(values.ca_cert_pem_path)
            .map_err(VaultRuntimeConfigError::VaultClientConfig)?;
        Ok(Self {
            client,
            addr,
            token,
            transit_mount,
            settings_key_name: values.settings_key_name.map(str::to_owned),
        })
    }

    /// Consume this generation into the serving Vault capability bundle and its bound settings
    /// key. The only secret copy is transferred immediately into the resolver's zeroizing owner;
    /// the original allocation is transferred into the key provider's zeroizing owner.
    pub(crate) fn into_runtime(
        self,
    ) -> Result<(VaultRuntimeDeps, KeyName), VaultRuntimeConfigError> {
        let Self {
            client,
            addr,
            token,
            transit_mount,
            settings_key_name,
        } = self;
        let stores =
            empty_vault_store_allowlist().map_err(VaultRuntimeConfigError::VaultClientConfig)?;
        warn_vault_startup_security(&stores);
        let resolver = VaultSecretResolver::new(
            client.clone(),
            addr.clone(),
            token.copy_secret_allocation(),
            DEFAULT_VAULT_TIMEOUT,
            stores,
        )
        .map_err(|e| {
            VaultRuntimeConfigError::VaultClientConfig(anyhow::anyhow!(
                "vault resolver config error: {e}"
            ))
        })?;
        let key_provider = VaultKeyProvider::new(
            client,
            addr,
            token.transfer_secret_allocation(),
            transit_mount,
            DEFAULT_VAULT_TIMEOUT,
        )
        .map_err(|e| {
            VaultRuntimeConfigError::VaultClientConfig(anyhow::anyhow!(
                "vault key provider config error: {e}"
            ))
        })?;
        let settings_key_name =
            settings_config_value_key_name_from_value(settings_key_name.as_deref())
                .map_err(VaultRuntimeConfigError::SettingsKeyNameConfig)?;
        Ok((
            VaultRuntimeDeps::new(resolver, key_provider),
            settings_key_name,
        ))
    }

    /// Consume this generation for settings maintenance without consulting ambient process state.
    pub(crate) fn into_settings_key_provider(
        self,
    ) -> Result<(VaultKeyProvider, KeyName), VaultRuntimeConfigError> {
        let Self {
            client,
            addr,
            token,
            transit_mount,
            settings_key_name,
        } = self;
        let key_provider = VaultKeyProvider::new(
            client,
            addr,
            token.transfer_secret_allocation(),
            transit_mount,
            DEFAULT_VAULT_TIMEOUT,
        )
        .map_err(|e| {
            VaultRuntimeConfigError::VaultClientConfig(anyhow::anyhow!(
                "vault key provider config error: {e}"
            ))
        })?;
        let settings_key_name =
            settings_config_value_key_name_from_value(settings_key_name.as_deref())
                .map_err(VaultRuntimeConfigError::SettingsKeyNameConfig)?;
        Ok((key_provider, settings_key_name))
    }
}

fn required_value(value: Option<String>, name: &'static str) -> anyhow::Result<String> {
    value.ok_or_else(|| anyhow::anyhow!("missing required env var: {name}"))
}

fn settings_config_value_key_name_from_value(raw: Option<&str>) -> anyhow::Result<KeyName> {
    let raw = raw.ok_or_else(|| {
        anyhow::anyhow!("missing required env var: {SETTINGS_CONFIG_VALUE_KEY_NAME_ENV}")
    })?;
    KeyName::try_new(raw.to_owned())
        .map_err(|e| anyhow::anyhow!("{SETTINGS_CONFIG_VALUE_KEY_NAME_ENV} is invalid: {e}"))
}

/// Integration-only explicit-values seam. Production callers must use
/// [`VaultRuntimeConfig::from_snapshot`].
#[cfg(any(test, feature = "integration"))]
pub(crate) fn build_vault_runtime_from_values(
    addr: String,
    token: String,
    transit_mount: String,
    settings_key_name: String,
) -> anyhow::Result<(VaultRuntimeDeps, KeyName)> {
    let config = VaultRuntimeConfig::from_values(VaultConfigValues {
        addr: Some(addr),
        token: Some(token.as_str()),
        transit_mount: Some(transit_mount),
        ca_cert_pem_path: None,
        settings_key_name: Some(settings_key_name.as_str()),
    })?;
    Ok(config.into_runtime()?)
}

/// 启动时安全警告（pre-GA）：vault `TenantStoreAllowlist` 为空 ⇒ 所有 secret resolve fail-closed Forbidden。
/// （TLS 已由 [`build_vault_tls_client`] rustls 接线，#1252，不再警告 no-TLS-backend。）
fn warn_vault_startup_security(stores: &TenantStoreAllowlist) {
    if stores.is_empty() {
        tracing::warn!(
            reason = "empty-allowlist",
            "vault TenantStoreAllowlist is empty: all secret resolve calls will return Forbidden (fail-closed); populate allowlist for production (#1272)"
        );
    }
}

/// 构造 vault HTTP client（rustls + ring + webpki-roots，#1252）：reqwest `rustls-tls-webpki-roots` feature
/// 选 ring crypto provider（`__rustls-ring`，禁 aws-lc，与 deny.toml openssl/aws-lc ban 一致）+ Mozilla 根 CA。
/// secret resolver 与 Transit `Signer` 共用——二者均经 https 访问 vault（signer 在 login/refresh 热路径真实签发）。
pub(crate) fn build_vault_tls_client_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<reqwest::Client> {
    let ca_path = get(VAULT_CA_CERT_PEM_PATH_ENV);
    build_vault_tls_client_from_value(ca_path.as_deref())
}

fn build_vault_tls_client_from_value(ca_path: Option<&str>) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().use_rustls_tls();
    if let Some(path) = ca_path {
        let trimmed = path.trim();
        anyhow::ensure!(
            !trimmed.is_empty(),
            "{VAULT_CA_CERT_PEM_PATH_ENV} must not be empty"
        );
        let pem = fs::read(trimmed).with_context(|| {
            format!("read {VAULT_CA_CERT_PEM_PATH_ENV} PEM bundle for Vault TLS")
        })?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem).with_context(|| {
            format!("{VAULT_CA_CERT_PEM_PATH_ENV} must point to a PEM CA bundle")
        })?;
        anyhow::ensure!(
            !certs.is_empty(),
            "{VAULT_CA_CERT_PEM_PATH_ENV} must contain at least one PEM CA certificate"
        );
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }
    builder.build().context("build vault rustls TLS client")
}

fn empty_vault_store_allowlist() -> anyhow::Result<TenantStoreAllowlist> {
    // #1272 owns per-store mount/prefix population; that authorization allowlist is independent
    // from this process-configuration snapshot migration.
    TenantStoreAllowlist::new(std::iter::empty())
        .map_err(|e| anyhow::anyhow!("vault store allowlist config error: {e}"))
}

/// vault base URL env（resolver + signer 复用，fail-fast 必填）。
pub(crate) const VAULT_ADDR_ENV: &str = "RSS_VAULT_ADDR";
/// vault token env（同上）。
pub(crate) const VAULT_TOKEN_ENV: &str = "RSS_VAULT_TOKEN";
pub(crate) const VAULT_TRANSIT_MOUNT_ENV: &str = "RSS_VAULT_TRANSIT_MOUNT";
pub(crate) const SETTINGS_CONFIG_VALUE_KEY_NAME_ENV: &str = "RSS_SETTINGS_CONFIG_VALUE_KEY_NAME";
/// Optional PEM CA cert path for private/dev Vault HTTPS endpoints.
pub(crate) const VAULT_CA_CERT_PEM_PATH_ENV: &str = "RSS_VAULT_CA_CERT_PEM_PATH";
const RSS_ACCESS_TOKEN_KEY_ID_ENV: &str = crate::config::RSS_ACCESS_TOKEN_SIGNING_ACTIVE_KEY_ID_ENV;

/// 从注入的配置读取器构造 vault `VaultSigner`（Transit ES256 签 access JWT）。
///
/// - `allow_http=false`（生产）：`VaultSigner::new`（HTTPS-only，fail-fast 拒非 https URL）+ rustls client。
/// - `allow_http=true`（集成测试 hermetic mock）：`VaultSigner::new_allow_http`（接受 http wiremock 地址）+
///   同 rustls client（兼处理 http 连接，保持 client 构造一致）。
///
/// 两路均用 `Jws` marshaling：JWT/JWS 需 raw `r‖s`（vault 默认 asn1=DER 会让 oidc 验签失败，OIDC-ALG-KEYPATH-01）。
pub(crate) fn build_vault_signer_with(
    get: impl Fn(&str) -> Option<String>,
    allow_http: bool,
) -> anyhow::Result<VaultSigner> {
    let addr = get(VAULT_ADDR_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {VAULT_ADDR_ENV}"))?;
    let token = get(VAULT_TOKEN_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {VAULT_TOKEN_ENV}"))?;
    let mount = get(VAULT_TRANSIT_MOUNT_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {VAULT_TRANSIT_MOUNT_ENV}"))?;
    let client = build_vault_tls_client_from(&get)?;
    if allow_http {
        VaultSigner::new_allow_http(
            client,
            addr,
            token,
            mount,
            DEFAULT_VAULT_TIMEOUT,
            vault::SignatureMarshaling::Jws,
        )
    } else {
        VaultSigner::new(
            client,
            addr,
            token,
            mount,
            DEFAULT_VAULT_TIMEOUT,
            vault::SignatureMarshaling::Jws,
        )
    }
    .map_err(|e| anyhow::anyhow!("vault signer config error: {e}"))
}

const RSS_ACCESS_JWKS_CLI: &str = "rss-access-jwks";
const RSS_ACCESS_JWKS_EXPORT_VAULT_TRANSIT_CLI: &str = "export-vault-transit";
const RSS_ACCESS_TOKEN_JWKS_PATH_ENV: &str = "RSS_ACCESS_TOKEN_JWKS_PATH";

pub fn is_rss_access_jwks_export_command(args: &[String]) -> bool {
    matches!(
        args,
        [cmd, sub, ..]
            if cmd == RSS_ACCESS_JWKS_CLI
                && sub == RSS_ACCESS_JWKS_EXPORT_VAULT_TRANSIT_CLI
    )
}

pub async fn run_rss_access_jwks_export_command(
    args: &[String],
    runtime_inputs: &crate::OperatorRuntimeInputs,
) -> anyhow::Result<()> {
    run_rss_access_jwks_export_command_from(
        args,
        |name| runtime_inputs.config().value(name).map(str::to_owned),
        false,
    )
    .await
}

async fn run_rss_access_jwks_export_command_from(
    args: &[String],
    get: impl Fn(&str) -> Option<String>,
    allow_http: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        is_rss_access_jwks_export_command(args),
        "usage: rss rss-access-jwks export-vault-transit [--out <path>]"
    );
    let out = rss_access_jwks_export_output_path(args, &get)?;
    let addr = get(VAULT_ADDR_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {VAULT_ADDR_ENV}"))?;
    let token = get(VAULT_TOKEN_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {VAULT_TOKEN_ENV}"))?;
    let mount = get(VAULT_TRANSIT_MOUNT_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {VAULT_TRANSIT_MOUNT_ENV}"))?;
    let export_kids = rss_access_jwks_export_kids(&get)?;
    let client = build_vault_tls_client_from(&get)?;
    let mut keys = Vec::with_capacity(export_kids.len());
    for kid in &export_kids {
        let url = vault_transit_key_metadata_url(&addr, &mount, kid, allow_http)?;
        let response = client
            .get(url)
            .header("X-Vault-Token", token.trim())
            .timeout(DEFAULT_VAULT_TIMEOUT)
            .send()
            .await
            .with_context(|| "read Vault Transit key metadata for a configured signing kid")?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .context("read Vault Transit key metadata response")?;
        anyhow::ensure!(
            status.is_success(),
            "Vault Transit key metadata request returned non-success status for a configured signing kid"
        );
        keys.push(vault_transit_key_response_to_rss_access_jwk(kid, &body)?);
    }
    let jwks = serialize_rss_access_jwks(&keys)?;
    write_jwks_atomic(&out, &jwks)
        .with_context(|| format!("write RSS access-token JWKS to {}", out.display()))
}

/// Kids that must appear in the exported JWKS: active + optional next + all retiring.
fn rss_access_jwks_export_kids(
    get: &impl Fn(&str) -> Option<String>,
) -> anyhow::Result<Vec<String>> {
    use crate::config::{
        RSS_ACCESS_TOKEN_SIGNING_ACTIVE_KEY_ID_ENV, RSS_ACCESS_TOKEN_SIGNING_NEXT_KEY_ID_ENV,
        RSS_ACCESS_TOKEN_SIGNING_RETIRING_ENV, parse_signing_retiring_raw,
    };

    let active = get(RSS_ACCESS_TOKEN_SIGNING_ACTIVE_KEY_ID_ENV)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "missing required env var: {RSS_ACCESS_TOKEN_SIGNING_ACTIVE_KEY_ID_ENV}"
            )
        })?;
    let active = active.trim().to_owned();

    let mut kids = vec![active];
    let mut seen = std::collections::BTreeSet::from([kids[0].clone()]);

    if let Some(next) = get(RSS_ACCESS_TOKEN_SIGNING_NEXT_KEY_ID_ENV)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
    {
        anyhow::ensure!(
            seen.insert(next.clone()),
            "{RSS_ACCESS_TOKEN_SIGNING_NEXT_KEY_ID_ENV} must not duplicate active or retiring kids"
        );
        kids.push(next);
    }

    if let Some(raw) = get(RSS_ACCESS_TOKEN_SIGNING_RETIRING_ENV)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
    {
        for (kid, _) in parse_signing_retiring_raw(&raw)? {
            anyhow::ensure!(
                seen.insert(kid.clone()),
                "{RSS_ACCESS_TOKEN_SIGNING_RETIRING_ENV} kids must be unique across active/next/retiring"
            );
            kids.push(kid);
        }
    }

    Ok(kids)
}

fn rss_access_jwks_export_output_path(
    args: &[String],
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<PathBuf> {
    let mut out = None;
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--out" => {
                anyhow::ensure!(out.is_none(), "--out may only be specified once");
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| anyhow::anyhow!("--out requires a path"))?;
                anyhow::ensure!(!value.trim().is_empty(), "--out requires a non-empty path");
                out = Some(PathBuf::from(value.trim()));
            }
            other => {
                anyhow::bail!("unknown rss-access-jwks export-vault-transit argument: {other}")
            }
        }
        index += 1;
    }
    if let Some(out) = out {
        return Ok(out);
    }
    let path = get(RSS_ACCESS_TOKEN_JWKS_PATH_ENV)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("missing required env var: {RSS_ACCESS_TOKEN_JWKS_PATH_ENV}")
        })?;
    Ok(PathBuf::from(path.trim()))
}

fn vault_transit_key_metadata_url(
    addr: &str,
    mount: &str,
    key_id: &str,
    allow_http: bool,
) -> anyhow::Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(addr.trim()).context("parse Vault base URL")?;
    match url.scheme() {
        "https" => {}
        "http" if allow_http => {}
        _ => anyhow::bail!("Vault base URL must use https"),
    }
    let mount_segments = vault_path_segments(mount, VAULT_TRANSIT_MOUNT_ENV)?;
    let key_segments = vault_path_segments(key_id, RSS_ACCESS_TOKEN_KEY_ID_ENV)?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|()| anyhow::anyhow!("Vault base URL cannot be a base for path segments"))?;
        segments
            .pop_if_empty()
            .push("v1")
            .extend(mount_segments.iter().map(String::as_str))
            .push("keys")
            .extend(key_segments.iter().map(String::as_str));
    }
    Ok(url)
}

fn vault_path_segments(raw: &str, label: &str) -> anyhow::Result<Vec<String>> {
    let trimmed = raw.trim().trim_matches('/');
    anyhow::ensure!(!trimmed.is_empty(), "{label} must not be empty");
    let mut segments = Vec::new();
    for segment in trimmed.split('/') {
        anyhow::ensure!(
            !segment.is_empty() && segment != "." && segment != "..",
            "{label} contains an invalid path segment"
        );
        segments.push(segment.to_owned());
    }
    Ok(segments)
}

#[derive(serde::Deserialize)]
struct VaultTransitKeyResponse {
    data: VaultTransitKeyData,
}

#[derive(serde::Deserialize)]
struct VaultTransitKeyData {
    latest_version: Option<u64>,
    keys: BTreeMap<String, VaultTransitKeyVersion>,
}

#[derive(serde::Deserialize)]
struct VaultTransitKeyVersion {
    public_key: Option<String>,
}

fn vault_transit_key_response_to_rss_access_jwks(
    kid: &str,
    body: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let jwk = vault_transit_key_response_to_rss_access_jwk(kid, body)?;
    serialize_rss_access_jwks(&[jwk])
}

fn vault_transit_key_response_to_rss_access_jwk(
    kid: &str,
    body: &[u8],
) -> anyhow::Result<serde_json::Value> {
    let response: VaultTransitKeyResponse =
        serde_json::from_slice(body).context("parse Vault Transit key metadata response")?;
    let public_key_pem = current_vault_public_key(&response.data)?;
    es256_public_key_pem_to_rss_access_jwk(kid, public_key_pem)
}

fn current_vault_public_key(data: &VaultTransitKeyData) -> anyhow::Result<&str> {
    let version = match data.latest_version {
        Some(version) => version.to_string(),
        None => data
            .keys
            .keys()
            .filter_map(|raw| raw.parse::<u64>().ok().map(|version| (version, raw)))
            .max_by_key(|(version, _)| *version)
            .map(|(_, raw)| raw.to_owned())
            .ok_or_else(|| anyhow::anyhow!("Vault Transit key metadata has no key versions"))?,
    };
    data.keys
        .get(&version)
        .and_then(|entry| entry.public_key.as_deref())
        .filter(|pem| !pem.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("Vault Transit current key version is missing public_key"))
}

fn es256_public_key_pem_to_rss_access_jwk(
    kid: &str,
    public_key_pem: &str,
) -> anyhow::Result<serde_json::Value> {
    use p256::elliptic_curve::sec1::ToEncodedPoint as _;
    use p256::pkcs8::DecodePublicKey as _;

    let public_key = p256::PublicKey::from_public_key_pem(public_key_pem)
        .map_err(|_| anyhow::anyhow!("decode P-256 public key"))?;
    let point = public_key.to_encoded_point(false);
    let x = point
        .x()
        .ok_or_else(|| anyhow::anyhow!("P-256 public key missing x coordinate"))?;
    let y = point
        .y()
        .ok_or_else(|| anyhow::anyhow!("P-256 public key missing y coordinate"))?;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    Ok(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "kid": kid,
        "alg": "ES256",
        "use": "sig",
        "x": b64.encode(x),
        "y": b64.encode(y)
    }))
}

fn serialize_rss_access_jwks(keys: &[serde_json::Value]) -> anyhow::Result<Vec<u8>> {
    let jwks = serde_json::json!({ "keys": keys });
    serde_json::to_vec_pretty(&jwks).context("serialize RSS access-token JWKS")
}

fn write_jwks_atomic(path: &Path, jwks: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("RSS access-token JWKS output path must have a parent directory")
        })?;
    fs::create_dir_all(parent).context("create RSS access-token JWKS output directory")?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            anyhow::anyhow!("RSS access-token JWKS output path must end in a file name")
        })?;
    let tmp = parent.join(format!(".{file_name}.tmp"));
    fs::write(&tmp, jwks).context("write temporary RSS access-token JWKS")?;
    fs::rename(&tmp, path).context("rename temporary RSS access-token JWKS into place")
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEMP_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    struct GetterSource<F>(F);

    impl<F> crate::config::RuntimeConfigSource for GetterSource<F>
    where
        F: Fn(&str) -> Option<String>,
    {
        fn read(
            &mut self,
            key: &crate::config::RuntimeConfigKey,
        ) -> crate::config::CapturedConfigValue {
            (self.0)(key.as_str()).map_or(crate::config::CapturedConfigValue::Missing, |value| {
                crate::config::CapturedConfigValue::Present(secure::SecretText::from_string(value))
            })
        }
    }

    #[allow(clippy::expect_used)]
    fn snapshot_from_get(
        get: impl Fn(&str) -> Option<String>,
    ) -> crate::config::RuntimeConfigSnapshot {
        crate::config::RuntimeConfigSnapshot::capture_test(GetterSource(get))
            .expect("closed test catalog")
    }

    fn valid_vault_value(name: &str) -> Option<String> {
        match name {
            VAULT_ADDR_ENV => Some("https://vault.snapshot.test:8200".to_owned()),
            VAULT_TOKEN_ENV => Some("vault-snapshot-token".to_owned()),
            VAULT_TRANSIT_MOUNT_ENV => Some("team/transit".to_owned()),
            SETTINGS_CONFIG_VALUE_KEY_NAME_ENV => Some("settings-snapshot-key".to_owned()),
            _ => None,
        }
    }

    fn unique_temp_path(name: &str) -> std::path::PathBuf {
        let seq = TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!("rss-runtime-{}-{seq}-{name}", std::process::id()))
    }

    #[allow(clippy::expect_used)]
    fn write_temp_file(name: &str, contents: &[u8]) -> std::path::PathBuf {
        let path = unique_temp_path(name);
        std::fs::write(&path, contents).expect("write temp file");
        path
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn runtime_infra_vault_snapshot_builds_runtime_and_settings_consumers() {
        let snapshot = snapshot_from_get(valid_vault_value);
        let config =
            VaultRuntimeConfig::from_snapshot(snapshot.view()).expect("valid snapshot config");
        assert_eq!(format!("{config:?}"), "VaultRuntimeConfig(<redacted>)");
        let (runtime, key_name) = config.into_runtime().expect("valid runtime adapters");
        assert_eq!(runtime.runtime_resources().len(), 2);
        assert_eq!(key_name.as_str(), "settings-snapshot-key");

        let maintenance =
            VaultRuntimeConfig::from_snapshot(snapshot.view()).expect("valid maintenance config");
        let (_provider, key_name) = maintenance
            .into_settings_key_provider()
            .expect("valid settings key provider");
        assert_eq!(key_name.as_str(), "settings-snapshot-key");

        let (runtime, key_name) = build_vault_runtime_from_values(
            "https://vault.explicit.test:8200".to_owned(),
            "vault-explicit-token".to_owned(),
            "transit".to_owned(),
            "settings-explicit-key".to_owned(),
        )
        .expect("valid explicit integration values");
        assert_eq!(runtime.runtime_resources().len(), 2);
        assert_eq!(key_name.as_str(), "settings-explicit-key");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn runtime_infra_vault_snapshot_missing_values_fail_in_mapping_order() {
        for (missing, expected) in [
            (VAULT_ADDR_ENV, VAULT_ADDR_ENV),
            (VAULT_TOKEN_ENV, VAULT_TOKEN_ENV),
            (VAULT_TRANSIT_MOUNT_ENV, VAULT_TRANSIT_MOUNT_ENV),
        ] {
            let snapshot = snapshot_from_get(|name| {
                if name == missing {
                    None
                } else {
                    valid_vault_value(name)
                }
            });
            let error = VaultRuntimeConfig::from_snapshot(snapshot.view())
                .expect_err("missing required snapshot value must fail");
            assert!(
                format!("{error:#}").contains(expected),
                "error must identify {expected}: {error:#}"
            );
        }

        let missing_key_name = snapshot_from_get(|name| {
            if name == SETTINGS_CONFIG_VALUE_KEY_NAME_ENV {
                None
            } else {
                valid_vault_value(name)
            }
        });
        let config = VaultRuntimeConfig::from_snapshot(missing_key_name.view())
            .expect("provider configuration is validated before settings key name");
        assert!(matches!(
            config.into_settings_key_provider(),
            Err(VaultRuntimeConfigError::SettingsKeyNameConfig(_))
        ));
    }

    #[test]
    fn runtime_infra_vault_snapshot_distinguishes_key_name_from_client_config_errors()
    -> anyhow::Result<()> {
        let missing_key_name = snapshot_from_get(|name| {
            if name == SETTINGS_CONFIG_VALUE_KEY_NAME_ENV {
                None
            } else {
                valid_vault_value(name)
            }
        });
        let config = VaultRuntimeConfig::from_snapshot(missing_key_name.view())?;
        assert!(matches!(
            config.into_settings_key_provider(),
            Err(VaultRuntimeConfigError::SettingsKeyNameConfig(_))
        ));

        let missing_addr = snapshot_from_get(|name| {
            if name == VAULT_ADDR_ENV {
                None
            } else {
                valid_vault_value(name)
            }
        });
        assert!(matches!(
            VaultRuntimeConfig::from_snapshot(missing_addr.view()),
            Err(VaultRuntimeConfigError::VaultClientConfig(_))
        ));
        Ok(())
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn runtime_infra_vault_snapshot_provider_errors_precede_invalid_settings_key_name()
    -> anyhow::Result<()> {
        for (field, invalid_value) in [
            (VAULT_ADDR_ENV, "not-a-vault-url"),
            (VAULT_TRANSIT_MOUNT_ENV, "transit/.."),
        ] {
            let snapshot = snapshot_from_get(|name| {
                if name == field {
                    Some(invalid_value.to_owned())
                } else if name == SETTINGS_CONFIG_VALUE_KEY_NAME_ENV {
                    Some("".to_owned())
                } else {
                    valid_vault_value(name)
                }
            });
            let config = VaultRuntimeConfig::from_snapshot(snapshot.view())
                .expect("snapshot capture must defer provider and key-name validation");
            let Err(error) = config.into_settings_key_provider() else {
                anyhow::bail!("invalid provider configuration must fail");
            };
            assert!(
                matches!(error, VaultRuntimeConfigError::VaultClientConfig(_)),
                "maintenance {field} must be classified as provider configuration: {error:#}"
            );

            let serving_config = VaultRuntimeConfig::from_snapshot(snapshot.view())?;
            let Err(error) = serving_config.into_runtime() else {
                anyhow::bail!("invalid serving provider configuration must fail");
            };
            assert!(
                matches!(error, VaultRuntimeConfigError::VaultClientConfig(_)),
                "serving {field} must be classified as provider configuration: {error:#}"
            );
        }
        Ok(())
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn runtime_infra_vault_snapshot_rejects_secret_whitespace_without_disclosure() {
        let secret = " vault-secret-with-whitespace ";
        let snapshot = snapshot_from_get(|name| {
            if name == VAULT_TOKEN_ENV {
                Some(secret.to_owned())
            } else {
                valid_vault_value(name)
            }
        });
        let error = VaultRuntimeConfig::from_snapshot(snapshot.view())
            .expect_err("whitespace-bearing token must fail");
        let chain = format!("{error:#}");
        assert!(chain.contains(VAULT_TOKEN_ENV));
        assert!(!chain.contains(secret));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn runtime_infra_vault_snapshot_ca_read_error_redacts_path() {
        let secret_path = unique_temp_path("secret-vault-ca-path-marker.pem");
        let rendered_path = secret_path.display().to_string();
        let snapshot = snapshot_from_get(|name| {
            if name == VAULT_CA_CERT_PEM_PATH_ENV {
                Some(rendered_path.clone())
            } else {
                valid_vault_value(name)
            }
        });
        let error = VaultRuntimeConfig::from_snapshot(snapshot.view())
            .expect_err("missing CA file must fail");
        let chain = format!("{error:#}");
        assert!(chain.contains(VAULT_CA_CERT_PEM_PATH_ENV));
        assert!(!chain.contains(&rendered_path));
        assert!(!chain.contains("secret-vault-ca-path-marker"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn runtime_infra_vault_snapshot_invalid_ca_redacts_path_and_pem() {
        let pem_marker = b"secret-invalid-vault-pem-marker";
        let secret_path = write_temp_file("secret-invalid-vault-ca-path.pem", pem_marker);
        let rendered_path = secret_path.display().to_string();
        let snapshot = snapshot_from_get(|name| {
            if name == VAULT_CA_CERT_PEM_PATH_ENV {
                Some(rendered_path.clone())
            } else {
                valid_vault_value(name)
            }
        });
        let error = VaultRuntimeConfig::from_snapshot(snapshot.view())
            .expect_err("invalid CA PEM must fail");
        let chain = format!("{error:#}");
        assert!(chain.contains(VAULT_CA_CERT_PEM_PATH_ENV));
        assert!(!chain.contains(&rendered_path));
        assert!(!chain.contains("secret-invalid-vault-pem-marker"));
    }

    #[test]
    fn runtime_infra_vault_snapshot_adapter_error_redacts_endpoint_and_token() -> anyhow::Result<()>
    {
        let endpoint = "not-a-vault-url-with-secret-userinfo";
        let token = "vault-secret-adapter-marker";
        let snapshot = snapshot_from_get(|name| match name {
            VAULT_ADDR_ENV => Some(endpoint.to_owned()),
            VAULT_TOKEN_ENV => Some(token.to_owned()),
            _ => valid_vault_value(name),
        });
        let config = VaultRuntimeConfig::from_snapshot(snapshot.view())?;
        let Err(error) = config.into_runtime() else {
            anyhow::bail!("invalid adapter endpoint must fail");
        };
        assert!(matches!(
            error,
            VaultRuntimeConfigError::VaultClientConfig(_)
        ));
        let chain = format!("{error:#}");
        assert!(chain.contains("vault resolver config error"));
        assert!(!chain.contains(endpoint));
        assert!(!chain.contains(token));
        Ok(())
    }

    // ── build_vault_signer_with fail-fast 测试 ───────────────────────────────────────────────

    #[test]
    fn build_vault_signer_missing_addr_fails_fast() {
        // 缺 VAULT_ADDR_ENV → fail-fast；错误含变量名，不含值。
        // 提供 token + mount，确保报错确为缺 addr 而非其它变量。
        let get = |k: &str| {
            if k == VAULT_TOKEN_ENV {
                Some("s.testtoken".to_string())
            } else if k == VAULT_TRANSIT_MOUNT_ENV {
                Some("transit".to_string())
            } else {
                None
            }
        };
        assert!(
            matches!(&build_vault_signer_with(get, false), Err(e) if format!("{e:#}").contains(VAULT_ADDR_ENV)),
            "缺 vault addr 须 fail-fast 且错误含变量名"
        );
    }

    #[test]
    fn build_vault_signer_missing_token_fails_fast() {
        // 提供 https addr（VaultSigner::new 校验 scheme）+ mount；缺 token → fail-fast。
        let get = |k: &str| {
            if k == VAULT_ADDR_ENV {
                Some("https://vault.test:8200".to_string())
            } else if k == VAULT_TRANSIT_MOUNT_ENV {
                Some("transit".to_string())
            } else {
                None
            }
        };
        assert!(
            matches!(&build_vault_signer_with(get, false), Err(e) if format!("{e:#}").contains(VAULT_TOKEN_ENV)),
            "缺 vault token 须 fail-fast 且错误含变量名"
        );
    }

    #[test]
    fn build_vault_signer_missing_mount_fails_fast() {
        // 提供 https addr + token；缺 transit mount → fail-fast（VaultSigner 需 mount）。
        let get = |k: &str| {
            if k == VAULT_ADDR_ENV {
                Some("https://vault.test:8200".to_string())
            } else if k == VAULT_TOKEN_ENV {
                Some("s.testtoken".to_string())
            } else {
                None
            }
        };
        assert!(
            matches!(&build_vault_signer_with(get, false), Err(e) if format!("{e:#}").contains(VAULT_TRANSIT_MOUNT_ENV)),
            "缺 vault transit mount 须 fail-fast 且错误含变量名"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn rss_access_jwks_export_command_and_profile_path_are_exact() {
        let command = vec![
            RSS_ACCESS_JWKS_CLI.to_owned(),
            RSS_ACCESS_JWKS_EXPORT_VAULT_TRANSIT_CLI.to_owned(),
        ];
        assert!(is_rss_access_jwks_export_command(&command));
        assert!(!is_rss_access_jwks_export_command(&[
            RSS_ACCESS_JWKS_CLI.to_owned()
        ]));

        let expected = std::path::PathBuf::from("/run/rss/rss-access.json");
        let path = rss_access_jwks_export_output_path(&command, |name| {
            (name == RSS_ACCESS_TOKEN_JWKS_PATH_ENV).then(|| expected.display().to_string())
        })
        .expect("profile-specific output path");
        assert_eq!(path, expected);
    }

    #[test]
    fn rss_access_jwks_export_rejects_duplicate_output_override() {
        let command = vec![
            RSS_ACCESS_JWKS_CLI.to_owned(),
            RSS_ACCESS_JWKS_EXPORT_VAULT_TRANSIT_CLI.to_owned(),
            "--out".to_owned(),
            "/run/rss/first.json".to_owned(),
            "--out".to_owned(),
            "/run/rss/second.json".to_owned(),
        ];
        assert!(rss_access_jwks_export_output_path(&command, |_| None).is_err());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn vault_transit_public_key_exports_es256_jwks_with_signing_kid() {
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::{EncodePublicKey, LineEnding};

        let key = SigningKey::from_slice(&[11u8; 32]).expect("valid P-256 scalar");
        let pem = key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode public key pem");
        let raw = serde_json::json!({
            "data": {
                "latest_version": 1,
                "keys": {
                    "1": { "public_key": pem }
                }
            }
        });

        let jwks = vault_transit_key_response_to_rss_access_jwks(
            "rss-access-es256",
            serde_json::to_vec(&raw).expect("json bytes").as_slice(),
        )
        .expect("vault public key exports to JWKS");
        let doc: serde_json::Value = serde_json::from_slice(&jwks).expect("valid jwks json");
        let key = &doc["keys"][0];
        assert_eq!(key["kid"], "rss-access-es256");
        assert_eq!(key["kty"], "EC");
        assert_eq!(key["crv"], "P-256");
        assert_eq!(key["alg"], "ES256");
        assert!(key.get("x").is_some(), "ES256 JWK must include x");
        assert!(key.get("y").is_some(), "ES256 JWK must include y");
        assert!(
            key.get("k").is_none(),
            "access JWT verifier JWKS must not fall back to HS256 oct key"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn rss_access_jwks_export_kids_merges_active_next_and_retiring() {
        let get = |name: &str| match name {
            crate::config::RSS_ACCESS_TOKEN_SIGNING_ACTIVE_KEY_ID_ENV => Some("active".to_owned()),
            crate::config::RSS_ACCESS_TOKEN_SIGNING_NEXT_KEY_ID_ENV => Some("next".to_owned()),
            crate::config::RSS_ACCESS_TOKEN_SIGNING_RETIRING_ENV => {
                Some("old=1800000000,older=1900000000".to_owned())
            }
            _ => None,
        };
        let kids = rss_access_jwks_export_kids(&get).expect("kids");
        assert_eq!(kids, vec!["active", "next", "old", "older"]);
    }

    #[test]
    fn rss_access_jwks_export_kids_rejects_overlapping_roles() {
        let get = |name: &str| match name {
            crate::config::RSS_ACCESS_TOKEN_SIGNING_ACTIVE_KEY_ID_ENV => Some("active".to_owned()),
            crate::config::RSS_ACCESS_TOKEN_SIGNING_RETIRING_ENV => {
                Some("active=1800000000".to_owned())
            }
            _ => None,
        };
        assert!(rss_access_jwks_export_kids(&get).is_err());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn serialize_rss_access_jwks_keeps_all_kids() {
        let keys = vec![
            serde_json::json!({"kid":"a","kty":"EC"}),
            serde_json::json!({"kid":"b","kty":"EC"}),
        ];
        let bytes = serialize_rss_access_jwks(&keys).expect("serialize");
        let doc: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(doc["keys"].as_array().expect("keys").len(), 2);
        assert_eq!(doc["keys"][0]["kid"], "a");
        assert_eq!(doc["keys"][1]["kid"], "b");
    }

    #[test]
    fn vault_transit_public_key_export_rejects_missing_current_public_key() -> anyhow::Result<()> {
        let raw = br#"{"data":{"latest_version":1,"keys":{"1":{}}}}"#;
        let Err(err) = vault_transit_key_response_to_rss_access_jwks("rss-access-es256", raw)
        else {
            anyhow::bail!("missing current public key must fail");
        };
        assert!(
            format!("{err:#}").contains("public_key"),
            "error should identify missing public_key: {err:#}"
        );
        Ok(())
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_vault_tls_client_rejects_empty_ca_path() {
        let err = build_vault_tls_client_from(|name| {
            (name == VAULT_CA_CERT_PEM_PATH_ENV).then(|| "  ".to_string())
        })
        .map(|_| ())
        .expect_err("empty Vault CA path is explicit misconfiguration");
        assert!(
            format!("{err:#}").contains(VAULT_CA_CERT_PEM_PATH_ENV),
            "error must identify Vault CA env: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_vault_tls_client_rejects_missing_ca_path() {
        let missing = unique_temp_path("missing-vault-ca.pem");
        let err = build_vault_tls_client_from(|name| {
            (name == VAULT_CA_CERT_PEM_PATH_ENV).then(|| missing.display().to_string())
        })
        .map(|_| ())
        .expect_err("missing Vault CA path must fail fast");
        assert!(
            format!("{err:#}").contains(VAULT_CA_CERT_PEM_PATH_ENV),
            "error must identify Vault CA env: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_vault_tls_client_rejects_invalid_ca_pem() {
        let invalid = write_temp_file("vault-invalid-ca.pem", b"not a pem");
        let err = build_vault_tls_client_from(|name| {
            (name == VAULT_CA_CERT_PEM_PATH_ENV).then(|| invalid.display().to_string())
        })
        .map(|_| ())
        .expect_err("invalid Vault CA PEM must fail fast");
        assert!(
            format!("{err:#}").contains(VAULT_CA_CERT_PEM_PATH_ENV),
            "error must identify Vault CA env: {err:#}"
        );
    }

    #[test]
    fn runtime_vault_client_construction_uses_rustls_builder_only() {
        let source = include_str!("vault.rs");
        let production_source = source
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .unwrap_or(source);
        assert!(
            production_source.contains("use_rustls_tls()"),
            "Vault client construction must explicitly select rustls"
        );
        assert!(
            !production_source.contains("reqwest::Client::new("),
            "runtime production source must not use reqwest::Client::new()"
        );
        assert!(
            !production_source.contains("Client::new("),
            "runtime production source must not use Client::new()"
        );
    }

    #[allow(clippy::expect_used)]
    fn test_ca() -> rcgen::CertifiedIssuer<'static, rcgen::KeyPair> {
        use rcgen::{
            BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, IsCa, KeyPair,
            KeyUsagePurpose,
        };

        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        CertifiedIssuer::self_signed(params, KeyPair::generate().expect("ca key"))
            .expect("self-signed ca")
    }

    #[allow(clippy::expect_used)]
    async fn spawn_private_ca_https_server() -> (String, String) {
        use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let ca = test_ca();
        let signing_key = KeyPair::generate().expect("server key");
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().expect("dns"))];
        params.is_ca = IsCa::ExplicitNoCa;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_cert = params
            .signed_by(&signing_key, &ca)
            .expect("server cert signed by private ca");
        let server_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert.der().clone()], server_key)
            .expect("server tls config");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind https fixture");
        let addr = listener.local_addr().expect("local addr");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        tokio::spawn(async move {
            let Ok((tcp, _peer)) = listener.accept().await else {
                return;
            };
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                return;
            };
            let mut buf = [0u8; 1024];
            let _ = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut buf)).await;
            let _ = tls
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
            let _ = tls.shutdown().await;
        });
        (format!("https://localhost:{}/", addr.port()), ca.pem())
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn runtime_infra_vault_snapshot_private_ca_round_trip_requires_configured_ca() {
        let (untrusted_url, _ca_pem) = spawn_private_ca_https_server().await;
        let snapshot = snapshot_from_get(valid_vault_value);
        let default_client = VaultRuntimeConfig::from_snapshot(snapshot.view())
            .expect("default vault config")
            .client;
        let untrusted = tokio::time::timeout(
            Duration::from_secs(5),
            default_client.get(&untrusted_url).send(),
        )
        .await
        .expect("request completes");
        assert!(
            untrusted.is_err(),
            "private CA endpoint must not be trusted without configured CA"
        );

        let (trusted_url, ca_pem) = spawn_private_ca_https_server().await;
        let ca_path = write_temp_file("vault-private-ca.pem", ca_pem.as_bytes());
        let snapshot = snapshot_from_get(|name| {
            if name == VAULT_CA_CERT_PEM_PATH_ENV {
                Some(ca_path.display().to_string())
            } else {
                valid_vault_value(name)
            }
        });
        let trusted_client = VaultRuntimeConfig::from_snapshot(snapshot.view())
            .expect("vault config with private CA")
            .client;
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            trusted_client.get(&trusted_url).send(),
        )
        .await
        .expect("trusted request completes")
        .expect("trusted request succeeds");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let body = response.text().await.expect("response body");
        assert_eq!(body, "ok");
    }
}
