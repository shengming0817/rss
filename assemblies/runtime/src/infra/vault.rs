use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use base64::Engine as _;
use diport::{DynKeyProvider, KeyName, KeyProvider, ManagedResource, RedactedBytes, ShutdownError};
use primitives::{HealthCheck, HealthStatus, ProbeName};
use secure::{Plaintext, ProtectionContext};
use tokio_util::sync::CancellationToken;
use vault::{
    TenantStoreAllowlist, VaultKeyProvider, VaultRuntimeDeps, VaultSecretResolver, VaultSigner,
    caps as vault_caps,
};

/// 默认 KeyProvider readiness 采样周期（5 秒）。
pub(crate) const DEFAULT_KEYPROVIDER_READINESS_INTERVAL: Duration = Duration::from_secs(5);
/// KeyProvider 保护 settings 持久化读写，摘流延迟上限与 Redis 一样按运行期强依赖收紧。
const MAX_KEYPROVIDER_READINESS_INTERVAL_SECS: u64 = 30;
/// keyprovider_ready 采样周期（env `RSS_KEYPROVIDER_READINESS_SAMPLE_INTERVAL_SECS`）。
pub(crate) fn build_keyprovider_readiness_interval_from(
    get: impl Fn(&str) -> Option<String>,
) -> Duration {
    match get("RSS_KEYPROVIDER_READINESS_SAMPLE_INTERVAL_SECS") {
        None => DEFAULT_KEYPROVIDER_READINESS_INTERVAL,
        Some(raw) => match raw.parse::<u64>() {
            Ok(n) if (1..=MAX_KEYPROVIDER_READINESS_INTERVAL_SECS).contains(&n) => {
                Duration::from_secs(n)
            }
            _ => {
                tracing::warn!(
                    env = "RSS_KEYPROVIDER_READINESS_SAMPLE_INTERVAL_SECS",
                    raw = %raw,
                    max_secs = MAX_KEYPROVIDER_READINESS_INTERVAL_SECS,
                    "invalid keyprovider readiness sample interval (need 1..=30s); using default 5s"
                );
                DEFAULT_KEYPROVIDER_READINESS_INTERVAL
            }
        },
    }
}

pub(crate) fn build_keyprovider_readiness_interval() -> Duration {
    build_keyprovider_readiness_interval_from(|n| std::env::var(n).ok())
}

// ── Vault secret resolver wiring ─────────────────────────────────────────────────────────────

/// 默认 Vault 请求超时（pre-GA 合理值；生产可经 env 覆盖，待后续 Vault 配置切片——非 #1320 范围）。
pub(crate) const DEFAULT_VAULT_TIMEOUT: Duration = Duration::from_secs(5);

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
    let mut builder = reqwest::Client::builder().use_rustls_tls();
    if let Some(path) = get(VAULT_CA_CERT_PEM_PATH_ENV) {
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

/// 从注入的配置读取器构造 `VaultSecretResolver`（fail-fast：必填 env 缺失立即返 `Err`）。
///
/// 必填变量：
/// - `RSS_VAULT_ADDR` — Vault base URL（如 `https://vault.example:8200`）。
/// - `RSS_VAULT_TOKEN` — Vault 认证 token（非空）。
///
/// mount 不再是全局 env——它是 **per-store 坐标**，随 `StoreBinding` 进 `TenantStoreAllowlist`（F1，
/// 坐标模型单源）。**Pre-GA：`TenantStoreAllowlist` 为空**——无生产 secret reader，所有 resolve 返
/// `Forbidden`（含 store binding 的 mount/prefix 配置加载待 #1272）。
pub(crate) fn build_vault_resolver_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<VaultSecretResolver> {
    let addr = get(VAULT_ADDR_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {VAULT_ADDR_ENV}"))?;
    let token = get(VAULT_TOKEN_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {VAULT_TOKEN_ENV}"))?;

    // rustls + ring + webpki-roots（#1252）：vault token 经 TLS 加密出网。
    let client = build_vault_tls_client_from(&get)?;

    // pre-GA 空 allowlist：无生产 secret reader → 所有 resolve fail-closed Forbidden（网络前拦截）。
    // 待后续 issue 填充 TenantStoreAllowlist（per-store mount + prefix，#1272 follow-up）。
    let stores = TenantStoreAllowlist::new(std::iter::empty())
        .map_err(|e| anyhow::anyhow!("vault store allowlist config error: {e}"))?;

    warn_vault_startup_security(&stores);

    VaultSecretResolver::new(client, addr, token, DEFAULT_VAULT_TIMEOUT, stores)
        .map_err(|e| anyhow::anyhow!("vault resolver config error: {e}"))
}

/// 从注入的配置读取器构造 Vault Transit KeyProvider。必填：
/// `RSS_VAULT_ADDR` / `RSS_VAULT_TOKEN` / `RSS_VAULT_TRANSIT_MOUNT`。
pub(crate) fn build_vault_key_provider_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<VaultKeyProvider> {
    let addr = get(VAULT_ADDR_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {VAULT_ADDR_ENV}"))?;
    let token = get(VAULT_TOKEN_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {VAULT_TOKEN_ENV}"))?;
    let mount = get(VAULT_TRANSIT_MOUNT_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {VAULT_TRANSIT_MOUNT_ENV}"))?;
    let client = build_vault_tls_client_from(&get)?;
    VaultKeyProvider::new(client, addr, token, mount, DEFAULT_VAULT_TIMEOUT)
        .map_err(|e| anyhow::anyhow!("vault key provider config error: {e}"))
}

/// settings ConfigValue 加密 keyset 名。空名等非法值经 [`KeyName`] funnel fail-fast。
pub fn build_settings_config_value_key_name_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<KeyName> {
    let raw = get(SETTINGS_CONFIG_VALUE_KEY_NAME_ENV).ok_or_else(|| {
        anyhow::anyhow!("missing required env var: {SETTINGS_CONFIG_VALUE_KEY_NAME_ENV}")
    })?;
    KeyName::try_new(raw)
        .map_err(|e| anyhow::anyhow!("{SETTINGS_CONFIG_VALUE_KEY_NAME_ENV} is invalid: {e}"))
}

/// 组合根级 vault capability bundle 构造（#1498）：env → `VaultSecretResolver`（fail-closed without env，
/// 见 [`build_vault_resolver_from`]）→ [`VaultRuntimeDeps`]（vault 的 dispatch + lifecycle 单源装配出口）。
///
/// vault env 缺失即 `Err`（fail-closed，不静默装配 vault）——本函数是 `run()` 装配 [`SharedRuntimeDeps::vault`]
/// 的构造点（取代旧 `wire_settings` 内联 resolver 构造，resolver 改经 bundle dispatch 注入）。
pub fn build_vault_runtime_deps(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<VaultRuntimeDeps> {
    Ok(VaultRuntimeDeps::new(
        build_vault_resolver_from(&get)?,
        build_vault_key_provider_from(get)?,
    ))
}

/// vault base URL env（resolver + signer 复用，fail-fast 必填）。
pub(crate) const VAULT_ADDR_ENV: &str = "RSS_VAULT_ADDR";
/// vault token env（同上）。
pub(crate) const VAULT_TOKEN_ENV: &str = "RSS_VAULT_TOKEN";
pub(crate) const VAULT_TRANSIT_MOUNT_ENV: &str = "RSS_VAULT_TRANSIT_MOUNT";
pub(crate) const SETTINGS_CONFIG_VALUE_KEY_NAME_ENV: &str = "RSS_SETTINGS_CONFIG_VALUE_KEY_NAME";
/// Optional PEM CA cert path for private/dev Vault HTTPS endpoints.
pub(crate) const VAULT_CA_CERT_PEM_PATH_ENV: &str = "RSS_VAULT_CA_CERT_PEM_PATH";
const JWT_KEY_ID_ENV: &str = "RSS_JWT_ES256_KEY_ID";

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

const OIDC_JWKS_CLI: &str = "oidc-jwks";
const OIDC_JWKS_EXPORT_VAULT_TRANSIT_CLI: &str = "export-vault-transit";
const OIDC_JWKS_PATH_ENV: &str = "RSS_OIDC_JWKS_PATH";

pub fn is_oidc_jwks_export_command(args: &[String]) -> bool {
    matches!(
        args,
        [cmd, sub, ..] if cmd == OIDC_JWKS_CLI && sub == OIDC_JWKS_EXPORT_VAULT_TRANSIT_CLI
    )
}

pub async fn run_oidc_jwks_export_command(args: &[String]) -> anyhow::Result<()> {
    run_oidc_jwks_export_command_from(args, |name| std::env::var(name).ok(), false).await
}

async fn run_oidc_jwks_export_command_from(
    args: &[String],
    get: impl Fn(&str) -> Option<String>,
    allow_http: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        is_oidc_jwks_export_command(args),
        "usage: rss oidc-jwks export-vault-transit [--out <path>]"
    );
    let out = oidc_jwks_export_output_path(args, &get)?;
    let addr = get(VAULT_ADDR_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {VAULT_ADDR_ENV}"))?;
    let token = get(VAULT_TOKEN_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {VAULT_TOKEN_ENV}"))?;
    let mount = get(VAULT_TRANSIT_MOUNT_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {VAULT_TRANSIT_MOUNT_ENV}"))?;
    let key_id = get(JWT_KEY_ID_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {JWT_KEY_ID_ENV}"))?;
    let client = build_vault_tls_client_from(&get)?;
    let url = vault_transit_key_metadata_url(&addr, &mount, &key_id, allow_http)?;
    let response = client
        .get(url)
        .header("X-Vault-Token", token.trim())
        .timeout(DEFAULT_VAULT_TIMEOUT)
        .send()
        .await
        .context("read Vault Transit key metadata")?;
    let status = response.status();
    let body = response
        .bytes()
        .await
        .context("read Vault Transit key metadata response")?;
    anyhow::ensure!(
        status.is_success(),
        "Vault Transit key metadata request returned non-success status"
    );
    let jwks = vault_transit_key_response_to_oidc_jwks(key_id.trim(), &body)?;
    write_jwks_atomic(&out, &jwks).with_context(|| format!("write OIDC JWKS to {}", out.display()))
}

fn oidc_jwks_export_output_path(
    args: &[String],
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<PathBuf> {
    let mut out = None;
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--out" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| anyhow::anyhow!("--out requires a path"))?;
                anyhow::ensure!(!value.trim().is_empty(), "--out requires a non-empty path");
                out = Some(PathBuf::from(value.trim()));
            }
            other => anyhow::bail!("unknown oidc-jwks export-vault-transit argument: {other}"),
        }
        index += 1;
    }
    if let Some(out) = out {
        return Ok(out);
    }
    let path = get(OIDC_JWKS_PATH_ENV)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {OIDC_JWKS_PATH_ENV}"))?;
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
    let key_segments = vault_path_segments(key_id, JWT_KEY_ID_ENV)?;
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

fn vault_transit_key_response_to_oidc_jwks(kid: &str, body: &[u8]) -> anyhow::Result<Vec<u8>> {
    let response: VaultTransitKeyResponse =
        serde_json::from_slice(body).context("parse Vault Transit key metadata response")?;
    let public_key_pem = current_vault_public_key(&response.data)?;
    es256_public_key_pem_to_jwks(kid, public_key_pem)
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

fn es256_public_key_pem_to_jwks(kid: &str, public_key_pem: &str) -> anyhow::Result<Vec<u8>> {
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
    let jwks = serde_json::json!({
        "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "kid": kid,
            "alg": "ES256",
            "use": "sig",
            "x": b64.encode(x),
            "y": b64.encode(y)
        }]
    });
    serde_json::to_vec_pretty(&jwks).context("serialize OIDC JWKS")
}

fn write_jwks_atomic(path: &Path, jwks: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| anyhow::anyhow!("OIDC JWKS output path must have a parent directory"))?;
    fs::create_dir_all(parent).context("create OIDC JWKS output directory")?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("OIDC JWKS output path must end in a file name"))?;
    let tmp = parent.join(format!(".{file_name}.tmp"));
    fs::write(&tmp, jwks).context("write temporary OIDC JWKS")?;
    fs::rename(&tmp, path).context("rename temporary OIDC JWKS into place")
}

// ── KeyProviderReadyProbe ─────────────────────────────────────────────────────────────────────

/// Vault Transit KeyProvider readiness probe stable name.
pub const KEYPROVIDER_READY_PROBE_NAME: &str = "keyprovider_ready";

const KEYPROVIDER_READINESS_TENANT: &str = "00000000-0000-4000-8000-000000000147";
const KEYPROVIDER_READINESS_MISMATCH_TENANT: &str = "00000000-0000-4000-8000-000000000148";
const KEYPROVIDER_READINESS_CONFIG_KEY: &str = "readiness.probe";
pub(crate) const KEYPROVIDER_READINESS_VALUE: &[u8] = b"rss-keyprovider-ready";
const KEYPROVIDER_CONFIG_FIELD: &str = "settings.config.value";
const KEYPROVIDER_CONFIG_SCHEME: u32 = 1;

pub struct KeyProviderReadyProbe {
    ready: Arc<std::sync::atomic::AtomicBool>,
    name: ProbeName,
}

impl KeyProviderReadyProbe {
    #[allow(clippy::expect_used)]
    pub fn new(ready: Arc<std::sync::atomic::AtomicBool>) -> Self {
        let name = ProbeName::parse(KEYPROVIDER_READY_PROBE_NAME).expect("valid probe name const");
        Self { ready, name }
    }
}

impl bootstrap::HealthProbe for KeyProviderReadyProbe {
    fn check(&self) -> HealthCheck {
        let (status, detail) = if self.ready.load(std::sync::atomic::Ordering::Acquire) {
            (HealthStatus::Healthy, "ready")
        } else {
            (HealthStatus::Unhealthy, "down")
        };
        HealthCheck::new(self.name.clone(), status, detail)
    }
}

fn keyprovider_readiness_aad() -> anyhow::Result<secure::DerivedAad> {
    let tenant = vocab::TenantId::parse(KEYPROVIDER_READINESS_TENANT)
        .context("keyprovider readiness tenant constant is invalid")?;
    ProtectionContext::authenticated_request(
        tenant,
        KEYPROVIDER_READINESS_CONFIG_KEY,
        KEYPROVIDER_CONFIG_FIELD,
        KEYPROVIDER_CONFIG_SCHEME,
    )
    .map(|ctx| ctx.derive())
    .context("keyprovider readiness aad")
}

fn keyprovider_readiness_mismatch_aad() -> anyhow::Result<secure::DerivedAad> {
    let tenant = vocab::TenantId::parse(KEYPROVIDER_READINESS_MISMATCH_TENANT)
        .context("keyprovider readiness mismatch tenant constant is invalid")?;
    ProtectionContext::authenticated_request(
        tenant,
        KEYPROVIDER_READINESS_CONFIG_KEY,
        KEYPROVIDER_CONFIG_FIELD,
        KEYPROVIDER_CONFIG_SCHEME,
    )
    .map(|ctx| ctx.derive())
    .context("keyprovider readiness mismatch aad")
}

pub(crate) async fn verify_keyprovider_ready(
    provider: &DynKeyProvider<'static>,
    key_name: KeyName,
) -> anyhow::Result<()> {
    let aad = keyprovider_readiness_aad()?;
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
            RedactedBytes::new(encrypted.ciphertext().to_vec()),
            key_ref.clone(),
            aad,
        )
        .await
        .context("key provider readiness decrypt")?;
    anyhow::ensure!(
        plaintext.expose() == KEYPROVIDER_READINESS_VALUE,
        "key provider readiness plaintext mismatch"
    );
    let mismatch_aad = keyprovider_readiness_mismatch_aad()?;
    match provider
        .decrypt(
            RedactedBytes::new(encrypted.ciphertext().to_vec()),
            key_ref,
            mismatch_aad,
        )
        .await
    {
        Ok(_) => anyhow::bail!("key provider accepted mismatched readiness aad"),
        Err(err) if err.kind() == diport::key_provider::KeyProviderErrorKind::Rejected => {}
        Err(err) => return Err(err).context("key provider readiness mismatched aad decrypt"),
    }
    Ok(())
}

pub(crate) struct KeyProviderReadinessSampler {
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
            && let Err(err) = handle.await
        {
            tracing::warn!(error = %err, "keyprovider readiness sampler join failed");
        }
        Ok(())
    }
}

pub(crate) fn spawn_keyprovider_readiness_sampler(
    vault: VaultRuntimeDeps,
    key_name: KeyName,
    period: Duration,
    token: CancellationToken,
    ready: Arc<std::sync::atomic::AtomicBool>,
) -> KeyProviderReadinessSampler {
    let child = token.child_token();
    let worker_token = child.clone();
    let provider = vault.for_domain::<vault_caps::Settings>().key_provider();
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                () = worker_token.cancelled() => break,
                () = tokio::time::sleep(period) => {
                    let is_ready = verify_keyprovider_ready(&provider, key_name.clone()).await.is_ok();
                    ready.store(is_ready, std::sync::atomic::Ordering::Release);
                }
            }
        }
    });
    KeyProviderReadinessSampler {
        handle: tokio::sync::Mutex::new(Some(handle)),
        token: child,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diport::{DynKeyProvider, KeyName};
    use std::sync::Arc;

    static TEMP_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

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

    /// KeyProviderReadyProbe：`true → Healthy("ready")` / `false → Unhealthy("down")`（fail-closed）。
    #[test]
    fn keyprovider_ready_probe_maps_flag_to_health() {
        use bootstrap::HealthProbe;
        use std::sync::atomic::{AtomicBool, Ordering};

        let flag = Arc::new(AtomicBool::new(true));
        let probe = KeyProviderReadyProbe::new(Arc::clone(&flag));
        let ready = probe.check();
        assert_eq!(ready.status(), HealthStatus::Healthy);
        assert_eq!(ready.detail(), "ready");
        assert_eq!(ready.name().as_str(), KEYPROVIDER_READY_PROBE_NAME);

        flag.store(false, Ordering::Release);
        let down = probe.check();
        assert_eq!(down.status(), HealthStatus::Unhealthy);
        assert_eq!(down.detail(), "down");
    }

    struct FailingKeyProvider;

    impl diport::KeyProvider for FailingKeyProvider {
        async fn encrypt(
            &self,
            _key: diport::KeyName,
            _plaintext: secure::Plaintext,
            _aad: secure::DerivedAad,
        ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
            Err(keyprovider_unavailable())
        }

        async fn decrypt(
            &self,
            _ciphertext: diport::RedactedBytes,
            _key: diport::KeyRef,
            _aad: secure::DerivedAad,
        ) -> Result<secure::Plaintext, diport::KeyProviderError> {
            Err(keyprovider_unavailable())
        }

        async fn rewrap(
            &self,
            _ciphertext: diport::RedactedBytes,
            _key: diport::KeyRef,
            _aad: secure::DerivedAad,
        ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
            Err(keyprovider_unavailable())
        }

        async fn shutdown(&self) -> Result<(), diport::KeyProviderError> {
            Ok(())
        }
    }

    struct AadBlindKeyProvider;

    impl diport::KeyProvider for AadBlindKeyProvider {
        async fn encrypt(
            &self,
            key: diport::KeyName,
            _plaintext: secure::Plaintext,
            _aad: secure::DerivedAad,
        ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
            Ok(diport::EncryptOutput::new(
                b"vault:v1:test".to_vec(),
                diport::KeyRef::new(key, diport::KeyVersion::new(1)),
            ))
        }

        async fn decrypt(
            &self,
            _ciphertext: diport::RedactedBytes,
            _key: diport::KeyRef,
            _aad: secure::DerivedAad,
        ) -> Result<secure::Plaintext, diport::KeyProviderError> {
            Ok(secure::Plaintext::new(KEYPROVIDER_READINESS_VALUE.to_vec()))
        }

        async fn rewrap(
            &self,
            _ciphertext: diport::RedactedBytes,
            _key: diport::KeyRef,
            _aad: secure::DerivedAad,
        ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
            Err(keyprovider_unavailable())
        }

        async fn shutdown(&self) -> Result<(), diport::KeyProviderError> {
            Ok(())
        }
    }

    fn keyprovider_unavailable() -> diport::KeyProviderError {
        diport::KeyProviderError::new(
            diport::key_provider::KeyProviderErrorKind::Unavailable,
            std::io::Error::other("test keyprovider unavailable"),
        )
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn keyprovider_startup_self_check_failure_is_error() {
        let provider = DynKeyProvider::new_box(FailingKeyProvider);
        let key = KeyName::try_new("settings-config").expect("valid key");

        let err = verify_keyprovider_ready(&provider, key)
            .await
            .expect_err("failing provider must fail readiness self-check");
        assert!(
            format!("{err:#}").contains("key provider readiness encrypt"),
            "startup self-check error should preserve encrypt context: {err:#}"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn keyprovider_startup_self_check_rejects_aad_blind_provider() {
        let provider = DynKeyProvider::new_box(AadBlindKeyProvider);
        let key = KeyName::try_new("settings-config").expect("valid key");

        let err = verify_keyprovider_ready(&provider, key)
            .await
            .expect_err("AAD-blind provider must fail readiness self-check");
        assert!(
            format!("{err:#}").contains("accepted mismatched readiness aad"),
            "startup self-check should prove wrong AAD fails closed: {err:#}"
        );
    }

    // #1498 vault capability bundle 构造（fail-closed 由 wire_settings 内联迁到 build_vault_runtime_deps，
    // 经 build_vault_resolver_from）——专项 DI 单测（注入 get，无 live vault / 无 env 副作用）。
    #[test]
    fn build_vault_runtime_deps_missing_addr_fails_fast() {
        // 缺 RSS_VAULT_ADDR → fail-fast（不静默装配 vault）；错误含变量名、不含值。
        let result = build_vault_runtime_deps(|_| None);
        assert!(
            matches!(&result, Err(e) if format!("{e:#}").contains(VAULT_ADDR_ENV)),
            "缺 vault addr env 须 fail-fast 且错误含变量名"
        );
    }

    #[test]
    fn build_vault_runtime_deps_missing_token_fails_fast() {
        // 仅 addr 在、缺 RSS_VAULT_TOKEN → fail-fast（独立验证 token 路径，非 || 宽松匹配）。
        let get = |k: &str| (k == VAULT_ADDR_ENV).then(|| "https://vault.example:8200".to_string());
        assert!(
            matches!(&build_vault_runtime_deps(get), Err(e) if format!("{e:#}").contains(VAULT_TOKEN_ENV)),
            "缺 vault token env 须 fail-fast 且错误含变量名"
        );
    }

    #[test]
    fn build_vault_runtime_deps_missing_transit_mount_fails_fast() {
        let get = |k: &str| match k {
            _ if k == VAULT_ADDR_ENV => Some("https://vault.example:8200".to_string()),
            _ if k == VAULT_TOKEN_ENV => Some("s.testtoken".to_string()),
            _ => None,
        };
        assert!(
            matches!(&build_vault_runtime_deps(get), Err(e) if format!("{e:#}").contains(VAULT_TRANSIT_MOUNT_ENV)),
            "缺 vault transit mount env 须 fail-fast 且错误含变量名"
        );
    }

    #[test]
    fn settings_config_value_key_name_missing_fails_fast() {
        assert!(
            matches!(
                &build_settings_config_value_key_name_from(|_| None),
                Err(e) if format!("{e:#}").contains(SETTINGS_CONFIG_VALUE_KEY_NAME_ENV)
            ),
            "缺 settings config value key name 须 fail-fast"
        );
    }

    #[test]
    #[allow(clippy::expect_used)] // reason: 有效 env 必构造成功，item-level carve-out。
    fn build_vault_runtime_deps_valid_env_single_sources_resolver() {
        // addr + token 在 → 构造成功（无 live vault：VaultSecretResolver::new 仅构造期校验 URL/token +
        // 空 allowlist + warn_vault_startup_security 告警路径）；runtime_resources 单源派生恰一条 resolver guard。
        let get = |k: &str| match k {
            _ if k == VAULT_ADDR_ENV => Some("https://vault.example:8200".to_string()),
            _ if k == VAULT_TOKEN_ENV => Some("s.testtoken".to_string()),
            _ if k == VAULT_TRANSIT_MOUNT_ENV => Some("transit".to_string()),
            _ => None,
        };
        let deps = build_vault_runtime_deps(get);
        assert!(deps.is_ok(), "有效 vault env 须构造成功");
        let resources = deps.expect("valid vault deps").runtime_resources();
        assert_eq!(
            resources.len(),
            2,
            "vault bundle 单源派生 resolver + key-provider guard"
        );
    }

    #[test]
    fn build_keyprovider_readiness_interval_uses_keyprovider_env_not_pg_env() {
        let d = build_keyprovider_readiness_interval_from(|n| match n {
            "RSS_PG_READINESS_SAMPLE_INTERVAL_SECS" => Some("300".to_string()),
            "RSS_KEYPROVIDER_READINESS_SAMPLE_INTERVAL_SECS" => Some("7".to_string()),
            _ => None,
        });
        assert_eq!(d, Duration::from_secs(7));
    }

    #[test]
    fn build_keyprovider_readiness_interval_rejects_pg_sized_upper_bound() {
        let d = build_keyprovider_readiness_interval_from(|n| {
            (n == "RSS_KEYPROVIDER_READINESS_SAMPLE_INTERVAL_SECS").then(|| "300".to_string())
        });
        assert_eq!(d, DEFAULT_KEYPROVIDER_READINESS_INTERVAL);
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

        let jwks = vault_transit_key_response_to_oidc_jwks(
            "rss-jwt-es256",
            serde_json::to_vec(&raw).expect("json bytes").as_slice(),
        )
        .expect("vault public key exports to JWKS");
        let doc: serde_json::Value = serde_json::from_slice(&jwks).expect("valid jwks json");
        let key = &doc["keys"][0];
        assert_eq!(key["kid"], "rss-jwt-es256");
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
    fn vault_transit_public_key_export_rejects_missing_current_public_key() -> anyhow::Result<()> {
        let raw = br#"{"data":{"latest_version":1,"keys":{"1":{}}}}"#;
        let Err(err) = vault_transit_key_response_to_oidc_jwks("rss-jwt-es256", raw) else {
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
    async fn build_vault_tls_client_private_ca_round_trip_requires_configured_ca() {
        let (untrusted_url, _ca_pem) = spawn_private_ca_https_server().await;
        let default_client = build_vault_tls_client_from(|_| None).expect("default vault client");
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
        let trusted_client = build_vault_tls_client_from(|name| {
            (name == VAULT_CA_CERT_PEM_PATH_ENV).then(|| ca_path.display().to_string())
        })
        .expect("vault client with private CA");
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
