use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use base64::Engine as _;
use diport::{DynManagedResource, ManagedResource, ShutdownError};
use oidc::JwksReadinessHandle;
use oidc::OidcProvider;
use primitives::{HealthCheck, HealthStatus, ProbeName};
use tokio_util::sync::CancellationToken;

use crate::SystemClock;
use crate::config::SnapshotConfig;
use crate::phase::OperatorRuntimeCapability;

const OIDC_JWKS_PATH_ENV: &str = "RSS_OIDC_JWKS_PATH";
const OIDC_JWKS_REFRESH_INTERVAL_ENV: &str = "RSS_OIDC_JWKS_REFRESH_INTERVAL_SECS";
pub(crate) const OIDC_JWKS_READY_PROBE_NAME: &str = "oidc_jwks_ready";
const OIDC_JWKS_SOURCE_ID: &str = "primary-idp";
const DEFAULT_OIDC_JWKS_REFRESH_INTERVAL_SECS: u64 = 60;
const MIN_OIDC_JWKS_REFRESH_INTERVAL_SECS: u64 = 5;
const MAX_OIDC_JWKS_REFRESH_INTERVAL_SECS: u64 = 3600;

/// Secret-safe classification of serving JWKS source failures.
///
/// The configured path is deliberately absent from every variant and message. Operators still
/// retain the actionable source category instead of receiving one lossy catch-all error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
enum RuntimeJwksLoadError {
    #[error("{OIDC_JWKS_PATH_ENV} source is unreadable")]
    Unreadable,
    #[error("{OIDC_JWKS_PATH_ENV} source is malformed")]
    Malformed,
    #[error("{OIDC_JWKS_PATH_ENV} source contains no usable keys")]
    NoUsableKeys,
    #[error("{OIDC_JWKS_PATH_ENV} source setup failed")]
    Setup,
}

impl From<oidc::JwksError> for RuntimeJwksLoadError {
    fn from(error: oidc::JwksError) -> Self {
        match error {
            oidc::JwksError::Unreadable => Self::Unreadable,
            oidc::JwksError::Malformed => Self::Malformed,
            oidc::JwksError::NoUsableKeys => Self::NoUsableKeys,
            oidc::JwksError::ZeroInterval | oidc::JwksError::NoRuntime => Self::Setup,
            _ => Self::Setup,
        }
    }
}

pub(crate) struct RuntimeOidcProvider {
    provider: Arc<OidcProvider>,
    jwks_readiness: JwksReadinessHandle,
}

pub(crate) struct PreparedRuntimeOidcProvider {
    builder: oidc::VerifierConfigBuilder,
    jwks_readiness: JwksReadinessHandle,
    clock: Box<dyn diport::Clock>,
}

impl PreparedRuntimeOidcProvider {
    pub(crate) fn finish(
        self,
        replay_store: Arc<diport::DynServiceTokenReplayStore<'static>>,
        replay_timeout: Duration,
    ) -> anyhow::Result<RuntimeOidcProvider> {
        let provider = finish_oidc_provider(
            self.builder
                .service_token_replay_store(replay_store, replay_timeout),
            self.clock,
        )?;
        Ok(RuntimeOidcProvider {
            provider: Arc::new(provider),
            jwks_readiness: self.jwks_readiness,
        })
    }
}

fn finish_oidc_provider(
    builder: oidc::VerifierConfigBuilder,
    clock: Box<dyn diport::Clock>,
) -> anyhow::Result<OidcProvider> {
    let config = builder
        .build()
        .map_err(|error| anyhow::anyhow!("invalid verifier config: {error}"))?;
    Ok(OidcProvider::new(config, clock))
}

impl RuntimeOidcProvider {
    pub(crate) fn provider(&self) -> Arc<OidcProvider> {
        Arc::clone(&self.provider)
    }

    pub(crate) fn jwks_readiness(&self) -> JwksReadinessHandle {
        self.jwks_readiness.clone()
    }

    pub(crate) fn managed_resource(&self) -> Box<DynManagedResource<'static>> {
        DynManagedResource::new_box(OidcProviderGuard(Arc::clone(&self.provider)))
    }
}

struct OidcProviderGuard(Arc<OidcProvider>);

impl ManagedResource for OidcProviderGuard {
    fn name(&self) -> &str {
        self.0.name()
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        ManagedResource::shutdown(&*self.0).await
    }
}

pub(crate) struct OidcJwksReadyProbe {
    name: ProbeName,
    handle: JwksReadinessHandle,
}

impl OidcJwksReadyProbe {
    #[allow(clippy::expect_used)]
    pub(crate) fn new(handle: JwksReadinessHandle) -> Self {
        Self {
            name: ProbeName::parse(OIDC_JWKS_READY_PROBE_NAME).expect("valid probe name const"),
            handle,
        }
    }
}

impl bootstrap::HealthProbe for OidcJwksReadyProbe {
    fn check(&self) -> HealthCheck {
        let (status, detail) = if self.handle.is_ready() {
            (HealthStatus::Healthy, "ready")
        } else {
            (HealthStatus::Unhealthy, "degraded")
        };
        HealthCheck::new(self.name.clone(), status, detail)
    }
}

/// 从进程配置快照构造 serving 验签 `OidcProvider`（issuer / audience / 本地 JWKS 文件源）。
///
/// HTTP listener 的生产 key-source 必须是本地 JWKS 文件（外部 agent / init-container 经 TLS 拉取后写入只读挂载）；
/// 静态 ES256 env 只保留给 operator CLI / 单测路径，不再作为 serving production fallback。
pub(crate) fn prepare_runtime_oidc_provider(
    config: SnapshotConfig<'_>,
) -> anyhow::Result<PreparedRuntimeOidcProvider> {
    prepare_runtime_oidc_provider_from_values(
        config.value("RSS_OIDC_ISSUER"),
        config.value("RSS_OIDC_AUDIENCE"),
        config.value("RSS_OIDC_TRUSTED_KINDS"),
        config.value(OIDC_JWKS_PATH_ENV),
        config.value(OIDC_JWKS_REFRESH_INTERVAL_ENV),
        Box::new(SystemClock),
    )
}

fn prepare_runtime_oidc_provider_from_values(
    issuer: Option<&str>,
    audience: Option<&str>,
    trusted_kinds: Option<&str>,
    jwks_path: Option<&str>,
    refresh_interval: Option<&str>,
    clock: Box<dyn diport::Clock>,
) -> anyhow::Result<PreparedRuntimeOidcProvider> {
    let issuer =
        issuer.ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_OIDC_ISSUER"))?;
    let audience =
        audience.ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_OIDC_AUDIENCE"))?;
    anyhow::ensure!(!issuer.trim().is_empty(), "oidc issuer must not be empty");
    anyhow::ensure!(
        !audience.trim().is_empty(),
        "oidc audience must not be empty"
    );
    let trusted_kinds = trusted_kinds
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_OIDC_TRUSTED_KINDS"))?;
    let jwks_path = jwks_path
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {OIDC_JWKS_PATH_ENV}"))?;
    let refresh_interval = oidc_jwks_refresh_interval_from(refresh_interval)?;
    let jwks = oidc::JwksKeySource::load_and_watch(
        OIDC_JWKS_SOURCE_ID,
        PathBuf::from(jwks_path.trim()),
        refresh_interval,
        CancellationToken::new(),
    )
    .map_err(RuntimeJwksLoadError::from)?;
    let jwks_readiness = jwks.readiness_handle();

    let mut builder = oidc::VerifierConfigBuilder::new(issuer, audience).keys_jwks(jwks);
    let mut trusted = 0usize;
    for kind in trusted_kinds
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        builder = builder.trust_kind(kind);
        trusted += 1;
    }
    if trusted == 0 {
        anyhow::bail!(
            "RSS_OIDC_TRUSTED_KINDS must list ≥1 trusted principal kind (else all JWTs 401)"
        );
    }
    Ok(PreparedRuntimeOidcProvider {
        builder,
        jwks_readiness,
        clock,
    })
}

#[cfg(test)]
fn build_runtime_oidc_provider_from_values(
    issuer: Option<&str>,
    audience: Option<&str>,
    trusted_kinds: Option<&str>,
    jwks_path: Option<&str>,
    refresh_interval: Option<&str>,
    replay_store: Option<Arc<diport::DynServiceTokenReplayStore<'static>>>,
    clock: Box<dyn diport::Clock>,
) -> anyhow::Result<RuntimeOidcProvider> {
    let prepared = prepare_runtime_oidc_provider_from_values(
        issuer,
        audience,
        trusted_kinds,
        jwks_path,
        refresh_interval,
        clock,
    )?;
    prepared.finish(
        replay_store
            .ok_or_else(|| anyhow::anyhow!("oidc service-token replay store is required"))?,
        Duration::from_secs(5),
    )
}

fn oidc_jwks_refresh_interval_from(raw: Option<&str>) -> anyhow::Result<Duration> {
    let Some(raw) = raw else {
        return Ok(Duration::from_secs(DEFAULT_OIDC_JWKS_REFRESH_INTERVAL_SECS));
    };
    let trimmed = raw.trim();
    anyhow::ensure!(
        !trimmed.is_empty(),
        "{OIDC_JWKS_REFRESH_INTERVAL_ENV} must not be empty"
    );
    let secs = trimmed
        .parse::<u64>()
        .with_context(|| format!("{OIDC_JWKS_REFRESH_INTERVAL_ENV} must be seconds"))?;
    anyhow::ensure!(
        (MIN_OIDC_JWKS_REFRESH_INTERVAL_SECS..=MAX_OIDC_JWKS_REFRESH_INTERVAL_SECS).contains(&secs),
        "{OIDC_JWKS_REFRESH_INTERVAL_ENV} must be in {MIN_OIDC_JWKS_REFRESH_INTERVAL_SECS}..={MAX_OIDC_JWKS_REFRESH_INTERVAL_SECS} seconds"
    );
    Ok(Duration::from_secs(secs))
}

/// 从 operator 配置快照构造验签 `OidcProvider`（issuer / audience / ES256·HS256 静态 key）。
///
/// - `RSS_OIDC_ISSUER` / `RSS_OIDC_AUDIENCE`：必填。
/// - `RSS_OIDC_TRUSTED_KINDS`：**必填**——本 IdP 可 assert 的 principal kind 逗号分隔白名单（如 `user,admin,device`）。
///   secure-by-default（OIDC-KIND-ALLOWLIST-01）：未配置则验签器剥离所有 kind → `Principal` 派生恒 `TokenInvalid`
///   → JWT **全 401**（评审 F1 修复的生产失效根因），故构造期 fail-fast 拒空。
/// - `RSS_OIDC_ES256_SEC1_B64URL`：JWT 路径 ES256 公钥，base64url(SEC1 未压缩点)，逗号分隔可多把（可选）。
/// - `RSS_OIDC_HS256_SECRET_B64URL`：service-token 路径 HS256 密钥，base64url（可选）。
/// - `RSS_OIDC_HS256_KID`：service-token 路径 key id；配置 HS256 secret 时必填。
///
/// Operator / maintenance CLI 与 serving 使用同一进程级配置代际，但仍保留独立的静态 key
/// provider 语义；调用方必须显式提供不可伪造的快照能力、durable replay store 和有界
/// deadline，不存在 ambient fallback 或 store-free HS256 配置。
pub(crate) fn build_operator_provider(
    config: SnapshotConfig<'_>,
    _operator: OperatorRuntimeCapability<'_>,
    replay_store: Arc<diport::DynServiceTokenReplayStore<'static>>,
    replay_timeout: Duration,
) -> anyhow::Result<OidcProvider> {
    build_provider_from_values(
        StaticOidcEnvValues {
            issuer: config.value("RSS_OIDC_ISSUER"),
            audience: config.value("RSS_OIDC_AUDIENCE"),
            trusted_kinds: config.value("RSS_OIDC_TRUSTED_KINDS"),
            es256: config.value("RSS_OIDC_ES256_SEC1_B64URL"),
            hs256: config.value("RSS_OIDC_HS256_SECRET_B64URL"),
            hs256_kid: config.value("RSS_OIDC_HS256_KID"),
        },
        replay_store,
        replay_timeout,
        Box::new(SystemClock),
    )
}

struct StaticOidcEnvValues<'a> {
    issuer: Option<&'a str>,
    audience: Option<&'a str>,
    trusted_kinds: Option<&'a str>,
    es256: Option<&'a str>,
    hs256: Option<&'a str>,
    hs256_kid: Option<&'a str>,
}

fn build_provider_from_values(
    values: StaticOidcEnvValues<'_>,
    replay_store: Arc<diport::DynServiceTokenReplayStore<'static>>,
    replay_timeout: Duration,
    clock: Box<dyn diport::Clock>,
) -> anyhow::Result<OidcProvider> {
    let issuer = values
        .issuer
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_OIDC_ISSUER"))?;
    let audience = values
        .audience
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_OIDC_AUDIENCE"))?;
    let trusted_kinds = values
        .trusted_kinds
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_OIDC_TRUSTED_KINDS"))?;
    let key_profile = static_key_profile_from_values(
        values.es256,
        values.hs256,
        values.hs256_kid,
        replay_store,
        replay_timeout,
    )?;
    provider_from_static_config(StaticOidcProviderConfig {
        issuer,
        audience,
        trusted_kinds_csv: trusted_kinds,
        key_profile,
        clock,
    })
}

fn static_key_profile_from_values<'a>(
    es256: Option<&'a str>,
    hs256: Option<&'a str>,
    hs256_kid: Option<&'a str>,
    replay_store: Arc<diport::DynServiceTokenReplayStore<'static>>,
    replay_timeout: Duration,
) -> anyhow::Result<StaticOidcKeyProfile<'a>> {
    let service_token = |secret_b64, key_id| Hs256ServiceTokenProfile {
        secret_b64,
        key_id,
        replay_store,
        replay_timeout,
    };
    match (es256, hs256, hs256_kid) {
        (Some(public_keys_b64), None, None) => Ok(StaticOidcKeyProfile::Es256 { public_keys_b64 }),
        (None, Some(secret_b64), Some(key_id)) => Ok(StaticOidcKeyProfile::ServiceTokenHs256(
            service_token(secret_b64, key_id),
        )),
        (Some(public_keys_b64), Some(secret_b64), Some(key_id)) => {
            Ok(StaticOidcKeyProfile::Es256AndServiceTokenHs256 {
                public_keys_b64,
                service_token: service_token(secret_b64, key_id),
            })
        }
        (_, Some(_), None) => {
            anyhow::bail!("missing required env var: RSS_OIDC_HS256_KID")
        }
        (_, None, Some(_)) => {
            anyhow::bail!("RSS_OIDC_HS256_KID requires RSS_OIDC_HS256_SECRET_B64URL")
        }
        (None, None, None) => {
            anyhow::bail!("at least one static OIDC key profile is required")
        }
    }
}

/// 静态 operator/test OIDC provider 的命名输入。
///
/// key source 必须经 [`StaticOidcKeyProfile`] 选择一个闭合 profile；serving 生产路径使用本地 JWKS
/// [`prepare_runtime_oidc_provider`]，两条路径最终都经同一个 verifier 构建漏斗。
pub struct StaticOidcProviderConfig<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub trusted_kinds_csv: &'a str,
    pub key_profile: StaticOidcKeyProfile<'a>,
    pub clock: Box<dyn diport::Clock>,
}

/// 静态 key source 的闭合 profile；无 key 状态无法构造。
pub enum StaticOidcKeyProfile<'a> {
    Es256 {
        public_keys_b64: &'a str,
    },
    ServiceTokenHs256(Hs256ServiceTokenProfile<'a>),
    Es256AndServiceTokenHs256 {
        public_keys_b64: &'a str,
        service_token: Hs256ServiceTokenProfile<'a>,
    },
}

/// HS256 service-token 所需的 key 与 replay protection 原子配置。
///
/// replay store 和 deadline 不再是与 HS256 key 分离的可选参数，因此调用方无法表达“HS256 已启用但
/// replay protection 缺失”的配置。
///
/// ```compile_fail
/// use runtime::Hs256ServiceTokenProfile;
///
/// let _ = Hs256ServiceTokenProfile {
///     secret_b64: "base64url-secret",
///     key_id: "cell-a.svc-a",
///     // replay_store 与 replay_timeout 是必填字段。
/// };
/// ```
pub struct Hs256ServiceTokenProfile<'a> {
    pub secret_b64: &'a str,
    pub key_id: &'a str,
    pub replay_store: Arc<diport::DynServiceTokenReplayStore<'static>>,
    pub replay_timeout: Duration,
}

/// 由命名静态 profile 装配 operator/test `OidcProvider`，纯函数且无 env 副作用。
///
/// - `trusted_kinds_csv`：逗号分隔 trusted principal kind（`.trust_kind` 白名单，OIDC-KIND-ALLOWLIST-01）；解析后
///   **空集 fail-fast**——无 trusted kind 的 provider 验签 JWT 恒剥离 kind → 派生 `TokenInvalid` → 全 401（F1 根因）。
/// - ES256 profile 接受逗号分隔 base64url(SEC1 未压缩点)；HS256 profile 将 secret/kid/replay
///   store/deadline 绑定为一个值。
pub fn provider_from_static_config(
    config: StaticOidcProviderConfig<'_>,
) -> anyhow::Result<OidcProvider> {
    let StaticOidcProviderConfig {
        issuer,
        audience,
        trusted_kinds_csv,
        key_profile,
        clock,
    } = config;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut keys = oidc::StaticKeySource::builder();
    let replay = match key_profile {
        StaticOidcKeyProfile::Es256 { public_keys_b64 } => {
            keys = add_es256_keys(keys, &b64, public_keys_b64)?;
            None
        }
        StaticOidcKeyProfile::ServiceTokenHs256(service_token) => {
            let (next, replay) = add_service_token_key(keys, &b64, service_token)?;
            keys = next;
            Some(replay)
        }
        StaticOidcKeyProfile::Es256AndServiceTokenHs256 {
            public_keys_b64,
            service_token,
        } => {
            keys = add_es256_keys(keys, &b64, public_keys_b64)?;
            let (next, replay) = add_service_token_key(keys, &b64, service_token)?;
            keys = next;
            Some(replay)
        }
    };

    let mut builder = oidc::VerifierConfigBuilder::new(issuer, audience).keys(keys.build());
    if let Some((replay_store, replay_timeout)) = replay {
        builder = builder.service_token_replay_store(replay_store, replay_timeout);
    }
    let mut trusted = 0usize;
    for kind in trusted_kinds_csv
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        builder = builder.trust_kind(kind);
        trusted += 1;
    }
    if trusted == 0 {
        anyhow::bail!(
            "RSS_OIDC_TRUSTED_KINDS must list ≥1 trusted principal kind (else all JWTs 401)"
        );
    }
    finish_oidc_provider(builder, clock)
}

fn add_es256_keys(
    mut keys: oidc::StaticKeySourceBuilder,
    b64: &base64::engine::general_purpose::GeneralPurpose,
    public_keys_b64: &str,
) -> anyhow::Result<oidc::StaticKeySourceBuilder> {
    for part in public_keys_b64.split(',').filter(|part| !part.is_empty()) {
        let sec1 = b64
            .decode(part)
            .context("RSS_OIDC_ES256_SEC1_B64URL not valid base64url")?;
        keys = keys
            .add_es256_sec1(&sec1)
            .map_err(|error| anyhow::anyhow!("invalid ES256 key: {error}"))?;
    }
    Ok(keys)
}

fn add_service_token_key(
    mut keys: oidc::StaticKeySourceBuilder,
    b64: &base64::engine::general_purpose::GeneralPurpose,
    profile: Hs256ServiceTokenProfile<'_>,
) -> anyhow::Result<(
    oidc::StaticKeySourceBuilder,
    (Arc<diport::DynServiceTokenReplayStore<'static>>, Duration),
)> {
    let Hs256ServiceTokenProfile {
        secret_b64,
        key_id,
        replay_store,
        replay_timeout,
    } = profile;
    anyhow::ensure!(
        !key_id.trim().is_empty(),
        "missing required env var: RSS_OIDC_HS256_KID"
    );
    let secret = b64
        .decode(secret_b64)
        .context("RSS_OIDC_HS256_SECRET_B64URL not valid base64url")?;
    keys = keys
        .add_hs256_secret_with_kid(key_id, &secret)
        .map_err(|error| anyhow::anyhow!("weak HS256 secret: {error}"))?;
    Ok((keys, (replay_store, replay_timeout)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn clk() -> Box<dyn diport::Clock> {
        Box::new(crate::SystemClock)
    }

    struct TestReplayStore;

    impl diport::ServiceTokenReplayStore for TestReplayStore {
        async fn check_and_record(
            &self,
            _key: &diport::ServiceTokenReplayKey,
            _expires_at: std::time::SystemTime,
            _deadline: diport::ServiceTokenReplayDeadline,
        ) -> Result<diport::ServiceTokenReplayDisposition, diport::ServiceTokenReplayStoreError>
        {
            Ok(diport::ServiceTokenReplayDisposition::Recorded)
        }
    }

    fn replay_store() -> Arc<diport::DynServiceTokenReplayStore<'static>> {
        diport::DynServiceTokenReplayStore::new_arc(TestReplayStore)
    }

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

    fn hs256_jwks(secret: &[u8], kid: &str) -> String {
        let key = B64.encode(secret);
        format!(r#"{{"keys":[{{"kty":"oct","kid":"{kid}","alg":"HS256","k":"{key}"}}]}}"#)
    }

    #[allow(clippy::expect_used)]
    fn tenant_binding(raw: &str) -> diport::ServiceTokenTenantBinding {
        diport::ServiceTokenTenantBinding::new(vocab::TenantId::parse(raw).expect("tenant"))
    }

    fn service_token_payload(jti: &str) -> String {
        format!(
            r#"{{"sub":"runtime-service","exp":4102444800,"iss":"https://issuer.test","aud":"rss-test","kind":"service","jti":"{jti}"}}"#
        )
    }

    #[allow(clippy::expect_used)]
    fn mint_hs256_bound_with_kid(
        secret: &[u8],
        kid: &str,
        payload_json: &str,
        tenant: &str,
    ) -> String {
        use hmac::{Hmac, Mac as _};
        use sha2::Sha256;

        let header = B64.encode(format!(r#"{{"alg":"HS256","kid":"{kid}"}}"#));
        let body = B64.encode(payload_json.as_bytes());
        let signing_input = format!("{header}.{body}");
        let binding = tenant_binding(tenant);
        let mac_input = diport::service_token_mac_input(signing_input.as_bytes(), &binding);
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
        mac.update(&mac_input);
        let tag = mac.finalize().into_bytes();
        format!("{signing_input}.{}", B64.encode(tag))
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn serving_oidc_snapshot_mapping_matches_explicit_values() {
        let secret = [0x22u8; 32];
        let jwks_path = write_temp_file(
            "snapshot-runtime-oidc-jwks.json",
            hs256_jwks(&secret, "svc-snapshot").as_bytes(),
        );
        let jwks_path = jwks_path.to_string_lossy();
        let snapshot = crate::config::test_snapshot(&[
            ("RSS_OIDC_ISSUER", "https://issuer.test"),
            ("RSS_OIDC_AUDIENCE", "rss-test"),
            ("RSS_OIDC_TRUSTED_KINDS", "service,user,admin"),
            (OIDC_JWKS_PATH_ENV, jwks_path.as_ref()),
            (OIDC_JWKS_REFRESH_INTERVAL_ENV, "5"),
        ])
        .expect("capture serving OIDC generation");

        let runtime = prepare_runtime_oidc_provider(snapshot.view())
            .and_then(|prepared| prepared.finish(replay_store(), Duration::from_secs(5)))
            .expect("serving HS256 uses the explicitly wired durable replay store");
        assert!(runtime.jwks_readiness().is_ready());
        runtime
            .managed_resource()
            .shutdown()
            .await
            .expect("shutdown snapshot-backed OIDC provider");
    }

    #[test]
    fn build_runtime_oidc_provider_from_values_missing_jwks_path_fails_fast() {
        let result = build_runtime_oidc_provider_from_values(
            Some("https://issuer.test"),
            Some("rss-test"),
            Some("service"),
            None,
            None,
            None,
            clk(),
        );
        assert!(
            matches!(&result, Err(err) if err.to_string().contains(OIDC_JWKS_PATH_ENV)),
            "runtime listener OIDC provider must require JWKS path"
        );
    }

    #[tokio::test]
    async fn build_runtime_oidc_provider_from_values_invalid_jwks_path_is_redacted() {
        const SECRET_PATH_FRAGMENT: &str = "tenant-secret-missing-runtime-jwks.json";
        let missing = unique_temp_path(SECRET_PATH_FRAGMENT);
        let missing = missing.to_string_lossy();
        let result = build_runtime_oidc_provider_from_values(
            Some("https://issuer.test"),
            Some("rss-test"),
            Some("service,user,admin"),
            Some(&missing),
            None,
            None,
            clk(),
        );
        let error = result
            .err()
            .map(|error| format!("{error:#}"))
            .unwrap_or_default();
        assert!(
            !error.is_empty(),
            "bad JWKS path must fail during runtime OIDC provider construction"
        );
        assert!(
            error.contains(OIDC_JWKS_PATH_ENV),
            "redacted error must identify the invalid setting"
        );
        assert!(
            !error.contains(SECRET_PATH_FRAGMENT),
            "redacted error must not expose the configured path"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn runtime_jwks_load_error_keeps_safe_typed_classification() {
        let malformed = write_temp_file("secret-malformed-jwks.json", b"not json");
        let empty = write_temp_file("secret-empty-jwks.json", br#"{"keys":[]}"#);

        for (path, expected) in [
            (malformed, RuntimeJwksLoadError::Malformed),
            (empty, RuntimeJwksLoadError::NoUsableKeys),
        ] {
            let path = path.to_string_lossy();
            let error = build_runtime_oidc_provider_from_values(
                Some("https://issuer.test"),
                Some("rss-test"),
                Some("service"),
                Some(&path),
                None,
                None,
                clk(),
            )
            .err()
            .expect("invalid JWKS source must fail");
            assert_eq!(
                error.downcast_ref::<RuntimeJwksLoadError>(),
                Some(&expected)
            );
            let rendered = format!("{error:#}");
            assert!(rendered.contains(OIDC_JWKS_PATH_ENV));
            assert!(!rendered.contains(path.as_ref()));
        }

        let missing = unique_temp_path("secret-unreadable-jwks.json");
        let missing = missing.to_string_lossy();
        let error = build_runtime_oidc_provider_from_values(
            Some("https://issuer.test"),
            Some("rss-test"),
            Some("service"),
            Some(&missing),
            None,
            None,
            clk(),
        )
        .err()
        .expect("unreadable JWKS source must fail");
        assert_eq!(
            error.downcast_ref::<RuntimeJwksLoadError>(),
            Some(&RuntimeJwksLoadError::Unreadable)
        );
        assert!(!format!("{error:#}").contains(missing.as_ref()));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn oidc_jwks_refresh_interval_is_range_checked() {
        assert_eq!(
            oidc_jwks_refresh_interval_from(None).expect("default"),
            Duration::from_secs(DEFAULT_OIDC_JWKS_REFRESH_INTERVAL_SECS)
        );
        for raw in ["", "4", "3601", "not-seconds"] {
            assert!(
                oidc_jwks_refresh_interval_from(Some(raw)).is_err(),
                "invalid refresh interval {raw:?} must fail"
            );
        }
        assert_eq!(
            oidc_jwks_refresh_interval_from(Some("5")).expect("min"),
            Duration::from_secs(MIN_OIDC_JWKS_REFRESH_INTERVAL_SECS)
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn build_runtime_oidc_provider_from_valid_jwks_registers_ready_probe() {
        let secret = [0x33u8; 32];
        let jwks_path = write_temp_file(
            "runtime-oidc-jwks.json",
            hs256_jwks(&secret, "svc-1").as_bytes(),
        );
        let jwks_path = jwks_path.to_string_lossy();
        let runtime = build_runtime_oidc_provider_from_values(
            Some("https://issuer.test"),
            Some("rss-test"),
            Some("service,user,admin"),
            Some(&jwks_path),
            None,
            Some(replay_store()),
            clk(),
        )
        .expect("valid runtime OIDC provider");

        let probe = OidcJwksReadyProbe::new(runtime.jwks_readiness());
        let check = bootstrap::HealthProbe::check(&probe);
        assert_eq!(check.name().as_str(), OIDC_JWKS_READY_PROBE_NAME);
        assert_eq!(check.status(), HealthStatus::Healthy);
        assert_eq!(check.detail(), "ready");

        let resource = runtime.managed_resource();
        resource.shutdown().await.expect("shutdown oidc provider");
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::expect_used)]
    async fn oidc_jwks_refresh_failure_marks_probe_unhealthy_and_keeps_last_good() {
        const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
        let secret = [0x44u8; 32];
        let jwks_path = write_temp_file(
            "runtime-oidc-jwks.json",
            hs256_jwks(&secret, "svc-1").as_bytes(),
        );
        let jwks_path_display = jwks_path.to_string_lossy();
        let runtime = build_runtime_oidc_provider_from_values(
            Some("https://issuer.test"),
            Some("rss-test"),
            Some("service,user,admin"),
            Some(&jwks_path_display),
            Some("5"),
            Some(replay_store()),
            clk(),
        )
        .expect("valid runtime OIDC provider");

        let before = mint_hs256_bound_with_kid(
            &secret,
            "svc-1",
            &service_token_payload("nonce-before-degraded"),
            TENANT,
        );
        diport::Pdp::verify(
            runtime.provider.as_ref(),
            &diport::RawCredential::service_token(before, tenant_binding(TENANT)),
        )
        .await
        .expect("initial last-good key verifies service token");

        std::fs::write(&jwks_path, b"not a jwks document").expect("corrupt jwks");
        let mut degraded = false;
        for _ in 0..10 {
            tokio::time::advance(Duration::from_secs(MIN_OIDC_JWKS_REFRESH_INTERVAL_SECS)).await;
            tokio::task::yield_now().await;
            if !runtime.jwks_readiness().is_ready() {
                degraded = true;
                break;
            }
        }
        assert!(degraded, "refresh failure should mark readiness degraded");

        let probe = OidcJwksReadyProbe::new(runtime.jwks_readiness());
        let check = bootstrap::HealthProbe::check(&probe);
        assert_eq!(check.status(), HealthStatus::Unhealthy);
        assert_eq!(check.detail(), "degraded");

        let after = mint_hs256_bound_with_kid(
            &secret,
            "svc-1",
            &service_token_payload("nonce-after-degraded"),
            TENANT,
        );
        diport::Pdp::verify(
            runtime.provider.as_ref(),
            &diport::RawCredential::service_token(after, tenant_binding(TENANT)),
        )
        .await
        .expect("refresh failure retains last-good keyset");

        let resource = runtime.managed_resource();
        resource.shutdown().await.expect("shutdown oidc provider");
    }

    #[test]
    fn static_env_values_without_keys_fail_fast() {
        let result = build_provider_from_values(
            StaticOidcEnvValues {
                issuer: Some("https://issuer.test"),
                audience: Some("rss"),
                trusted_kinds: Some("user"),
                es256: None,
                hs256: None,
                hs256_kid: None,
            },
            replay_store(),
            Duration::from_secs(5),
            clk(),
        );
        assert!(matches!(&result, Err(error) if error.to_string().contains("key profile")));
    }

    #[test]
    fn static_profile_empty_trusted_kinds_fails_fast() {
        // 评审 F1：无 trusted kind ⇒ JWT kind 被剥离 ⇒ 派生 TokenInvalid ⇒ 全 401，构造期 fail-fast 拒。
        let secret = B64.encode([7u8; 32]);
        let r = provider_from_static_config(StaticOidcProviderConfig {
            issuer: "https://issuer.test",
            audience: "rss",
            trusted_kinds_csv: "  ,  ",
            key_profile: StaticOidcKeyProfile::ServiceTokenHs256(Hs256ServiceTokenProfile {
                secret_b64: &secret,
                key_id: "cell-a.svc-a",
                replay_store: replay_store(),
                replay_timeout: Duration::from_secs(5),
            }),
            clock: clk(),
        });
        assert!(matches!(&r, Err(e) if e.to_string().contains("RSS_OIDC_TRUSTED_KINDS")));
    }

    #[test]
    fn build_provider_from_values_missing_trusted_kinds_fails_fast() {
        // issuer + audience 在、trusted kinds 缺 → fail-fast（F1 生产失效根因守）。
        let result = build_provider_from_values(
            StaticOidcEnvValues {
                issuer: Some("https://issuer.test"),
                audience: Some("rss"),
                trusted_kinds: None,
                es256: None,
                hs256: None,
                hs256_kid: None,
            },
            replay_store(),
            Duration::from_secs(5),
            clk(),
        );
        assert!(matches!(&result, Err(e) if e.to_string().contains("RSS_OIDC_TRUSTED_KINDS")));
    }

    #[test]
    fn build_provider_from_values_missing_issuer_fails_fast() {
        // 显式 raw values 缺 RSS_OIDC_ISSUER → fail-fast（错误含变量名，不含值）。
        // OidcProvider 无 Debug（不能 expect_err），用 matches! 既断言 Err 又锁错误文案。
        let result = build_provider_from_values(
            StaticOidcEnvValues {
                issuer: None,
                audience: None,
                trusted_kinds: None,
                es256: None,
                hs256: None,
                hs256_kid: None,
            },
            replay_store(),
            Duration::from_secs(5),
            clk(),
        );
        assert!(matches!(&result, Err(e) if e.to_string().contains("RSS_OIDC_ISSUER")));
    }

    #[test]
    fn build_provider_from_values_missing_audience_fails_fast() {
        // issuer 存在、audience 缺失 → fail-fast 命中 audience 那行（独立于 issuer 缺失路径）。
        let result = build_provider_from_values(
            StaticOidcEnvValues {
                issuer: Some("https://issuer.test"),
                audience: None,
                trusted_kinds: None,
                es256: None,
                hs256: None,
                hs256_kid: None,
            },
            replay_store(),
            Duration::from_secs(5),
            clk(),
        );
        assert!(matches!(&result, Err(e) if e.to_string().contains("RSS_OIDC_AUDIENCE")));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_provider_from_values_happy_hs256() {
        let secret = B64.encode([7u8; 32]);
        build_provider_from_values(
            StaticOidcEnvValues {
                issuer: Some("https://issuer.test"),
                audience: Some("rss"),
                trusted_kinds: Some("user,admin"),
                es256: None,
                hs256: Some(&secret),
                hs256_kid: Some("cell-a.svc-a"),
            },
            replay_store(),
            Duration::from_secs(5),
            clk(),
        )
        .expect("issuer + aud + trusted kinds + hs256 key ⇒ 构造成功");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn operator_provider_consumes_captured_snapshot_without_ambient_fallback() {
        let secret = B64.encode([7u8; 32]);
        let snapshot = crate::config::test_snapshot(&[
            ("RSS_OIDC_ISSUER", "https://issuer.test"),
            ("RSS_OIDC_AUDIENCE", "rss"),
            ("RSS_OIDC_TRUSTED_KINDS", "user,admin"),
            ("RSS_OIDC_HS256_SECRET_B64URL", &secret),
            ("RSS_OIDC_HS256_KID", "cell-a.svc-a"),
        ])
        .expect("capture operator OIDC values");

        let inputs = crate::phase::OperatorRuntimeInputs::new(
            crate::phase::PreparedRuntimeInputs::new(snapshot, None),
        );
        build_operator_provider(
            inputs.config(),
            inputs.operator_capability(),
            replay_store(),
            Duration::from_secs(5),
        )
        .expect("operator provider must consume the captured generation");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_provider_from_values_preserves_combined_static_profile() {
        use p256::ecdsa::SigningKey;

        let signing_key = SigningKey::from_slice(&[8u8; 32]).expect("signing key");
        let public_keys_b64 = B64.encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let secret = B64.encode([7u8; 32]);
        build_provider_from_values(
            StaticOidcEnvValues {
                issuer: Some("https://issuer.test"),
                audience: Some("rss"),
                trusted_kinds: Some("user,admin"),
                es256: Some(&public_keys_b64),
                hs256: Some(&secret),
                hs256_kid: Some("cell-a.svc-a"),
            },
            replay_store(),
            Duration::from_secs(5),
            clk(),
        )
        .expect("combined ES256 JWT + HS256 service-token profile");
    }

    #[test]
    fn static_es256_profile_bad_base64_fails_fast() {
        // ES256 串非 base64url → fail-fast（误配在 setup 期暴露，非运行时静默）。
        let bad = provider_from_static_config(StaticOidcProviderConfig {
            issuer: "https://issuer.test",
            audience: "rss",
            trusted_kinds_csv: "user",
            key_profile: StaticOidcKeyProfile::Es256 {
                public_keys_b64: "!!not-b64!!",
            },
            clock: clk(),
        });
        assert!(bad.is_err());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn static_service_token_profile_with_hs256_ok() {
        let secret = B64.encode([7u8; 32]);
        let p = provider_from_static_config(StaticOidcProviderConfig {
            issuer: "https://issuer.test",
            audience: "rss",
            trusted_kinds_csv: "user",
            key_profile: StaticOidcKeyProfile::ServiceTokenHs256(Hs256ServiceTokenProfile {
                secret_b64: &secret,
                key_id: "cell-a.svc-a",
                replay_store: replay_store(),
                replay_timeout: Duration::from_secs(5),
            }),
            clock: clk(),
        });
        assert!(
            p.is_ok(),
            "有效 HS256 key + issuer/aud + trusted kind ⇒ 构造成功"
        );
        let _ = p.expect("ok");
    }

    #[test]
    fn static_env_values_hs256_without_kid_fail_fast() {
        let secret = B64.encode([7u8; 32]);
        let result = build_provider_from_values(
            StaticOidcEnvValues {
                issuer: Some("https://issuer.test"),
                audience: Some("rss"),
                trusted_kinds: Some("user"),
                es256: None,
                hs256: Some(&secret),
                hs256_kid: None,
            },
            replay_store(),
            Duration::from_secs(5),
            clk(),
        );
        assert!(
            matches!(&result, Err(error) if error.to_string().contains("RSS_OIDC_HS256_KID")),
            "HS256 construction must require a key id"
        );
    }
}
