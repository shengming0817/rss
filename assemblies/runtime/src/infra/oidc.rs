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

use crate::{RuntimeServiceTokenReplayGuard, SystemClock};

const OIDC_JWKS_PATH_ENV: &str = "RSS_OIDC_JWKS_PATH";
const OIDC_JWKS_REFRESH_INTERVAL_ENV: &str = "RSS_OIDC_JWKS_REFRESH_INTERVAL_SECS";
pub(crate) const OIDC_JWKS_READY_PROBE_NAME: &str = "oidc_jwks_ready";
const OIDC_JWKS_SOURCE_ID: &str = "primary-idp";
const DEFAULT_OIDC_JWKS_REFRESH_INTERVAL_SECS: u64 = 60;
const MIN_OIDC_JWKS_REFRESH_INTERVAL_SECS: u64 = 5;
const MAX_OIDC_JWKS_REFRESH_INTERVAL_SECS: u64 = 3600;

pub(crate) struct RuntimeOidcProvider {
    provider: Arc<OidcProvider>,
    jwks_readiness: JwksReadinessHandle,
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

/// 从 env 构造 serving 验签 `OidcProvider`（issuer / audience / 本地 JWKS 文件源）。
///
/// HTTP listener 的生产 key-source 必须是本地 JWKS 文件（外部 agent / init-container 经 TLS 拉取后写入只读挂载）；
/// 静态 ES256 env 只保留给 operator CLI / 单测路径，不再作为 serving production fallback。
pub(crate) fn build_runtime_oidc_provider() -> anyhow::Result<RuntimeOidcProvider> {
    build_runtime_oidc_provider_from(|name| std::env::var(name).ok(), Box::new(SystemClock))
}

pub(crate) fn build_runtime_oidc_provider_from(
    get: impl Fn(&str) -> Option<String>,
    clock: Box<dyn diport::Clock>,
) -> anyhow::Result<RuntimeOidcProvider> {
    let issuer = get("RSS_OIDC_ISSUER")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_OIDC_ISSUER"))?;
    let audience = get("RSS_OIDC_AUDIENCE")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_OIDC_AUDIENCE"))?;
    let trusted_kinds = get("RSS_OIDC_TRUSTED_KINDS")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_OIDC_TRUSTED_KINDS"))?;
    let jwks_path = get(OIDC_JWKS_PATH_ENV)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {OIDC_JWKS_PATH_ENV}"))?;
    let refresh_interval =
        oidc_jwks_refresh_interval_from(get(OIDC_JWKS_REFRESH_INTERVAL_ENV).as_deref())?;
    let jwks = oidc::JwksKeySource::load_and_watch(
        OIDC_JWKS_SOURCE_ID,
        PathBuf::from(jwks_path.trim()),
        refresh_interval,
        CancellationToken::new(),
    )
    .with_context(|| format!("load OIDC JWKS source from {OIDC_JWKS_PATH_ENV}"))?;
    let jwks_readiness = jwks.readiness_handle();

    let mut builder = oidc::VerifierConfigBuilder::new(&issuer, &audience)
        .keys_jwks(jwks)
        .service_token_replay_guard(Arc::new(RuntimeServiceTokenReplayGuard::default()));
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
    let config = builder
        .build()
        .map_err(|e| anyhow::anyhow!("invalid verifier config: {e}"))?;
    Ok(RuntimeOidcProvider {
        provider: Arc::new(OidcProvider::new(config, clock)),
        jwks_readiness,
    })
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

/// 从 env 构造生产验签 `OidcProvider`（issuer / audience / ES256·HS256 静态 key）。
///
/// - `RSS_OIDC_ISSUER` / `RSS_OIDC_AUDIENCE`：必填。
/// - `RSS_OIDC_TRUSTED_KINDS`：**必填**——本 IdP 可 assert 的 principal kind 逗号分隔白名单（如 `user,admin,device`）。
///   secure-by-default（OIDC-KIND-ALLOWLIST-01）：未配置则验签器剥离所有 kind → `Principal` 派生恒 `TokenInvalid`
///   → JWT **全 401**（评审 F1 修复的生产失效根因），故构造期 fail-fast 拒空。
/// - `RSS_OIDC_ES256_SEC1_B64URL`：JWT 路径 ES256 公钥，base64url(SEC1 未压缩点)，逗号分隔可多把（可选）。
/// - `RSS_OIDC_HS256_SECRET_B64URL`：service-token 路径 HS256 密钥，base64url（可选）。
/// - `RSS_OIDC_HS256_KID`：service-token 路径 key id；配置 HS256 secret 时必填。
///
/// 薄壳：注入 `std::env::var` 读取器，委托可测核心 [`build_provider_from`]。
pub fn build_provider() -> anyhow::Result<OidcProvider> {
    build_provider_from(|name| std::env::var(name).ok())
}

pub(crate) fn build_provider_with_replay_guard(
    replay_guard: Arc<dyn diport::ServiceTokenReplayGuard>,
) -> anyhow::Result<OidcProvider> {
    build_provider_from_with_replay_guard(|name| std::env::var(name).ok(), Some(replay_guard))
}

/// 由注入的配置读取器构造 `OidcProvider`（DI：测试传 fake getter，无 env 副作用——workspace `forbid(unsafe)`
/// 下测试不能 `set_var`，故读取器入参化）。错误只含变量**名**，不含值（无 PII / 无 secret 泄漏）。
pub(crate) fn build_provider_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<OidcProvider> {
    build_provider_from_with_replay_guard(get, None)
}

fn build_provider_from_with_replay_guard(
    get: impl Fn(&str) -> Option<String>,
    replay_guard: Option<Arc<dyn diport::ServiceTokenReplayGuard>>,
) -> anyhow::Result<OidcProvider> {
    let issuer = get("RSS_OIDC_ISSUER")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_OIDC_ISSUER"))?;
    let audience = get("RSS_OIDC_AUDIENCE")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_OIDC_AUDIENCE"))?;
    let trusted_kinds = get("RSS_OIDC_TRUSTED_KINDS")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_OIDC_TRUSTED_KINDS"))?;
    provider_from_b64_with_replay_guard(
        &issuer,
        &audience,
        &trusted_kinds,
        get("RSS_OIDC_ES256_SEC1_B64URL").as_deref(),
        get("RSS_OIDC_HS256_SECRET_B64URL").as_deref(),
        get("RSS_OIDC_HS256_KID").as_deref(),
        ProviderAuthDeps {
            clock: Box::new(SystemClock),
            replay_guard,
        },
    )
}

/// 由已读出的配置串装配生产 `OidcProvider`（纯函数，无 env 副作用——**生产装配唯一路径**，e2e 经此覆盖以杜绝
/// 测试/生产配置漂移，评审 F2）。
///
/// - `trusted_kinds_csv`：逗号分隔 trusted principal kind（`.trust_kind` 白名单，OIDC-KIND-ALLOWLIST-01）；解析后
///   **空集 fail-fast**——无 trusted kind 的 provider 验签 JWT 恒剥离 kind → 派生 `TokenInvalid` → 全 401（F1 根因）。
/// - `es256_csv` = 逗号分隔 base64url(SEC1 未压缩点)；`hs256_b64` = base64url HS256 密钥。两集皆空时
///   `VerifierConfigBuilder::build` fail-fast 拒（无 key 的 provider 验签恒失败、是配置错误）。
/// - `clock`：验签时钟（构造器位置参，rust-standards「Clock 是构造器位置参」）。生产传 [`SystemClock`]，
///   e2e 传 `FixedClock` 经**同一生产装配路径**覆盖（评审 F2：杜绝测试/生产配置漂移）。
pub fn provider_from_b64(
    issuer: &str,
    audience: &str,
    trusted_kinds_csv: &str,
    es256_csv: Option<&str>,
    hs256_b64: Option<&str>,
    hs256_kid: Option<&str>,
    clock: Box<dyn diport::Clock>,
) -> anyhow::Result<OidcProvider> {
    provider_from_b64_with_replay_guard(
        issuer,
        audience,
        trusted_kinds_csv,
        es256_csv,
        hs256_b64,
        hs256_kid,
        ProviderAuthDeps {
            clock,
            replay_guard: None,
        },
    )
}

struct ProviderAuthDeps {
    clock: Box<dyn diport::Clock>,
    replay_guard: Option<Arc<dyn diport::ServiceTokenReplayGuard>>,
}

fn provider_from_b64_with_replay_guard(
    issuer: &str,
    audience: &str,
    trusted_kinds_csv: &str,
    es256_csv: Option<&str>,
    hs256_b64: Option<&str>,
    hs256_kid: Option<&str>,
    deps: ProviderAuthDeps,
) -> anyhow::Result<OidcProvider> {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut keys = oidc::StaticKeySource::builder();
    if let Some(es) = es256_csv {
        for part in es.split(',').filter(|s| !s.is_empty()) {
            let sec1 = b64
                .decode(part)
                .context("RSS_OIDC_ES256_SEC1_B64URL not valid base64url")?;
            keys = keys
                .add_es256_sec1(&sec1)
                .map_err(|e| anyhow::anyhow!("invalid ES256 key: {e}"))?;
        }
    }
    if let Some(hs) = hs256_b64 {
        let kid = hs256_kid
            .filter(|kid| !kid.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_OIDC_HS256_KID"))?;
        let secret = b64
            .decode(hs)
            .context("RSS_OIDC_HS256_SECRET_B64URL not valid base64url")?;
        keys = keys
            .add_hs256_secret_with_kid(kid, &secret)
            .map_err(|e| anyhow::anyhow!("weak HS256 secret: {e}"))?;
    }

    let mut builder = oidc::VerifierConfigBuilder::new(issuer, audience).keys(keys.build());
    if hs256_b64.is_some() {
        builder = builder.service_token_replay_guard(
            deps.replay_guard
                .unwrap_or_else(|| Arc::new(RuntimeServiceTokenReplayGuard::default())),
        );
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
        // F1 根因 fail-fast：无 trusted kind ⇒ JWT 的 kind 被剥离 ⇒ Principal 派生 TokenInvalid ⇒ 全 401。
        anyhow::bail!(
            "RSS_OIDC_TRUSTED_KINDS must list ≥1 trusted principal kind (else all JWTs 401)"
        );
    }
    let config = builder
        .build()
        .map_err(|e| anyhow::anyhow!("invalid verifier config: {e}"))?;
    Ok(OidcProvider::new(config, deps.clock))
}

#[cfg(test)]
mod tests {
    use super::*;

    const B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn clk() -> Box<dyn diport::Clock> {
        Box::new(crate::SystemClock)
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

    fn runtime_oidc_get(
        jwks_path: &std::path::Path,
        refresh_interval: Option<&str>,
        name: &str,
    ) -> Option<String> {
        match name {
            "RSS_OIDC_ISSUER" => Some("https://issuer.test".to_string()),
            "RSS_OIDC_AUDIENCE" => Some("rss-test".to_string()),
            "RSS_OIDC_TRUSTED_KINDS" => Some("service,user,admin".to_string()),
            OIDC_JWKS_PATH_ENV => Some(jwks_path.display().to_string()),
            OIDC_JWKS_REFRESH_INTERVAL_ENV => refresh_interval.map(str::to_owned),
            _ => None,
        }
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

    #[test]
    fn build_runtime_oidc_provider_from_missing_jwks_path_fails_fast() {
        let result = build_runtime_oidc_provider_from(
            |name| match name {
                "RSS_OIDC_ISSUER" => Some("https://issuer.test".to_string()),
                "RSS_OIDC_AUDIENCE" => Some("rss-test".to_string()),
                "RSS_OIDC_TRUSTED_KINDS" => Some("service".to_string()),
                _ => None,
            },
            clk(),
        );
        assert!(
            matches!(&result, Err(err) if err.to_string().contains(OIDC_JWKS_PATH_ENV)),
            "runtime listener OIDC provider must require JWKS path"
        );
    }

    #[tokio::test]
    async fn build_runtime_oidc_provider_from_invalid_jwks_path_fails_fast() {
        let missing = unique_temp_path("missing-runtime-jwks.json");
        let result =
            build_runtime_oidc_provider_from(|name| runtime_oidc_get(&missing, None, name), clk());
        assert!(
            matches!(&result, Err(err) if format!("{err:#}").contains(OIDC_JWKS_PATH_ENV)),
            "bad JWKS path should fail during runtime OIDC provider construction"
        );
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
        let runtime = build_runtime_oidc_provider_from(
            |name| runtime_oidc_get(&jwks_path, None, name),
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
        let runtime = build_runtime_oidc_provider_from(
            |name| runtime_oidc_get(&jwks_path, Some("5"), name),
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
    fn provider_from_b64_empty_keys_fails_fast() {
        // 无任何 key → VerifierConfigBuilder::build fail-fast（无 key 的 provider 是配置错误）。
        assert!(
            provider_from_b64(
                "https://issuer.test",
                "rss",
                "user",
                None,
                None,
                None,
                clk()
            )
            .is_err()
        );
    }

    #[test]
    fn provider_from_b64_empty_trusted_kinds_fails_fast() {
        // 评审 F1：无 trusted kind ⇒ JWT kind 被剥离 ⇒ 派生 TokenInvalid ⇒ 全 401，构造期 fail-fast 拒。
        let secret = B64.encode([7u8; 32]);
        let r = provider_from_b64(
            "https://issuer.test",
            "rss",
            "  ,  ",
            None,
            Some(&secret),
            Some("cell-a.svc-a"),
            clk(),
        );
        assert!(matches!(&r, Err(e) if e.to_string().contains("RSS_OIDC_TRUSTED_KINDS")));
    }

    #[test]
    fn build_provider_from_missing_trusted_kinds_fails_fast() {
        // issuer + audience 在、trusted kinds 缺 → fail-fast（F1 生产失效根因守）。
        let get = |k: &str| match k {
            "RSS_OIDC_ISSUER" => Some("https://issuer.test".to_string()),
            "RSS_OIDC_AUDIENCE" => Some("rss".to_string()),
            _ => None,
        };
        assert!(
            matches!(&build_provider_from(get), Err(e) if e.to_string().contains("RSS_OIDC_TRUSTED_KINDS"))
        );
    }

    #[test]
    fn build_provider_from_missing_issuer_fails_fast() {
        // 注入恒空读取器 → 缺 RSS_OIDC_ISSUER fail-fast（错误含变量名，不读真 env）。
        // OidcProvider 无 Debug（不能 expect_err），用 matches! 既断言 Err 又锁错误文案。
        let result = build_provider_from(|_| None);
        assert!(matches!(&result, Err(e) if e.to_string().contains("RSS_OIDC_ISSUER")));
    }

    #[test]
    fn build_provider_from_missing_audience_fails_fast() {
        // issuer 存在、audience 缺失 → fail-fast 命中 audience 那行（独立于 issuer 缺失路径）。
        let get = |k: &str| (k == "RSS_OIDC_ISSUER").then(|| "https://issuer.test".to_string());
        let result = build_provider_from(get);
        assert!(matches!(&result, Err(e) if e.to_string().contains("RSS_OIDC_AUDIENCE")));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_provider_from_happy_hs256() {
        let secret = B64.encode([7u8; 32]);
        let get = |k: &str| match k {
            "RSS_OIDC_ISSUER" => Some("https://issuer.test".to_string()),
            "RSS_OIDC_AUDIENCE" => Some("rss".to_string()),
            "RSS_OIDC_TRUSTED_KINDS" => Some("user,admin".to_string()),
            "RSS_OIDC_HS256_SECRET_B64URL" => Some(secret.clone()),
            "RSS_OIDC_HS256_KID" => Some("cell-a.svc-a".to_string()),
            _ => None,
        };
        build_provider_from(get).expect("issuer + aud + trusted kinds + hs256 key ⇒ 构造成功");
    }

    #[test]
    fn provider_from_b64_bad_base64_fails_fast() {
        // ES256 串非 base64url → fail-fast（误配在 setup 期暴露，非运行时静默）。
        let bad = provider_from_b64(
            "https://issuer.test",
            "rss",
            "user",
            Some("!!not-b64!!"),
            None,
            None,
            clk(),
        );
        assert!(bad.is_err());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn provider_from_b64_with_hs256_ok() {
        let secret = B64.encode([7u8; 32]);
        let p = provider_from_b64(
            "https://issuer.test",
            "rss",
            "user",
            None,
            Some(&secret),
            Some("cell-a.svc-a"),
            clk(),
        );
        assert!(
            p.is_ok(),
            "有效 HS256 key + issuer/aud + trusted kind ⇒ 构造成功"
        );
        let _ = p.expect("ok");
    }
}
