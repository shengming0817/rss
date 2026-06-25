//! rss — RSS 组合根（Root 层）：从配置构造生产验签 provider，按 listener 装配
//! `finalize_routes → finalize_auth → .layer(verify_bridge)` 的认证接线接缝。
//!
//! 本 crate（#1198 / T004 / PR-C）只落地**认证接线接缝 + e2e**；socket bind / `axum::serve` / 信号优雅关停 /
//! 全量生产域注册 / 全量 config 编排 = **Join #1017**。live JWKS 远程拉取 + 轮转 = **T003/#1197**（本 PR 用
//! `StaticKeySource` 构造期注入 key，构造器签名已为其留稳）。
//!
//! 安全同批门（ADR-006 §5）：依赖图引真 verifier（`oidc` backend）、不引 stub Pdp（`memory` 经 deny.toml 禁
//! server/rss；bins 生产 `src/` 无内联 `impl diport::Pdp`，`rss_pdp_impl_adapter_only` dylint 守 +
//! `cargo xtask verify` 的 pdp-allow 计数门守逃生门用量）。`OidcProvider` 必填 `VerifierConfig` + `Box<dyn Clock>`
//! ⇒ 无 key/clock 不可构造（编译期守）。
//!
//! NOTE: `bins/server` 与 `bins/rss` 的 `auth_bridge.rs` / `lib.rs` / `tests/auth_e2e.rs` **字节级同步**
//! （仅 crate 名不同，tasks.md T004.2 既定 duplicate-now）；改一处须同步另一处；逻辑增长时提取 `assemblies/authwire` 再删副本。

pub mod auth_bridge;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Context as _;
use base64::Engine as _;
use diport::DynSecretResolver;
use oidc::OidcProvider;
use postgres::{PgConfig, PgPassword, PgSecretRepo, PgStore, PoolReadiness};
use primitives::{
    AuthPlan, AuthScheme, HealthCheck, HealthStatus, ListenerKind, ProbeName, RequiredScheme,
};
use settings::{
    SecretService, SettingsDomain, SettingsService, empty_flag_store,
    ports::{DynConfigRepo, DynConfigUnitOfWork},
};
use vault::{TenantStoreAllowlist, VaultSecretResolver};

/// 生产系统时钟（组合根注入 `OidcProvider`）。
///
/// 组合根是 sanctioned 直读系统时钟点（`diport::Clock` rustdoc：「prod `SystemClock` 内部调 `SystemTime::now`，
/// 受 clippy `disallowed_methods` 约束、仅在 adapter / 组合根 item-level 解禁」）。
pub struct SystemClock;

impl diport::Clock for SystemClock {
    fn now(&self) -> SystemTime {
        // reason: 组合根生产时钟——唯一 sanctioned 直读系统时钟点（rust-standards「Clock 构造器位置参」的 prod 实现）。
        #[allow(clippy::disallowed_methods)]
        SystemTime::now()
    }
}

/// 从 env 构造生产验签 `OidcProvider`（issuer / audience / ES256·HS256 静态 key）。
///
/// - `RSS_OIDC_ISSUER` / `RSS_OIDC_AUDIENCE`：必填。
/// - `RSS_OIDC_TRUSTED_KINDS`：**必填**——本 IdP 可 assert 的 principal kind 逗号分隔白名单（如 `user,admin,device`）。
///   secure-by-default（OIDC-KIND-ALLOWLIST-01）：未配置则验签器剥离所有 kind → `Principal` 派生恒 `TokenInvalid`
///   → JWT **全 401**（评审 F1 修复的生产失效根因），故构造期 fail-fast 拒空。
/// - `RSS_OIDC_ES256_SEC1_B64URL`：JWT 路径 ES256 公钥，base64url(SEC1 未压缩点)，逗号分隔可多把（可选）。
/// - `RSS_OIDC_HS256_SECRET_B64URL`：service-token 路径 HS256 密钥，base64url（可选）。
///
/// 薄壳：注入 `std::env::var` 读取器，委托可测核心 [`build_provider_from`]。
pub fn build_provider() -> anyhow::Result<OidcProvider> {
    build_provider_from(|name| std::env::var(name).ok())
}

/// 由注入的配置读取器构造 `OidcProvider`（DI：测试传 fake getter，无 env 副作用——workspace `forbid(unsafe)`
/// 下测试不能 `set_var`，故读取器入参化）。错误只含变量**名**，不含值（无 PII / 无 secret 泄漏）。
fn build_provider_from(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<OidcProvider> {
    let issuer = get("RSS_OIDC_ISSUER")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_OIDC_ISSUER"))?;
    let audience = get("RSS_OIDC_AUDIENCE")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_OIDC_AUDIENCE"))?;
    let trusted_kinds = get("RSS_OIDC_TRUSTED_KINDS")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_OIDC_TRUSTED_KINDS"))?;
    provider_from_b64(
        &issuer,
        &audience,
        &trusted_kinds,
        get("RSS_OIDC_ES256_SEC1_B64URL").as_deref(),
        get("RSS_OIDC_HS256_SECRET_B64URL").as_deref(),
        Box::new(SystemClock),
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
    clock: Box<dyn diport::Clock>,
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
        let secret = b64
            .decode(hs)
            .context("RSS_OIDC_HS256_SECRET_B64URL not valid base64url")?;
        keys = keys
            .add_hs256_secret(&secret)
            .map_err(|e| anyhow::anyhow!("weak HS256 secret: {e}"))?;
    }

    let mut builder = oidc::VerifierConfigBuilder::new(issuer, audience).keys(keys.build());
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
    Ok(OidcProvider::new(config, clock))
}

/// listener → 认证方案策略（runtime-api.md §Listener：单 listener 单 scheme）。
fn auth_scheme(listener: ListenerKind) -> AuthScheme {
    match listener {
        ListenerKind::Primary | ListenerKind::Admin => AuthScheme::Jwt,
        ListenerKind::Internal => AuthScheme::ServiceToken,
        ListenerKind::Health => AuthScheme::NoAuth,
        // ListenerKind non_exhaustive——未知 listener fail-closed 要求 JWT 认证（绝不默认 NoAuth）+ 配置期 warn 埋点。
        _ => {
            tracing::warn!(listener = ?listener, "unknown ListenerKind; fail-closed to JWT auth scheme");
            AuthScheme::Jwt
        }
    }
}

/// listener → 验签桥应验证的方案（`NoAuth` listener 不挂桥 ⇒ `None`）。
///
/// `Mtls`（传输层鉴权，非本桥职责）与 `non_exhaustive` 未知方案均 → `None`（不挂桥 ⇒ 该 listener 的 Require
/// 路由由 enforce fail-closed 401）+ 配置期 warn 埋点（消除「required_scheme 说要 Mtls 桥、但 bridge 不支持 Mtls」
/// 的死代码 + 不一致，评审 F2）。
fn required_scheme(listener: ListenerKind) -> Option<RequiredScheme> {
    match auth_scheme(listener) {
        AuthScheme::Jwt | AuthScheme::JwtFromAssembly => Some(RequiredScheme::Jwt),
        AuthScheme::ServiceToken => Some(RequiredScheme::ServiceToken),
        AuthScheme::NoAuth => None,
        other => {
            tracing::warn!(scheme = ?other, "listener auth scheme has no verify-bridge; Require routes fail-closed 401");
            None
        }
    }
}

/// 排空 registry 的 per-listener `UnfinalizedRoutes`，按 listener 装配 `finalize_auth` + 外层验签桥。
///
/// 每 listener：`finalize_auth(routes, plan)`（消费 `UnfinalizedRoutes` 产 `AuthenticatedRoutes`，注入
/// AuthPlan 与 framework 中间件）→ 据 `required_scheme` 叠外层 `verify_bridge`（`NoAuth` listener 无桥）。
/// 产出 `AuthenticatedRoutes` 交 #1017 经 `into_make_service` 绑 socket + serve——bind 点天生只能消费已认证
/// router（ROUTE-AUTH-FUNNEL-01/02：未跑 finalize_auth 的 router 无 bindable 出口）。
pub fn assemble_authed_routers(
    mut registry: bootstrap::Registry,
    provider: Arc<OidcProvider>,
) -> anyhow::Result<Vec<(ListenerKind, httpserve::AuthenticatedRoutes)>> {
    let mut out = Vec::new();
    for (listener, routes) in registry.finalize_routes().context("finalize_routes")? {
        let scheme = auth_scheme(listener);
        let plan = AuthPlan::new(listener, scheme).context("build auth plan")?;
        let authed = httpserve::finalize_auth(routes, plan).context("finalize_auth")?;
        let required = required_scheme(listener);
        let wired = match required {
            Some(req) => auth_bridge::apply_verify_bridge(authed, provider.clone(), req),
            None => authed,
        };
        // 装配决策可观测：operator 启动时从日志核查每 listener 的 auth scheme + 是否挂验签桥
        //（闭值枚举，无 PII）——否则「Primary 究竟 Jwt+桥 还是意外 NoAuth」从日志无从核查。
        tracing::info!(
            listener = ?listener,
            auth_scheme = ?scheme,
            verify_bridge = required.is_some(),
            "listener auth wiring assembled"
        );
        out.push((listener, wired));
    }
    Ok(out)
}

// ── postgres 配置 wiring ─────────────────────────────────────────────────────────────────────

/// 从注入的配置读取器构造 `PgConfig`（fail-fast：任一必填 env 缺失立即返 `Err`）。
///
/// 必填变量：
/// - `RSS_PG_HOST` — postgres 主机（非空）。
/// - `RSS_PG_PORT` — postgres 端口（非零 u16，默认 5432 需显式声明）。
/// - `RSS_PG_DATABASE` — 数据库名（非空）。
/// - `RSS_PG_USERNAME` — 连接用户（非空）。
/// - `RSS_PG_PASSWORD` — 连接密码（非空）。
///
/// TLS 默认 `VerifyFull`（零信任）；生产须配私有 CA 证书（`PgConfig::with_ssl_root_cert` 待 Join #1017）。
/// **禁止 localhost fallback**（生产配置规范，rust-standards §安全检查点）。
pub(crate) fn build_pg_config_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<PgConfig> {
    let host = get("RSS_PG_HOST")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_PG_HOST"))?;
    let port_str = get("RSS_PG_PORT")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_PG_PORT"))?;
    let port: u16 = port_str.parse().with_context(|| {
        format!("RSS_PG_PORT must be a valid port number (1-65535): {port_str}")
    })?;
    let database = get("RSS_PG_DATABASE")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_PG_DATABASE"))?;
    let username = get("RSS_PG_USERNAME")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_PG_USERNAME"))?;
    let password = get("RSS_PG_PASSWORD")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_PG_PASSWORD"))?;

    // PgConfig::new 存储参数；validate 在 PgStore::connect 内调用（pub(crate)）。
    // 这里只做构造，连接时再 fail-fast（组合根在 wire_settings 中 connect）。
    Ok(PgConfig::new(
        host,
        port,
        database,
        username,
        PgPassword::new(password),
    ))
}

/// 从 `std::env` 构造 `PgConfig`。
pub fn build_pg_config() -> anyhow::Result<PgConfig> {
    build_pg_config_from(|name| std::env::var(name).ok())
}

// ── Vault secret resolver wiring ─────────────────────────────────────────────────────────────

/// 默认 Vault 请求超时（pre-GA 合理值；生产可经 env 覆盖，待 Join #1017）。
const DEFAULT_VAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// 启动时安全警告（pre-GA 安全警告，Finding 6）：系统默认 TLS + 空 allowlist。
// reason: tracing::warn! 宏展开在 clippy cognitive_complexity 计数时贡献额外节点，
// 实际控制流简单（2 warn！+ 1 if），item-level carve-out（error-handling.md §Carve-out）。
#[allow(clippy::cognitive_complexity)]
fn warn_vault_startup_security(stores: &TenantStoreAllowlist) {
    tracing::warn!(
        reason = "system-default-tls",
        "vault client using system-default TLS; production must configure rustls+ring (#1017)"
    );
    if stores.is_empty() {
        tracing::warn!(
            reason = "empty-allowlist",
            "vault TenantStoreAllowlist is empty: all secret resolve calls will return Forbidden (fail-closed); populate allowlist for production (#1272)"
        );
    }
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
    let addr = get("RSS_VAULT_ADDR")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_VAULT_ADDR"))?;
    let token = get("RSS_VAULT_TOKEN")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_VAULT_TOKEN"))?;

    // Join #1017: 配置 TLS client（rustls + ring，对齐 sqlx）；当前传 Client::new()（pre-GA）。
    let client = reqwest::Client::new();

    // pre-GA 空 allowlist：无生产 secret reader → 所有 resolve fail-closed Forbidden（网络前拦截）。
    // 待后续 issue 填充 TenantStoreAllowlist（per-store mount + prefix，#1272 follow-up）。
    let stores = TenantStoreAllowlist::new(std::iter::empty())
        .map_err(|e| anyhow::anyhow!("vault store allowlist config error: {e}"))?;

    warn_vault_startup_security(&stores);

    VaultSecretResolver::new(client, addr, token, DEFAULT_VAULT_TIMEOUT, stores)
        .map_err(|e| anyhow::anyhow!("vault resolver config error: {e}"))
}

// ── ConfigsReadyProbe ─────────────────────────────────────────────────────────────────────────

/// probe 探针稳定名（`ProbeName::parse` 校验合法字符；underscore_case，与 prometheus metric 约定一致）。
const CONFIGS_READY_PROBE_NAME: &str = "configs_ready";

/// postgres 连接池 readiness 探针——报告配置存储（postgres pool）当前状态。
///
/// `check`（sync，non-blocking）：读 `PgStore::pool_readiness()` 原子计数器，无 I/O：
/// - `PoolReadiness::Ready` → `Healthy`（`detail = "ready"`）
/// - `PoolReadiness::Saturated` → `Degraded`（`detail = "saturated"`）
/// - `PoolReadiness::Down` → `Unhealthy`（`detail = "down"`）
///
/// `detail` 固定 `&'static str` const（`HealthCheck::detail` 类型约束，禁夹带 runtime PII）。
pub struct ConfigsReadyProbe {
    store: Arc<PgStore>,
    /// 探针自报名（重建 `HealthCheck` 时 registry 使用声明名权威，此字段保留供 debug inspect）。
    name: ProbeName,
}

impl ConfigsReadyProbe {
    /// 构造 `ConfigsReadyProbe`。
    ///
    /// `name` 应使用 [`CONFIGS_READY_PROBE_NAME`] 常量以确保与 registry 声明名一致。
    #[allow(clippy::expect_used)]
    pub fn new(store: Arc<PgStore>) -> Self {
        // reason: CONFIGS_READY_PROBE_NAME 是 kebab-case const literal，ProbeName::parse 仅失败于
        // 非法字符；const 已手工验证，expect 是构造期 programmer error（此处不可恢复）。
        let name = ProbeName::parse(CONFIGS_READY_PROBE_NAME).expect("valid probe name const");
        Self { store, name }
    }
}

/// `PoolReadiness` → `(HealthStatus, detail)`（纯函数，可独立测试）。
fn readiness_to_health(r: PoolReadiness) -> (HealthStatus, &'static str) {
    match r {
        PoolReadiness::Ready => (HealthStatus::Healthy, "ready"),
        PoolReadiness::Saturated => (HealthStatus::Degraded, "saturated"),
        PoolReadiness::Down => (HealthStatus::Unhealthy, "down"),
        // reason: PoolReadiness 是 non_exhaustive；未知变体 fail-closed（Unhealthy）。
        _ => (HealthStatus::Unhealthy, "unknown"),
    }
}

impl bootstrap::HealthProbe for ConfigsReadyProbe {
    fn check(&self) -> HealthCheck {
        let (status, detail) = readiness_to_health(self.store.pool_readiness());
        HealthCheck::new(self.name.clone(), status, detail)
    }
}

// ── settings + secret wiring ─────────────────────────────────────────────────────────────────

/// 接线 settings 域：构造 `SettingsService` + `SecretService`，注册 `ConfigsReadyProbe`。
///
/// - `store`：已建 `PgStore`（`Arc` 共享给 probe + repo）。
/// - `registry`：bootstrap registry，用于注册 `ConfigsReadyProbe`（`probe` 方法）。
///
/// 返回 `(SettingsService, SecretService)` 供组合根继续组装（#1017 绑 domain + serve）。
///
/// # 注意
///
/// 当前 `empty_flag_store()` 返回空 in-mem store（`seed-data` feature，fail-closed 语义）；
/// 生产 flag store 待 #1120。
pub async fn wire_settings(
    store: Arc<PgStore>,
    registry: &mut bootstrap::Registry,
) -> anyhow::Result<(SettingsService, SecretService)> {
    // 注册 configs_ready probe（bootstrap 声明名权威，重建 HealthCheck 时用声明名）。
    let probe_name = ProbeName::parse(CONFIGS_READY_PROBE_NAME)
        .context("configs_ready probe name is invalid")?;
    registry
        .probe(probe_name, Box::new(ConfigsReadyProbe::new(store.clone())))
        .context("register configs_ready probe")?;

    // 构造 vault resolver（pre-GA 空 allowlist → 所有 resolve fail-closed Forbidden）。
    let resolver = build_vault_resolver_from(|name| std::env::var(name).ok())
        .context("vault resolver config")?;

    // PgConfigRepo / PgSecretRepo 持 pool clone（内部 Arc，轻量），接受 &PgStore。
    let config_repo_r = postgres::PgConfigRepo::new(&store, Box::new(SystemClock));
    let config_repo_w = postgres::PgConfigRepo::new(&store, Box::new(SystemClock));
    let pg_secret_repo = PgSecretRepo::new(&store);

    let settings_svc = SettingsService::with_postgres(
        DynConfigRepo::new_box(config_repo_r),
        DynConfigUnitOfWork::new_box(config_repo_w),
        empty_flag_store(),
        Box::new(SystemClock),
    );

    let secret_svc = SecretService::with_postgres(
        settings::ports::DynSecretRepo::new_box(pg_secret_repo),
        DynSecretResolver::new_box(resolver),
        Box::new(SystemClock),
    );

    Ok((settings_svc, secret_svc))
}

/// 生产组合根入口：构造 provider → compose 域 → 装配认证接线。
///
/// settings + secret wiring 待 Join #1017（`wire_settings` 已就位，`run` 内待接线）。
/// socket bind / serve / 信号优雅关停 = **Join #1017**。
pub fn run() -> anyhow::Result<()> {
    let provider = Arc::new(build_provider()?);
    // settings domain 已注册（#1272/#1274）；wire_settings 在 Join #1017 接线（需异步 PgStore::connect）。
    let registry = bootstrap::compose(&[&SettingsDomain]).context("compose domains")?;
    let _authed = assemble_authed_routers(registry, provider)?;
    // TODO(#1017): 消费 `_authed`——对每个 `(listener, AuthenticatedRoutes)` 调 `.into_make_service()`（**唯一**
    //   bindable 出口，ROUTE-AUTH-FUNNEL-02）→ `axum::serve(<该 listener 的 socket>, make_service)`；+ 信号优雅
    //   关停 + 全量生产域注册（identity/settings/audit/...）+ PgStore::connect + run_migrations + wire_settings
    //   （生产 settings/secret wiring，C2/#1309）。`_authed` 当前被 drop（bind 点未接线）；接线时勿绕开
    //   `into_make_service` 改走裸 router 路径（类型层已封死，见 httpserve::routes）。
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE_NO_PAD;

    /// 测试时钟（这些测试只验构造成功/失败，不验 token exp，故 SystemClock 即可）。
    fn clk() -> Box<dyn diport::Clock> {
        Box::new(SystemClock)
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn auth_scheme_per_listener() {
        assert_eq!(auth_scheme(ListenerKind::Primary), AuthScheme::Jwt);
        assert_eq!(auth_scheme(ListenerKind::Admin), AuthScheme::Jwt);
        assert_eq!(
            auth_scheme(ListenerKind::Internal),
            AuthScheme::ServiceToken
        );
        assert_eq!(auth_scheme(ListenerKind::Health), AuthScheme::NoAuth);
    }

    #[test]
    fn required_scheme_maps_and_health_is_none() {
        assert_eq!(
            required_scheme(ListenerKind::Primary),
            Some(RequiredScheme::Jwt)
        );
        assert_eq!(
            required_scheme(ListenerKind::Internal),
            Some(RequiredScheme::ServiceToken)
        );
        assert_eq!(required_scheme(ListenerKind::Health), None);
    }

    #[test]
    fn provider_from_b64_empty_keys_fails_fast() {
        // 无任何 key → VerifierConfigBuilder::build fail-fast（无 key 的 provider 是配置错误）。
        assert!(
            provider_from_b64("https://issuer.test", "rss", "user", None, None, clk()).is_err()
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
            _ => None,
        };
        build_provider_from(get).expect("issuer + aud + trusted kinds + hs256 key ⇒ 构造成功");
    }

    #[test]
    fn system_clock_now_is_after_epoch() {
        use diport::Clock as _;
        // 覆盖组合根生产时钟读点（disallowed_methods item-level 解禁线）。
        assert!(SystemClock.now() > SystemTime::UNIX_EPOCH);
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
            clk(),
        );
        assert!(
            p.is_ok(),
            "有效 HS256 key + issuer/aud + trusted kind ⇒ 构造成功"
        );
        let _ = p.expect("ok");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn assemble_empty_registry_yields_no_routers() {
        let secret = B64.encode([7u8; 32]);
        let provider = Arc::new(
            provider_from_b64(
                "https://issuer.test",
                "rss",
                "user",
                None,
                Some(&secret),
                clk(),
            )
            .expect("provider"),
        );
        let registry = bootstrap::compose(&[]).expect("compose empty");
        let routers = assemble_authed_routers(registry, provider).expect("assemble ok");
        assert!(routers.is_empty(), "空域图 ⇒ 无 per-listener router");
    }

    // ── build_pg_config_from 测试 ──────────────────────────────────────────────────────────

    fn full_pg_get(k: &str) -> Option<String> {
        match k {
            "RSS_PG_HOST" => Some("pg.internal".to_string()),
            "RSS_PG_PORT" => Some("5432".to_string()),
            "RSS_PG_DATABASE" => Some("rss_db".to_string()),
            "RSS_PG_USERNAME" => Some("rss_user".to_string()),
            "RSS_PG_PASSWORD" => Some("s3cr3t".to_string()),
            _ => None,
        }
    }

    /// 全必填 env 均有 → 构造成功。
    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_from_happy() {
        let cfg = build_pg_config_from(full_pg_get).expect("all required vars present");
        // 验证 host 被记录（不泄露 password，只断言端口和 host 可 debug 比较）。
        let debug = format!("{cfg:?}");
        assert!(debug.contains("pg.internal"), "host 在 debug 输出中");
        assert!(!debug.contains("s3cr3t"), "password 不在 debug 输出中");
    }

    /// `RSS_PG_HOST` 缺失 → Err 含变量名（fail-fast）。
    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_from_missing_host() {
        let get = |k: &str| {
            if k == "RSS_PG_HOST" {
                None
            } else {
                full_pg_get(k)
            }
        };
        let err = build_pg_config_from(get).expect_err("host required");
        assert!(
            err.to_string().contains("RSS_PG_HOST"),
            "error contains var name"
        );
    }

    /// `RSS_PG_PASSWORD` 缺失 → Err 含变量名（fail-fast）。
    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_from_missing_password() {
        let get = |k: &str| {
            if k == "RSS_PG_PASSWORD" {
                None
            } else {
                full_pg_get(k)
            }
        };
        let err = build_pg_config_from(get).expect_err("password required");
        assert!(
            err.to_string().contains("RSS_PG_PASSWORD"),
            "error contains var name"
        );
    }

    /// `RSS_PG_PORT` 缺失 → Err 含变量名（fail-fast）。
    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_from_missing_port() {
        let get = |k: &str| {
            if k == "RSS_PG_PORT" {
                None
            } else {
                full_pg_get(k)
            }
        };
        let err = build_pg_config_from(get).expect_err("port required");
        assert!(
            err.to_string().contains("RSS_PG_PORT"),
            "error contains var name"
        );
    }

    /// 默认 TLS 模式 = VerifyFull（零信任；禁 localhost 回退）。
    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_defaults_ssl_verify_full() {
        use postgres::PgSslMode;
        let cfg = build_pg_config_from(full_pg_get).expect("ok");
        // PgConfig 的 ssl_mode 字段私有，经 connect_options() 读取；此处通过 debug 输出检查（适度）。
        // VerifyFull 是安全默认值（rust-standards §安全检查点）。
        let debug = format!("{cfg:?}");
        assert!(
            debug.contains("VerifyFull"),
            "默认 TLS = VerifyFull，但 debug 输出为: {debug}"
        );
        // 通过 fn-pointer smoke 绑定确认 PgSslMode::VerifyFull 变体可构造（Anti-vacuity）。
        let _mode: PgSslMode = PgSslMode::VerifyFull;
    }

    // ── ConfigsReadyProbe / readiness_to_health 测试 ─────────────────────────────────────

    /// `PoolReadiness::Ready` → `(Healthy, "ready")`。
    #[test]
    fn configs_ready_maps_ready_to_healthy() {
        let (status, detail) = readiness_to_health(PoolReadiness::Ready);
        assert_eq!(status, HealthStatus::Healthy);
        assert_eq!(detail, "ready");
    }

    /// `PoolReadiness::Down` → `(Unhealthy, "down")`。
    #[test]
    fn configs_ready_maps_down_to_unhealthy() {
        let (status, detail) = readiness_to_health(PoolReadiness::Down);
        assert_eq!(status, HealthStatus::Unhealthy);
        assert_eq!(detail, "down");
    }

    /// `PoolReadiness::Saturated` → `(Degraded, "saturated")`。
    #[test]
    fn configs_ready_maps_saturated_to_degraded() {
        let (status, detail) = readiness_to_health(PoolReadiness::Saturated);
        assert_eq!(status, HealthStatus::Degraded);
        assert_eq!(detail, "saturated");
    }

    /// detail 是 `&'static str`（编译期类型约束；类型已由 HealthCheck::detail() -> &'static str 守）。
    #[test]
    fn configs_ready_detail_is_static() {
        // `readiness_to_health` 返回 `(HealthStatus, &'static str)`——类型级 Hard 约束。
        // 赋值为 `&'static str` 类型绑定即证明（如果改返 String，此处编译失败）。
        let (_status, detail): (HealthStatus, &'static str) =
            readiness_to_health(PoolReadiness::Ready);
        let _ = detail;
    }

    /// `CONFIGS_READY_PROBE_NAME` 是合法 `ProbeName`（`ProbeName::parse` 校验 kebab-case 字符集）。
    /// registry.probe 接受注册 + 重复注册返 Err（probe 名唯一性守）。
    #[test]
    #[allow(clippy::expect_used)]
    fn configs_ready_registers_and_is_unique() {
        // reason: CONFIGS_READY_PROBE_NAME 是 const literal，parse 只可能在字符非法时失败。
        let probe_name_a =
            primitives::ProbeName::parse(CONFIGS_READY_PROBE_NAME).expect("valid probe name const");
        let probe_name_b =
            primitives::ProbeName::parse(CONFIGS_READY_PROBE_NAME).expect("valid probe name const");
        let mut registry = bootstrap::compose(&[&SettingsDomain]).expect("compose settings");

        // 注册一个实现了 HealthProbe 的占位 probe（不需要 PgStore，不连 DB）。
        struct NullProbe;
        impl bootstrap::HealthProbe for NullProbe {
            fn check(&self) -> HealthCheck {
                let name = primitives::ProbeName::parse("configs_ready").expect("valid");
                HealthCheck::new(name, HealthStatus::Healthy, "null")
            }
        }

        // 第一次注册成功。
        registry
            .probe(probe_name_a, Box::new(NullProbe))
            .expect("first register ok");

        // 重复注册同名 probe → Err（bootstrap registry 守唯一性）。
        let result = registry.probe(probe_name_b, Box::new(NullProbe));
        assert!(result.is_err(), "duplicate probe name should be rejected");
    }
}
