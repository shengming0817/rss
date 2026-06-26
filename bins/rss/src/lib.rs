//! rss — RSS 组合根（Root 层）：从配置构造生产验签 provider，按 listener 装配
//! `finalize_routes → finalize_auth → .layer(verify_bridge)` 的认证接线接缝，并驱动运行时入口
//! （tokio 运行时 + per-listener socket bind + `axum::serve` + 信号优雅关停 + wire_X call-site，#1320）。
//!
//! 运行时入口（[`run`]，#1320 Join）：`compose` 域 → `PgStore::connect` + migrations → `wire_settings`
//! （注册 `configs_ready` probe）→ `assemble_authed_routers` → 组合根挂 Health listener（healthz/readyz）→
//! 逐 listener bind socket + serve（经 `httpd::HttpServer` + `bootstrap::ShutdownStack`）→ SIGTERM/SIGINT
//! 优雅 drain。各域业务 handler ↔ service 接线 = #1309 及后续域 PR（本 PR 仅打通 async runtime、wire_X
//! call-site 与 readiness probe）。live JWKS 远程拉取 + 轮转 = **T003/#1197**（本 PR 用 `StaticKeySource`
//! 构造期注入 key，构造器签名已为其留稳）。listener / pg / vault 传输层 TLS（rustls+ring）= 后续 TLS 切片。
//!
//! 安全同批门（ADR-006 §5）：依赖图引真 verifier（`oidc` backend）、不引 stub Pdp（`memory` 经 deny.toml 禁
//! server/rss；bins 生产 `src/` 无内联 `impl diport::Pdp`，`rss_pdp_impl_adapter_only` dylint 守 +
//! `cargo xtask verify` 的 pdp-allow 计数门守逃生门用量）。`OidcProvider` 必填 `VerifierConfig` + `Box<dyn Clock>`
//! ⇒ 无 key/clock 不可构造（编译期守）。
//!
//! NOTE: `bins/server` 与 `bins/rss` 的 `auth_bridge.rs` / `lib.rs` / `tests/auth_e2e.rs` **字节级同步**
//! （仅 crate 名不同，tasks.md T004.2 既定 duplicate-now）；改一处须同步另一处；逻辑增长时提取 `assemblies/authwire` 再删副本。

pub mod auth_bridge;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Context as _;
use axum::http::Method;
use base64::Engine as _;
use bootstrap::shutdown::ShutdownStack;
use diport::{DynManagedResource, DynSecretResolver};
use httpd::HttpServer;
use oidc::OidcProvider;
use postgres::{PgConfig, PgPassword, PgSecretRepo, PgStore, PoolReadiness};
use primitives::{
    AuthPlan, AuthScheme, HealthCheck, HealthStatus, ListenerKind, ProbeName, RequiredScheme,
};
use settings::{
    SecretService, SettingsDomain, SettingsService, empty_flag_store,
    ports::{DynConfigRepo, DynConfigUnitOfWork},
};
use tokio_util::sync::CancellationToken;
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
/// 产出 `AuthenticatedRoutes` 经 `into_make_service` 绑 socket + serve（[`serve_until_signal`]）——bind 点
/// 天生只能消费已认证 router（ROUTE-AUTH-FUNNEL-01/02：未跑 finalize_auth 的 router 无 bindable 出口）。
///
/// 借 `&mut Registry`（仅 drain `finalize_routes`，**不**消费）：registry 的探针在此后仍存活，组合根经
/// [`bootstrap::Registry::take_health_reporter`] 取出探针装入 `Arc<HealthReporter>`（`Send + Sync`）注入
/// Health listener 的 readyz handler（每请求 `report`，[`health_listener`]）；整体非 `Sync` 的 `Registry`
/// 无法进 axum handler 闭包。
pub fn assemble_authed_routers(
    registry: &mut bootstrap::Registry,
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
/// TLS 默认 `VerifyFull`（零信任）；生产须配私有 CA 证书（`PgConfig::with_ssl_root_cert` 待后续 TLS 切片，
/// rustls+ring，pg/vault/listener 同批——非本运行时入口 #1320 范围）。
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

/// 默认 Vault 请求超时（pre-GA 合理值；生产可经 env 覆盖，待后续 Vault 配置切片——非 #1320 范围）。
const DEFAULT_VAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// 启动时安全警告（pre-GA 安全警告，Finding 6）：系统默认 TLS + 空 allowlist。
// reason: tracing::warn! 宏展开在 clippy cognitive_complexity 计数时贡献额外节点，
// 实际控制流简单（2 warn！+ 1 if），item-level carve-out（error-handling.md §Carve-out）。
#[allow(clippy::cognitive_complexity)]
fn warn_vault_startup_security(stores: &TenantStoreAllowlist) {
    tracing::warn!(
        reason = "system-default-tls",
        "vault client using system-default TLS; production must configure rustls+ring (后续 TLS 切片)"
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

    // 后续 TLS 切片: 配置 TLS client（rustls + ring，对齐 sqlx）；当前传 Client::new()（pre-GA，非 #1320 范围）。
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
/// 返回 `(SettingsService, SecretService)` 供组合根继续组装（业务 handler ↔ service 接线 = #1309 及后续
/// 域 PR；本 PR #1320 仅打通 async runtime + wire_X call-site + `configs_ready` probe 注册）。
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

// ── Health listener（框架/组合根归属：healthz + readyz）─────────────────────────────────────────

/// Health listener 路由组前缀（liveness/readiness 在专用 listener 上；operator 配 k8s probe 路径指向此前缀下）。
const HEALTH_ROUTE_PREFIX: &str = "/health/v1";
/// liveness 端点契约 ID（框架归属基础设施探针，非域 wire 契约）。
const HEALTHZ_CONTRACT_ID: &str = "framework.healthz";
/// readiness 端点契约 ID（框架归属）。
const READYZ_CONTRACT_ID: &str = "framework.readyz";

/// 构造 Health listener 的已认证路由（`/health/v1/healthz` liveness + `/health/v1/readyz` readiness）。
///
/// Health 是**框架/组合根**归属：域 crate 不声明 health 路由组，组合根在此经公开 funnel
/// （`UnfinalizedRoutes::empty().nest_group::<Health>` → `finalize_auth`）挂载——产物仍是 `AuthenticatedRoutes`
/// （ROUTE-AUTH-FUNNEL：health router 也经 finalize_auth + request_id/trace 中间件，与业务 listener 一致）。
/// `NoAuth` plan（Health listener 无验签桥）。readyz handler 闭包持 `Arc<HealthReporter>`（`Send + Sync`，
/// 整体非 `Sync` 的 `Registry` 无法进 handler）每请求 `report`（worst-of 聚合所有已注册探针，含 `configs_ready`）。
///
/// `pub`：供冒烟 e2e（`tests/runtime_serve_e2e.rs`）经真实 socket 绑定验证 serve + readyz + 优雅关停闭环。
pub fn health_listener(
    reporter: Arc<bootstrap::HealthReporter>,
) -> anyhow::Result<(ListenerKind, httpserve::AuthenticatedRoutes)> {
    let routes = httpserve::UnfinalizedRoutes::empty()
        .nest_group::<httpserve::Health, core::convert::Infallible>(
            HEALTH_ROUTE_PREFIX,
            move |rb| {
                Ok(rb
                    .mount(
                        httpserve::Route {
                            method: Method::GET,
                            path: "/healthz",
                            contract_id: HEALTHZ_CONTRACT_ID,
                        },
                        httpserve::health::healthz(),
                    )
                    .mount(
                        httpserve::Route {
                            method: Method::GET,
                            path: "/readyz",
                            contract_id: READYZ_CONTRACT_ID,
                        },
                        httpserve::health::readyz(move || reporter.report()),
                    ))
            },
        )
        .context("nest health route group")?;
    let plan =
        AuthPlan::new(ListenerKind::Health, AuthScheme::NoAuth).context("health auth plan")?;
    let authed = httpserve::finalize_auth(routes, plan).context("finalize_auth health")?;
    Ok((ListenerKind::Health, authed))
}

// ── listener bind 地址（per-listener env，缺配 fail-fast）─────────────────────────────────────────

/// listener → bind 地址 env 变量名（`RSS_<LISTENER>_LISTEN_ADDR`，值为 `host:port` SocketAddr 串）。
///
/// `ListenerKind` 为 `non_exhaustive`：未知 listener 无 env、fail-fast（绝不静默 bind 未知 listener）。
fn listener_addr_env(listener: ListenerKind) -> anyhow::Result<&'static str> {
    Ok(match listener {
        ListenerKind::Primary => "RSS_PRIMARY_LISTEN_ADDR",
        ListenerKind::Internal => "RSS_INTERNAL_LISTEN_ADDR",
        ListenerKind::Admin => "RSS_ADMIN_LISTEN_ADDR",
        ListenerKind::Health => "RSS_HEALTH_LISTEN_ADDR",
        other => {
            anyhow::bail!("listener {other:?} has no listen-addr env var (unknown ListenerKind)")
        }
    })
}

/// ShutdownStack 关闭日志的稳定 listener 名（区分多 listener）。
fn listener_name(listener: ListenerKind) -> &'static str {
    match listener {
        ListenerKind::Primary => "http-primary",
        ListenerKind::Internal => "http-internal",
        ListenerKind::Admin => "http-admin",
        ListenerKind::Health => "http-health",
        // ListenerKind non_exhaustive——未知 listener 用 fallback 名 + 配置期 warn 埋点（与 auth_scheme
        // 的未知 listener 处理一致）；实际 bind 时 listener_addr_env 已 fail-fast 拒未知 listener。
        _ => {
            tracing::warn!(listener = ?listener, "unknown ListenerKind; using fallback name 'http-unknown'");
            "http-unknown"
        }
    }
}

/// 由注入的配置读取器解析 listener bind 地址（DI 核心，可测）。**fail-fast**：有路由的 listener 缺
/// `RSS_<LISTENER>_LISTEN_ADDR` 或值非法 SocketAddr 立即 `Err`（不静默 ready）。错误含 env 变量名。
fn listener_addr_from(
    listener: ListenerKind,
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<SocketAddr> {
    let var = listener_addr_env(listener)?;
    let raw = get(var)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {var} (listener has routes)"))?;
    raw.parse::<SocketAddr>()
        .with_context(|| format!("{var} must be a valid host:port SocketAddr: {raw}"))
}

/// 从 `std::env` 解析 listener bind 地址（薄壳，委托 [`listener_addr_from`]）。
fn listener_addr(listener: ListenerKind) -> anyhow::Result<SocketAddr> {
    listener_addr_from(listener, |name| std::env::var(name).ok())
}

// ── per-listener bind + serve + 信号优雅关停 ───────────────────────────────────────────────────

/// 逐 listener bind socket + serve，经 `ShutdownStack` 托管；SIGTERM/SIGINT → LIFO 优雅 drain。
///
/// 每 listener：解析 bind 地址（fail-fast）→ `HttpServer::bind`（async fail-fast，注册前暴露端口冲突）→
/// 经 `ShutdownStack::register_with_token` 在同步 funnel 闭包内 `bound.serve(svc, token)` spawn serve task
/// （SHUTDOWN-TOKEN-FUNNEL-01）。信号到达 → `stack.shutdown()` 阶段 1 广播 cancel 触发各 serve graceful
/// drain、阶段 2 LIFO await 收敛。任一 listener 关闭失败聚合后非零退出（不静默丢弃）。
async fn serve_until_signal(
    listeners: Vec<(ListenerKind, httpserve::AuthenticatedRoutes)>,
) -> anyhow::Result<()> {
    // 生产装配：真实 env 地址解析 + 真实信号 future（薄壳，委托可测核心 [`serve_until`]）。
    serve_until(listeners, listener_addr, wait_for_shutdown_signal()).await
}

/// 可测核心：注入 `addr_resolver`（listener→bind 地址）与 `shutdown` future（关停触发），驱动 bind 各
/// listener socket → 经 `ShutdownStack` 托管 serve → `shutdown` resolve 后 LIFO 优雅 drain。
///
/// 生产经 [`serve_until_signal`] 注入真实 env 解析 + 信号 future；测试注入 `|_| Ok(127.0.0.1:0)` + 立即
/// resolve 的 future，覆盖 bind 循环 + 多 listener + ensure-非空 + drain 聚合（serve_until_signal 本身依赖
/// OS 信号不可 hermetic 测，故抽核心）。任一 listener 关闭失败聚合后非零退出（不静默丢弃）。
// reason: bind 循环 + 启动就绪 / drain 多条 tracing 宏展开在 cognitive_complexity 计数贡献额外节点；
// 实际控制流是「bind 各 listener → 等关停 → shutdown」三段——item-level carve-out（error-handling.md §Carve-out）。
#[allow(clippy::cognitive_complexity)]
async fn serve_until<R, S>(
    listeners: Vec<(ListenerKind, httpserve::AuthenticatedRoutes)>,
    addr_resolver: R,
    shutdown: S,
) -> anyhow::Result<()>
where
    R: Fn(ListenerKind) -> anyhow::Result<SocketAddr>,
    S: std::future::Future<Output = anyhow::Result<()>>,
{
    anyhow::ensure!(
        !listeners.is_empty(),
        "no listener has routes to serve (refusing to start with zero bound sockets)"
    );
    let listener_count = listeners.len();
    let mut stack = ShutdownStack::new(CancellationToken::new());
    for (listener, routes) in listeners {
        bind_and_register(&mut stack, listener, routes, &addr_resolver).await?;
    }
    // 启动就绪汇总（operator 一眼确认全部 listener 已绑定 + 服务就绪）。
    tracing::info!(listener_count, "all listeners bound; server ready");

    // shutdown future resolve（生产 = 信号到达，已记 signal 名）→ 仅记 drain 动作（不重复信号事件）。
    shutdown.await?;
    tracing::info!("draining listeners (graceful)");
    report_shutdown_failures(stack.shutdown().await)
}

/// bind 单 listener socket（async fail-fast）+ 经 funnel 同步 serve-spawn 注册进 `ShutdownStack`。
///
/// async bind 在注册前完成 ⇒ 端口冲突 fail-fast；同步 `bound.serve(svc, token)` 在 `register_with_token`
/// 闭包内消费注入的 child token（SHUTDOWN-TOKEN-FUNNEL-01）。`addr_resolver` 由 [`serve_until`] 注入
/// （生产 = env 解析，测试 = `127.0.0.1:0` ephemeral）。
async fn bind_and_register<R>(
    stack: &mut ShutdownStack,
    listener: ListenerKind,
    routes: httpserve::AuthenticatedRoutes,
    addr_resolver: &R,
) -> anyhow::Result<()>
where
    R: Fn(ListenerKind) -> anyhow::Result<SocketAddr>,
{
    let name = listener_name(listener);
    let addr = addr_resolver(listener)?;
    let bound = HttpServer::bind(name, addr)
        .await
        .with_context(|| format!("bind {name} listener at {addr}"))?;
    tracing::info!(listener = ?listener, name, addr = %bound.local_addr(), "listener bound");
    let svc = routes.into_make_service();
    stack.register_with_token(move |token| DynManagedResource::new_box(bound.serve(svc, token)));
    Ok(())
}

/// 聚合 `ShutdownStack::shutdown` 的 per-listener 失败：空 = 干净退出 `Ok`；非空 = 记录每条 + 非零退出 `Err`
/// （不静默丢弃关闭错误，决定进程退出码）。
fn report_shutdown_failures(
    failures: Vec<bootstrap::shutdown::ResourceShutdownError>,
) -> anyhow::Result<()> {
    if failures.is_empty() {
        tracing::info!("all listeners drained; exiting");
        return Ok(());
    }
    for f in &failures {
        tracing::error!(error = %f, "listener shutdown failure");
    }
    anyhow::bail!(
        "graceful shutdown completed with {} listener failure(s)",
        failures.len()
    )
}

/// 阻塞至收到关闭信号：unix SIGTERM / SIGINT（容器编排发 SIGTERM、Ctrl-C 发 SIGINT）；非 unix 退回 Ctrl-C。
// reason: cfg(unix) 分支内 tokio::select! + 2 条 tracing 宏展开在 cognitive_complexity 计数贡献额外节点；
// 实际控制流是「装两个 signal stream + select 其一」——item-level carve-out（error-handling.md §Carve-out）。
#[allow(clippy::cognitive_complexity)]
async fn wait_for_shutdown_signal() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
        let mut int = signal(SignalKind::interrupt()).context("install SIGINT handler")?;
        tokio::select! {
            _ = term.recv() => tracing::info!(signal = "SIGTERM", "shutdown signal received"),
            _ = int.recv() => tracing::info!(signal = "SIGINT", "shutdown signal received"),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("install ctrl-c handler")?;
        tracing::info!(signal = "ctrl-c", "shutdown signal received");
    }
    Ok(())
}

/// 装配生产 tracing subscriber（fmt + `RUST_LOG` env filter，默认 `info`）。
///
/// 组合根 binary 入口在 [`run`] **之前**调用（`main`）——否则运行时入口的全部结构化日志（bind / serve /
/// shutdown / fail-fast）皆为 no-op、生产零可见性。仅生产入口调用；测试不调（各测试自设 subscriber，见
/// `auth_e2e` 的 `set_default`），故本 fn 不进 `run`（避免与测试 subscriber 冲突 / 全局 init 重复 panic）。
pub fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// 生产组合根入口（运行时入口 Join #1320）：compose 域 → connect pg + migrations → wire_settings
/// （注册 `configs_ready` probe）→ 装配认证接线 → 挂 Health listener → bind + serve + 信号优雅关停。
///
/// 缺配 / 连不上 / migration 失败均 **fail-fast**（不静默 ready）。各域业务 handler ↔ service 接线
/// = #1309 及后续域 PR；本 fn 仅打通 async runtime + ≥1 个 wire_X call-site + readiness probe。
/// tracing subscriber 由 [`init_tracing`] 在 `main` 中先于本 fn 装配。
pub async fn run() -> anyhow::Result<()> {
    let provider = Arc::new(build_provider()?);
    // settings domain 已注册（#1272/#1274）；后续域（identity/audit/…）随各自 wire_X PR 加入 compose 列表。
    let mut registry = bootstrap::compose(&[&SettingsDomain]).context("compose domains")?;

    // postgres：connect + migrations（生产 fail-fast，缺配/连不上不静默 ready）。
    let pg = Arc::new(
        PgStore::connect(&build_pg_config()?)
            .await
            .context("connect postgres")?,
    );
    pg.run_migrations()
        .await
        .context("run postgres migrations")?;

    // wire_settings（≥1 个 wire_X call-site，#1320 DoD）：注册 configs_ready probe + 造 settings/secret service。
    let (settings_svc, secret_svc) = wire_settings(pg.clone(), &mut registry)
        .await
        .context("wire settings")?;
    // reason: 业务 handler ↔ service 接线属 #1309（本 PR 仅打通 runtime + wire_X call-site + probe）；service
    //   暂不接 handler，configs_ready probe 已注册并持 `Arc<PgStore>`（pg Arc 亦存活）⇒ readyz 仍生效。
    let _ = (settings_svc, secret_svc);

    // 装配域路由认证接线（drain registry 路由组，借 &mut——probe 留存供下方 readyz）。
    let mut listeners =
        assemble_authed_routers(&mut registry, provider).context("assemble authed routers")?;

    // Health listener（框架归属）：readyz 经 Arc<HealthReporter>（Send+Sync）每请求聚合探针。registry 路由组
    // 已 drain，探针经 take_health_reporter 移出（整体非 Sync 的 Registry 无法进 axum handler 闭包）。
    let reporter = Arc::new(registry.take_health_reporter());
    listeners.push(health_listener(reporter).context("build health listener")?);

    // bind 各 listener socket + serve + 信号优雅关停。
    serve_until_signal(listeners).await
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
        let mut registry = bootstrap::compose(&[]).expect("compose empty");
        let routers = assemble_authed_routers(&mut registry, provider).expect("assemble ok");
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

    // ── listener bind 地址解析（fail-fast）─────────────────────────────────────────────

    /// 各标准 listener → 正确 env 变量名（per-listener `RSS_<LISTENER>_LISTEN_ADDR`）。
    #[test]
    #[allow(clippy::expect_used)]
    fn listener_addr_env_maps_each_listener() {
        assert_eq!(
            listener_addr_env(ListenerKind::Primary).expect("primary"),
            "RSS_PRIMARY_LISTEN_ADDR"
        );
        assert_eq!(
            listener_addr_env(ListenerKind::Internal).expect("internal"),
            "RSS_INTERNAL_LISTEN_ADDR"
        );
        assert_eq!(
            listener_addr_env(ListenerKind::Admin).expect("admin"),
            "RSS_ADMIN_LISTEN_ADDR"
        );
        assert_eq!(
            listener_addr_env(ListenerKind::Health).expect("health"),
            "RSS_HEALTH_LISTEN_ADDR"
        );
    }

    /// 有路由的 listener 缺 addr env → fail-fast，错误含 env 变量名（不静默 ready）。
    #[test]
    #[allow(clippy::expect_used)]
    fn listener_addr_missing_env_fails_fast() {
        let err = listener_addr_from(ListenerKind::Primary, |_| None).expect_err("missing addr");
        assert!(
            err.to_string().contains("RSS_PRIMARY_LISTEN_ADDR"),
            "error 含 env 变量名: {err}"
        );
    }

    /// addr env 值非法 SocketAddr → fail-fast，错误含 env 变量名。
    #[test]
    #[allow(clippy::expect_used)]
    fn listener_addr_invalid_value_fails_fast() {
        let err = listener_addr_from(ListenerKind::Health, |_| Some("not-an-addr".to_string()))
            .expect_err("invalid addr");
        assert!(
            err.to_string().contains("RSS_HEALTH_LISTEN_ADDR"),
            "含 env 名: {err}"
        );
    }

    /// 合法 `host:port` → 解析成功。
    #[test]
    #[allow(clippy::expect_used)]
    fn listener_addr_valid_value_parses() {
        let addr = listener_addr_from(ListenerKind::Primary, |_| Some("0.0.0.0:8080".to_string()))
            .expect("valid addr");
        assert_eq!(addr.port(), 8080);
    }

    // ── shutdown 失败聚合（report_shutdown_failures）────────────────────────────────────

    /// 空失败列表 → `Ok`（干净退出）；非空 → `Err` 含失败计数（非零退出码不静默丢弃关闭错误）。
    #[test]
    #[allow(clippy::expect_used)]
    fn report_shutdown_failures_ok_when_empty_err_when_failures() {
        use bootstrap::shutdown::{ResourceShutdownError, ShutdownFailureKind};

        assert!(
            report_shutdown_failures(Vec::new()).is_ok(),
            "无失败 → Ok 干净退出"
        );

        let failures = vec![
            ResourceShutdownError {
                name: "http-primary".to_owned(),
                kind: ShutdownFailureKind::Panicked,
            },
            ResourceShutdownError {
                name: "http-health".to_owned(),
                kind: ShutdownFailureKind::BudgetExhausted,
            },
        ];
        let err = report_shutdown_failures(failures).expect_err("非空失败 → Err");
        assert!(
            err.to_string().contains("2 listener failure"),
            "error 含失败计数: {err}"
        );
    }

    // ── serve_until 生产 serve 循环（注入 addr + shutdown future，hermetic）────────────────

    /// 测试 reporter（空探针）。
    #[allow(clippy::expect_used)]
    fn test_reporter() -> Arc<bootstrap::HealthReporter> {
        let mut reg = bootstrap::compose(&[]).expect("compose");
        Arc::new(reg.take_health_reporter())
    }

    /// 注入 `127.0.0.1:0` ephemeral 地址解析器（测试用）。
    fn ephemeral_addr(_l: ListenerKind) -> anyhow::Result<SocketAddr> {
        "127.0.0.1:0".parse::<SocketAddr>().map_err(Into::into)
    }

    /// serve_until 核心：注入 ephemeral addr + 立即 resolve 的 shutdown → bind 全部 listener + 干净 drain。
    /// 覆盖生产 serve loop（serve_until_signal 薄壳依赖 OS 信号不可 hermetic 测）：2 listener bind 循环 + drain。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn serve_until_binds_all_listeners_and_drains_clean() {
        let listeners = vec![
            health_listener(test_reporter()).expect("h1"),
            health_listener(test_reporter()).expect("h2"),
        ];
        serve_until(
            listeners,
            ephemeral_addr,
            std::future::ready(anyhow::Ok(())),
        )
        .await
        .expect("serve_until binds 2 listeners + drains clean");
    }

    /// serve_until 空 listeners → fail-fast Err（拒绝零 socket 启动）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn serve_until_empty_listeners_errs() {
        let err = serve_until(
            Vec::new(),
            ephemeral_addr,
            std::future::ready(anyhow::Ok(())),
        )
        .await
        .expect_err("空 listeners 拒绝启动");
        assert!(
            err.to_string().contains("zero bound sockets"),
            "error: {err}"
        );
    }

    /// serve_until addr_resolver 失败 → bind 前 fail-fast 冒泡 Err（不静默 ready）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn serve_until_addr_resolver_failure_propagates() {
        let listeners = vec![health_listener(test_reporter()).expect("health")];
        let err = serve_until(
            listeners,
            |_| anyhow::bail!("no addr configured for listener"),
            std::future::ready(anyhow::Ok(())),
        )
        .await
        .expect_err("addr resolver 失败");
        assert!(
            err.to_string().contains("no addr configured"),
            "error: {err}"
        );
    }

    // ── Health listener readyz/healthz（经 funnel 出口 oneshot）──────────────────────────

    /// Health listener 经 funnel 构造（NoAuth）：空探针 → readyz 503（fail-closed）；
    /// 注册一个 Healthy 探针 → readyz 200。
    #[tokio::test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    async fn health_listener_readyz_reflects_probes() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt as _;

        let mut empty_reg = bootstrap::compose(&[]).expect("compose empty");
        let empty = Arc::new(empty_reg.take_health_reporter());
        let (_, authed) = health_listener(empty).expect("health listener");
        let resp = authed
            .into_router_for_test()
            .oneshot(
                Request::builder()
                    .uri("/health/v1/readyz")
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("oneshot");
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "空探针 → readyz fail-closed 503"
        );

        struct HealthyProbe;
        impl bootstrap::HealthProbe for HealthyProbe {
            fn check(&self) -> HealthCheck {
                HealthCheck::new(
                    ProbeName::parse("ok").expect("name"),
                    HealthStatus::Healthy,
                    "ready",
                )
            }
        }
        let mut reg = bootstrap::compose(&[]).expect("compose");
        reg.probe(
            ProbeName::parse("ok").expect("name"),
            Box::new(HealthyProbe),
        )
        .expect("register probe");
        let reporter = Arc::new(reg.take_health_reporter());
        let (_, authed) = health_listener(reporter).expect("health listener");
        let resp = authed
            .into_router_for_test()
            .oneshot(
                Request::builder()
                    .uri("/health/v1/readyz")
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK, "Healthy 探针 → readyz 200");
    }

    /// Health listener liveness 端点 `/health/v1/healthz` 恒 200（存活即活）。
    #[tokio::test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    async fn health_listener_healthz_is_200() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt as _;

        let mut reg = bootstrap::compose(&[]).expect("compose");
        let reporter = Arc::new(reg.take_health_reporter());
        let (listener, authed) = health_listener(reporter).expect("health listener");
        assert_eq!(listener, ListenerKind::Health);
        let resp = authed
            .into_router_for_test()
            .oneshot(
                Request::builder()
                    .uri("/health/v1/healthz")
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK, "liveness 恒 200");
    }
}
