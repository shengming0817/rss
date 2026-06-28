//! runtime — RSS 生产组合根（Root 层，#1309 抽离自 bins 双写）：从配置构造生产验签 provider，按 listener 装配
//! `finalize_routes → finalize_auth → .layer(verify_bridge)` 的认证接线接缝，并驱动运行时入口
//! （tokio 运行时 + per-listener socket bind + `axum::serve` + 信号优雅关停 + wire_X call-site，#1320）。
//!
//! 运行时入口（[`run`]，#1320 Join）：`compose` 域 → `PgStore::connect` + migrations → `wire_settings`
//! → F8 接线（`PgDbReadiness` 采样 worker + `configs_ready` probe 注册）→ `assemble_authed_routers`
//! → 组合根挂 Health listener（healthz/readyz）→ 逐 listener bind socket + serve（经 `httpd::HttpServer`
//! + `bootstrap::ShutdownStack`）→ SIGTERM/SIGINT 优雅 drain。各域业务 handler ↔ service 接线 = #1309
//!   及后续域 PR（本 PR 仅打通 async runtime、wire_X call-site 与 readiness probe）。live JWKS 远程拉取
//! + 轮转 = **T003/#1197**（本 PR 用 `StaticKeySource` 构造期注入 key，构造器签名已为其留稳）。
//!   listener / pg / vault 传输层 TLS（rustls+ring）= 后续 TLS 切片。
//!
//! 安全同批门（ADR-006 §5）：依赖图引真 verifier（`oidc` backend）、不引 stub Pdp（`memory` 经 deny.toml 禁
//! server/rss/runtime；bins 生产 `src/` 无内联 `impl diport::Pdp`，`rss_pdp_impl_adapter_only` dylint 守 +
//! `cargo xtask verify` 的 pdp-allow 计数门守逃生门用量）。`OidcProvider` 必填 `VerifierConfig` + `Box<dyn Clock>`
//! ⇒ 无 key/clock 不可构造（编译期守）。
//!
//! INVARIANT: BINS-AUTH-SYNC-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }(Hard, #1309) — `bins/rss` + `bins/server` 均仅 `main.rs` 调
//! `runtime::run()`，组合根逻辑单一副本；auth wiring 一致性由「单一 `run()` 源」编译期保证，
//! 原 xtask Medium 守卫 `bins_auth_sync.rs` 退役（双写消除、无第二副本可漂移）。

pub mod auth_bridge;
pub mod event_transport;
pub mod module;

pub use module::SharedRuntimeDeps;

use bootstrap::DomainModuleResult;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Context as _;
use audit::AuditDomain;
use audit::ports::{AuditChainHasher, DynAuditRepo};
use axum::http::Method;
use base64::Engine as _;
use bootstrap::shutdown::ShutdownStack;
use crypto::RustCryptoMacVerifier;
use diport::DynManagedResource;
use httpd::HttpServer;
use identity::{
    IdentityDomain, LoginService, RefreshService,
    ports::{DynCredentialRepo, DynRefreshTokenStore, DynSessionLifecycle},
};
use oidc::OidcProvider;
use postgres::{
    PgConfig, PgDbReadiness, PgPassword, PgRuntimeDeps, PgSslMode, PoolReadiness, caps,
};
use primitives::{
    AuthPlan, AuthScheme, HealthCheck, HealthStatus, ListenerKind, MacKey, ProbeName,
    RequiredScheme,
};
use ratelimit::GovernorLimiter;
use settings::ports::DynSecretRepo;
use settings::{SettingsDomain, SettingsService, empty_flag_store};
use tokio_util::sync::CancellationToken;
use vault::{TenantStoreAllowlist, VaultRuntimeDeps, VaultSecretResolver, VaultSigner};

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

/// Test/lightweight auth decision audit sink provider.
///
/// Production uses `postgres::PgAuthAuditSink` through `PgRuntimeDeps`; this provider exists for unit tests and
/// non-production assembly checks where no durable store is available.
#[derive(Clone, Default)]
pub struct TracingAuthAuditSink;

impl diport::AuditSink for TracingAuthAuditSink {
    async fn record(&self, event: diport::AuditEvent) -> Result<(), diport::AuditSinkError> {
        let outcome = match event.outcome {
            diport::AuditOutcome::Success => "success",
            diport::AuditOutcome::Failure { reason } => reason,
            _ => "unknown",
        };
        tracing::info!(
            audit.action = event.action,
            audit.outcome = outcome,
            resource.kind = event.resource_kind,
            principal.kind = ?event.principal_kind,
            "http auth audit event"
        );
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), diport::AuditSinkError> {
        Ok(())
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

/// 默认限流配额：10 req/s，burst 20（per-peer-IP keyed，组合根 owner；可配置化 follow-up #1106）。
///
/// `NonZeroU32::new(10/20)` 对字面量非零常量不可失败——`expect` 是构造期 programmer error
/// （此处不可恢复，item-level carve-out，error-handling.md §Carve-out）。
#[allow(clippy::expect_used)]
fn default_rate_quota() -> ratelimit::QuotaConfig {
    // reason: 10 / 20 是 compile-time 字面量，NonZeroU32::new 仅在 0 时返 None；
    // 字面量非零，此 expect 是构造期 programmer error（不可恢复，item-level carve-out）。
    ratelimit::QuotaConfig::per_second(
        std::num::NonZeroU32::new(10).expect("non-zero rate-per-second constant"),
        std::num::NonZeroU32::new(20).expect("non-zero burst constant"),
    )
}

/// 排空 registry 的 per-listener `UnfinalizedRoutes`，按 listener 装配 `finalize_auth` + 外层验签桥
/// + rate-limit 中间件（组合根叠加点，INVARIANT RATELIMIT-BEFORE-AUTH-01）。
///
/// 每 listener：`finalize_auth(routes, plan)`（消费 `UnfinalizedRoutes` 产 `AuthenticatedRoutes`，注入
/// AuthPlan 与 framework 中间件）→ 据 `required_scheme` 叠外层 `verify_bridge`（`NoAuth` listener 无桥）
/// → 叠 rate-limit（[`httpserve::rate_limit`]，outer 于验签桥；peer-IP keyed per-request）。
/// 产出 `AuthenticatedRoutes` 经 `into_make_service` 绑 socket + serve（[`serve_until_signal`]）——bind 点
/// 天生只能消费已认证 router（ROUTE-AUTH-FUNNEL-01/02：未跑 finalize_auth 的 router 无 bindable 出口）。
///
/// 层序（外→内）：body-limit（httpserve sealed_router，最外防护）→ rate-limit（本函数 verify-bridge 后叠）
/// → 验签桥 → trace → enforce → handler。rate-limit outer 于验签桥保证限流在 auth 计算前生效
/// （INVARIANT RATELIMIT-BEFORE-AUTH-01：组合根在 verify-bridge 后 .layer ⇒ outer 于桥）。
///
/// Health listener 由 [`health_listener`] 单独构造、**不经本函数、不叠限流**——探针不限速（k8s
/// liveness/readiness 在高负载下不应被限流触发级联重启），有意设计。
///
/// 借 `&mut Registry`（仅 drain `finalize_routes`，**不**消费）：registry 的探针在此后仍存活，组合根经
/// [`bootstrap::Registry::take_health_reporter`] 取出探针装入 `Arc<HealthReporter>`（`Send + Sync`）注入
/// Health listener 的 readyz handler（每请求 `report`，[`health_listener`]）；整体非 `Sync` 的 `Registry`
/// 无法进 axum handler 闭包。
pub fn assemble_authed_routers(
    registry: &mut bootstrap::Registry,
    provider: Arc<OidcProvider>,
    audit_sink: httpserve::AuditSinkHandle,
    audit_clock: Arc<dyn diport::Clock>,
) -> anyhow::Result<Vec<(ListenerKind, httpserve::AuthenticatedRoutes)>> {
    // 默认限流配额（owner=组合根，可调）：10 req/s，burst 20。peer-IP keyed（见 #1106 / RealIP follow-up）。
    // 共享跨所有 listener——统一 per-IP 预算，避免分散 listener 各自独立 bucket 使 burst 预算 N 倍膨胀。
    //
    // 已知限制（multi-instance）：in-mem `GovernorLimiter` 是 per-instance 独立桶，N 副本部署下
    // 每实例独立配额（全局视图 ≈ N × 单实例率）；全局一致限流须 redis-distributed provider（future）。
    // 叠加 peer-IP-after-proxy 退化（RealIP follow-up），本限流当前为单实例 best-effort 防护。
    let rate_limiter = Arc::new(GovernorLimiter::new(default_rate_quota()));
    let mut out = Vec::new();
    for (listener, routes) in registry.finalize_routes().context("finalize_routes")? {
        let scheme = auth_scheme(listener);
        let plan = AuthPlan::new(listener, scheme).context("build auth plan")?;
        let authed = httpserve::finalize_auth_with_audit(
            routes,
            plan,
            audit_sink.clone(),
            audit_clock.clone(),
        )
        .context("finalize_auth")?;
        let required = required_scheme(listener);
        let wired = match required {
            Some(req) => auth_bridge::apply_verify_bridge(authed, provider.clone(), req),
            None => authed,
        };
        // INVARIANT RATELIMIT-BEFORE-AUTH-01 —— rate-limit 在 verify-bridge 之后 .layer，
        // 层序上 outer 于桥（请求方向先 rate-limit 后验签），在 auth 计算前拦截超额请求。
        let wired = wired.layer(axum::middleware::from_fn_with_state(
            Arc::clone(&rate_limiter),
            httpserve::rate_limit::<GovernorLimiter>,
        ));
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
/// TLS 默认 `VerifyFull`（零信任）；可选 `RSS_PG_SSL_MODE` 经 [`parse_pg_ssl_mode`] 显式降级（容器内连
/// 未启 TLS 的 dev postgres 时用 `prefer` / `disable`）。生产私有 CA 根证书经 `PgConfig::with_ssl_root_cert`
/// 注入（待后续 TLS 切片，rustls+ring，pg/vault/listener 同批——非本运行时入口 #1320 范围）。
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
    Ok(
        PgConfig::new(host, port, database, username, PgPassword::new(password))
            .with_ssl_mode(parse_pg_ssl_mode(get("RSS_PG_SSL_MODE"))),
    )
}

/// 解析可选 `RSS_PG_SSL_MODE` → [`PgSslMode`]（libpq 拼写：`disable` / `allow` / `prefer` / `require` /
/// `verify-ca` / `verify-full`，大小写与前后空白不敏感）。
///
/// - 未配置 → `VerifyFull`（零信任默认，强制 TLS + 校验证书链/主机名）。
/// - 显式合法值 → 对应模式（容器内 dev postgres 无 TLS 时经 `prefer` / `disable` 显式降级，不静默）。
/// - 显式非法值 / 空串 → `tracing::warn!` + **fail-closed 回退 `VerifyFull`**（误配不降级安全姿态）。
///
/// 安全姿态非强依赖配置，故误配 fail-soft（warn + 安全默认）而非 fail-fast——与 [`build_readiness_interval_from`]
/// 同范式；但回退方向恒为**更严**的 `VerifyFull`，绝不因误配静默放宽。
pub(crate) fn parse_pg_ssl_mode(raw: Option<String>) -> PgSslMode {
    let Some(raw) = raw else {
        return PgSslMode::VerifyFull;
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "disable" => PgSslMode::Disable,
        "allow" => PgSslMode::Allow,
        "prefer" => PgSslMode::Prefer,
        "require" => PgSslMode::Require,
        "verify-ca" => PgSslMode::VerifyCa,
        "verify-full" => PgSslMode::VerifyFull,
        _ => {
            tracing::warn!(
                env = "RSS_PG_SSL_MODE",
                raw = %raw,
                "invalid pg ssl mode (need disable|allow|prefer|require|verify-ca|verify-full); \
                 falling back to verify-full (zero-trust)"
            );
            PgSslMode::VerifyFull
        }
    }
}

/// 从 `std::env` 构造 `PgConfig`。
pub fn build_pg_config() -> anyhow::Result<PgConfig> {
    build_pg_config_from(|name| std::env::var(name).ok())
}

/// 从 `std::env` 构造 [`event_transport::EventTransportConfig`]。
pub fn build_event_transport_config() -> anyhow::Result<event_transport::EventTransportConfig> {
    event_transport::build_event_transport_config_from(|name| std::env::var(name).ok())
}

// ── DB readiness 采样周期 helper ───────────────────────────────────────────────────────────────

/// 默认 DB readiness 采样周期（5 秒）。
const DEFAULT_READINESS_INTERVAL: Duration = Duration::from_secs(5);

/// 采样间隔上限（秒）：限制 DB 失联后维持旧 Ready 状态的最长时间。
const MAX_READINESS_INTERVAL_SECS: u64 = 300;

/// configs_ready DB 采样周期（env `RSS_PG_READINESS_SAMPLE_INTERVAL_SECS`）。
///
/// - 未配置 → 静默取默认 5s。
/// - 显式配置但解析失败 / 为 0 / 超出上限（300s）→ `tracing::warn!` + 默认 5s。
///
/// 间隔是探针新鲜度 hint 非强依赖，故显式误配 fail-soft（warn+默认）而非 fail-fast。
pub(crate) fn build_readiness_interval_from(get: impl Fn(&str) -> Option<String>) -> Duration {
    match get("RSS_PG_READINESS_SAMPLE_INTERVAL_SECS") {
        None => DEFAULT_READINESS_INTERVAL,
        Some(raw) => match raw.parse::<u64>() {
            Ok(n) if (1..=MAX_READINESS_INTERVAL_SECS).contains(&n) => Duration::from_secs(n),
            _ => {
                tracing::warn!(
                    env = "RSS_PG_READINESS_SAMPLE_INTERVAL_SECS",
                    raw = %raw,
                    max_secs = MAX_READINESS_INTERVAL_SECS,
                    "invalid readiness sample interval (need 1..=300s); using default 5s"
                );
                DEFAULT_READINESS_INTERVAL
            }
        },
    }
}

fn build_readiness_interval() -> Duration {
    build_readiness_interval_from(|n| std::env::var(n).ok())
}

// ── Vault secret resolver wiring ─────────────────────────────────────────────────────────────

/// 默认 Vault 请求超时（pre-GA 合理值；生产可经 env 覆盖，待后续 Vault 配置切片——非 #1320 范围）。
const DEFAULT_VAULT_TIMEOUT: Duration = Duration::from_secs(5);

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
fn build_vault_tls_client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .use_rustls_tls()
        .build()
        .context("build vault rustls TLS client")
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
    let client = build_vault_tls_client()?;

    // pre-GA 空 allowlist：无生产 secret reader → 所有 resolve fail-closed Forbidden（网络前拦截）。
    // 待后续 issue 填充 TenantStoreAllowlist（per-store mount + prefix，#1272 follow-up）。
    let stores = TenantStoreAllowlist::new(std::iter::empty())
        .map_err(|e| anyhow::anyhow!("vault store allowlist config error: {e}"))?;

    warn_vault_startup_security(&stores);

    VaultSecretResolver::new(client, addr, token, DEFAULT_VAULT_TIMEOUT, stores)
        .map_err(|e| anyhow::anyhow!("vault resolver config error: {e}"))
}

/// 组合根级 vault capability bundle 构造（#1498）：env → `VaultSecretResolver`（fail-closed without env，
/// 见 [`build_vault_resolver_from`]）→ [`VaultRuntimeDeps`]（vault 的 dispatch + lifecycle 单源装配出口）。
///
/// vault env 缺失即 `Err`（fail-closed，不静默装配 vault）——本函数是 `run()` 装配 [`SharedRuntimeDeps::vault`]
/// 的构造点（取代旧 `wire_settings` 内联 resolver 构造，resolver 改经 bundle dispatch 注入）。
pub fn build_vault_runtime_deps(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<VaultRuntimeDeps> {
    Ok(VaultRuntimeDeps::new(build_vault_resolver_from(get)?))
}

/// 组合根级 redis capability bundle 构造：`RSS_REDIS_URL` → deadpool redis pool + PING → [`redis::RedisRuntimeDeps`].
///
/// 缺 `RSS_REDIS_URL` 或 Redis 不可达均 fail-fast；错误上下文只含 env/resource 名，不含 URL 值。
/// 生命周期关闭经 `RedisRuntimeDeps::runtime_resources()` 单源进入
/// [`DomainModuleResult::resources`]。
pub async fn build_redis_runtime_deps(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<redis::RedisRuntimeDeps> {
    let url = get("RSS_REDIS_URL")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_REDIS_URL"))?;
    let pool = deadpool_redis::Config::from_url(url)
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .context("create redis pool")?;
    verify_redis_pool(&pool)
        .await
        .context("verify redis connectivity for RSS_REDIS_URL")?;
    Ok(redis::RedisRuntimeDeps::setup(pool))
}

async fn verify_redis_pool(pool: &deadpool_redis::Pool) -> anyhow::Result<()> {
    let mut conn = pool.get().await.context("connect redis resource")?;
    let pong: String = deadpool_redis::redis::cmd("PING")
        .query_async(&mut *conn)
        .await
        .context("ping redis resource")?;
    anyhow::ensure!(pong == "PONG", "redis resource returned non-PONG ping");
    Ok(())
}

// ── ConfigsReadyProbe ─────────────────────────────────────────────────────────────────────────

/// probe 探针稳定名（`ProbeName::parse` 校验合法字符；underscore_case，与 prometheus metric 约定一致）。
///
/// `pub const`：e2e 测试（`configs_ready_e2e.rs`）经 `runtime::CONFIGS_READY_PROBE_NAME` 引用，
/// 避免硬编码字符串——改名即编译期捕获（[D6] #1309 review）。
pub const CONFIGS_READY_PROBE_NAME: &str = "configs_ready";

/// DB readiness 采样探针——读 [`PgDbReadiness`] 采样状态，非 pool 计数器。
///
/// `check`（sync，non-blocking）：读 `PgDbReadiness::snapshot()` 原子状态，无 I/O：
/// - `PoolReadiness::Ready` → `Healthy`（`detail = "ready"`）
/// - `PoolReadiness::Down` → `Unhealthy`（`detail = "down"`）
///
/// `detail` 固定 `&'static str` const（`HealthCheck::detail` 类型约束，禁夹带 runtime PII）。
pub struct ConfigsReadyProbe {
    health: Arc<PgDbReadiness>,
    /// 探针自报名（重建 `HealthCheck` 时 registry 使用声明名权威，此字段保留供 debug inspect）。
    name: ProbeName,
}

impl ConfigsReadyProbe {
    /// 构造 `ConfigsReadyProbe`（读 `PgDbReadiness` 采样状态，非 pool 计数器）。
    ///
    /// `name` 应使用 [`CONFIGS_READY_PROBE_NAME`] 常量以确保与 registry 声明名一致。
    #[allow(clippy::expect_used)]
    pub fn new(health: Arc<PgDbReadiness>) -> Self {
        // reason: CONFIGS_READY_PROBE_NAME 是 kebab-case const literal，ProbeName::parse 仅失败于
        // 非法字符；const 已手工验证，expect 是构造期 programmer error（此处不可恢复）。
        let name = ProbeName::parse(CONFIGS_READY_PROBE_NAME).expect("valid probe name const");
        Self { health, name }
    }
}

/// `PoolReadiness` → `(HealthStatus, detail)`（纯函数，可独立测试）。
///
/// - `Ready` → `Healthy`/"ready"（HTTP 200）
/// - `Saturated` → `Degraded`/"saturated"（HTTP 200；池饱和可服务，编排器不摘流）
/// - `Down` → `Unhealthy`/"down"（HTTP 503）
/// - 未知（non_exhaustive）→ `Unhealthy`/"unknown"（fail-closed）
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
        let (status, detail) = readiness_to_health(self.health.snapshot());
        HealthCheck::new(self.name.clone(), status, detail)
    }
}

// ── RlsReadyProbe ──────────────────────────────────────────────────────────────────────────────

/// RLS 能力门 readyz 兜底探针稳定名（underscore_case，与 prometheus 约定一致）。
pub const RLS_READY_PROBE_NAME: &str = "rls_ready";

/// RLS 能力门 readyz 兜底探针——读 [`PgRuntimeDeps::rls_ready_handle`] 的启动核验镜像（非 pool）。
///
/// 启动期 `verify_rls_capability` 失败时 `setup` 直接 fail-fast（进程不进入服务态），故进程在跑 ⇒ 此探针
/// 恒 `Healthy`；其价值是把「durable RLS 能力已就绪」这一不变式**显式暴露**到 readyz（运维可见），并为
/// 后续周期性再核验留接线点（届时改为写采样状态即可，探针形态不变）。
///
/// `check`（sync，non-blocking）：读 `AtomicBool`（Acquire），`true → Healthy("ready")` /
/// `false → Unhealthy("not-enforced")`（fail-closed）。`detail` 固定 `&'static str` const（禁夹带 PII）。
pub struct RlsReadyProbe {
    ready: Arc<std::sync::atomic::AtomicBool>,
    name: ProbeName,
}

impl RlsReadyProbe {
    /// 构造 `RlsReadyProbe`（读 RLS 能力门镜像）。`name` 应使用 [`RLS_READY_PROBE_NAME`] 常量。
    #[allow(clippy::expect_used)]
    pub fn new(ready: Arc<std::sync::atomic::AtomicBool>) -> Self {
        // reason: RLS_READY_PROBE_NAME 是 underscore_case const literal，ProbeName::parse 仅失败于非法
        // 字符；const 已手工验证，expect 是构造期 programmer error（不可恢复，同 ConfigsReadyProbe）。
        let name = ProbeName::parse(RLS_READY_PROBE_NAME).expect("valid probe name const");
        Self { ready, name }
    }
}

impl bootstrap::HealthProbe for RlsReadyProbe {
    fn check(&self) -> HealthCheck {
        let (status, detail) = if self.ready.load(std::sync::atomic::Ordering::Acquire) {
            (HealthStatus::Healthy, "ready")
        } else {
            (HealthStatus::Unhealthy, "not-enforced")
        };
        HealthCheck::new(self.name.clone(), status, detail)
    }
}

// ── settings + secret wiring ─────────────────────────────────────────────────────────────────

/// 接线 settings 域（#1430 PERSIST-009 settings 首条 durable module 闭环）：构造 config 应用服务 + secret
/// 仓储端口、产出 `configs_ready` readiness 探针，返回 `(SettingsDomain, DomainModuleResult)`。
///
/// - `deps`：共享基础设施（[`SharedRuntimeDeps`]）——内部持 [`PgRuntimeDeps`] capability bundle；settings
///   wiring 只拿 `PgDomainDeps<caps::Settings>`，拿不到 identity repo 或裸 pool。
///
/// [`SettingsDomain`] 持构造好的 config 服务 + secret 仓储端口，经 `Domain::init` 挂 config-publish /
/// secret-publish 路由（service 经 route 闭包捕获、**绝不**经 result 出向，WIRING-DEPS-NO-HANDOFF-01）；
/// `configs_ready` 探针经 [`DomainModuleResult`] 出向（探针包 `PgDbReadiness` = adapter 类型，须在组合根构造、
/// 不能放域 crate `Domain::init`）。组合根 `compose(&[&settings_domain, ..])` 装配路由 + `merge(module)` 聚合探针。
///
/// secret-publish 路由 State 持 `Arc<DynSecretRepo>`（publish 路径不需 resolver）：**不构造 `SecretService`**——
/// 其 `Box<DynSecretResolver>`（diport infra 端口，ADR-003 Amendment #1095 故意 `Send` 非 `Sync`）使整体非 `Sync`、
/// 不可作 axum State。vault resolver 句柄经 `deps.vault.runtime_resources()` 在 `run()` 注册 guard（lifecycle 不变）。
///
/// # 注意
///
/// 当前 `empty_flag_store()` 返回空 in-mem store（`seed-data` feature，fail-closed 语义）；生产 flag store
/// 待 #1120。`SystemClock` 仍硬编码——clock 注入（rust-standards「Clock 构造器位置参」）属 tangential，不在本 PR scope。
pub async fn wire_settings(
    deps: &SharedRuntimeDeps,
) -> anyhow::Result<(SettingsDomain, DomainModuleResult)> {
    // 单一 settings bundle（PERSIST-003）：read+write config + secret repo 同 pool、单 clock 经 Arc 扇出，预包装
    // 域形 dyn port——组合根不再散装构造 repo / 手工 DynX 包裹 / 配对 read↔write。
    let (configs, writer, secrets) = deps
        .pg
        .for_domain::<caps::Settings>()
        .settings_bundle(Arc::new(SystemClock))
        .into_parts();

    // config 应用服务（L2 OutboxFact：CAS 写 + outbox co-tx）→ 经 Arc 作 config-publish 路由 axum State。
    let config_svc =
        SettingsService::with_postgres(configs, writer, empty_flag_store(), Box::new(SystemClock));
    // secret 仓储端口 → 经 Arc 作 secret-publish 路由 axum State（`DynSecretRepo` 已 Send+Sync）。
    let secret_repo: Arc<DynSecretRepo<'static>> = Arc::from(secrets);

    let module = settings_module_result(deps.pg.readiness_handle())?;
    Ok((
        SettingsDomain::new(Arc::new(config_svc), secret_repo),
        module,
    ))
}

/// settings 域 readiness 产物：`configs_ready` 探针（读共享 `PgDbReadiness`）。
///
/// 从 [`wire_settings`] 抽出——后者前半段 vault resolver / pg repo 构造受 env + 真实 pg 门控（integration only），
/// 而本探针 emission 只需 `Arc<PgDbReadiness>`（无 I/O）。独立成纯函数后 `#[cfg(test)]` 可脱离 vault env / 真实 pg
/// 单测探针 emission 契约（恰一条 configs_ready、无 resources/workers）。
fn settings_module_result(readiness: Arc<PgDbReadiness>) -> anyhow::Result<DomainModuleResult> {
    // configs_ready 探针：读 SharedRuntimeDeps 注入的共享 PgDbReadiness（框架 sampler 写）。作 settings 域
    // readiness 产物经 result 出向——不能放纯声明的 `Domain::init`（需运行时构造的 handle）。
    let probe_name = ProbeName::parse(CONFIGS_READY_PROBE_NAME)
        .context("configs_ready probe name is invalid")?;
    Ok(DomainModuleResult {
        probes: vec![(probe_name, Box::new(ConfigsReadyProbe::new(readiness)))],
        ..Default::default()
    })
}

// ── audit wiring（#1230）────────────────────────────────────────────────────────────────────────

/// 从 env 构造审计 keyed-HMAC 链 hasher（生产 [`RustCryptoMacVerifier`] backend；DI：注入读取器供测试，
/// 无 env 副作用——workspace `forbid(unsafe)` 下测试不能 `set_var`）。
///
/// - `RSS_AUDIT_CHAIN_KEY_B64URL`：**必填**——审计链 HMAC key，base64url。缺失 fail-fast（生产审计链不可无 key）。
///
/// fail-fast：非 base64url → 错；解码后 <32B → 错（[`AuditChainHasher::new`] 返回 `None`，链 key 强度
/// `docs/rules/audit-ledger.md`）。错误只含变量**名**，不含 key 值（无 secret 泄漏）。
fn build_audit_hasher(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<AuditChainHasher<RustCryptoMacVerifier>> {
    let b64 = get("RSS_AUDIT_CHAIN_KEY_B64URL")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_AUDIT_CHAIN_KEY_B64URL"))?;
    let key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&b64)
        .context("RSS_AUDIT_CHAIN_KEY_B64URL not valid base64url")?;
    AuditChainHasher::new(RustCryptoMacVerifier, MacKey::from_bytes(key_bytes)).ok_or_else(|| {
        anyhow::anyhow!("audit chain key must be at least 32 bytes (weak key, see audit-ledger.md)")
    })
}

/// 接线 audit 域：env 链 key（fail-fast）→ [`RustCryptoMacVerifier`] hasher → [`PgAuditRepo`] durable provider
/// → erased `Arc<DynAuditRepo>` → [`AuditDomain`]（组合根注入路径，与 in-mem 同形）。
///
/// - `deps`：共享基础设施（[`SharedRuntimeDeps`]）——内部持 [`PgRuntimeDeps`] capability bundle；audit
///   wiring 只拿 `PgDomainDeps<caps::Audit>`，拿不到 settings/identity repo 或裸 pool。
///
/// **bootstrap 启动 tail-verify（跨租户全量巡检）defer 到 Part B**：跨租户枚举（`SELECT DISTINCT tenant_id`）
/// 在 FORCE RLS 下需专用 `rss_audit_admin` 角色限定 permissive RLS 池（非 BYPASSRLS，见 `docs/rules/tenancy.md`）
/// ——与跨租户 admin 读同一基础设施，统一随 Part B 落地。本 PR 的读路径完整性硬保证是 `list` 内增量
/// [`AuditChainHasher::verify_window`]（篡改 fail-closed → 500，不下发脏数据）；per-tenant [`PgAuditRepo`] 的
/// `verify_tail` 已就绪（集成测试覆盖），供 Part B boot sweep + 运维巡检调用。
pub fn wire_audit(deps: &SharedRuntimeDeps) -> anyhow::Result<AuditDomain> {
    let hasher = build_audit_hasher(|name| std::env::var(name).ok()).context("audit chain key")?;
    let repo = deps.pg.for_domain::<caps::Audit>().audit_repo(hasher);
    let dyn_repo: Arc<DynAuditRepo<'static>> = Arc::from(DynAuditRepo::new_box(repo));
    Ok(AuditDomain::new(dyn_repo))
}

const DEFAULT_IDENTITY_SESSION_TTL_SECS: u64 = 3_600;
const MAX_IDENTITY_SESSION_TTL_SECS: u64 = 90 * 24 * 60 * 60;
const IDENTITY_SESSION_TTL_ENV: &str = "RSS_IDENTITY_SESSION_TTL_SECS";

fn identity_session_ttl_secs(env: impl Fn(&str) -> Option<String>) -> anyhow::Result<u64> {
    match env(IDENTITY_SESSION_TTL_ENV) {
        Some(raw) => {
            let ttl = raw.parse::<u64>().with_context(|| {
                format!("{IDENTITY_SESSION_TTL_ENV} must be an integer seconds value")
            })?;
            anyhow::ensure!(ttl > 0, "{IDENTITY_SESSION_TTL_ENV} must be > 0");
            anyhow::ensure!(
                ttl <= MAX_IDENTITY_SESSION_TTL_SECS,
                "{IDENTITY_SESSION_TTL_ENV} must be <= {MAX_IDENTITY_SESSION_TTL_SECS}"
            );
            Ok(ttl)
        }
        None => Ok(DEFAULT_IDENTITY_SESSION_TTL_SECS),
    }
}

/// vault base URL env（resolver + signer 复用，fail-fast 必填）。
const VAULT_ADDR_ENV: &str = "RSS_VAULT_ADDR";
/// vault token env（同上）。
const VAULT_TOKEN_ENV: &str = "RSS_VAULT_TOKEN";

/// JWT access-token 签发 env（ES256，组合根注入 vault `Signer`，#1252）。
const JWT_ISSUER_ENV: &str = "RSS_JWT_ISSUER";
const JWT_AUDIENCE_ENV: &str = "RSS_JWT_AUDIENCE";
/// vault Transit sign key 名 = JOSE `kid`（验签侧据 kid 选 oidc ES256 公钥；二者须由运维一致接线，OIDC-ALG-KEYPATH-01）。
const JWT_KEY_ID_ENV: &str = "RSS_JWT_ES256_KEY_ID";
const JWT_ACCESS_TTL_ENV: &str = "RSS_JWT_ACCESS_TTL_SECS";
/// vault Transit mount path（如 `transit`，per-deploy）。
const VAULT_TRANSIT_MOUNT_ENV: &str = "RSS_VAULT_TRANSIT_MOUNT";
/// refresh token 有效期 env（缺省 30 天）。
const REFRESH_TTL_ENV: &str = "RSS_REFRESH_TTL_SECS";
const DEFAULT_REFRESH_TTL_SECS: u64 = 30 * 24 * 60 * 60;
const MAX_REFRESH_TTL_SECS: u64 = 365 * 24 * 60 * 60; // 1 year（refresh 长于 session）
/// access JWT 签名用途（vault Transit purpose 归因，固定字面量）。
const JWT_SIGNING_PURPOSE: &str = "auth.jwt.access";

fn refresh_ttl_secs(env: impl Fn(&str) -> Option<String>) -> anyhow::Result<u64> {
    match env(REFRESH_TTL_ENV) {
        Some(raw) => {
            let ttl = raw
                .parse::<u64>()
                .with_context(|| format!("{REFRESH_TTL_ENV} must be an integer seconds value"))?;
            anyhow::ensure!(ttl > 0, "{REFRESH_TTL_ENV} must be > 0");
            anyhow::ensure!(
                ttl <= MAX_REFRESH_TTL_SECS,
                "{REFRESH_TTL_ENV} must be <= {MAX_REFRESH_TTL_SECS}"
            );
            Ok(ttl)
        }
        None => Ok(DEFAULT_REFRESH_TTL_SECS),
    }
}

/// 从注入的配置读取器构造 vault `VaultSigner`（Transit ES256 签 access JWT）。
///
/// - `allow_http=false`（生产）：`VaultSigner::new`（HTTPS-only，fail-fast 拒非 https URL）+ rustls client。
/// - `allow_http=true`（集成测试 hermetic mock）：`VaultSigner::new_allow_http`（接受 http wiremock 地址）+
///   同 rustls client（兼处理 http 连接，保持 client 构造一致）。
///
/// 两路均用 `Jws` marshaling：JWT/JWS 需 raw `r‖s`（vault 默认 asn1=DER 会让 oidc 验签失败，OIDC-ALG-KEYPATH-01）。
fn build_vault_signer_with(
    get: impl Fn(&str) -> Option<String>,
    allow_http: bool,
) -> anyhow::Result<VaultSigner> {
    let addr = get(VAULT_ADDR_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {VAULT_ADDR_ENV}"))?;
    let token = get(VAULT_TOKEN_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {VAULT_TOKEN_ENV}"))?;
    let mount = get(VAULT_TRANSIT_MOUNT_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {VAULT_TRANSIT_MOUNT_ENV}"))?;
    let client = build_vault_tls_client()?;
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

/// 从 env 构造 access JWT 签发配置（ES256；issuer/audience/key-id/ttl 必填 fail-fast，对称
/// `JwtIssuer::new` 构造期校验）。`key` = vault Transit sign key 名 = JOSE `kid`（验签侧据此选公钥）。
fn build_jwt_issuer_config(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<authn::JwtIssuerConfig> {
    let issuer = get(JWT_ISSUER_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {JWT_ISSUER_ENV}"))?;
    let audience = get(JWT_AUDIENCE_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {JWT_AUDIENCE_ENV}"))?;
    let key_id = get(JWT_KEY_ID_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {JWT_KEY_ID_ENV}"))?;
    let ttl_secs = get(JWT_ACCESS_TTL_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {JWT_ACCESS_TTL_ENV}"))?
        .parse::<u64>()
        .with_context(|| format!("{JWT_ACCESS_TTL_ENV} must be an integer seconds value"))?;
    anyhow::ensure!(ttl_secs > 0, "{JWT_ACCESS_TTL_ENV} must be > 0");
    Ok(authn::JwtIssuerConfig {
        key: diport::KeyId::new(key_id),
        alg: authn::JwtAlg::Es256,
        purpose: diport::SigningPurpose::new(JWT_SIGNING_PURPOSE),
        issuer,
        audience,
        ttl: Duration::from_secs(ttl_secs),
    })
}

/// 接线 identity 域（生产路径）：薄壳，委托 [`wire_identity_with`]（读 `std::env`，HTTPS-only signer）。
pub fn wire_identity(deps: &SharedRuntimeDeps) -> anyhow::Result<IdentityDomain<VaultSigner>> {
    wire_identity_with(deps, |n| std::env::var(n).ok(), false)
}

/// 接线 identity 域（可注入配置读取器 + http 允许标志，供集成测试注入 hermetic mock vault）：
/// postgres credential/session/refresh store + vault `Signer`（经 [`build_vault_signer_with`]）
/// 经 [`authn::JwtIssuer`] 签 access JWT + SystemClock + session/refresh TTL（#1252）。
///
/// - `get`：配置读取器（生产 = `|n| std::env::var(n).ok()`；测试 = 注入 mock vault URL + JWT 配置）。
///   消费 `RSS_VAULT_ADDR`、`RSS_VAULT_TOKEN`、`RSS_VAULT_TRANSIT_MOUNT`、`RSS_JWT_ISSUER`、
///   `RSS_JWT_AUDIENCE`、`RSS_JWT_ES256_KEY_ID`、`RSS_JWT_ACCESS_TTL_SECS`、
///   `RSS_IDENTITY_SESSION_TTL_SECS`（可选）、`RSS_REFRESH_TTL_SECS`（可选）。
/// - `vault_allow_http`：`true` 接受 http URL（wiremock hermetic 测试）；`false` HTTPS-only（生产）。
///
/// 生产行为与 [`wire_identity`] 完全等价。单态化 `S = vault::VaultSigner`。
pub fn wire_identity_with(
    deps: &SharedRuntimeDeps,
    get: impl Fn(&str) -> Option<String>,
    vault_allow_http: bool,
) -> anyhow::Result<IdentityDomain<VaultSigner>> {
    let identity_pg = deps.pg.for_domain::<caps::Identity>();
    // get 借用（非 Copy）⇒ |n| get(n) 重借传给各 build helper（每次创建新引用闭包，get 始终可用）。
    let ttl = Duration::from_secs(identity_session_ttl_secs(|n| get(n))?);
    let refresh_ttl = Duration::from_secs(refresh_ttl_secs(|n| get(n))?);

    let credentials = Arc::from(DynCredentialRepo::new_box(identity_pg.credential_repo()));
    let lifecycle = Arc::from(DynSessionLifecycle::new_box(
        identity_pg.session_lifecycle(Box::new(SystemClock)),
    ));

    // vault `Signer` + JWT issuer（#1252）：access JWT 经 vault Transit ES256 签。signer shutdown 是 no-op
    // （reqwest pool drop 即释放），同 Pdp `provider` 不入 ShutdownStack——无需独立句柄注册。
    let signer = Arc::new(build_vault_signer_with(|n| get(n), vault_allow_http)?);
    let issuer = Arc::new(
        authn::JwtIssuer::new(
            signer,
            Box::new(SystemClock),
            build_jwt_issuer_config(|n| get(n))?,
        )
        .map_err(|e| anyhow::anyhow!("jwt issuer config error: {e}"))?,
    );

    let refresh = Arc::new(RefreshService::new(
        DynRefreshTokenStore::new_box(identity_pg.refresh_token_store()),
        issuer,
        Box::new(SystemClock),
        refresh_ttl,
    ));
    let login = Arc::new(LoginService::new(
        credentials,
        lifecycle,
        Arc::clone(&refresh),
        Box::new(SystemClock),
        ttl,
    ));
    Ok(IdentityDomain::new(login, refresh))
}

// ── Health listener（框架/组合根归属：healthz + readyz）─────────────────────────────────────────

/// Health listener 路由组前缀（liveness/readiness 在专用 listener 上；operator 配 k8s probe 路径指向此前缀下）。
const HEALTH_ROUTE_PREFIX: &str = "/health/v1";
/// liveness 端点契约 ID（框架归属基础设施探针，非域 wire 契约）。
const HEALTHZ_CONTRACT_ID: &str = "framework.healthz";
/// readiness 端点契约 ID（框架归属）。
const READYZ_CONTRACT_ID: &str = "framework.readyz";
/// `/metrics` scrape 端点契约 ID（框架归属基础设施导出，非域 wire 契约——同 healthz/readyz 为 inline 常量，
/// 无 `contracts/` 条目 / `frameworkContracts` 声明）。
const METRICS_CONTRACT_ID: &str = "framework.metrics";

/// 构造 Health listener 的已认证路由（`/health/v1/healthz` liveness + `/health/v1/readyz` readiness）。
///
/// Health 是**框架/组合根**归属：域 crate 不声明 health 路由组，组合根在此经公开 funnel
/// （`UnfinalizedRoutes::empty().nest_group::<Health>` → `finalize_auth`）挂载——产物仍是 `AuthenticatedRoutes`
/// （ROUTE-AUTH-FUNNEL：health router 也经 finalize_auth + request_id/trace 中间件，与业务 listener 一致）。
/// `NoAuth` plan（Health listener 无验签桥）。readyz handler 闭包持 `Arc<HealthReporter>`（`Send + Sync`，
/// 整体非 `Sync` 的 `Registry` 无法进 handler）每请求 `report`（worst-of 聚合所有已注册探针，含 `configs_ready`）。
///
/// `metrics` 是组合根注入的 `Arc<dyn diport::MetricsExporter>`（生产 = Prometheus，测试 = 替身）——`/metrics`
/// scrape handler 每请求 `render()` 取 exposition body。**必填**（非 `Option`/silent-noop，runtime-api Option 范式）。
///
/// **scrape 路径**：metrics 与 healthz/readyz 同组挂在 [`HEALTH_ROUTE_PREFIX`] 下，完整路径
/// `/health/v1/metrics`（非 Prometheus 默认 `/metrics`）——运维须在 scrape target 显式配
/// `metrics_path: /health/v1/metrics`（否则默认 `/metrics` 抓取得 404、被记空抓取）。挂 Health listener（内部
/// 网络面）而非对外 Primary：scrape 流量与 health probe 同隔离，且非-Primary `Route` 类型层无法降级 Public。
///
/// `pub`：供冒烟 e2e（`tests/runtime_serve_e2e.rs`）经真实 socket 绑定验证 serve + readyz + `/metrics` + 优雅关停闭环。
pub fn health_listener(
    reporter: Arc<bootstrap::HealthReporter>,
    metrics: Arc<dyn diport::MetricsExporter>,
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
                    )
                    .mount(
                        // `/metrics` 在 Health listener（内部网络面）；非-Primary `Route` 无 opt-out 字段 ⇒ 不可降级 Public。
                        httpserve::Route {
                            method: Method::GET,
                            path: "/metrics",
                            contract_id: METRICS_CONTRACT_ID,
                        },
                        httpserve::health::metrics(move || metrics.render()),
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
/// `register_background`：在 bind 循环前注册后台 worker（如 readiness 采样 task）进同一 `ShutdownStack`——
/// LIFO 下后台 worker 在所有 listener drain 后最后停（注册顺序决定停止顺序逆序）。
///
/// 每 listener：解析 bind 地址（fail-fast）→ `HttpServer::bind`（async fail-fast，注册前暴露端口冲突）→
/// 经 `ShutdownStack::register_with_token` 在同步 funnel 闭包内 `bound.serve(svc, token)` spawn serve task
/// （SHUTDOWN-TOKEN-FUNNEL-01）。信号到达 → `stack.shutdown()` 阶段 1 广播 cancel 触发各 serve graceful
/// drain、阶段 2 LIFO await 收敛。任一 listener 关闭失败聚合后非零退出（不静默丢弃）。
async fn serve_until_signal(
    listeners: Vec<(ListenerKind, httpserve::AuthenticatedRoutes)>,
    register_background: impl FnOnce(&mut ShutdownStack),
) -> anyhow::Result<()> {
    // 生产装配：真实 env 地址解析 + 真实信号 future（薄壳，委托可测核心 [`serve_until`]）。
    serve_until(
        listeners,
        register_background,
        listener_addr,
        wait_for_shutdown_signal(),
    )
    .await
}

/// 可测核心：注入 `addr_resolver`（listener→bind 地址）与 `shutdown` future（关停触发），驱动 bind 各
/// listener socket → 经 `ShutdownStack` 托管 serve → `shutdown` resolve 后 LIFO 优雅 drain。
///
/// `register_background`：bind 循环前注册后台 worker 进 `ShutdownStack`（LIFO：先注册后停——sampler 先注册
/// 则最后停，确保 listener drain 后 sampler 才停）。
///
/// 生产经 [`serve_until_signal`] 注入真实 env 解析 + 信号 future；测试注入 `|_| Ok(127.0.0.1:0)` + 立即
/// resolve 的 future，覆盖 bind 循环 + 多 listener + ensure-非空 + drain 聚合（serve_until_signal 本身依赖
/// OS 信号不可 hermetic 测，故抽核心）。任一 listener 关闭失败聚合后非零退出（不静默丢弃）。
// reason: bind 循环 + 启动就绪 / drain 多条 tracing 宏展开在 cognitive_complexity 计数贡献额外节点；
// 实际控制流是「bind 各 listener → 等关停 → shutdown」三段——item-level carve-out（error-handling.md §Carve-out）。
#[allow(clippy::cognitive_complexity)]
async fn serve_until<B, R, S>(
    listeners: Vec<(ListenerKind, httpserve::AuthenticatedRoutes)>,
    register_background: B,
    addr_resolver: R,
    shutdown: S,
) -> anyhow::Result<()>
where
    B: FnOnce(&mut ShutdownStack),
    R: Fn(ListenerKind) -> anyhow::Result<SocketAddr>,
    S: std::future::Future<Output = anyhow::Result<()>>,
{
    anyhow::ensure!(
        !listeners.is_empty(),
        "no listener has routes to serve (refusing to start with zero bound sockets)"
    );
    let listener_count = listeners.len();
    let mut stack = ShutdownStack::new(CancellationToken::new());
    // 先注册后台 worker（LIFO：listener 后注册先 drain，sampler 先注册后停——确保 listener drain 后采样停）。
    register_background(&mut stack);
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

/// otel OTLP/gRPC 导出端点环境变量（**按需开启**：未设 → 不导出 trace，仅 fmt 日志；设了 → 按 scheme 派发 typed endpoint）。
const OTEL_ENDPOINT_ENV: &str = "RSS_OTEL_ENDPOINT";

/// 由注入的配置读取器构建可选 otel trace 导出 exporter（DI 核心，可测；**不**触碰全局 subscriber）。
///
/// **按需开启**：[`OTEL_ENDPOINT_ENV`] 未设 → `Ok(None)`（仅 fmt 日志，不导出 trace）。设了则按 scheme 派发
/// typed [`otel::OtelEndpoint`]——`https://` → TLS（生产默认）；`http://` → 仅 loopback host 显式明文 opt-in
/// （非 loopback 即 `Err`，零信任 fail-closed）；其它 scheme → `Err`。**fail-fast**：误配在组合根接线期即暴露，
/// 不静默退回 fmt（值非法 ≠ 未配）。返回的 exporter 由 [`run`] 接管生命周期（注册进 `ShutdownStack` 关停时 flush）。
fn build_trace_export(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<Option<otel::OtelExporter>> {
    let Some(raw) = get(OTEL_ENDPOINT_ENV) else {
        return Ok(None);
    };
    let endpoint = if raw.starts_with("https://") {
        otel::OtelEndpoint::tls(raw.as_str()).context("RSS_OTEL_ENDPOINT https (TLS) endpoint")?
    } else if raw.starts_with("http://") {
        otel::OtelEndpoint::insecure_localhost(raw.as_str())
            .context("RSS_OTEL_ENDPOINT http endpoint must target a loopback host")?
    } else {
        // 错误只含变量名、不含 raw 值（endpoint 可携 userinfo/token，避免明文进启动日志；调试细节经
        // OtelEndpoint::{tls,insecure_localhost} 的 error chain 上层已足够）。
        anyhow::bail!("{OTEL_ENDPOINT_ENV} must be https:// (TLS) or http:// to a loopback host");
    };
    let provider = otel::build_otlp_provider(endpoint).context("build OTLP/gRPC trace provider")?;
    Ok(Some(otel::OtelExporter::new(provider)))
}

/// 装配生产 tracing subscriber（fmt + `RUST_LOG` env filter + 可选 otel OTLP/gRPC 桥接 Layer，默认 `info`）。
///
/// 组合根 binary 入口在 [`run`] **之前**调用（`main`）——否则运行时入口的全部结构化日志（bind / serve /
/// shutdown / fail-fast）皆为 no-op、生产零可见性。仅生产入口调用；测试不调（各测试自设 subscriber，见
/// `auth_e2e` 的 `set_default`），故本 fn 不进 `run`（避免与测试 subscriber 冲突 / 全局 init 重复 panic）。
///
/// 返回构建出的 [`otel::OtelExporter`]（若 [`OTEL_ENDPOINT_ENV`] 已配；否则 `None`）——`main` 把它交给 [`run`]，
/// 由组合根注册进 `ShutdownStack`，关停时 flush 未导出 span。`Err` = endpoint 误配（fail-fast，见 [`build_trace_export`]）。
///
/// **覆盖边界**：本 fn 是薄壳（同 `listener_addr` 之于 `listener_addr_from`）——可测逻辑全在内核
/// [`build_trace_export`]（5 态表驱动单测覆盖 endpoint 派发 / fail-fast）。薄壳本身的全局
/// `registry().…with(otel_layer).init()` 是进程级一次性 init，仅生产 `main` 执行、无法单元测试（测试各自
/// `set_default`，见 `auth_e2e`），故不单测；`otel_layer` 的 `Some/None` 两态由 `build_trace_export` 单测间接覆盖。
pub fn init_tracing() -> anyhow::Result<Option<otel::OtelExporter>> {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let trace_export = build_trace_export(|name| std::env::var(name).ok())?;
    // Option<Layer> 即 no-op layer（None → 不导出 trace）：覆盖「配 / 未配 endpoint」两态，subscriber 形态恒定。
    let otel_layer = trace_export.as_ref().map(|e| e.layer());
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .with(otel_layer)
        .init();
    Ok(trace_export)
}

/// 生产组合根入口（运行时入口 Join #1320）：compose 域 → connect pg + migrations → wire_settings
/// → F8 接线（`PgDbReadiness` 采样 worker + `configs_ready` probe）→ 装配认证接线 → 挂 Health listener
/// → bind + serve + 信号优雅关停。
///
/// 缺配 / 连不上 / migration 失败均 **fail-fast**（不静默 ready）。各域业务 handler ↔ service 接线
/// = #1309 及后续域 PR；本 fn 仅打通 async runtime + ≥1 个 wire_X call-site + readiness probe。
/// tracing subscriber 由 [`init_tracing`] 在 `main` 中先于本 fn 装配。
// reason: 组合根入口顺序编排（pg setup〔connect+migrations〕 → wire_settings → F8 probe → serve）
// 多条 tracing 宏展开在 cognitive_complexity 计数贡献额外节点——item-level carve-out（error-handling.md §Carve-out）。
#[allow(clippy::cognitive_complexity)]
pub async fn run(trace_export: Option<otel::OtelExporter>) -> anyhow::Result<()> {
    let provider = Arc::new(build_provider()?);

    // postgres capability bundle（#1423）：集中 connect + migrations + readiness handle（生产 fail-fast，
    // 缺配/连不上/迁移失败不静默 ready）。`setup` 是唯一公开构造路径（PG-BUNDLE-FUNNEL-01）。
    let pg = PgRuntimeDeps::setup(&build_pg_config()?)
        .await
        .context("setup postgres deps")?;

    // vault capability bundle（#1498）：env → resolver → VaultRuntimeDeps（单源装配出口）。vault env 缺失即
    // fail-fast（不静默装配 vault）；resolver 经 bundle dispatch 注入 settings，guard 经 runtime_resources 单源。
    let vault =
        build_vault_runtime_deps(|name| std::env::var(name).ok()).context("setup vault deps")?;
    // redis capability bundle 是 demo-optional（#332 F2）：分布式 lock/CAS provider 当前为 draft、组合根无
    // consumer（见 assembly.toml 注释），故未配 `RSS_REDIS_URL` 即跳过、不打断默认 demo 路径；配了则照常
    // PING + fail-fast（durable 部署仍 fail-closed）。go-live（active + wire_distributed）落地时改回必配。
    let redis = if std::env::var_os("RSS_REDIS_URL").is_some() {
        Some(
            build_redis_runtime_deps(|name| std::env::var(name).ok())
                .await
                .context("setup redis deps")?,
        )
    } else {
        tracing::warn!(
            "RSS_REDIS_URL 未配置：跳过 redis capability bundle（distributed lock/CAS provider 为 draft、组合根无 consumer）"
        );
        None
    };

    // 共享基础设施依赖（infra 流入各域 wire_X；「字段仅 infra」是约定，机器门见 #1448）。
    let deps = SharedRuntimeDeps {
        pg: pg.clone(),
        redis,
        vault,
    };

    // Prometheus 指标导出（#1253）：装进程级 `metrics` global recorder（counter!/gauge! 发射点经此写入）+ 持 render 句柄。
    // **fail-fast**：global recorder 已装（重复 install）即 Err——误配在接线期暴露，不静默 noop。Arc<dyn> 共享给 /metrics handler。
    // PromExporter 的 ManagedResource::shutdown 是文档化 no-op（pull exporter 无后台任务/连接），故不进 ShutdownStack。
    //
    // assembly.toml 治理豁免（与 oidc/vault/postgres 等 adapter 同——均在组合根注入、不在 `[[diportProviders]]` 声明）：
    // `cargo xtask assembly validate` 的 `DiportPort` 仅 gate `diport::RevocationStore` 的「production 必须 durability=persistent」。
    // `MetricsExporter` 是无状态 pull port，无 ephemeral/persistent 之分、无 dev/demo vs prod provider 选择，治理无可校验项 ⇒ 不入 enum。
    let metrics_exporter: Arc<dyn diport::MetricsExporter> =
        Arc::new(prometheus::PromExporter::install().context("install prometheus recorder")?);

    // wire_audit（#1230）：env 链 key fail-fast → RustCrypto hasher → PgAuditRepo → erased AuditDomain。
    let audit_domain = wire_audit(&deps).context("wire audit")?;
    let identity_domain = wire_identity(&deps).context("wire identity")?;
    // settings durable module（#1430 PERSIST-009）：domain 实例持 config 服务 + secret 仓储端口（挂 config-publish /
    // secret-publish 业务路由）；module 携 configs_ready 探针。
    let (settings_domain, settings_module) = wire_settings(&deps).await.context("wire settings")?;

    // settings/identity/audit domain 实例注册（声明 routes/subscribers/probes）。
    let mut registry = bootstrap::compose(&[&settings_domain, &identity_domain, &audit_domain])
        .context("compose domains")?;

    // 聚合各域 module result（settings configs_ready 探针；后续域只需多一行 module.merge(wire_X(&deps).await?)）。
    let mut module = DomainModuleResult::default();
    module.merge(settings_module);
    // provider capability bundle 单源装配（#1498）：vault resolver guard 经 runtime_resources() 单源排进
    // module.resources，组合根不再逐 channel 手写 register_detached（D5）。redis 为 demo-optional（未配
    // RSS_REDIS_URL 时 None），仅在已装配时排入 pool guard（#332 F2）；amqp 待各自 durable body 接入。
    if let Some(redis) = &deps.redis {
        module.resources.extend(redis.runtime_resources());
    }
    module.resources.extend(deps.vault.runtime_resources());

    // 框架归属 RLS 能力门 readyz 兜底探针（须先于 take_health_reporter）：把启动期 verify_rls_capability
    // 的结果显式暴露到 readyz（启动已 fail-fast，故进程在跑时恒 ready；运维可见 + 周期再核验接线点）。
    let rls_probe_name =
        ProbeName::parse(RLS_READY_PROBE_NAME).context("parse rls_ready probe name")?;
    registry
        .probe(
            rls_probe_name,
            Box::new(RlsReadyProbe::new(pg.rls_ready_handle())),
        )
        .context("register rls_ready probe")?;

    // 事件传输接线（#1251）：topology-gated durable AMQP/Redis + outbox relay + consumer workers。
    // Demo 拓扑 fail-fast（生产不走 in-memory 路径；TOPO-INMEM-SEAL-01 组合根层保证）。
    let event_cfg = build_event_transport_config().context("event transport config")?;
    if event_cfg.topology == bootstrap::Topology::Demo {
        anyhow::bail!(
            "RSS_TOPOLOGY=demo is not supported in the production runtime; \
             use durable-shared or durable-isolated"
        );
    }
    let event_subscribers = registry.drain_subscribers();
    let event_runtime = event_transport::wire_event_transport(&pg, event_subscribers, event_cfg)
        .await
        .context("wire event transport")?;
    let event_infra_guards = event_runtime.infra_guards;
    module.merge(event_runtime.module);

    // 排空 module 探针进 registry（须先于 take_health_reporter，readyz 才聚合域 + event worker probes）。
    for (name, probe) in module.probes {
        let probe_label = name.as_str().to_owned();
        registry
            .probe(name, probe)
            .with_context(|| format!("register module probe '{probe_label}'"))?;
    }

    // module detached 资源 / 后台 worker（域 + event transport 统一出口）——移出供 serve 闭包排空。
    let domain_resources = module.resources;
    let domain_workers = module.workers;
    let period = build_readiness_interval();
    tracing::info!(
        sample_interval_secs = period.as_secs(),
        "pg readiness sampler interval configured"
    );

    // 装配域路由认证接线（drain registry 路由组，借 &mut——probe 留存供下方 readyz）。
    // Auth decision audit is a flat durable sink, not the `audit::AuditRepo` hash-chain actor model.
    let auth_audit_sink =
        httpserve::AuditSinkHandle::new(pg.for_domain::<caps::Audit>().auth_audit_sink());
    let auth_audit_clock: Arc<dyn diport::Clock> = Arc::new(SystemClock);
    let mut listeners =
        assemble_authed_routers(&mut registry, provider, auth_audit_sink, auth_audit_clock)
            .context("assemble authed routers")?;

    // Health listener（框架归属）：readyz 经 Arc<HealthReporter>（Send+Sync）每请求聚合探针。registry 路由组
    // 已 drain，探针经 take_health_reporter 移出（整体非 Sync 的 Registry 无法进 axum handler 闭包）。
    let reporter = Arc::new(registry.take_health_reporter());
    listeners.push(health_listener(reporter, metrics_exporter).context("build health listener")?);

    // LIFO 注册顺序：otel exporter 先注册（最后关，关停期 span flush）→ pg pool guard → sampler →
    // event infra guards（AMQP+Redis）→ module resources/workers（event + 域）→
    // listeners 最后注册（最先 drain）。完整关停（LIFO 逆序）：listeners → 域 workers → 域 resources →
    //   event workers（relay+consumers drain）→ event infra guards（AMQP+Redis 断连）→ sampler → pg pool guard
    //   → otel exporter（trace flush 在所有组件静默后）。otel 仅在配了 RSS_OTEL_ENDPOINT 时存在。
    serve_until_signal(listeners, move |stack| {
        // otel trace 导出 exporter（若已配 RSS_OTEL_ENDPOINT）**最先**注册 → LIFO 最后 drain：span flush 在所有
        // 组件（listeners → workers → 域 resources → sampler → pool guard）全部静默后执行，不丢失关停期 span。
        // reason: trace flush 须在不再产生新 span 后做，故注册在最前（=最后关）；未配 endpoint 时 None，无注册。
        if let Some(exporter) = trace_export {
            stack.register_detached(DynManagedResource::new_box(exporter));
        }
        // 再注册框架 pg infra（非域产物）：pool guard（LIFO 较后关——sampler 停后再关池，避免在已关闭 pool 上发 probe）。
        stack.register_detached(DynManagedResource::new_box(pg.store_guard()));
        // 再注册 sampler（spawn+adopt 收口进 bundle；child token 广播取消；LIFO：listener drain → sampler 停 → pool close）。
        stack.register_with_token(move |token| {
            DynManagedResource::new_box(pg.spawn_readiness_sampler(period, token))
        });
        // 事件传输 infra guards（AMQP + Redis）先于 workers 注册 → LIFO 在 workers drain 后才断连接。
        for g in event_infra_guards {
            stack.register_detached(g);
        }
        // module 产物注册在事件传输 infra 之后 → LIFO 先于 AMQP/Redis 排空（relay/consumer drain 后再断连接）。
        for r in domain_resources {
            stack.register_detached(r);
        }
        for w in domain_workers {
            stack.register_with_token(w);
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "integration")]
    use diport::ManagedResource as _;

    const B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE_NO_PAD;

    /// 测试时钟（这些测试只验构造成功/失败，不验 token exp，故 SystemClock 即可）。
    fn clk() -> Box<dyn diport::Clock> {
        Box::new(SystemClock)
    }

    /// settings 域产物：恰一条 `configs_ready` 探针、resources / workers 空。
    ///
    /// 直测 [`settings_module_result`]（脱离 vault env / 真实 pg），覆盖 `wire_settings` 的探针 emission
    /// 契约——该路径在 integration Ok 分支（需 vault+pg）外不可达，故抽出后单测以满足新增覆盖。
    #[test]
    #[allow(clippy::expect_used)]
    fn settings_module_result_emits_single_configs_ready_probe() {
        let readiness = Arc::new(PgDbReadiness::new());
        let result = settings_module_result(readiness).expect("settings_module_result ok");
        assert_eq!(result.probes.len(), 1, "仅 configs_ready 一条探针");
        assert_eq!(result.probes[0].0.as_str(), CONFIGS_READY_PROBE_NAME);
        assert!(result.resources.is_empty(), "settings 今无 detached 资源");
        assert!(result.workers.is_empty(), "settings 今无后台 worker");
    }

    /// RlsReadyProbe：`true → Healthy("ready")` / `false → Unhealthy("not-enforced")`（fail-closed）。
    #[test]
    fn rls_ready_probe_maps_flag_to_health() {
        use bootstrap::HealthProbe;
        use std::sync::atomic::{AtomicBool, Ordering};

        let flag = Arc::new(AtomicBool::new(true));
        let probe = RlsReadyProbe::new(Arc::clone(&flag));
        let ready = probe.check();
        assert_eq!(ready.status(), HealthStatus::Healthy);
        assert_eq!(ready.detail(), "ready");
        assert_eq!(ready.name().as_str(), RLS_READY_PROBE_NAME);

        flag.store(false, Ordering::Release);
        let down = probe.check();
        assert_eq!(down.status(), HealthStatus::Unhealthy);
        assert_eq!(down.detail(), "not-enforced");
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

    // ── audit chain key wiring（#1230）─────────────────────────────────────────

    #[test]
    fn build_audit_hasher_missing_key_fails_fast() {
        // 缺 RSS_AUDIT_CHAIN_KEY_B64URL → fail-fast（生产审计链不可无 key）；错误含变量名、不含值。
        let result = build_audit_hasher(|_| None);
        assert!(
            matches!(&result, Err(e) if e.to_string().contains("RSS_AUDIT_CHAIN_KEY_B64URL")),
            "缺 key env 须 fail-fast 且错误含变量名"
        );
    }

    #[test]
    fn build_audit_hasher_invalid_base64_fails_fast() {
        let get = |k: &str| (k == "RSS_AUDIT_CHAIN_KEY_B64URL").then(|| "!!not-b64!!".to_string());
        assert!(
            build_audit_hasher(get).is_err(),
            "非 base64url key 须 fail-fast"
        );
    }

    #[test]
    fn build_audit_hasher_weak_key_fails_fast() {
        // 解码后 <32B → AuditChainHasher::new 返回 None → fail-fast（链 key 强度，audit-ledger.md）。
        let short = B64.encode([0x5au8; 16]);
        let get = move |k: &str| (k == "RSS_AUDIT_CHAIN_KEY_B64URL").then(|| short.clone());
        assert!(
            matches!(&build_audit_hasher(get), Err(e) if e.to_string().contains("at least 32 bytes")),
            "弱 key（<32B）须 fail-fast"
        );
    }

    #[test]
    fn build_audit_hasher_valid_32b_key_ok() {
        // 32B key（base64url）→ 构造成功（生产 RustCrypto hasher 装配路径）。
        let key = B64.encode([0x42u8; 32]);
        let get = move |k: &str| (k == "RSS_AUDIT_CHAIN_KEY_B64URL").then(|| key.clone());
        assert!(build_audit_hasher(get).is_ok(), "有效 32B key 须构造成功");
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
    #[allow(clippy::expect_used)] // reason: 有效 env 必构造成功，item-level carve-out。
    fn build_vault_runtime_deps_valid_env_single_sources_resolver() {
        // addr + token 在 → 构造成功（无 live vault：VaultSecretResolver::new 仅构造期校验 URL/token +
        // 空 allowlist + warn_vault_startup_security 告警路径）；runtime_resources 单源派生恰一条 resolver guard。
        let get = |k: &str| match k {
            _ if k == VAULT_ADDR_ENV => Some("https://vault.example:8200".to_string()),
            _ if k == VAULT_TOKEN_ENV => Some("s.testtoken".to_string()),
            _ => None,
        };
        let deps = build_vault_runtime_deps(get);
        assert!(deps.is_ok(), "有效 vault env 须构造成功");
        let resources = deps.expect("valid vault deps").runtime_resources();
        assert_eq!(resources.len(), 1, "vault bundle 单源派生 resolver guard");
    }

    #[tokio::test]
    async fn build_redis_runtime_deps_missing_url_fails_fast() {
        let result = build_redis_runtime_deps(|_| None).await;
        assert!(
            matches!(&result, Err(e) if format!("{e:#}").contains("RSS_REDIS_URL")),
            "缺 redis url env 须 fail-fast 且错误含变量名"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn build_redis_runtime_deps_unreachable_url_fails_fast() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);

        let result = build_redis_runtime_deps(|name| {
            (name == "RSS_REDIS_URL").then(|| format!("redis://{addr}"))
        })
        .await;
        assert!(
            matches!(&result, Err(e) if format!("{e:#}").contains("RSS_REDIS_URL")),
            "不可达 redis url 须启动期 fail-fast 且错误含变量名"
        );
    }

    #[cfg(feature = "integration")]
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn build_redis_runtime_deps_valid_env_single_sources_pool_guard() {
        let fixture = testkit::env_or_redis().await.expect("redis fixture");
        let url = fixture.url().to_string();
        let deps =
            build_redis_runtime_deps(|name| (name == "RSS_REDIS_URL").then(|| url.clone())).await;
        assert!(deps.is_ok(), "有效 redis url 须构造成功");
        let resources = deps.expect("valid redis deps").runtime_resources();
        assert_eq!(resources.len(), 1, "redis bundle 单源派生 pool guard");
        assert_eq!(resources[0].name(), "redis", "redis resource 即 pool guard");
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
        let routers = assemble_authed_routers(
            &mut registry,
            provider,
            httpserve::AuditSinkHandle::new(TracingAuthAuditSink),
            Arc::new(SystemClock),
        )
        .expect("assemble ok");
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

    /// `RSS_PG_SSL_MODE` 解析：未配置 / 非法 / 空 → fail-closed VerifyFull；合法 libpq 拼写 → 对应模式。
    ///
    /// `PgSslMode`（sqlx 上游）未实现 `PartialEq`，故表驱动用 `Debug` 变体名断言（fieldless enum 的 derive
    /// `Debug` 恒等于变体名，与 [`build_pg_config_defaults_ssl_verify_full`] 同范式）。
    #[test]
    fn parse_pg_ssl_mode_maps_and_falls_back_to_verify_full() {
        let cases = [
            (None, "VerifyFull"), // 未配置 → 零信任默认（强制 TLS + 校验证书链/主机名）
            (Some("disable"), "Disable"), // 合法 libpq 拼写 → 对应模式
            (Some("PREFER"), "Prefer"), // 大小写不敏感
            (Some("  require "), "Require"), // 前后空白不敏感
            (Some("verify-ca"), "VerifyCa"),
            (Some("verify-full"), "VerifyFull"),
            (Some("allow"), "Allow"),
            (Some("bogus"), "VerifyFull"), // 非法值 → fail-closed 回退（恒向更严）
            (Some(""), "VerifyFull"),      // 空串 → fail-closed 回退
        ];
        for (raw, expected) in cases {
            let got = format!("{:?}", parse_pg_ssl_mode(raw.map(str::to_owned)));
            assert_eq!(got, expected, "RSS_PG_SSL_MODE={raw:?}");
        }
    }

    // ── ConfigsReadyProbe / readiness_to_health 测试 ─────────────────────────────────────

    /// `PoolReadiness::Ready` → `(Healthy, "ready")`。
    #[test]
    fn configs_ready_maps_ready_to_healthy() {
        let (status, detail) = readiness_to_health(PoolReadiness::Ready);
        assert_eq!(status, HealthStatus::Healthy);
        assert_eq!(detail, "ready");
    }

    /// `PoolReadiness::Saturated` → `(Degraded, "saturated")`（池饱和降级，HTTP 200 不摘流）。
    #[test]
    fn configs_ready_maps_saturated_to_degraded() {
        let (status, detail) = readiness_to_health(PoolReadiness::Saturated);
        assert_eq!(status, HealthStatus::Degraded);
        assert_eq!(detail, "saturated");
    }

    /// `PoolReadiness::Down` → `(Unhealthy, "down")`。
    #[test]
    fn configs_ready_maps_down_to_unhealthy() {
        let (status, detail) = readiness_to_health(PoolReadiness::Down);
        assert_eq!(status, HealthStatus::Unhealthy);
        assert_eq!(detail, "down");
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
        let mut registry = bootstrap::compose(&[]).expect("empty compose");

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

    /// `RLS_READY_PROBE_NAME` 是合法 `ProbeName`；真实 `RlsReadyProbe` 可注册 + 重名拒绝（与 configs_ready 对称）。
    #[test]
    #[allow(clippy::expect_used)]
    fn rls_ready_registers_and_is_unique() {
        use std::sync::atomic::AtomicBool;
        // reason: RLS_READY_PROBE_NAME 是 const literal，parse 只可能在字符非法时失败。
        let name_a =
            primitives::ProbeName::parse(RLS_READY_PROBE_NAME).expect("valid probe name const");
        let name_b =
            primitives::ProbeName::parse(RLS_READY_PROBE_NAME).expect("valid probe name const");
        let mut registry = bootstrap::compose(&[]).expect("empty compose");
        let flag = Arc::new(AtomicBool::new(true));

        registry
            .probe(name_a, Box::new(RlsReadyProbe::new(Arc::clone(&flag))))
            .expect("first register ok");
        let result = registry.probe(name_b, Box::new(RlsReadyProbe::new(flag)));
        assert!(
            result.is_err(),
            "duplicate rls_ready probe name should be rejected"
        );
    }

    // ── build_readiness_interval_from 测试 ────────────────────────────────────────────────

    /// 未配置 → 静默取默认 5s（非显式误配，不 warn）。
    #[test]
    fn build_readiness_interval_default_when_missing() {
        let d = build_readiness_interval_from(|_| None);
        assert_eq!(d, DEFAULT_READINESS_INTERVAL, "缺省 → 5s");
    }

    /// 合法正整数（在 1..=300 范围内）→ 对应秒数。
    #[test]
    fn build_readiness_interval_custom_value() {
        let d = build_readiness_interval_from(|n| {
            (n == "RSS_PG_READINESS_SAMPLE_INTERVAL_SECS").then(|| "10".to_string())
        });
        assert_eq!(d, Duration::from_secs(10));
    }

    /// 显式非法（非数字 / 0）→ warn + 默认 5s（fail-soft；间隔是 hint 非强依赖）。
    #[test]
    fn build_readiness_interval_invalid_falls_back() {
        let d1 = build_readiness_interval_from(|n| {
            (n == "RSS_PG_READINESS_SAMPLE_INTERVAL_SECS").then(|| "not-a-number".to_string())
        });
        assert_eq!(d1, DEFAULT_READINESS_INTERVAL, "非数字 → warn + 默认");
        let d2 = build_readiness_interval_from(|n| {
            (n == "RSS_PG_READINESS_SAMPLE_INTERVAL_SECS").then(|| "0".to_string())
        });
        assert_eq!(d2, DEFAULT_READINESS_INTERVAL, "0 → warn + 默认");
    }

    /// 越界（> MAX_READINESS_INTERVAL_SECS=300）→ warn + 默认 5s。
    #[test]
    fn build_readiness_interval_above_max_warns_and_defaults() {
        let d = build_readiness_interval_from(|n| {
            (n == "RSS_PG_READINESS_SAMPLE_INTERVAL_SECS").then(|| "999".to_string())
        });
        assert_eq!(d, DEFAULT_READINESS_INTERVAL, "999 > 300 → warn + 默认 5s");
    }

    /// 下边界 1s → 对应（合法最小值）。
    #[test]
    fn build_readiness_interval_boundary_min() {
        let d = build_readiness_interval_from(|n| {
            (n == "RSS_PG_READINESS_SAMPLE_INTERVAL_SECS").then(|| "1".to_string())
        });
        assert_eq!(d, Duration::from_secs(1), "1 → 1s（合法下边界）");
    }

    /// 上边界 300s → 对应（合法最大值）。
    #[test]
    fn build_readiness_interval_boundary_max() {
        let d = build_readiness_interval_from(|n| {
            (n == "RSS_PG_READINESS_SAMPLE_INTERVAL_SECS").then(|| "300".to_string())
        });
        assert_eq!(d, Duration::from_secs(300), "300 → 300s（合法上边界）");
    }

    // ── identity_session_ttl_secs 测试 ────────────────────────────────────────────────

    #[test]
    #[allow(clippy::expect_used)]
    fn identity_session_ttl_defaults_when_missing() {
        let ttl = identity_session_ttl_secs(|_| None).expect("default ttl");
        assert_eq!(ttl, DEFAULT_IDENTITY_SESSION_TTL_SECS);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn identity_session_ttl_accepts_valid_value() {
        let ttl = identity_session_ttl_secs(|n| {
            (n == IDENTITY_SESSION_TTL_ENV).then(|| "7200".to_string())
        })
        .expect("valid ttl");
        assert_eq!(ttl, 7_200);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn identity_session_ttl_rejects_non_integer() {
        let err = identity_session_ttl_secs(|n| {
            (n == IDENTITY_SESSION_TTL_ENV).then(|| "not-a-number".to_string())
        })
        .expect_err("non-integer ttl must fail");
        assert!(
            err.to_string().contains("integer seconds value"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn identity_session_ttl_rejects_zero() {
        let err =
            identity_session_ttl_secs(|n| (n == IDENTITY_SESSION_TTL_ENV).then(|| "0".to_string()))
                .expect_err("zero ttl must fail");
        assert!(
            err.to_string().contains("must be > 0"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn identity_session_ttl_rejects_above_max() {
        let err = identity_session_ttl_secs(|n| {
            (n == IDENTITY_SESSION_TTL_ENV).then(|| (MAX_IDENTITY_SESSION_TTL_SECS + 1).to_string())
        })
        .expect_err("above max ttl must fail");
        assert!(
            err.to_string()
                .contains(&format!("must be <= {MAX_IDENTITY_SESSION_TTL_SECS}")),
            "unexpected error: {err:#}"
        );
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

    /// 测试用 `/metrics` 渲染替身（固定 exposition）——不装进程级 global recorder，避免与 `PromExporter::install`
    /// 进程单例争用。健康/serve 测试只验路由组装与 bind，不验真实指标内容。
    #[derive(Clone)]
    struct FixedMetrics(&'static str);
    impl diport::MetricsExporter for FixedMetrics {
        fn render(&self) -> String {
            self.0.to_owned()
        }
    }
    fn noop_metrics() -> Arc<dyn diport::MetricsExporter> {
        Arc::new(FixedMetrics("# noop\n"))
    }

    // ── build_trace_export：otel 导出按需开启 + endpoint typed 安全边界（fail-fast）─────────────
    // get 注入式（不读真实 env），覆盖 None / TLS / loopback-http / 非 loopback 明文 / 非法 scheme 五态。

    #[test]
    #[allow(clippy::expect_used)] // reason: 测试断言失败路径用 expect 直观定位（error-handling §Carve-out item-level）
    fn build_trace_export_unset_endpoint_is_none() {
        // 未配 RSS_OTEL_ENDPOINT → 仅 fmt 日志、不导出 trace（按需开启），且非 Err。
        let out = build_trace_export(|_| None).expect("unset endpoint is Ok(None)");
        assert!(out.is_none(), "unset endpoint must yield None");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: 测试断言失败路径用 expect 直观定位（error-handling §Carve-out item-level）
    async fn build_trace_export_loopback_http_builds_exporter() {
        // 明文 http 指向 loopback → 显式 opt-in，构建出 exporter（connect_lazy，不连真实 collector）。
        let out = build_trace_export(|name| {
            (name == OTEL_ENDPOINT_ENV).then(|| "http://localhost:4317".to_owned())
        })
        .expect("loopback http endpoint builds exporter");
        assert!(out.is_some(), "loopback http must build Some(exporter)");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: 测试断言失败路径用 expect 直观定位（error-handling §Carve-out item-level）
    async fn build_trace_export_tls_https_builds_exporter() {
        let out = build_trace_export(|name| {
            (name == OTEL_ENDPOINT_ENV).then(|| "https://collector.internal:4317".to_owned())
        })
        .expect("https TLS endpoint builds exporter");
        assert!(out.is_some(), "https endpoint must build Some(exporter)");
    }

    #[test]
    #[allow(clippy::expect_used)] // reason: 测试断言失败路径用 expect 直观定位（error-handling §Carve-out item-level）
    fn build_trace_export_nonloopback_http_is_err() {
        // 明文 http 指向非 loopback host → fail-closed Err（不静默放行明文导出到远端）。
        let err = build_trace_export(|name| {
            (name == OTEL_ENDPOINT_ENV).then(|| "http://collector.internal:4317".to_owned())
        })
        .map(|_| ()) // OtelExporter 非 Debug，expect_err 前把 Ok 臂折叠成 ()
        .expect_err("non-loopback plaintext must fail-fast");
        assert!(
            format!("{err:#}").contains("loopback"),
            "err 应提示 loopback 约束: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)] // reason: 测试断言失败路径用 expect 直观定位（error-handling §Carve-out item-level）
    fn build_trace_export_bad_scheme_is_err() {
        // 非 http(s) scheme → fail-fast（误配在接线期暴露，不静默退回 fmt）。
        let err = build_trace_export(|name| {
            (name == OTEL_ENDPOINT_ENV).then(|| "grpc://collector:4317".to_owned())
        })
        .map(|_| ()) // OtelExporter 非 Debug，expect_err 前把 Ok 臂折叠成 ()
        .expect_err("non http(s) scheme must fail-fast");
        assert!(
            err.to_string().contains(OTEL_ENDPOINT_ENV),
            "err 应含 env 变量名: {err}"
        );
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
            health_listener(test_reporter(), noop_metrics()).expect("h1"),
            health_listener(test_reporter(), noop_metrics()).expect("h2"),
        ];
        serve_until(
            listeners,
            |_stack| {}, // 无后台 worker（测 serve 循环本身）
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
            |_stack| {}, // 无后台 worker（测 serve 循环本身）
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
        let listeners = vec![health_listener(test_reporter(), noop_metrics()).expect("health")];
        let err = serve_until(
            listeners,
            |_stack| {}, // 无后台 worker（测 serve 循环本身）
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
        let (_, authed) = health_listener(empty, noop_metrics()).expect("health listener");
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
        let (_, authed) = health_listener(reporter, noop_metrics()).expect("health listener");
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

    /// Down 路径（fail-closed，不连 DB）：新建 `PgDbReadiness`（初值 Down）→ readyz 503。
    ///
    /// 验证在未经任何采样 tick 前，`ConfigsReadyProbe` 报 Down → overall unhealthy → 503。
    /// 迁自 `tests/configs_ready_e2e.rs`（原在 integration feature 门控下，azure 不跑）——
    /// 此测试无需真实 DB，应在非 integration 路径下运行（[T2] #1309 review）。
    #[tokio::test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    async fn configs_ready_initial_down_readyz_503() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt as _;

        // 初值 Down（fail-closed，不连 DB）。
        let health = Arc::new(PgDbReadiness::new());
        let mut reg = bootstrap::compose(&[]).expect("compose");
        reg.probe(
            ProbeName::parse(CONFIGS_READY_PROBE_NAME).expect("valid probe name"),
            Box::new(ConfigsReadyProbe::new(Arc::clone(&health))),
        )
        .expect("register probe");
        let reporter = Arc::new(reg.take_health_reporter());

        let (_listener, authed) =
            health_listener(reporter, noop_metrics()).expect("health listener");
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
            "初值 Down（未采样）→ readyz fail-closed 503"
        );
    }

    // ── refresh_ttl_secs 测试 ────────────────────────────────────────────────────────────────

    #[test]
    #[allow(clippy::expect_used)]
    fn refresh_ttl_secs_rejects_zero() {
        let err = refresh_ttl_secs(|n| (n == REFRESH_TTL_ENV).then(|| "0".to_string()))
            .expect_err("zero refresh ttl must fail");
        assert!(
            err.to_string().contains("must be > 0"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn refresh_ttl_secs_rejects_above_max() {
        let err = refresh_ttl_secs(|n| {
            (n == REFRESH_TTL_ENV).then(|| (MAX_REFRESH_TTL_SECS + 1).to_string())
        })
        .expect_err("above max refresh ttl must fail");
        assert!(
            err.to_string()
                .contains(&format!("must be <= {MAX_REFRESH_TTL_SECS}")),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn refresh_ttl_secs_defaults_to_30_days() {
        let ttl = refresh_ttl_secs(|_| None).expect("default refresh ttl");
        assert_eq!(ttl, DEFAULT_REFRESH_TTL_SECS, "缺省 → 30 天");
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

    // ── build_jwt_issuer_config fail-fast 测试 ───────────────────────────────────────────────

    #[test]
    fn build_jwt_issuer_config_missing_issuer_fails_fast() {
        // 所有其它 env 在，缺 issuer → fail-fast（错误含 env 名）。
        let get = |k: &str| {
            if k == JWT_AUDIENCE_ENV {
                Some("rss".to_string())
            } else if k == JWT_KEY_ID_ENV {
                Some("my-key".to_string())
            } else if k == JWT_ACCESS_TTL_ENV {
                Some("3600".to_string())
            } else {
                None
            }
        };
        assert!(
            matches!(&build_jwt_issuer_config(get), Err(e) if format!("{e:#}").contains(JWT_ISSUER_ENV)),
            "缺 JWT issuer 须 fail-fast 且错误含变量名"
        );
    }

    #[test]
    fn build_jwt_issuer_config_missing_audience_fails_fast() {
        // issuer 在，缺 audience → fail-fast。
        let get = |k: &str| {
            if k == JWT_ISSUER_ENV {
                Some("https://issuer.test".to_string())
            } else if k == JWT_KEY_ID_ENV {
                Some("my-key".to_string())
            } else if k == JWT_ACCESS_TTL_ENV {
                Some("3600".to_string())
            } else {
                None
            }
        };
        assert!(
            matches!(&build_jwt_issuer_config(get), Err(e) if format!("{e:#}").contains(JWT_AUDIENCE_ENV)),
            "缺 JWT audience 须 fail-fast 且错误含变量名"
        );
    }

    #[test]
    fn build_jwt_issuer_config_missing_key_fails_fast() {
        // issuer + audience 在，缺 key_id → fail-fast。
        let get = |k: &str| {
            if k == JWT_ISSUER_ENV {
                Some("https://issuer.test".to_string())
            } else if k == JWT_AUDIENCE_ENV {
                Some("rss".to_string())
            } else if k == JWT_ACCESS_TTL_ENV {
                Some("3600".to_string())
            } else {
                None
            }
        };
        assert!(
            matches!(&build_jwt_issuer_config(get), Err(e) if format!("{e:#}").contains(JWT_KEY_ID_ENV)),
            "缺 JWT key_id 须 fail-fast 且错误含变量名"
        );
    }

    #[test]
    fn build_jwt_issuer_config_zero_access_ttl_fails_fast() {
        // 全必填在，ttl_secs = 0 → ensure!(ttl > 0) fail-fast。
        let get = |k: &str| {
            if k == JWT_ISSUER_ENV {
                Some("https://issuer.test".to_string())
            } else if k == JWT_AUDIENCE_ENV {
                Some("rss".to_string())
            } else if k == JWT_KEY_ID_ENV {
                Some("my-key".to_string())
            } else if k == JWT_ACCESS_TTL_ENV {
                Some("0".to_string())
            } else {
                None
            }
        };
        assert!(
            matches!(&build_jwt_issuer_config(get), Err(e) if e.to_string().contains("must be > 0")),
            "access ttl = 0 须 fail-fast"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_jwt_issuer_config_happy() {
        // 全必填 env 均有 → 构造成功。
        let get = |k: &str| {
            if k == JWT_ISSUER_ENV {
                Some("https://issuer.test".to_string())
            } else if k == JWT_AUDIENCE_ENV {
                Some("rss".to_string())
            } else if k == JWT_KEY_ID_ENV {
                Some("my-es256-key".to_string())
            } else if k == JWT_ACCESS_TTL_ENV {
                Some("3600".to_string())
            } else {
                None
            }
        };
        build_jwt_issuer_config(get).expect("all JWT issuer vars present → Ok");
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
        let (listener, authed) =
            health_listener(reporter, noop_metrics()).expect("health listener");
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
