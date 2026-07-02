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
//!   Internal listener 默认走 SPIFFE/mTLS；service-token 仅在显式迁移配置下绑定。
//!
//! 安全同批门（ADR-006 §5）：依赖图引真 verifier（`oidc` backend）、不引 stub Pdp（`memory` 经 deny.toml 禁
//! server/rss/runtime；bins 生产 `src/` 无内联 `impl diport::Pdp`，`rss_pdp_impl_adapter_only` dylint 守 +
//! `cargo xtask verify` 的 pdp-allow 计数门守逃生门用量）。`OidcProvider` 必填 `VerifierConfig` + `Box<dyn Clock>`
//! ⇒ 无 key/clock 不可构造（编译期守）。
//!
//! INVARIANT: BINS-AUTH-SYNC-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }(Hard, #1309) — `bins/server` 是 serving-only thin entry；`bins/rss` 先
//! dispatch 显式 operator CLI（当前含 settings ConfigValue maintenance），未知参数 fail-closed，未命中 CLI
//! 时再调用同一份 `runtime::run()` serving 组合根。auth wiring 一致性由「单一 `run()` 源」编译期保证，原
//! xtask Medium 守卫 `bins_auth_sync.rs` 退役（双写消除、无第二副本可漂移）。

pub mod auth_bridge;
pub mod distributed_runtime;
pub mod event_transport;
pub mod module;

pub use distributed_runtime::{DistributedRuntimeDeps, wire_distributed};
pub use module::SharedRuntimeDeps;

use bootstrap::DomainModuleResult;

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::Context as _;
use audit::AuditDomain;
use audit::ports::{AuditChainHasher, DynAuditRepo};
use axum::http::Method;
use base64::Engine as _;
use bootstrap::shutdown::ShutdownStack;
use crypto::RustCryptoMacVerifier;
use diport::{
    DynKeyProvider, DynManagedResource, KeyName, KeyProvider, ManagedResource, ObjectStore,
    RedactedBytes, ShutdownError,
};
use httpd::HttpServer;
use identity::{
    IdentityDomain, LoginService, RbacAdminService, RefreshService,
    ports::{
        DynCredentialRepo, DynPolicyRepo, DynRefreshTokenStore, DynRoleBindingLifecycle,
        DynRoleRepo, DynSessionLifecycle,
    },
};
use oidc::OidcProvider;
use postgres::{
    ConfigValueMaintenanceCapability, ConfigValueMaintenanceOperation,
    ConfigValueMaintenanceOptions, ConfigValueProtection, ConfigValueProtections,
    LegacyConfigPlaintextPolicy, MaintenanceAuditOutcome, PgAuthAuditSink, PgConfig, PgDbReadiness,
    PgMaintenanceDeps, PgPassword, PgRuntimeDeps, PgSslMode, PoolReadiness, caps,
};
use primitives::{
    AuthPlan, AuthScheme, HealthCheck, HealthStatus, ListenerKind, MacKey, ProbeName,
    RequiredScheme,
};
use ratelimit::GovernorLimiter;
use s3::{S3RuntimeDeps, S3Store};
use secure::{Plaintext, PlaintextEndpointPolicy, ProtectionContext};
use settings::ports::DynSecretRepo;
use settings::{SettingsDomain, SettingsService, empty_flag_store};
use tokio_util::sync::CancellationToken;
use vault::{
    TenantStoreAllowlist, VaultKeyProvider, VaultRuntimeDeps, VaultSecretResolver, VaultSigner,
    caps as vault_caps,
};

/// Internal listener auth mode. Default is mTLS; `service-token` is a transitional opt-in.
const INTERNAL_AUTH_SCHEME_ENV: &str = "RSS_INTERNAL_AUTH_SCHEME";
const INTERNAL_AUTH_SCHEME_MTLS: &str = "mtls";
const INTERNAL_AUTH_SCHEME_SERVICE_TOKEN: &str = "service-token";
/// Comma-separated exact SPIFFE IDs accepted on the Internal mTLS listener.
const INTERNAL_MTLS_SPIFFE_ALLOW_SET_ENV: &str = "RSS_INTERNAL_MTLS_SPIFFE_ALLOW_SET";
/// SPIFFE Workload API endpoint env var consumed by the upstream `spiffe` source.
const SPIFFE_ENDPOINT_SOCKET_ENV: &str = "SPIFFE_ENDPOINT_SOCKET";
/// Comma-separated remote domains that must have outbound domain transport configured.
const DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV: &str = "RSS_DOMAIN_TRANSPORT_REQUIRED_DOMAINS";
/// Shared remote domain transport endpoint fallback (`durable-shared` only).
const DOMAIN_TRANSPORT_SHARED_URL_ENV: &str = "RSS_DOMAIN_TRANSPORT_URL";
/// Local workload SPIFFE ID expected from the outbound SPIRE source.
const DOMAIN_TRANSPORT_LOCAL_SPIFFE_ID_ENV: &str = "RSS_DOMAIN_TRANSPORT_MTLS_LOCAL_SPIFFE_ID";
const DOMAIN_TRANSPORT_URL_ENV_SUFFIX: &str = "DOMAIN_TRANSPORT_URL";
const DOMAIN_TRANSPORT_MTLS_SPIFFE_ALLOW_SET_ENV_SUFFIX: &str =
    "DOMAIN_TRANSPORT_MTLS_SPIFFE_ALLOW_SET";
/// Explicit migration ticket required for non-loopback Internal service-token listeners.
const INTERNAL_SERVICE_TOKEN_MIGRATION_TICKET_ENV: &str =
    "RSS_INTERNAL_SERVICE_TOKEN_MIGRATION_TICKET";
/// Unix timestamp after which the transitional Internal service-token listener must fail startup.
const INTERNAL_SERVICE_TOKEN_MIGRATION_EXPIRES_AT_UNIX_ENV: &str =
    "RSS_INTERNAL_SERVICE_TOKEN_MIGRATION_EXPIRES_AT_UNIX";

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

#[derive(Default)]
struct RuntimeServiceTokenReplayGuard {
    seen: Mutex<HashMap<String, SystemTime>>,
}

impl diport::ServiceTokenReplayGuard for RuntimeServiceTokenReplayGuard {
    fn check_and_record(
        &self,
        nonce: &str,
        expires_at: SystemTime,
    ) -> Result<(), diport::ServiceTokenReplayError> {
        // reason: runtime assembly owns this in-process fallback guard; production clock read is local to
        // replay-state expiry pruning and does not leak into domain logic.
        #[allow(clippy::disallowed_methods)]
        let now = SystemTime::now();
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| diport::ServiceTokenReplayError::Guard)?;
        seen.retain(|_, expires_at| *expires_at > now);
        if seen.contains_key(nonce) {
            return Err(diport::ServiceTokenReplayError::Replayed);
        }
        seen.insert(nonce.to_string(), expires_at);
        Ok(())
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
/// - `RSS_OIDC_HS256_KID`：service-token 路径 key id；配置 HS256 secret 时必填。
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
        get("RSS_OIDC_HS256_KID").as_deref(),
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
    hs256_kid: Option<&str>,
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
        builder =
            builder.service_token_replay_guard(Arc::new(RuntimeServiceTokenReplayGuard::default()));
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
    Ok(OidcProvider::new(config, clock))
}

/// listener → 认证方案策略（runtime-api.md §Listener：单 listener 单 scheme）。
fn auth_scheme(listener: ListenerKind) -> anyhow::Result<AuthScheme> {
    auth_scheme_from(listener, |name| std::env::var(name).ok())
}

fn auth_scheme_from(
    listener: ListenerKind,
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<AuthScheme> {
    Ok(match listener {
        ListenerKind::Primary | ListenerKind::Admin => AuthScheme::Jwt,
        ListenerKind::Internal => internal_auth_scheme_from(get)?,
        ListenerKind::Health => AuthScheme::NoAuth,
        // ListenerKind non_exhaustive——未知 listener fail-closed 要求 JWT 认证（绝不默认 NoAuth）+ 配置期 warn 埋点。
        _ => {
            tracing::warn!(listener = ?listener, "unknown ListenerKind; fail-closed to JWT auth scheme");
            AuthScheme::Jwt
        }
    })
}

fn internal_auth_scheme_from(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<AuthScheme> {
    let Some(raw) = get(INTERNAL_AUTH_SCHEME_ENV) else {
        return Ok(AuthScheme::Mtls);
    };
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        INTERNAL_AUTH_SCHEME_MTLS => Ok(AuthScheme::Mtls),
        INTERNAL_AUTH_SCHEME_SERVICE_TOKEN => {
            tracing::warn!(
                env = INTERNAL_AUTH_SCHEME_ENV,
                "internal listener using transitional service-token auth; mTLS is the default"
            );
            Ok(AuthScheme::ServiceToken)
        }
        "" => anyhow::bail!(
            "{INTERNAL_AUTH_SCHEME_ENV} must be either '{INTERNAL_AUTH_SCHEME_MTLS}' or '{INTERNAL_AUTH_SCHEME_SERVICE_TOKEN}'"
        ),
        _ => anyhow::bail!(
            "{INTERNAL_AUTH_SCHEME_ENV} has unsupported value '{raw}' (expected '{INTERNAL_AUTH_SCHEME_MTLS}' or '{INTERNAL_AUTH_SCHEME_SERVICE_TOKEN}')"
        ),
    }
}

fn required_scheme_for_auth_scheme(scheme: AuthScheme) -> Option<RequiredScheme> {
    match scheme {
        AuthScheme::Jwt | AuthScheme::JwtFromAssembly => Some(RequiredScheme::Jwt),
        AuthScheme::ServiceToken => Some(RequiredScheme::ServiceToken),
        AuthScheme::Mtls => Some(RequiredScheme::Mtls),
        AuthScheme::NoAuth => None,
        other => {
            tracing::warn!(scheme = ?other, "listener auth scheme has no verify-bridge; Require routes fail-closed 401");
            None
        }
    }
}

pub struct AssembledListener {
    listener: ListenerKind,
    routes: httpserve::AuthenticatedRoutes,
    mtls_health: Option<Arc<MtlsHealthSlot>>,
}

impl AssembledListener {
    pub fn listener(&self) -> ListenerKind {
        self.listener
    }

    pub fn into_parts(self) -> (ListenerKind, httpserve::AuthenticatedRoutes) {
        (self.listener, self.routes)
    }

    fn plain(listener: ListenerKind, routes: httpserve::AuthenticatedRoutes) -> Self {
        Self {
            listener,
            routes,
            mtls_health: None,
        }
    }
}

struct MtlsHealthSlot {
    config: Mutex<Option<httpd::MtlsServerConfig>>,
}

impl MtlsHealthSlot {
    fn new() -> Self {
        Self {
            config: Mutex::new(None),
        }
    }

    fn set(&self, config: httpd::MtlsServerConfig) -> anyhow::Result<()> {
        let mut guard = self
            .config
            .lock()
            .map_err(|_| anyhow::anyhow!("mtls health slot lock poisoned"))?;
        *guard = Some(config);
        Ok(())
    }

    fn check(&self) -> (HealthStatus, &'static str) {
        let Ok(guard) = self.config.lock() else {
            return (HealthStatus::Unhealthy, "slot-poisoned");
        };
        match guard.as_ref() {
            Some(config) if config.is_healthy() => (HealthStatus::Healthy, "ready"),
            Some(_) => (HealthStatus::Unhealthy, "down"),
            None => (HealthStatus::Unhealthy, "not-bound"),
        }
    }
}

struct MtlsSourceHealthProbe {
    name: ProbeName,
    slot: Arc<MtlsHealthSlot>,
}

impl MtlsSourceHealthProbe {
    fn new(name: ProbeName, slot: Arc<MtlsHealthSlot>) -> Self {
        Self { name, slot }
    }
}

impl bootstrap::HealthProbe for MtlsSourceHealthProbe {
    fn check(&self) -> HealthCheck {
        let (status, detail) = self.slot.check();
        HealthCheck::new(self.name.clone(), status, detail)
    }
}

const MTLS_SOURCE_READY_PROBE_NAME: &str = "mtls_source_ready";

fn mtls_probe_name(listener: ListenerKind) -> anyhow::Result<ProbeName> {
    anyhow::ensure!(
        listener == ListenerKind::Internal,
        "mTLS health probe is only wired for Internal"
    );
    ProbeName::parse(MTLS_SOURCE_READY_PROBE_NAME).context("valid mtls probe name")
}

struct MtlsRouteAuthorizer {
    allow_set: authn::MtlsAllowSet,
}

impl httpserve::RouteAuthorizer for MtlsRouteAuthorizer {
    fn authorize<'a>(
        &'a self,
        request: httpserve::RouteAuthorizationRequest,
    ) -> Pin<Box<dyn Future<Output = httpserve::RouteAuthorizationDecision> + Send + 'a>> {
        Box::pin(async move {
            let allowed = request.principal_kind == vocab::PrincipalKind::Service
                && authn::SpiffeId::parse(&request.principal_id)
                    .map(|id| self.allow_set.allows(&id))
                    .unwrap_or(false);
            if allowed {
                httpserve::RouteAuthorizationDecision::Allow
            } else {
                httpserve::RouteAuthorizationDecision::Deny
            }
        })
    }
}

fn mtls_route_authorizer_from_env(
    listener: ListenerKind,
) -> anyhow::Result<Arc<dyn httpserve::RouteAuthorizer>> {
    let allow_set = mtls_allow_set_from_env(listener, |name| std::env::var(name).ok())?;
    Ok(Arc::new(MtlsRouteAuthorizer { allow_set }))
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

/// 排空 registry 的 per-listener `UnfinalizedRoutes`，按 listener 装配 auth finalizer + 外层验签桥
/// + rate-limit 中间件（组合根叠加点，INVARIANT RATELIMIT-BEFORE-AUTH-01）。
///
/// Primary listener：`finalize_primary_auth_with_audit(routes, plan, ..., primary_authorizer)` 注入
/// `RouteAuthorizer`；Admin listener 也注入同一 Authorizer 供 field projection 消费；其它非 Primary
/// listener：`finalize_auth_with_audit(routes, plan, ...)`。三者均消费
/// `UnfinalizedRoutes` 产 `AuthenticatedRoutes` 并注入 AuthPlan 与 framework 中间件。随后据
/// `required_scheme` 叠外层 `verify_bridge`（`NoAuth` listener 无桥）
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
    primary_authorizer: Arc<dyn httpserve::RouteAuthorizer>,
) -> anyhow::Result<Vec<AssembledListener>> {
    // 默认限流配额（owner=组合根，可调）：10 req/s，burst 20。peer-IP keyed（见 #1106 / RealIP follow-up）。
    // 共享跨所有 listener——统一 per-IP 预算，避免分散 listener 各自独立 bucket 使 burst 预算 N 倍膨胀。
    //
    // 已知限制（multi-instance）：in-mem `GovernorLimiter` 是 per-instance 独立桶，N 副本部署下
    // 每实例独立配额（全局视图 ≈ N × 单实例率）；全局一致限流须 redis-distributed provider（future）。
    // 叠加 peer-IP-after-proxy 退化（RealIP follow-up），本限流当前为单实例 best-effort 防护。
    let rate_limiter = Arc::new(GovernorLimiter::new(default_rate_quota()));
    let mut out = Vec::new();
    for (listener, routes) in registry.finalize_routes().context("finalize_routes")? {
        let scheme = auth_scheme(listener).context("resolve listener auth scheme")?;
        let plan = AuthPlan::new(listener, scheme).context("build auth plan")?;
        let mtls_health = if scheme == AuthScheme::Mtls {
            let slot = Arc::new(MtlsHealthSlot::new());
            let probe_name = mtls_probe_name(listener)?;
            registry
                .probe(
                    probe_name.clone(),
                    Box::new(MtlsSourceHealthProbe::new(probe_name, slot.clone())),
                )
                .context("register mtls source health probe")?;
            Some(slot)
        } else {
            None
        };
        let authed = finalize_listener_auth(
            listener,
            routes,
            plan,
            audit_sink.clone(),
            audit_clock.clone(),
            primary_authorizer.clone(),
            scheme,
        )
        .context("finalize_auth")?;
        let required = required_scheme_for_auth_scheme(scheme);
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
        out.push(AssembledListener {
            listener,
            routes: wired,
            mtls_health,
        });
    }
    Ok(out)
}

fn finalize_listener_auth(
    listener: ListenerKind,
    routes: httpserve::UnfinalizedRoutes,
    plan: AuthPlan,
    audit_sink: httpserve::AuditSinkHandle,
    audit_clock: Arc<dyn diport::Clock>,
    primary_authorizer: Arc<dyn httpserve::RouteAuthorizer>,
    scheme: AuthScheme,
) -> anyhow::Result<httpserve::AuthenticatedRoutes> {
    if listener == ListenerKind::Primary {
        return httpserve::finalize_primary_auth_with_audit(
            routes,
            plan,
            audit_sink,
            audit_clock,
            primary_authorizer,
        )
        .map_err(Into::into);
    }
    if listener == ListenerKind::Admin {
        return httpserve::finalize_auth_with_audit_and_authorizer(
            routes,
            plan,
            audit_sink,
            audit_clock,
            primary_authorizer,
        )
        .map_err(Into::into);
    }
    if scheme == AuthScheme::Mtls {
        return httpserve::finalize_auth_with_audit_and_authorizer(
            routes,
            plan,
            audit_sink,
            audit_clock,
            mtls_route_authorizer_from_env(listener)?,
        )
        .map_err(Into::into);
    }
    httpserve::finalize_auth_with_audit(routes, plan, audit_sink, audit_clock).map_err(Into::into)
}

// ── postgres 配置 wiring ─────────────────────────────────────────────────────────────────────

const PG_SSL_ROOT_CERT_PATH_ENV: &str = "RSS_PG_SSL_ROOT_CERT_PATH";

/// 从注入的配置读取器构造 serving `PgConfig`（fail-fast：任一必填 env 缺失立即返 `Err`）。
///
/// 必填变量：
/// - `RSS_PG_HOST` — postgres 主机（非空）。
/// - `RSS_PG_PORT` — postgres 端口（非零 u16，默认 5432 需显式声明）。
/// - `RSS_PG_DATABASE` — 数据库名（非空）。
/// - `RSS_PG_USERNAME` — 连接用户（非空）。
/// - `RSS_PG_PASSWORD` — 连接密码（非空）。
///
/// TLS 默认 `VerifyFull`（零信任）；可选 `RSS_PG_SSL_MODE` 经 [`parse_pg_ssl_mode`] 显式降级（容器内连
/// 未启 TLS 的 dev postgres 时用 `prefer` / `disable`）。生产私有 CA 根证书经
/// `RSS_PG_SSL_ROOT_CERT_PATH` → `PgConfig::with_ssl_root_cert` 注入。
/// **禁止 localhost fallback**（生产配置规范，rust-standards §安全检查点）。
pub(crate) fn build_pg_config_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<PgConfig> {
    build_pg_config_with_user_env(&get, "RSS_PG_USERNAME", "RSS_PG_PASSWORD")
}

fn build_pg_config_with_user_env(
    get: &impl Fn(&str) -> Option<String>,
    username_env: &'static str,
    password_env: &'static str,
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
    let username = get(username_env)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {username_env}"))?;
    let password = get(password_env)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {password_env}"))?;

    // PgConfig::new 存储参数；validate 在 PgStore::connect 内调用（pub(crate)）。
    // 这里只做构造，连接时再 fail-fast（组合根在 wire_settings 中 connect）。
    let mut config = PgConfig::new(host, port, database, username, PgPassword::new(password))
        .with_ssl_mode(parse_pg_ssl_mode(get("RSS_PG_SSL_MODE")));
    if let Some(path) = pg_ssl_root_cert_path_from(get)? {
        config = config.with_ssl_root_cert(path);
    }
    Ok(config)
}

fn pg_ssl_root_cert_path_from(
    get: &impl Fn(&str) -> Option<String>,
) -> anyhow::Result<Option<PathBuf>> {
    let Some(raw) = get(PG_SSL_ROOT_CERT_PATH_ENV) else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    anyhow::ensure!(
        !trimmed.is_empty(),
        "{PG_SSL_ROOT_CERT_PATH_ENV} must not be empty"
    );
    let path = PathBuf::from(trimmed);
    let metadata = fs::metadata(&path)
        .with_context(|| format!("{PG_SSL_ROOT_CERT_PATH_ENV} must point to a readable file"))?;
    anyhow::ensure!(
        metadata.is_file(),
        "{PG_SSL_ROOT_CERT_PATH_ENV} must point to a file"
    );
    let _ = fs::File::open(&path)
        .with_context(|| format!("{PG_SSL_ROOT_CERT_PATH_ENV} must point to a readable file"))?;
    Ok(Some(path))
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

pub(crate) fn build_pg_audit_admin_config_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<Option<PgConfig>> {
    let username = get("RSS_PG_AUDIT_ADMIN_USERNAME");
    let password = get("RSS_PG_AUDIT_ADMIN_PASSWORD");
    match (username, password) {
        (None, None) => Ok(None),
        (Some(_), Some(_)) => build_pg_config_with_user_env(
            &get,
            "RSS_PG_AUDIT_ADMIN_USERNAME",
            "RSS_PG_AUDIT_ADMIN_PASSWORD",
        )
        .map(Some),
        (None, Some(_)) => Err(anyhow::anyhow!(
            "missing required env var: RSS_PG_AUDIT_ADMIN_USERNAME"
        )),
        (Some(_), None) => Err(anyhow::anyhow!(
            "missing required env var: RSS_PG_AUDIT_ADMIN_PASSWORD"
        )),
    }
}

pub fn build_pg_audit_admin_config() -> anyhow::Result<Option<PgConfig>> {
    build_pg_audit_admin_config_from(|name| std::env::var(name).ok())
}

/// 从注入的配置读取器构造 migrator `PgConfig`。
///
/// Host / port / database / TLS mode 与 serving 连接一致；用户名和密码必须来自
/// `RSS_PG_MIGRATOR_USERNAME` / `RSS_PG_MIGRATOR_PASSWORD`，避免长期 serving role 继承 DDL 能力。
pub(crate) fn build_pg_migrator_config_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<PgConfig> {
    build_pg_config_with_user_env(&get, "RSS_PG_MIGRATOR_USERNAME", "RSS_PG_MIGRATOR_PASSWORD")
}

/// 从 `std::env` 构造 migrator `PgConfig`。
pub fn build_pg_migrator_config() -> anyhow::Result<PgConfig> {
    build_pg_migrator_config_from(|name| std::env::var(name).ok())
}

/// 从注入的配置读取器构造 legacy plaintext `ConfigValue` 启动策略。
///
/// `RSS_SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES` 是安全豁免开关：缺省为 deny；显式非法值 fail-fast。
pub(crate) fn legacy_config_plaintext_policy_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<LegacyConfigPlaintextPolicy> {
    let Some(raw) = get(SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES_ENV) else {
        return Ok(LegacyConfigPlaintextPolicy::Deny);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(LegacyConfigPlaintextPolicy::AllowTemporary),
        "0" | "false" | "no" => Ok(LegacyConfigPlaintextPolicy::Deny),
        _ => anyhow::bail!(
            "{SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES_ENV} must be true/false (or 1/0, yes/no)"
        ),
    }
}

fn legacy_config_plaintext_policy() -> anyhow::Result<LegacyConfigPlaintextPolicy> {
    legacy_config_plaintext_policy_from(|name| std::env::var(name).ok())
}

/// 从 `std::env` 构造 [`event_transport::EventTransportConfig`]。
pub fn build_event_transport_config() -> anyhow::Result<event_transport::EventTransportConfig> {
    event_transport::build_event_transport_config_from(|name| std::env::var(name).ok())
}

fn domain_transport_required_domains_from(
    get: &impl Fn(&str) -> Option<String>,
) -> anyhow::Result<Vec<String>> {
    let raw = get(DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV).ok_or_else(|| {
        anyhow::anyhow!("missing required env var: {DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV}")
    })?;
    let mut domains = Vec::new();
    for part in raw.split(',') {
        let domain = part.trim();
        anyhow::ensure!(
            !domain.is_empty(),
            "{DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV} must not contain empty entries"
        );
        anyhow::ensure!(
            !domain.chars().any(char::is_control) && !domain.chars().any(char::is_whitespace),
            "{DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV} entries must not contain whitespace or control characters"
        );
        domains.push(domain.to_uppercase());
    }
    anyhow::ensure!(
        !domains.is_empty(),
        "{DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV} must list at least one domain"
    );
    domains.sort();
    domains.dedup();
    Ok(domains)
}

fn domain_transport_url_env(domain: &str) -> String {
    format!(
        "RSS_{}_{}",
        domain.to_ascii_uppercase(),
        DOMAIN_TRANSPORT_URL_ENV_SUFFIX
    )
}

fn domain_transport_mtls_allow_set_env(domain: &str) -> String {
    format!(
        "RSS_{}_{}",
        domain.to_ascii_uppercase(),
        DOMAIN_TRANSPORT_MTLS_SPIFFE_ALLOW_SET_ENV_SUFFIX
    )
}

fn domain_transport_config_from(
    required_domains: &[String],
    get: &impl Fn(&str) -> Option<String>,
) -> bootstrap::DomainTransportConfig {
    let mut per_domain = BTreeMap::new();
    for domain in required_domains {
        let env = domain_transport_url_env(domain);
        if let Some(url) = get(&env) {
            per_domain.insert(domain.clone(), bootstrap::DomainTransportUrl::new(url));
        }
    }
    let shared = get(DOMAIN_TRANSPORT_SHARED_URL_ENV).map(bootstrap::DomainTransportUrl::new);
    bootstrap::DomainTransportConfig::new(per_domain, shared)
}

fn outbound_mtls_policy_for_domain_from(
    domain: &str,
    get: &impl Fn(&str) -> Option<String>,
) -> anyhow::Result<authn::OutboundMtlsPolicy> {
    let local_raw = get(DOMAIN_TRANSPORT_LOCAL_SPIFFE_ID_ENV).ok_or_else(|| {
        anyhow::anyhow!("missing required env var: {DOMAIN_TRANSPORT_LOCAL_SPIFFE_ID_ENV}")
    })?;
    let local = authn::SpiffeId::parse(local_raw.trim())
        .map_err(|e| anyhow::anyhow!("{DOMAIN_TRANSPORT_LOCAL_SPIFFE_ID_ENV} invalid: {e}"))?;
    let allow_env = domain_transport_mtls_allow_set_env(domain);
    let raw_allow_set =
        get(&allow_env).ok_or_else(|| anyhow::anyhow!("missing required env var: {allow_env}"))?;
    let server_allow_set = mtls_allow_set_from_csv_for_env(&raw_allow_set, &allow_env)?;
    let trust_domain_names = server_allow_set
        .iter()
        .map(|id| id.trust_domain().as_str().to_owned())
        .collect::<Vec<_>>();
    let trust_domains = authn::MtlsTrustDomainAllowSet::new(trust_domain_names)
        .map_err(|e| anyhow::anyhow!("{allow_env} trust domains invalid: {e}"))?;
    authn::OutboundMtlsPolicy::new(local, server_allow_set, trust_domains)
        .map_err(|e| anyhow::anyhow!("{allow_env} outbound mTLS policy invalid: {e}"))
}

fn build_domain_transport_targets_from(
    topology: bootstrap::Topology,
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<Vec<httpd::DomainHttpTargetConfig>> {
    let required_domains = domain_transport_required_domains_from(&get)?;
    let cfg = domain_transport_config_from(&required_domains, &get);
    let required_refs = required_domains
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let resolved = bootstrap::domaintransport::resolve(topology, cfg, &required_refs)
        .context("resolve domain transport topology")?;
    let bootstrap::ResolvedDomainTransport::Remote { per_domain } = resolved else {
        return Ok(Vec::new());
    };
    let mut targets = Vec::with_capacity(per_domain.len());
    for (domain, url) in per_domain {
        let policy = outbound_mtls_policy_for_domain_from(&domain, &get)?;
        targets.push(
            httpd::DomainHttpTargetConfig::new(&domain, url.expose(), policy)
                .with_context(|| format!("build outbound domain transport target {domain}"))?,
        );
    }
    Ok(targets)
}

trait RuntimeDomainTransport:
    distributed::DomainTransport + ManagedResource + Clone + Send + Sync + 'static
{
    fn readiness(&self) -> httpd::DomainHttpReadiness;
}

impl RuntimeDomainTransport for httpd::SharedDomainHttpTransport {
    fn readiness(&self) -> httpd::DomainHttpReadiness {
        httpd::SharedDomainHttpTransport::readiness(self)
    }
}

struct DomainTransportRuntime<T> {
    transport: T,
}

impl<T> DomainTransportRuntime<T>
where
    T: RuntimeDomainTransport,
{
    fn new(transport: T) -> Self {
        Self { transport }
    }

    fn dispatch_handle(&self) -> Arc<dyn distributed::DomainTransport> {
        Arc::new(distributed::InstrumentedDomainTransport::new(
            self.transport.clone(),
            distributed::TransportMode::Remote,
            Box::new(SystemClock),
        ))
    }

    fn module_result(&self) -> anyhow::Result<DomainModuleResult> {
        let probe_name = ProbeName::parse(DOMAIN_TRANSPORT_READY_PROBE_NAME)
            .context("parse domain_transport_ready probe name")?;
        Ok(DomainModuleResult {
            probes: vec![(
                probe_name,
                Box::new(DomainTransportReadyProbe::new(self.transport.clone())),
            )],
            resources: vec![DynManagedResource::new_box(self.transport.clone())],
            workers: Vec::new(),
        })
    }
}

pub const DOMAIN_TRANSPORT_READY_PROBE_NAME: &str = "domain_transport_ready";

struct DomainTransportReadyProbe<T> {
    transport: T,
    name: ProbeName,
}

impl<T> DomainTransportReadyProbe<T>
where
    T: RuntimeDomainTransport,
{
    #[allow(clippy::expect_used)]
    fn new(transport: T) -> Self {
        let name =
            ProbeName::parse(DOMAIN_TRANSPORT_READY_PROBE_NAME).expect("valid probe name const");
        Self { transport, name }
    }
}

impl<T> bootstrap::HealthProbe for DomainTransportReadyProbe<T>
where
    T: RuntimeDomainTransport,
{
    fn check(&self) -> HealthCheck {
        let readiness = self.transport.readiness();
        let status = if readiness.is_ready() {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unhealthy
        };
        HealthCheck::new(self.name.clone(), status, readiness.detail())
    }
}

async fn wire_domain_transport_from(
    topology: bootstrap::Topology,
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<DomainTransportRuntime<httpd::SharedDomainHttpTransport>> {
    let targets = build_domain_transport_targets_from(topology, &get)?;
    anyhow::ensure!(
        !targets.is_empty(),
        "outbound domain transport must resolve remote targets"
    );
    let endpoint = get(SPIFFE_ENDPOINT_SOCKET_ENV);
    let transport = httpd::DomainHttpTransport::from_spire(targets, endpoint.as_deref())
        .await
        .with_context(|| {
            format!(
                "build outbound domain transport mTLS client ({} optional override)",
                SPIFFE_ENDPOINT_SOCKET_ENV
            )
        })?;
    Ok(DomainTransportRuntime::new(
        httpd::SharedDomainHttpTransport::new(transport),
    ))
}

// ── Session expiry sweeper helper ─────────────────────────────────────────────────────────────

const SESSION_SWEEP_INTERVAL_ENV: &str = "RSS_SESSION_SWEEP_INTERVAL_MS";
const DEFAULT_SESSION_SWEEP_INTERVAL_MS: u64 = 300_000;
const MIN_SESSION_SWEEP_INTERVAL_MS: u64 = 1_000;
const DEFAULT_SESSION_SWEEP_INTERVAL: Duration =
    Duration::from_millis(DEFAULT_SESSION_SWEEP_INTERVAL_MS);
pub const SESSION_SWEEPER_PROBE_NAME: &str = "session_sweeper";
const SESSION_SWEEPER_WORKER_NAME: &str = "session-sweeper";

/// sessions 过期清理周期（env `RSS_SESSION_SWEEP_INTERVAL_MS`）。
///
/// 未配置取默认 5 分钟；显式配置解析失败或小于 1 秒时 warn + 默认，避免误配导致热 DELETE 循环。
pub(crate) fn build_session_sweeper_interval_from(
    get: impl Fn(&str) -> Option<String>,
) -> Duration {
    match get(SESSION_SWEEP_INTERVAL_ENV) {
        None => DEFAULT_SESSION_SWEEP_INTERVAL,
        Some(raw) => match raw.trim().parse::<u64>() {
            Ok(ms) if ms >= MIN_SESSION_SWEEP_INTERVAL_MS => Duration::from_millis(ms),
            _ => {
                tracing::warn!(
                    env = SESSION_SWEEP_INTERVAL_ENV,
                    raw = %raw,
                    default_ms = DEFAULT_SESSION_SWEEP_INTERVAL_MS,
                    min_ms = MIN_SESSION_SWEEP_INTERVAL_MS,
                    "invalid session sweep interval (expected u64 ms >= 1000); using default"
                );
                DEFAULT_SESSION_SWEEP_INTERVAL
            }
        },
    }
}

fn build_session_sweeper_interval() -> Duration {
    build_session_sweeper_interval_from(|name| std::env::var(name).ok())
}

// ── DB readiness 采样周期 helper ───────────────────────────────────────────────────────────────

/// 默认 DB readiness 采样周期（5 秒）。
const DEFAULT_READINESS_INTERVAL: Duration = Duration::from_secs(5);
/// 默认 Redis readiness 采样周期（5 秒）。
const DEFAULT_REDIS_READINESS_INTERVAL: Duration = Duration::from_secs(5);
/// 默认 KeyProvider readiness 采样周期（5 秒）。
const DEFAULT_KEYPROVIDER_READINESS_INTERVAL: Duration = Duration::from_secs(5);
/// 默认 S3 canary 周期（60 秒）。
const DEFAULT_S3_CANARY_INTERVAL: Duration = Duration::from_secs(60);
/// 默认 S3 canary 单轮超时（5 秒）。
const DEFAULT_S3_CANARY_TIMEOUT: Duration = Duration::from_secs(5);

/// 采样间隔上限（秒）：限制 DB 失联后维持旧 Ready 状态的最长时间。
const MAX_READINESS_INTERVAL_SECS: u64 = 300;
/// Redis 是 distributed lock 运行期依赖，摘流延迟上限更短。
const MAX_REDIS_READINESS_INTERVAL_SECS: u64 = 30;
/// KeyProvider 保护 settings 持久化读写，摘流延迟上限与 Redis 一样按运行期强依赖收紧。
const MAX_KEYPROVIDER_READINESS_INTERVAL_SECS: u64 = 30;
const MAX_S3_CANARY_INTERVAL_SECS: u64 = 300;
const MAX_S3_CANARY_TIMEOUT_SECS: u64 = 60;

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

/// redis_ready 采样周期（env `RSS_REDIS_READINESS_SAMPLE_INTERVAL_SECS`）。
pub(crate) fn build_redis_readiness_interval_from(
    get: impl Fn(&str) -> Option<String>,
) -> Duration {
    match get("RSS_REDIS_READINESS_SAMPLE_INTERVAL_SECS") {
        None => DEFAULT_REDIS_READINESS_INTERVAL,
        Some(raw) => match raw.parse::<u64>() {
            Ok(n) if (1..=MAX_REDIS_READINESS_INTERVAL_SECS).contains(&n) => Duration::from_secs(n),
            _ => {
                tracing::warn!(
                    env = "RSS_REDIS_READINESS_SAMPLE_INTERVAL_SECS",
                    raw = %raw,
                    max_secs = MAX_REDIS_READINESS_INTERVAL_SECS,
                    "invalid redis readiness sample interval (need 1..=30s); using default 5s"
                );
                DEFAULT_REDIS_READINESS_INTERVAL
            }
        },
    }
}

fn build_redis_readiness_interval() -> Duration {
    build_redis_readiness_interval_from(|n| std::env::var(n).ok())
}

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

fn build_keyprovider_readiness_interval() -> Duration {
    build_keyprovider_readiness_interval_from(|n| std::env::var(n).ok())
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
fn build_vault_tls_client_from(
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

pub(crate) fn plaintext_endpoint_policy_from(
    get: impl Fn(&str) -> Option<String>,
    env: &str,
) -> anyhow::Result<PlaintextEndpointPolicy> {
    let Some(raw) = get(env) else {
        return Ok(PlaintextEndpointPolicy::Deny);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(PlaintextEndpointPolicy::AllowLoopback),
        "dev-container" => Ok(PlaintextEndpointPolicy::AllowDevContainer),
        "0" | "false" | "no" => Ok(PlaintextEndpointPolicy::Deny),
        _ => anyhow::bail!("{env} must be false, true, or dev-container"),
    }
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

/// `rss` binary 是否请求 settings ConfigValue 维护命令。
#[must_use]
pub fn is_settings_config_value_maintenance_command(args: &[String]) -> bool {
    matches!(
        args,
        [cmd, sub, ..] if cmd == "settings-config-values" && sub == "maintenance"
    )
}

fn parse_config_value_maintenance_operation(
    raw: &str,
) -> anyhow::Result<ConfigValueMaintenanceOperation> {
    match raw {
        "backfill" => Ok(ConfigValueMaintenanceOperation::Backfill),
        "rewrap" => Ok(ConfigValueMaintenanceOperation::Rewrap),
        "both" => Ok(ConfigValueMaintenanceOperation::Both),
        other => anyhow::bail!(
            "unknown settings config value maintenance operation: {other}; expected backfill|rewrap|both"
        ),
    }
}

fn parse_positive_usize(raw: &str, flag: &str) -> anyhow::Result<usize> {
    let value = raw
        .parse::<usize>()
        .with_context(|| format!("{flag} must be a positive integer"))?;
    anyhow::ensure!(value > 0, "{flag} must be greater than zero");
    Ok(value)
}

#[derive(Debug, Clone)]
struct SettingsConfigValueMaintenanceArgs {
    options: ConfigValueMaintenanceOptions,
    operator_service_token: String,
    operator_tenant: vocab::TenantId,
}

fn parse_settings_config_value_maintenance_args(
    args: &[String],
) -> anyhow::Result<SettingsConfigValueMaintenanceArgs> {
    anyhow::ensure!(
        is_settings_config_value_maintenance_command(args),
        "usage: rss settings-config-values maintenance --operator-service-token <token> --operator-tenant <uuid> [--operation backfill|rewrap|both] [--tenant <uuid>] [--batch-size <n>] [--max-rows <n>] [--dry-run]"
    );
    let mut options = ConfigValueMaintenanceOptions::default();
    let mut operator_service_token = None;
    let mut operator_tenant = None;
    let mut it = args[2..].iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--operator-service-token" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--operator-service-token requires a value"))?;
                let trimmed = raw.trim();
                anyhow::ensure!(
                    !trimmed.is_empty(),
                    "--operator-service-token must be non-empty"
                );
                operator_service_token = Some(trimmed.to_owned());
            }
            "--operator-tenant" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--operator-tenant requires a value"))?;
                let tenant = vocab::TenantId::parse(raw)
                    .with_context(|| format!("--operator-tenant must be a tenant UUID: {raw}"))?;
                operator_tenant = Some(tenant);
            }
            "--operation" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--operation requires a value"))?;
                options = ConfigValueMaintenanceOptions::new(
                    parse_config_value_maintenance_operation(raw)?,
                )
                .with_tenant_opt(options.tenant_opt())
                .with_batch_size(options.batch_size())
                .with_max_rows(options.max_rows())
                .with_dry_run(options.dry_run());
            }
            "--tenant" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--tenant requires a value"))?;
                let tenant = vocab::TenantId::parse(raw)
                    .with_context(|| format!("--tenant must be a tenant UUID: {raw}"))?;
                options = options.with_tenant(tenant);
            }
            "--batch-size" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--batch-size requires a value"))?;
                options = options.with_batch_size(parse_positive_usize(raw, "--batch-size")?);
            }
            "--max-rows" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--max-rows requires a value"))?;
                options = options.with_max_rows(Some(parse_positive_usize(raw, "--max-rows")?));
            }
            "--dry-run" => {
                options = options.with_dry_run(true);
            }
            other => {
                anyhow::bail!("unknown settings config value maintenance argument: {other}");
            }
        }
    }
    let operator_service_token = operator_service_token
        .ok_or_else(|| anyhow::anyhow!("--operator-service-token is required"))?;
    let operator_tenant =
        operator_tenant.ok_or_else(|| anyhow::anyhow!("--operator-tenant is required"))?;
    Ok(SettingsConfigValueMaintenanceArgs {
        options,
        operator_service_token,
        operator_tenant,
    })
}

fn settings_config_value_maintenance_resource_id(
    options: &ConfigValueMaintenanceOptions,
) -> String {
    let scope = options
        .tenant_opt()
        .map(|tenant| format!("tenant:{tenant}"))
        .unwrap_or_else(|| "all".to_owned());
    let max_rows = options
        .max_rows()
        .map(|max_rows| max_rows.to_string())
        .unwrap_or_else(|| "none".to_owned());
    format!(
        "operation={} scope={} dry_run={} batch_size={} max_rows={}",
        options.operation().as_str(),
        scope,
        options.dry_run(),
        options.batch_size(),
        max_rows
    )
}

const UNVERIFIED_CONFIG_MAINTENANCE_OPERATOR: &str = "unverified-service-token";

async fn verified_config_value_maintenance_operator_subject(
    service_token: &str,
    operator_tenant: vocab::TenantId,
    pdp: &diport::DynPdp<'_>,
) -> anyhow::Result<String> {
    let (_token, principal) = authn::verify_service_token(
        service_token,
        diport::ServiceTokenTenantBinding::new(operator_tenant),
        pdp,
    )
    .await
    .context("verify settings config value maintenance operator service token")?;
    anyhow::ensure!(
        principal.kind() == vocab::PrincipalKind::Service,
        "settings config value maintenance operator must be a service principal"
    );
    Ok(principal.audit_subject().to_owned())
}

async fn record_config_value_maintenance_finish_audit(
    pg: &PgMaintenanceDeps,
    operator_subject: &str,
    resource_id: &str,
    outcome: MaintenanceAuditOutcome<'_>,
) -> anyhow::Result<()> {
    pg.record_config_value_maintenance_audit(
        operator_subject,
        "settings.config-values.maintenance.finish",
        outcome,
        resource_id,
    )
    .await
    .context("record settings config value maintenance finish audit")
}

async fn settings_config_value_maintenance_operator_subject(
    pg: &PgMaintenanceDeps,
    parsed: &SettingsConfigValueMaintenanceArgs,
    resource_id: &str,
) -> anyhow::Result<String> {
    let operator_provider = match build_provider() {
        Ok(provider) => provider,
        Err(err) => {
            record_config_value_maintenance_finish_audit(
                pg,
                UNVERIFIED_CONFIG_MAINTENANCE_OPERATOR,
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_provider_config",
                },
            )
            .await?;
            return Err(err).context("settings config value maintenance operator verifier");
        }
    };
    let operator_pdp = diport::DynPdp::from_ref(&operator_provider);
    match verified_config_value_maintenance_operator_subject(
        &parsed.operator_service_token,
        parsed.operator_tenant,
        operator_pdp,
    )
    .await
    {
        Ok(subject) => Ok(subject),
        Err(err) => {
            record_config_value_maintenance_finish_audit(
                pg,
                UNVERIFIED_CONFIG_MAINTENANCE_OPERATOR,
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_auth",
                },
            )
            .await?;
            Err(err)
        }
    }
}

async fn settings_config_value_maintenance_protection(
    pg: &PgMaintenanceDeps,
    operator_subject: &str,
    resource_id: &str,
) -> anyhow::Result<ConfigValueProtection> {
    let key_provider = match build_vault_key_provider_from(|name| std::env::var(name).ok()) {
        Ok(provider) => provider,
        Err(err) => {
            record_config_value_maintenance_finish_audit(
                pg,
                operator_subject,
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "key_provider_config",
                },
            )
            .await?;
            return Err(err).context("settings config value maintenance key provider");
        }
    };
    let key_name = match build_settings_config_value_key_name_from(|name| std::env::var(name).ok())
    {
        Ok(key_name) => key_name,
        Err(err) => {
            record_config_value_maintenance_finish_audit(
                pg,
                operator_subject,
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "key_name_config",
                },
            )
            .await?;
            return Err(err).context("settings config value key name");
        }
    };
    Ok(ConfigValueProtection::new(
        DynKeyProvider::new_box(key_provider),
        key_name,
    ))
}

/// 执行 `rss settings-config-values maintenance`。
pub async fn run_settings_config_value_maintenance(args: &[String]) -> anyhow::Result<()> {
    let parsed = parse_settings_config_value_maintenance_args(args)?;
    let options = parsed.options.clone();
    let resource_id = settings_config_value_maintenance_resource_id(&options);
    let pg = PgRuntimeDeps::setup_maintenance(&build_pg_migrator_config()?)
        .await
        .context("setup postgres maintenance deps")?;
    pg.record_config_value_maintenance_audit(
        UNVERIFIED_CONFIG_MAINTENANCE_OPERATOR,
        "settings.config-values.maintenance.start",
        MaintenanceAuditOutcome::Success,
        &resource_id,
    )
    .await
    .context("record settings config value maintenance start audit")?;
    let operator_subject = match settings_config_value_maintenance_operator_subject(
        &pg,
        &parsed,
        &resource_id,
    )
    .await
    {
        Ok(subject) => subject,
        Err(err) => {
            pg.shutdown().await.ok();
            return Err(err);
        }
    };
    let capability =
        ConfigValueMaintenanceCapability::from_verified_service_subject(operator_subject.clone())
            .context("settings config value maintenance operator subject")?;
    let protection =
        match settings_config_value_maintenance_protection(&pg, &operator_subject, &resource_id)
            .await
        {
            Ok(protection) => protection,
            Err(err) => {
                pg.shutdown().await.ok();
                return Err(err);
            }
        };
    let maintenance = pg.config_value_maintenance(protection, capability);
    let report = match maintenance.run(&options).await {
        Ok(report) => report,
        Err(err) => {
            record_config_value_maintenance_finish_audit(
                &pg,
                &operator_subject,
                &resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "run_error",
                },
            )
            .await
            .context("record settings config value maintenance failure audit")?;
            pg.shutdown().await.ok();
            return Err(err).context("settings config value maintenance");
        }
    };
    let audit_outcome = if report.failed == 0 {
        MaintenanceAuditOutcome::Success
    } else {
        MaintenanceAuditOutcome::Failure {
            reason: "failed_rows",
        }
    };
    record_config_value_maintenance_finish_audit(
        &pg,
        &operator_subject,
        &resource_id,
        audit_outcome,
    )
    .await?;
    let scope = options
        .tenant_opt()
        .map(|tenant| format!("tenant:{tenant}"))
        .unwrap_or_else(|| "all".to_owned());
    let max_rows = options
        .max_rows()
        .map(|max_rows| max_rows.to_string())
        .unwrap_or_else(|| "none".to_owned());
    println!(
        "operation={} dry_run={} scope={} batch_size={} max_rows={} selected={} backfilled={} rewrapped={} unchanged={} failed={} remaining_plaintext={}",
        options.operation().as_str(),
        options.dry_run(),
        scope,
        options.batch_size(),
        max_rows,
        report.selected,
        report.backfilled,
        report.rewrapped,
        report.unchanged,
        report.failed,
        report.remaining_plaintext
    );
    pg.shutdown().await.ok();
    anyhow::ensure!(
        report.failed == 0,
        "settings config value maintenance completed with failed rows"
    );
    Ok(())
}

const REDIS_ALLOW_PLAINTEXT_ENV: &str = "RSS_REDIS_ALLOW_PLAINTEXT";

/// 组合根级 redis capability bundle 构造：`RSS_REDIS_URL` → typed TLS endpoint → deadpool redis pool + PING → [`redis::RedisRuntimeDeps`].
///
/// 缺 `RSS_REDIS_URL` 或 Redis 不可达均 fail-fast；错误上下文只含 env/resource 名，不含 URL 值。
/// 生命周期关闭经 `RedisRuntimeDeps::runtime_resources()` 单源进入
/// [`DomainModuleResult::resources`]。
pub async fn build_redis_runtime_deps(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<redis::RedisRuntimeDeps> {
    let policy = plaintext_endpoint_policy_from(&get, REDIS_ALLOW_PLAINTEXT_ENV)?;
    let url = get("RSS_REDIS_URL")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_REDIS_URL"))?;
    let endpoint = secure::RedisEndpoint::parse(url, policy).context(
        "RSS_REDIS_URL must be rediss:// or loopback redis:// with explicit plaintext opt-in",
    )?;
    #[allow(clippy::disallowed_methods)]
    // reason: 唯一 Redis pool builder callsite；endpoint 已经由 secure::RedisEndpoint 校验。
    let raw_url = endpoint.expose();
    let pool = deadpool_redis::Config::from_url(raw_url)
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

// ── S3 object-store wiring + canary ──────────────────────────────────────────────────────────

const S3_ENDPOINT_URL_ENV: &str = "RSS_S3_ENDPOINT_URL";
const S3_BUCKET_ENV: &str = "RSS_S3_BUCKET";
const S3_ACCESS_KEY_ID_ENV: &str = "RSS_S3_ACCESS_KEY_ID";
const S3_SECRET_ACCESS_KEY_ENV: &str = "RSS_S3_SECRET_ACCESS_KEY";
const S3_SESSION_TOKEN_ENV: &str = "RSS_S3_SESSION_TOKEN";
const S3_REGION_ENV: &str = "RSS_S3_REGION";
const S3_FORCE_PATH_STYLE_ENV: &str = "RSS_S3_FORCE_PATH_STYLE";
const S3_ALLOW_PLAINTEXT_ENV: &str = "RSS_S3_ALLOW_PLAINTEXT";
const S3_CANARY_KEY_PREFIX_ENV: &str = "RSS_S3_CANARY_KEY_PREFIX";
const S3_CANARY_INTERVAL_SECS_ENV: &str = "RSS_S3_CANARY_INTERVAL_SECS";
const S3_CANARY_TIMEOUT_SECS_ENV: &str = "RSS_S3_CANARY_TIMEOUT_SECS";
const DEFAULT_S3_REGION: &str = "us-east-1";
const DEFAULT_S3_CANARY_KEY_PREFIX: &str = "rss/runtime-canary";
const S3_CANARY_COLLECT_LIMIT: usize = 1024;
const S3_CANARY_PAYLOAD: &[u8] = b"rss-s3-canary";
pub const S3_READY_PROBE_NAME: &str = "s3_object_store_ready";

fn required_env(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
) -> anyhow::Result<String> {
    let value = get(name).ok_or_else(|| anyhow::anyhow!("missing required env var: {name}"))?;
    let trimmed = value.trim();
    anyhow::ensure!(!trimmed.is_empty(), "{name} must not be empty");
    Ok(trimmed.to_string())
}

fn parse_bool_env(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: bool,
) -> anyhow::Result<bool> {
    let Some(raw) = get(name) else {
        return Ok(default);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => anyhow::bail!("{name} must be false or true"),
    }
}

fn s3_plaintext_policy_from(
    get: &impl Fn(&str) -> Option<String>,
) -> anyhow::Result<PlaintextEndpointPolicy> {
    let Some(raw) = get(S3_ALLOW_PLAINTEXT_ENV) else {
        return Ok(PlaintextEndpointPolicy::Deny);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(PlaintextEndpointPolicy::AllowLoopback),
        "dev-container" => Ok(PlaintextEndpointPolicy::AllowDevContainer),
        "0" | "false" | "no" => Ok(PlaintextEndpointPolicy::Deny),
        _ => anyhow::bail!("{S3_ALLOW_PLAINTEXT_ENV} must be false, true, or dev-container"),
    }
}

fn validate_s3_bucket(raw: String) -> anyhow::Result<String> {
    let bucket = raw.trim();
    anyhow::ensure!(
        (3..=63).contains(&bucket.len()),
        "{S3_BUCKET_ENV} must be 3..=63 characters"
    );
    anyhow::ensure!(
        bucket
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'),
        "{S3_BUCKET_ENV} must contain only lowercase letters, digits, dots, or hyphens"
    );
    let first = bucket.as_bytes()[0];
    let last = bucket.as_bytes()[bucket.len() - 1];
    anyhow::ensure!(
        (first.is_ascii_lowercase() || first.is_ascii_digit())
            && (last.is_ascii_lowercase() || last.is_ascii_digit()),
        "{S3_BUCKET_ENV} must start and end with a lowercase letter or digit"
    );
    anyhow::ensure!(
        !bucket.contains("..") && !bucket.contains(".-") && !bucket.contains("-."),
        "{S3_BUCKET_ENV} must not contain adjacent dots or dot-hyphen pairs"
    );
    anyhow::ensure!(
        bucket.parse::<std::net::Ipv4Addr>().is_err(),
        "{S3_BUCKET_ENV} must not be formatted as an IPv4 address"
    );
    Ok(bucket.to_string())
}

pub fn build_s3_runtime_deps_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<S3RuntimeDeps> {
    let endpoint = secure::S3Endpoint::parse(
        required_env(&get, S3_ENDPOINT_URL_ENV)?,
        s3_plaintext_policy_from(&get)?,
    )
    .with_context(|| {
        format!("{S3_ENDPOINT_URL_ENV} must be https:// or loopback http:// with explicit opt-in")
    })?;
    let bucket = validate_s3_bucket(required_env(&get, S3_BUCKET_ENV)?)?;
    let access_key_id = required_env(&get, S3_ACCESS_KEY_ID_ENV)?;
    let secret_access_key = required_env(&get, S3_SECRET_ACCESS_KEY_ENV)?;
    let session_token = get(S3_SESSION_TOKEN_ENV).and_then(|raw| {
        let trimmed = raw.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    });
    let region = get(S3_REGION_ENV)
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .unwrap_or_else(|| DEFAULT_S3_REGION.to_string());
    let force_path_style = parse_bool_env(&get, S3_FORCE_PATH_STYLE_ENV, false)?;
    let http_client = if endpoint.is_plaintext() {
        aws_smithy_http_client::Builder::new().build_http()
    } else {
        aws_smithy_http_client::Builder::new()
            .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
                aws_smithy_http_client::tls::rustls_provider::CryptoMode::Ring,
            ))
            .build_https()
    };
    let credentials = aws_sdk_s3::config::Credentials::new(
        access_key_id,
        secret_access_key,
        session_token,
        None,
        "rss-runtime-env",
    );
    let config = aws_sdk_s3::config::Builder::new()
        .behavior_version_latest()
        .region(aws_sdk_s3::config::Region::new(region))
        .credentials_provider(credentials)
        .endpoint_url(endpoint.expose())
        .force_path_style(force_path_style)
        .http_client(http_client)
        .build();
    let store = S3Store::new(aws_sdk_s3::Client::from_conf(config), bucket)
        .context("construct s3 object store")?;
    Ok(S3RuntimeDeps::new(store))
}

fn parse_s3_duration_secs(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: Duration,
    max_secs: u64,
) -> anyhow::Result<Duration> {
    let Some(raw) = get(name) else {
        return Ok(default);
    };
    let secs = raw
        .trim()
        .parse::<u64>()
        .with_context(|| format!("{name} must be an integer number of seconds"))?;
    anyhow::ensure!(
        secs > 0 && secs <= max_secs,
        "{name} must be 1..={max_secs}"
    );
    Ok(Duration::from_secs(secs))
}

fn validate_s3_canary_prefix(raw: String) -> anyhow::Result<String> {
    let prefix = raw.trim().trim_matches('/');
    anyhow::ensure!(
        !prefix.is_empty(),
        "{S3_CANARY_KEY_PREFIX_ENV} must not be empty"
    );
    anyhow::ensure!(
        !prefix.contains("//")
            && prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.')),
        "{S3_CANARY_KEY_PREFIX_ENV} must contain only ASCII path-safe characters"
    );
    Ok(prefix.to_string())
}

#[derive(Clone)]
struct S3CanaryConfig {
    key: diport::ObjectKey,
    interval: Duration,
    timeout: Duration,
}

fn build_s3_canary_config_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<S3CanaryConfig> {
    let prefix = validate_s3_canary_prefix(
        get(S3_CANARY_KEY_PREFIX_ENV).unwrap_or_else(|| DEFAULT_S3_CANARY_KEY_PREFIX.to_string()),
    )?;
    let interval = parse_s3_duration_secs(
        &get,
        S3_CANARY_INTERVAL_SECS_ENV,
        DEFAULT_S3_CANARY_INTERVAL,
        MAX_S3_CANARY_INTERVAL_SECS,
    )?;
    let timeout = parse_s3_duration_secs(
        &get,
        S3_CANARY_TIMEOUT_SECS_ENV,
        DEFAULT_S3_CANARY_TIMEOUT,
        MAX_S3_CANARY_TIMEOUT_SECS,
    )?;
    anyhow::ensure!(
        timeout <= interval,
        "{S3_CANARY_TIMEOUT_SECS_ENV} must be <= {S3_CANARY_INTERVAL_SECS_ENV}"
    );
    Ok(S3CanaryConfig {
        key: diport::ObjectKey::new(format!("{prefix}/{}.txt", uuid::Uuid::new_v4())),
        interval,
        timeout,
    })
}

async fn verify_s3_canary_round<S>(store: &S, key: diport::ObjectKey) -> anyhow::Result<()>
where
    S: ObjectStore,
{
    store
        .put_object(key.clone(), S3_CANARY_PAYLOAD.to_vec())
        .await
        .context("s3 canary put")?;
    let payload = store
        .get_object(key.clone())
        .await
        .context("s3 canary get after put")?
        .ok_or_else(|| anyhow::anyhow!("s3 canary object missing after put"))?;
    let bytes = payload
        .collect_limited(S3_CANARY_COLLECT_LIMIT)
        .await
        .context("s3 canary collect")?;
    anyhow::ensure!(bytes == S3_CANARY_PAYLOAD, "s3 canary payload mismatch");
    store
        .delete_object(key.clone())
        .await
        .context("s3 canary delete")?;
    anyhow::ensure!(
        store
            .get_object(key)
            .await
            .context("s3 canary get after delete")?
            .is_none(),
        "s3 canary object still exists after delete"
    );
    Ok(())
}

pub struct S3ReadyProbe {
    ready: Arc<std::sync::atomic::AtomicBool>,
    name: ProbeName,
}

impl S3ReadyProbe {
    #[allow(clippy::expect_used)]
    pub fn new(ready: Arc<std::sync::atomic::AtomicBool>) -> Self {
        let name = ProbeName::parse(S3_READY_PROBE_NAME).expect("valid probe name const");
        Self { ready, name }
    }
}

impl bootstrap::HealthProbe for S3ReadyProbe {
    fn check(&self) -> HealthCheck {
        let (status, detail) = if self.ready.load(std::sync::atomic::Ordering::Acquire) {
            (HealthStatus::Healthy, "ready")
        } else {
            (HealthStatus::Unhealthy, "down")
        };
        HealthCheck::new(self.name.clone(), status, detail)
    }
}

struct S3CanarySampler {
    handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    token: CancellationToken,
}

impl ManagedResource for S3CanarySampler {
    fn name(&self) -> &str {
        "s3-canary-sampler"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.token.cancel();
        let mut handle = self.handle.lock().await;
        if let Some(handle) = handle.take()
            && let Err(err) = handle.await
        {
            tracing::warn!(error = %err, "s3 canary sampler join failed");
        }
        Ok(())
    }
}

fn spawn_s3_canary_sampler(
    s3: S3RuntimeDeps,
    config: S3CanaryConfig,
    token: CancellationToken,
    ready: Arc<std::sync::atomic::AtomicBool>,
) -> S3CanarySampler {
    let child = token.child_token();
    let worker_token = child.clone();
    let store = s3.object_store();
    let handle = tokio::spawn(async move {
        loop {
            let round = tokio::time::timeout(
                config.timeout,
                verify_s3_canary_round(&*store, config.key.clone()),
            )
            .await;
            let is_ready = match round {
                Ok(Ok(())) => true,
                Ok(Err(err)) => {
                    tracing::warn!(error = %err, "s3 canary round failed");
                    false
                }
                Err(_) => {
                    tracing::warn!("s3 canary round timed out");
                    false
                }
            };
            ready.store(is_ready, std::sync::atomic::Ordering::Release);
            tokio::select! {
                () = worker_token.cancelled() => break,
                () = tokio::time::sleep(config.interval) => {}
            }
        }
    });
    S3CanarySampler {
        handle: tokio::sync::Mutex::new(Some(handle)),
        token: child,
    }
}

fn wire_s3_canary(
    deps: &SharedRuntimeDeps,
    config: S3CanaryConfig,
) -> anyhow::Result<DomainModuleResult> {
    let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let probe_name =
        ProbeName::parse(S3_READY_PROBE_NAME).context("parse s3_object_store_ready probe name")?;
    let probe_ready = Arc::clone(&ready);
    let worker_ready = Arc::clone(&ready);
    let s3 = deps.s3.clone();
    let worker: bootstrap::WorkerSpec = Box::new(move |token| {
        DynManagedResource::new_box(spawn_s3_canary_sampler(
            s3.clone(),
            config,
            token,
            worker_ready,
        ))
    });
    Ok(DomainModuleResult {
        probes: vec![(probe_name, Box::new(S3ReadyProbe::new(probe_ready)))],
        resources: Vec::new(),
        workers: vec![worker],
    })
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

// ── RedisReadyProbe ───────────────────────────────────────────────────────────────────────────

/// Redis readiness probe stable name.
pub const REDIS_READY_PROBE_NAME: &str = "redis_ready";

/// Redis dependency readiness probe. Startup PING is fail-fast; this probe keeps the dependency
/// visible to `/readyz` and lets later Redis outages fail readiness.
pub struct RedisReadyProbe {
    ready: Arc<std::sync::atomic::AtomicBool>,
    name: ProbeName,
}

impl RedisReadyProbe {
    #[allow(clippy::expect_used)]
    pub fn new(ready: Arc<std::sync::atomic::AtomicBool>) -> Self {
        let name = ProbeName::parse(REDIS_READY_PROBE_NAME).expect("valid probe name const");
        Self { ready, name }
    }
}

impl bootstrap::HealthProbe for RedisReadyProbe {
    fn check(&self) -> HealthCheck {
        let (status, detail) = if self.ready.load(std::sync::atomic::Ordering::Acquire) {
            (HealthStatus::Healthy, "ready")
        } else {
            (HealthStatus::Unhealthy, "down")
        };
        HealthCheck::new(self.name.clone(), status, detail)
    }
}

struct RedisReadinessSampler {
    handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    token: CancellationToken,
}

impl ManagedResource for RedisReadinessSampler {
    fn name(&self) -> &str {
        "redis-readiness-sampler"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.token.cancel();
        let mut handle = self.handle.lock().await;
        if let Some(handle) = handle.take()
            && let Err(err) = handle.await
        {
            tracing::warn!(error = %err, "redis readiness sampler join failed");
        }
        Ok(())
    }
}

fn spawn_redis_readiness_sampler(
    redis: redis::RedisRuntimeDeps,
    period: Duration,
    token: CancellationToken,
    ready: Arc<std::sync::atomic::AtomicBool>,
) -> RedisReadinessSampler {
    let child = token.child_token();
    let worker_token = child.clone();
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                () = worker_token.cancelled() => break,
                () = tokio::time::sleep(period) => {
                    let is_ready = redis.ping().await.is_ok();
                    ready.store(is_ready, std::sync::atomic::Ordering::Release);
                }
            }
        }
    });
    RedisReadinessSampler {
        handle: tokio::sync::Mutex::new(Some(handle)),
        token: child,
    }
}

// ── KeyProviderReadyProbe ─────────────────────────────────────────────────────────────────────

/// Vault Transit KeyProvider readiness probe stable name.
pub const KEYPROVIDER_READY_PROBE_NAME: &str = "keyprovider_ready";

const KEYPROVIDER_READINESS_TENANT: &str = "00000000-0000-4000-8000-000000000147";
const KEYPROVIDER_READINESS_MISMATCH_TENANT: &str = "00000000-0000-4000-8000-000000000148";
const KEYPROVIDER_READINESS_CONFIG_KEY: &str = "readiness.probe";
const KEYPROVIDER_READINESS_VALUE: &[u8] = b"rss-keyprovider-ready";
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

async fn verify_keyprovider_ready(
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

struct KeyProviderReadinessSampler {
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

fn spawn_keyprovider_readiness_sampler(
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

// ── SessionSweeperProbe / worker ──────────────────────────────────────────────────────────────

const SESSION_SWEEPER_HEALTHY: u8 = 0;
const SESSION_SWEEPER_DEGRADED: u8 = 1;
const SESSION_SWEEPER_STOPPED: u8 = 2;

struct SessionSweeperHealth(std::sync::atomic::AtomicU8);

impl SessionSweeperHealth {
    fn healthy() -> Self {
        Self(std::sync::atomic::AtomicU8::new(SESSION_SWEEPER_HEALTHY))
    }

    fn mark_healthy(&self) {
        self.0.store(
            SESSION_SWEEPER_HEALTHY,
            std::sync::atomic::Ordering::Release,
        );
    }

    fn mark_degraded(&self) {
        self.0.store(
            SESSION_SWEEPER_DEGRADED,
            std::sync::atomic::Ordering::Release,
        );
    }

    fn mark_stopped(&self) {
        self.0.store(
            SESSION_SWEEPER_STOPPED,
            std::sync::atomic::Ordering::Release,
        );
    }

    fn status_detail(&self) -> (HealthStatus, &'static str) {
        match self.0.load(std::sync::atomic::Ordering::Acquire) {
            SESSION_SWEEPER_HEALTHY => (HealthStatus::Healthy, "worker"),
            SESSION_SWEEPER_DEGRADED => (HealthStatus::Degraded, "degraded"),
            _ => (HealthStatus::Unhealthy, "stopped"),
        }
    }
}

struct SessionSweeperStoppedGuard(Arc<SessionSweeperHealth>);

impl Drop for SessionSweeperStoppedGuard {
    fn drop(&mut self) {
        self.0.mark_stopped();
    }
}

struct SessionSweeperProbe {
    name: ProbeName,
    health: Arc<SessionSweeperHealth>,
}

impl bootstrap::HealthProbe for SessionSweeperProbe {
    fn check(&self) -> HealthCheck {
        let (status, detail) = self.health.status_detail();
        HealthCheck::new(self.name.clone(), status, detail)
    }
}

struct SessionSweeperWorker {
    handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    token: CancellationToken,
}

impl ManagedResource for SessionSweeperWorker {
    fn name(&self) -> &str {
        SESSION_SWEEPER_WORKER_NAME
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.token.cancel();
        let mut handle = self.handle.lock().await;
        if let Some(handle) = handle.take()
            && let Err(err) = handle.await
        {
            tracing::warn!(error = %err, "session sweeper worker join failed");
        }
        Ok(())
    }
}

fn spawn_session_sweeper(
    sweeper: postgres::PgSessionSweeper,
    period: Duration,
    token: CancellationToken,
    health: Arc<SessionSweeperHealth>,
) -> SessionSweeperWorker {
    let child = token.child_token();
    let worker_token = child.clone();
    let handle = tokio::spawn(async move {
        let _stopped = SessionSweeperStoppedGuard(Arc::clone(&health));
        let mut ticker = tokio::time::interval(period);
        loop {
            tokio::select! {
                biased;
                () = worker_token.cancelled() => break,
                _ = ticker.tick() => {
                    tokio::select! {
                        biased;
                        () = worker_token.cancelled() => break,
                        deleted = sweeper.sweep_expired() => {
                            match deleted {
                                Ok(deleted) => {
                                    tracing::debug!(target_table = "sessions", deleted, "session sweeper: tick completed");
                                    health.mark_healthy();
                                }
                                Err(err) => {
                                    tracing::warn!(
                                        target_table = "sessions",
                                        error = %err,
                                        "session sweeper: sweep failed, marking worker degraded; backing off to next tick"
                                    );
                                    health.mark_degraded();
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    SessionSweeperWorker {
        handle: tokio::sync::Mutex::new(Some(handle)),
        token: child,
    }
}

fn session_sweeper_module_result(
    worker: bootstrap::WorkerSpec,
    health: Arc<SessionSweeperHealth>,
) -> anyhow::Result<DomainModuleResult> {
    let probe_name = ProbeName::parse(SESSION_SWEEPER_PROBE_NAME)
        .context("session_sweeper probe name is invalid")?;
    Ok(DomainModuleResult {
        probes: vec![(
            probe_name.clone(),
            Box::new(SessionSweeperProbe {
                name: probe_name,
                health,
            }),
        )],
        workers: vec![worker],
        ..Default::default()
    })
}

fn wire_session_sweeper(pg: &PgRuntimeDeps) -> anyhow::Result<DomainModuleResult> {
    let period = build_session_sweeper_interval();
    let sweeper = pg.infra().session_sweeper();
    let health = Arc::new(SessionSweeperHealth::healthy());
    let worker_health = Arc::clone(&health);
    let worker: bootstrap::WorkerSpec = Box::new(move |token| {
        DynManagedResource::new_box(spawn_session_sweeper(sweeper, period, token, worker_health))
    });
    tracing::info!(
        interval_ms = period.as_millis(),
        "session sweeper interval configured"
    );
    session_sweeper_module_result(worker, health)
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
    let vault_settings = deps.vault.for_domain::<vault_caps::Settings>();
    let key_name = deps.settings_config_value_key_name.clone();
    let probe_provider = vault_settings.key_provider();
    verify_keyprovider_ready(&probe_provider, key_name.clone())
        .await
        .context("verify settings config value key provider")?;

    // 单一 settings bundle（PERSIST-003）：read+write config + secret repo 同 pool、单 clock 经 Arc 扇出，预包装
    // 域形 dyn port——组合根不再散装构造 repo / 手工 DynX 包裹 / 配对 read↔write。
    let (configs, writer, secrets) = deps
        .pg
        .for_domain::<caps::Settings>()
        .settings_bundle(
            Arc::new(SystemClock),
            ConfigValueProtections::new(
                vault_settings.key_provider(),
                vault_settings.key_provider(),
                key_name.clone(),
            ),
        )
        .into_parts();

    // config 应用服务（L2 OutboxFact：CAS 写 + outbox co-tx）→ 经 Arc 作 config-publish 路由 axum State。
    let config_svc =
        SettingsService::with_postgres(configs, writer, empty_flag_store(), Box::new(SystemClock));
    // secret 仓储端口 → 经 Arc 作 secret-publish 路由 axum State（`DynSecretRepo` 已 Send+Sync）。
    let secret_repo: Arc<DynSecretRepo<'static>> = Arc::from(secrets);

    let keyprovider_ready = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let mut module =
        settings_module_result(deps.pg.readiness_handle(), Arc::clone(&keyprovider_ready))?;
    let vault_for_sampler = deps.vault.clone();
    module.workers.push(Box::new(move |token| {
        DynManagedResource::new_box(spawn_keyprovider_readiness_sampler(
            vault_for_sampler.clone(),
            key_name.clone(),
            build_keyprovider_readiness_interval(),
            token,
            Arc::clone(&keyprovider_ready),
        ))
    }));
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
fn settings_module_result(
    readiness: Arc<PgDbReadiness>,
    keyprovider_ready: Arc<std::sync::atomic::AtomicBool>,
) -> anyhow::Result<DomainModuleResult> {
    // configs_ready 探针：读 SharedRuntimeDeps 注入的共享 PgDbReadiness（框架 sampler 写）。作 settings 域
    // readiness 产物经 result 出向——不能放纯声明的 `Domain::init`（需运行时构造的 handle）。
    let probe_name = ProbeName::parse(CONFIGS_READY_PROBE_NAME)
        .context("configs_ready probe name is invalid")?;
    let keyprovider_probe_name = ProbeName::parse(KEYPROVIDER_READY_PROBE_NAME)
        .context("keyprovider_ready probe name is invalid")?;
    Ok(DomainModuleResult {
        probes: vec![
            (probe_name, Box::new(ConfigsReadyProbe::new(readiness))),
            (
                keyprovider_probe_name,
                Box::new(KeyProviderReadyProbe::new(keyprovider_ready)),
            ),
        ],
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
pub fn wire_audit(deps: &SharedRuntimeDeps) -> anyhow::Result<AuditDomain<PgAuthAuditSink>> {
    let hasher = build_audit_hasher(|name| std::env::var(name).ok()).context("audit chain key")?;
    let audit_deps = deps.pg.for_domain::<caps::Audit>();
    let repo = audit_deps.audit_repo(hasher);
    let dyn_repo: Arc<DynAuditRepo<'static>> = Arc::from(DynAuditRepo::new_box(repo));
    let admin_repo = build_audit_hasher(|name| std::env::var(name).ok())
        .context("audit admin chain key")
        .map(|hasher| {
            audit_deps
                .audit_admin_repo(hasher)
                .map(|repo| Arc::from(audit::ports::DynAuditAdminRepo::new_box(repo)))
        })?;
    Ok(AuditDomain::new(
        dyn_repo,
        admin_repo,
        audit_deps.auth_audit_sink(),
        Arc::new(SystemClock),
    ))
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
/// Optional PEM CA cert path for private/dev Vault HTTPS endpoints.
const VAULT_CA_CERT_PEM_PATH_ENV: &str = "RSS_VAULT_CA_CERT_PEM_PATH";

/// JWT access-token 签发 env（ES256，组合根注入 vault `Signer`，#1252）。
const JWT_ISSUER_ENV: &str = "RSS_JWT_ISSUER";
const JWT_AUDIENCE_ENV: &str = "RSS_JWT_AUDIENCE";
/// vault Transit sign key 名 = JOSE `kid`（验签侧据 kid 选 oidc ES256 公钥；二者须由运维一致接线，OIDC-ALG-KEYPATH-01）。
const JWT_KEY_ID_ENV: &str = "RSS_JWT_ES256_KEY_ID";
const JWT_ACCESS_TTL_ENV: &str = "RSS_JWT_ACCESS_TTL_SECS";
/// vault Transit mount path（如 `transit`，per-deploy）。
const VAULT_TRANSIT_MOUNT_ENV: &str = "RSS_VAULT_TRANSIT_MOUNT";
/// settings ConfigValue 加密使用的 Vault Transit keyset 名。
const SETTINGS_CONFIG_VALUE_KEY_NAME_ENV: &str = "RSS_SETTINGS_CONFIG_VALUE_KEY_NAME";
/// 临时允许启动时存在 legacy plaintext settings ConfigValue 行的安全豁免。
const SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES_ENV: &str =
    "RSS_SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES";
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
    let roles_for_admin = Arc::from(DynRoleRepo::new_box(identity_pg.role_repo()));
    let roles_for_list = Arc::from(DynRoleRepo::new_box(identity_pg.role_repo()));
    let policies = Arc::from(DynPolicyRepo::new_box(identity_pg.policy_repo()));
    let bindings = Arc::from(DynRoleBindingLifecycle::new_box(
        identity_pg.role_binding_lifecycle(Box::new(SystemClock)),
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
    let rbac_admin = Arc::new(RbacAdminService::new(
        roles_for_admin,
        Arc::clone(&bindings),
        Box::new(SystemClock),
    ));
    Ok(IdentityDomain::new(
        login,
        refresh,
        rbac_admin,
        roles_for_list,
        bindings,
        policies,
        Arc::new(SystemClock),
    ))
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
/// （ROUTE-AUTH-FUNNEL：health router 也经 finalize_auth + request_id/correlation 封口；trace 由
/// `httpserve` 的 listener policy 对 Health 禁用，避免 probe/scrape span 噪声）。
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

const LISTENER_ALLOW_PLAINTEXT_ENV: &str = "RSS_LISTENER_ALLOW_PLAINTEXT";

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
    // reason: composition-root startup policy compares operator-provided migration expiry with the
    // process clock. Domain logic still receives clocks by DI; this is env guard evaluation.
    #[allow(clippy::disallowed_methods)]
    let now = SystemTime::now();
    listener_addr_from_at(listener, get, now)
}

fn listener_addr_from_at(
    listener: ListenerKind,
    get: impl Fn(&str) -> Option<String>,
    now: SystemTime,
) -> anyhow::Result<SocketAddr> {
    let var = listener_addr_env(listener)?;
    let raw = get(var)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {var} (listener has routes)"))?;
    let addr = raw
        .parse::<SocketAddr>()
        .with_context(|| format!("{var} must be a valid host:port SocketAddr: {raw}"))?;
    let scheme = auth_scheme_from(listener, &get)
        .context("resolve listener auth scheme for plaintext policy")?;
    enforce_listener_plaintext_policy(listener, scheme, addr, &get, now)?;
    Ok(addr)
}

fn enforce_listener_plaintext_policy(
    listener: ListenerKind,
    scheme: AuthScheme,
    addr: SocketAddr,
    get: impl Fn(&str) -> Option<String>,
    now: SystemTime,
) -> anyhow::Result<()> {
    if scheme == AuthScheme::Mtls {
        return Ok(());
    }
    let policy = plaintext_endpoint_policy_from(&get, LISTENER_ALLOW_PLAINTEXT_ENV)?;
    match policy {
        PlaintextEndpointPolicy::Deny => anyhow::bail!(
            "{LISTENER_ALLOW_PLAINTEXT_ENV} must explicitly allow plaintext listener {listener:?} at {addr}"
        ),
        PlaintextEndpointPolicy::AllowLoopback => {
            anyhow::ensure!(
                addr.ip().is_loopback(),
                "{LISTENER_ALLOW_PLAINTEXT_ENV}=true only allows loopback plaintext listener binds"
            );
        }
        PlaintextEndpointPolicy::AllowDevContainer => {
            anyhow::ensure!(
                addr.ip().is_loopback() || addr.ip().is_unspecified(),
                "{LISTENER_ALLOW_PLAINTEXT_ENV}=dev-container only allows loopback or wildcard demo listener binds"
            );
        }
    }
    enforce_internal_service_token_migration_guard(listener, scheme, addr, &get, now)
}

fn enforce_internal_service_token_migration_guard(
    listener: ListenerKind,
    scheme: AuthScheme,
    addr: SocketAddr,
    get: impl Fn(&str) -> Option<String>,
    now: SystemTime,
) -> anyhow::Result<()> {
    if listener != ListenerKind::Internal || scheme != AuthScheme::ServiceToken {
        return Ok(());
    }
    if addr.ip().is_loopback() {
        return Ok(());
    }
    let ticket = get(INTERNAL_SERVICE_TOKEN_MIGRATION_TICKET_ENV).ok_or_else(|| {
        anyhow::anyhow!("missing required env var: {INTERNAL_SERVICE_TOKEN_MIGRATION_TICKET_ENV}")
    })?;
    anyhow::ensure!(
        !ticket.trim().is_empty(),
        "{INTERNAL_SERVICE_TOKEN_MIGRATION_TICKET_ENV} must not be empty"
    );
    let raw_expires =
        get(INTERNAL_SERVICE_TOKEN_MIGRATION_EXPIRES_AT_UNIX_ENV).ok_or_else(|| {
            anyhow::anyhow!(
                "missing required env var: {INTERNAL_SERVICE_TOKEN_MIGRATION_EXPIRES_AT_UNIX_ENV}"
            )
        })?;
    let expires_at = service_token_migration_expiry(raw_expires.trim())?;
    anyhow::ensure!(
        expires_at > now,
        "{INTERNAL_SERVICE_TOKEN_MIGRATION_EXPIRES_AT_UNIX_ENV} has expired"
    );
    Ok(())
}

fn service_token_migration_expiry(raw: &str) -> anyhow::Result<SystemTime> {
    let seconds = raw.parse::<u64>().with_context(|| {
        format!("{INTERNAL_SERVICE_TOKEN_MIGRATION_EXPIRES_AT_UNIX_ENV} must be unix seconds")
    })?;
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{INTERNAL_SERVICE_TOKEN_MIGRATION_EXPIRES_AT_UNIX_ENV} is out of range"
            )
        })
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
    listeners: Vec<AssembledListener>,
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
    listeners: Vec<AssembledListener>,
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
    for listener in listeners {
        bind_and_register(&mut stack, listener, &addr_resolver).await?;
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
// reason: this is the per-listener assembly junction; keeping bind, auth-scheme selection, and
// plaintext/mTLS ShutdownStack registration together makes fail-fast startup order explicit.
#[allow(clippy::cognitive_complexity)]
async fn bind_and_register<R>(
    stack: &mut ShutdownStack,
    listener: AssembledListener,
    addr_resolver: &R,
) -> anyhow::Result<()>
where
    R: Fn(ListenerKind) -> anyhow::Result<SocketAddr>,
{
    let AssembledListener {
        listener,
        routes,
        mtls_health,
    } = listener;
    let name = listener_name(listener);
    let addr = addr_resolver(listener)?;
    let bound = HttpServer::bind(name, addr)
        .await
        .with_context(|| format!("bind {name} listener at {addr}"))?;
    tracing::info!(listener = ?listener, name, addr = %bound.local_addr(), "listener bound");
    let scheme = auth_scheme(listener).context("resolve listener auth scheme for serve")?;
    let svc = routes.into_make_service();
    match scheme {
        AuthScheme::Mtls => {
            let mtls = mtls_config_from_env(listener)
                .await
                .with_context(|| format!("build {name} mTLS config"))?;
            if let Some(slot) = &mtls_health {
                slot.set(mtls.clone())?;
            }
            stack.register_with_token(move |token| {
                DynManagedResource::new_box(bound.serve_mtls(svc, mtls, token))
            });
        }
        _ => {
            if listener == ListenerKind::Internal && scheme == AuthScheme::ServiceToken {
                tracing::warn!(
                    listener = ?listener,
                    "binding transitional Internal service-token listener; mTLS is the default"
                );
            }
            stack.register_with_token(move |token| {
                DynManagedResource::new_box(bound.serve(svc, token))
            });
        }
    }
    Ok(())
}

fn mtls_allow_set_from_csv(raw: &str) -> anyhow::Result<authn::MtlsAllowSet> {
    mtls_allow_set_from_csv_for_env(raw, INTERNAL_MTLS_SPIFFE_ALLOW_SET_ENV)
}

fn mtls_allow_set_from_csv_for_env(raw: &str, env: &str) -> anyhow::Result<authn::MtlsAllowSet> {
    let mut ids = Vec::new();
    for part in raw.split(',') {
        let trimmed = part.trim();
        anyhow::ensure!(!trimmed.is_empty(), "{env} must not contain empty entries");
        ids.push(trimmed.to_owned());
    }
    authn::MtlsAllowSet::new(ids).map_err(|e| anyhow::anyhow!("{env} invalid: {e}"))
}

fn mtls_allow_set_from_env(
    listener: ListenerKind,
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<authn::MtlsAllowSet> {
    anyhow::ensure!(
        listener == ListenerKind::Internal,
        "mTLS listener config is only wired for Internal"
    );
    let raw = get(INTERNAL_MTLS_SPIFFE_ALLOW_SET_ENV).ok_or_else(|| {
        anyhow::anyhow!("missing required env var: {INTERNAL_MTLS_SPIFFE_ALLOW_SET_ENV}")
    })?;
    mtls_allow_set_from_csv(&raw)
}

async fn mtls_config_from_env(listener: ListenerKind) -> anyhow::Result<httpd::MtlsServerConfig> {
    let allow_set = mtls_allow_set_from_env(listener, |name| std::env::var(name).ok())?;
    let endpoint = std::env::var(SPIFFE_ENDPOINT_SOCKET_ENV).ok();
    httpd::MtlsServerConfig::from_spire(allow_set, endpoint.as_deref())
        .await
        .with_context(|| {
            format!(
                "build Internal listener mTLS config ({} optional override)",
                SPIFFE_ENDPOINT_SOCKET_ENV
            )
        })
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
    let audit_admin_config =
        build_pg_audit_admin_config().context("build audit admin postgres config")?;
    let pg = PgRuntimeDeps::setup_with_audit_admin_config(
        &build_pg_migrator_config()?,
        &build_pg_config()?,
        audit_admin_config.as_ref(),
        legacy_config_plaintext_policy()?,
    )
    .await
    .context("setup postgres deps")?;

    // vault capability bundle（#1498）：env → resolver → VaultRuntimeDeps（单源装配出口）。vault env 缺失即
    // fail-fast（不静默装配 vault）；resolver 经 bundle dispatch 注入 settings，guard 经 runtime_resources 单源。
    let vault =
        build_vault_runtime_deps(|name| std::env::var(name).ok()).context("setup vault deps")?;
    let settings_config_value_key_name =
        build_settings_config_value_key_name_from(|name| std::env::var(name).ok())
            .context("settings config value key name")?;
    // redis capability bundle（#1571 go-live）：Redis 是 distributed lock provider 的生产硬依赖。
    // 缺 `RSS_REDIS_URL` 或启动期 PING 失败均 fail-fast，不保留 demo-optional 生产路径。
    let redis = build_redis_runtime_deps(|name| std::env::var(name).ok())
        .await
        .context("setup redis deps")?;
    // s3 capability bundle（#1164）：生产 object-store 真实接线。缺 S3 env 或 TLS/endpoint 误配均 fail-fast；
    // readiness 由下方 runtime canary worker 周期执行真实 put/get/delete/get-miss。
    let s3 =
        build_s3_runtime_deps_from(|name| std::env::var(name).ok()).context("setup s3 deps")?;
    let s3_canary_config =
        build_s3_canary_config_from(|name| std::env::var(name).ok()).context("s3 canary config")?;
    let event_cfg = build_event_transport_config().context("event transport config")?;
    if event_cfg.topology == bootstrap::Topology::Demo {
        anyhow::bail!(
            "RSS_TOPOLOGY=demo is not supported in the production runtime; \
             use durable-shared or durable-isolated"
        );
    }
    let domain_transport =
        wire_domain_transport_from(event_cfg.topology, |name| std::env::var(name).ok())
            .await
            .context("wire outbound domain transport")?;

    // 共享基础设施依赖（infra 流入各域 wire_X；「字段仅 infra」是约定，机器门见 #1448）。
    let deps = SharedRuntimeDeps {
        pg: pg.clone(),
        redis,
        s3,
        vault,
        settings_config_value_key_name,
        domain_transport: domain_transport.dispatch_handle(),
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
    module.merge(wire_session_sweeper(&pg).context("wire session sweeper")?);
    module.merge(wire_s3_canary(&deps, s3_canary_config).context("wire s3 canary")?);
    // provider capability bundle 单源装配（#1498）：Redis / vault guards 经 runtime_resources() 单源排进
    // module.resources，组合根不再逐 channel 手写 register_detached（D5）。
    module.resources.extend(deps.redis.runtime_resources());
    module.resources.extend(deps.s3.runtime_resources());
    module.resources.extend(deps.vault.runtime_resources());
    let pg_readiness_period = build_readiness_interval();
    let redis_readiness_period = build_redis_readiness_interval();

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
    let redis_ready = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let redis_probe_name =
        ProbeName::parse(REDIS_READY_PROBE_NAME).context("parse redis_ready probe name")?;
    registry
        .probe(
            redis_probe_name,
            Box::new(RedisReadyProbe::new(Arc::clone(&redis_ready))),
        )
        .context("register redis_ready probe")?;

    // 事件传输接线（#1251）：topology-gated durable AMQP/Redis + outbox relay + consumer workers。
    // Demo 拓扑已在构造 SharedRuntimeDeps 前 fail-fast；production runtime 不走 in-memory path。
    module.merge(
        domain_transport
            .module_result()
            .context("wire outbound domain transport module")?,
    );
    let distributed = wire_distributed(&deps).context("wire distributed")?;
    let event_subscribers =
        event_transport::bridge_generated_subscriptions(registry.drain_subscribers())
            .context("bridge generated event subscriptions")?;
    let event_runtime =
        event_transport::wire_event_transport(&pg, distributed, event_subscribers, event_cfg)
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
    let redis_for_sampler = deps.redis.clone();
    module.workers.push(Box::new(move |token| {
        DynManagedResource::new_box(spawn_redis_readiness_sampler(
            redis_for_sampler.clone(),
            redis_readiness_period,
            token,
            Arc::clone(&redis_ready),
        ))
    }));
    let domain_resources = module.resources;
    let domain_workers = module.workers;
    tracing::info!(
        sample_interval_secs = pg_readiness_period.as_secs(),
        "pg readiness sampler interval configured"
    );
    tracing::info!(
        sample_interval_secs = redis_readiness_period.as_secs(),
        "redis readiness sampler interval configured"
    );

    // 装配域路由认证接线（drain registry 路由组，借 &mut——probe 留存供下方 readyz）。
    // Auth decision audit is a flat durable sink, not the `audit::AuditRepo` hash-chain actor model.
    let auth_audit_sink =
        httpserve::AuditSinkHandle::new(pg.for_domain::<caps::Audit>().auth_audit_sink());
    let auth_audit_clock: Arc<dyn diport::Clock> = Arc::new(SystemClock);
    let mut listeners = assemble_authed_routers(
        &mut registry,
        provider,
        auth_audit_sink,
        auth_audit_clock,
        identity_domain.primary_authorizer(),
    )
    .context("assemble authed routers")?;

    // Health listener（框架归属）：readyz 经 Arc<HealthReporter>（Send+Sync）每请求聚合探针。registry 路由组
    // 已 drain，探针经 take_health_reporter 移出（整体非 Sync 的 Registry 无法进 axum handler 闭包）。
    let reporter = Arc::new(registry.take_health_reporter());
    let (listener, routes) =
        health_listener(reporter, metrics_exporter).context("build health listener")?;
    listeners.push(AssembledListener::plain(listener, routes));

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
        if let Some(guard) = pg.audit_admin_store_guard() {
            stack.register_detached(DynManagedResource::new_box(guard));
        }
        // 再注册 sampler（spawn+adopt 收口进 bundle；child token 广播取消；LIFO：listener drain → sampler 停 → pool close）。
        stack.register_with_token(move |token| {
            DynManagedResource::new_box(pg.spawn_readiness_sampler(pg_readiness_period, token))
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
    use diport::ServiceTokenReplayGuard;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE_NO_PAD;
    static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_temp_path(name: &str) -> std::path::PathBuf {
        let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("rss-runtime-{}-{seq}-{name}", std::process::id()))
    }

    #[allow(clippy::expect_used)]
    fn write_temp_file(name: &str, contents: &[u8]) -> std::path::PathBuf {
        let path = unique_temp_path(name);
        std::fs::write(&path, contents).expect("write temp file");
        path
    }

    #[allow(clippy::expect_used)]
    fn create_temp_dir(name: &str) -> std::path::PathBuf {
        let path = unique_temp_path(name);
        std::fs::create_dir(&path).expect("create temp dir");
        path
    }

    #[cfg(unix)]
    #[allow(clippy::expect_used)]
    fn write_unreadable_temp_file(name: &str, contents: &[u8]) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = write_temp_file(name, contents);
        let mut permissions = std::fs::metadata(&path)
            .expect("metadata temp file")
            .permissions();
        permissions.set_mode(0o000);
        std::fs::set_permissions(&path, permissions).expect("make temp file unreadable");
        path
    }

    /// 测试时钟（这些测试只验构造成功/失败，不验 token exp，故 SystemClock 即可）。
    fn clk() -> Box<dyn diport::Clock> {
        Box::new(SystemClock)
    }

    #[derive(Clone)]
    struct AllowAuthorizer;

    impl httpserve::RouteAuthorizer for AllowAuthorizer {
        fn authorize<'a>(
            &'a self,
            _request: httpserve::RouteAuthorizationRequest,
        ) -> Pin<Box<dyn Future<Output = httpserve::RouteAuthorizationDecision> + Send + 'a>>
        {
            Box::pin(async { httpserve::RouteAuthorizationDecision::Allow })
        }
    }

    fn allow_authorizer() -> Arc<dyn httpserve::RouteAuthorizer> {
        Arc::new(AllowAuthorizer)
    }

    fn full_s3_get(k: &str) -> Option<String> {
        match k {
            "RSS_S3_ENDPOINT_URL" => Some("https://s3.us-east-1.amazonaws.com".to_string()),
            "RSS_S3_BUCKET" => Some("rss-prod-bucket".to_string()),
            "RSS_S3_ACCESS_KEY_ID" => Some("access-key".to_string()),
            "RSS_S3_SECRET_ACCESS_KEY" => Some("secret-key".to_string()),
            _ => None,
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_s3_runtime_deps_missing_endpoint_fails_fast() {
        let result = build_s3_runtime_deps_from(|k| {
            if k == "RSS_S3_ENDPOINT_URL" {
                None
            } else {
                full_s3_get(k)
            }
        });
        let err = result.err().expect("missing endpoint must fail");
        assert!(format!("{err:#}").contains("RSS_S3_ENDPOINT_URL"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_s3_runtime_deps_rejects_plaintext_by_default() {
        let result = build_s3_runtime_deps_from(|k| match k {
            "RSS_S3_ENDPOINT_URL" => Some("http://127.0.0.1:9000".to_string()),
            _ => full_s3_get(k),
        });
        let err = result.err().expect("plaintext needs explicit opt-in");
        assert!(format!("{err:#}").contains("RSS_S3_ENDPOINT_URL"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_s3_runtime_deps_rejects_non_loopback_plaintext_even_with_opt_in() {
        let result = build_s3_runtime_deps_from(|k| match k {
            "RSS_S3_ENDPOINT_URL" => Some("http://minio.internal:9000".to_string()),
            "RSS_S3_ALLOW_PLAINTEXT" => Some("true".to_string()),
            _ => full_s3_get(k),
        });
        let err = result
            .err()
            .expect("non-loopback plaintext must fail closed");
        assert!(format!("{err:#}").contains("loopback"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_s3_runtime_deps_allows_dev_container_minio_only_with_explicit_policy() {
        let deps = build_s3_runtime_deps_from(|k| match k {
            "RSS_S3_ENDPOINT_URL" => Some("http://minio:9000".to_string()),
            "RSS_S3_ALLOW_PLAINTEXT" => Some("dev-container".to_string()),
            "RSS_S3_FORCE_PATH_STYLE" => Some("true".to_string()),
            _ => full_s3_get(k),
        })
        .expect("dev-container minio endpoint should build");
        assert_eq!(deps.runtime_resources()[0].name(), "s3");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_s3_runtime_deps_https_single_sources_resource_guard() {
        let deps = build_s3_runtime_deps_from(full_s3_get).expect("valid s3 config");
        let resources = deps.runtime_resources();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].name(), "s3");
    }

    #[derive(Clone, Copy)]
    enum CanaryScript {
        Happy,
        MissingAfterPut,
        PresentAfterDelete,
    }

    #[derive(Clone)]
    struct ScriptedObjectStore {
        script: CanaryScript,
        calls: Arc<std::sync::Mutex<Vec<&'static str>>>,
    }

    impl ScriptedObjectStore {
        fn new(script: CanaryScript) -> Self {
            Self {
                script,
                calls: Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        #[allow(clippy::expect_used)]
        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().expect("calls mutex").clone()
        }

        fn record(&self, call: &'static str) -> Result<(), diport::ObjectStoreError> {
            self.calls
                .lock()
                .map_err(|_| {
                    diport::ObjectStoreError::new(std::io::Error::other("calls mutex poisoned"))
                })?
                .push(call);
            Ok(())
        }
    }

    impl diport::ObjectStore for ScriptedObjectStore {
        async fn put_object(
            &self,
            _key: diport::ObjectKey,
            _body: Vec<u8>,
        ) -> Result<(), diport::ObjectStoreError> {
            self.record("put")
        }

        async fn get_object(
            &self,
            _key: diport::ObjectKey,
        ) -> Result<Option<diport::ObjectPayload>, diport::ObjectStoreError> {
            let get_count = {
                let mut calls = self.calls.lock().map_err(|_| {
                    diport::ObjectStoreError::new(std::io::Error::other("calls mutex poisoned"))
                })?;
                calls.push("get");
                calls.iter().filter(|&&call| call == "get").count()
            };
            match (self.script, get_count) {
                (CanaryScript::MissingAfterPut, 1) => Ok(None),
                (CanaryScript::PresentAfterDelete, 2) => Ok(Some(diport::ObjectPayload::new(
                    Box::pin(futures::stream::once(async {
                        Ok::<Vec<u8>, diport::ObjectStoreError>(S3_CANARY_PAYLOAD.to_vec())
                    })),
                ))),
                (_, 1) => Ok(Some(diport::ObjectPayload::new(Box::pin(
                    futures::stream::once(async {
                        Ok::<Vec<u8>, diport::ObjectStoreError>(S3_CANARY_PAYLOAD.to_vec())
                    }),
                )))),
                _ => Ok(None),
            }
        }

        async fn delete_object(
            &self,
            _key: diport::ObjectKey,
        ) -> Result<(), diport::ObjectStoreError> {
            self.record("delete")
        }

        async fn shutdown(&self) -> Result<(), diport::ObjectStoreError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn s3_canary_roundtrip_runs_put_get_delete_get_miss() -> anyhow::Result<()> {
        let store = ScriptedObjectStore::new(CanaryScript::Happy);
        verify_s3_canary_round(&store, diport::ObjectKey::new("rss/runtime-canary/test")).await?;
        assert_eq!(store.calls(), vec!["put", "get", "delete", "get"]);
        Ok(())
    }

    #[tokio::test]
    async fn s3_canary_roundtrip_fails_when_written_object_is_missing() {
        let store = ScriptedObjectStore::new(CanaryScript::MissingAfterPut);
        let result =
            verify_s3_canary_round(&store, diport::ObjectKey::new("rss/runtime-canary/test")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn s3_canary_roundtrip_fails_when_delete_does_not_remove_object() {
        let store = ScriptedObjectStore::new(CanaryScript::PresentAfterDelete);
        let result =
            verify_s3_canary_round(&store, diport::ObjectKey::new("rss/runtime-canary/test")).await;
        assert!(result.is_err());
    }

    fn identity_storage_error(message: &'static str) -> identity::ports::IdentityError {
        identity::ports::IdentityError::Storage(Box::new(std::io::Error::other(message)))
    }

    #[derive(Clone)]
    struct StaticRoleRepo {
        roles: Arc<std::collections::BTreeMap<String, identity::ports::Role>>,
    }

    impl StaticRoleRepo {
        fn new(roles: Vec<identity::ports::Role>) -> Self {
            Self {
                roles: Arc::new(
                    roles
                        .into_iter()
                        .map(|role| (role.id().as_str().to_string(), role))
                        .collect(),
                ),
            }
        }
    }

    impl identity::ports::RoleRepo for StaticRoleRepo {
        async fn find(
            &self,
            _tenant: vocab::TenantId,
            id: identity::ports::RoleId,
        ) -> Result<Option<identity::ports::Role>, identity::ports::IdentityError> {
            Ok(self.roles.get(id.as_str()).cloned())
        }

        async fn save(
            &self,
            _tenant: vocab::TenantId,
            _role: identity::ports::Role,
        ) -> Result<(), identity::ports::IdentityError> {
            Err(identity_storage_error(
                "runtime test role repo is read-only",
            ))
        }

        async fn list(
            &self,
            _tenant: vocab::TenantId,
            _page: identity::ports::RolePage,
        ) -> Result<identity::ports::RoleListResult, identity::ports::IdentityError> {
            Ok(identity::ports::RoleListResult {
                roles: self.roles.values().cloned().collect(),
                has_more: false,
            })
        }
    }

    #[derive(Clone)]
    struct StaticRoleBindings {
        bindings: Arc<Vec<(vocab::TenantId, String, String)>>,
    }

    impl StaticRoleBindings {
        fn new(bindings: Vec<(vocab::TenantId, String, String)>) -> Self {
            Self {
                bindings: Arc::new(bindings),
            }
        }
    }

    impl identity::ports::RoleBindingLifecycle for StaticRoleBindings {
        async fn assign_and_emit(
            &self,
            _binding: identity::ports::RoleBinding,
            _entry: consistency::Entry,
            _envelope: diport::OutboxEnvelopeParts,
        ) -> Result<(), diport::OutboxEmitError> {
            Err(diport::OutboxEmitError::new(std::io::Error::other(
                "runtime test binding lifecycle is read-only",
            )))
        }

        async fn revoke_and_emit(
            &self,
            _tenant: vocab::TenantId,
            _role_id: identity::ports::RoleId,
            _subject: String,
            _entry: consistency::Entry,
            _envelope: diport::OutboxEnvelopeParts,
        ) -> Result<bool, diport::OutboxEmitError> {
            Err(diport::OutboxEmitError::new(std::io::Error::other(
                "runtime test binding lifecycle is read-only",
            )))
        }

        async fn list_for_subject(
            &self,
            tenant: vocab::TenantId,
            subject: String,
        ) -> Result<Vec<identity::ports::RoleBinding>, identity::ports::IdentityError> {
            self.bindings
                .iter()
                .filter(|(binding_tenant, binding_subject, _)| {
                    *binding_tenant == tenant && *binding_subject == subject
                })
                .map(|(_, binding_subject, role_id)| {
                    identity::ports::RoleBinding::hydrate(binding_subject.clone(), role_id, tenant)
                })
                .collect()
        }
    }

    struct EmptyPolicyRepo;

    impl identity::ports::PolicyRepo for EmptyPolicyRepo {
        async fn create(
            &self,
            _tenant: vocab::TenantId,
            _policy: identity::ports::Policy,
        ) -> Result<identity::ports::Policy, identity::ports::IdentityError> {
            Err(identity_storage_error(
                "runtime test policy repo is read-only",
            ))
        }

        async fn update(
            &self,
            _tenant: vocab::TenantId,
            _policy: identity::ports::Policy,
            _expected: identity::ports::PolicyVersion,
        ) -> Result<identity::ports::Policy, identity::ports::IdentityError> {
            Err(identity_storage_error(
                "runtime test policy repo is read-only",
            ))
        }

        async fn delete(
            &self,
            _tenant: vocab::TenantId,
            _id: identity::ports::PolicyId,
            _expected: identity::ports::PolicyVersion,
        ) -> Result<bool, identity::ports::IdentityError> {
            Err(identity_storage_error(
                "runtime test policy repo is read-only",
            ))
        }

        async fn find(
            &self,
            _tenant: vocab::TenantId,
            _id: identity::ports::PolicyId,
        ) -> Result<Option<identity::ports::Policy>, identity::ports::IdentityError> {
            Ok(None)
        }

        async fn list_effective(
            &self,
            _tenant: vocab::TenantId,
            _scope: identity::ports::PolicyRouteScope,
            _at: SystemTime,
        ) -> Result<Vec<identity::ports::Policy>, identity::ports::IdentityError> {
            Ok(Vec::new())
        }
    }

    struct UnusedCredentialRepo;

    impl identity::ports::CredentialRepo for UnusedCredentialRepo {
        async fn find_by_user_id(
            &self,
            _tenant: vocab::TenantId,
            _user_id: ids::UserId,
        ) -> Result<Option<identity::ports::Credential>, identity::ports::IdentityError> {
            Ok(None)
        }

        async fn authenticate(
            &self,
            _tenant: vocab::TenantId,
            _login: identity::ports::LoginIdentifier,
            _candidate: String,
            _now: SystemTime,
        ) -> Result<identity::ports::AuthOutcome, identity::ports::IdentityError> {
            Err(identity_storage_error(
                "runtime test credential repo must not be called",
            ))
        }

        async fn save(
            &self,
            _credential: identity::ports::Credential,
        ) -> Result<(), identity::ports::IdentityError> {
            Err(identity_storage_error(
                "runtime test credential repo is read-only",
            ))
        }

        async fn bump_version(
            &self,
            _expected: u32,
            _next: identity::ports::Credential,
        ) -> Result<(), identity::ports::IdentityError> {
            Err(identity_storage_error(
                "runtime test credential repo is read-only",
            ))
        }

        async fn lockout_status(
            &self,
            _tenant: vocab::TenantId,
            _login: identity::ports::LoginIdentifier,
            _now: SystemTime,
        ) -> Result<bool, identity::ports::IdentityError> {
            Ok(false)
        }
    }

    struct UnusedSessionLifecycle;

    impl identity::ports::SessionLifecycle for UnusedSessionLifecycle {
        async fn persist_session_and_emit(
            &self,
            _session: identity::ports::Session,
            _entry: consistency::Entry,
            _envelope: diport::OutboxEnvelopeParts,
        ) -> Result<(), diport::OutboxEmitError> {
            Err(diport::OutboxEmitError::new(std::io::Error::other(
                "runtime test session lifecycle must not be called",
            )))
        }

        async fn find(
            &self,
            _tenant: vocab::TenantId,
            _session_id: identity::ports::SessionId,
        ) -> Result<Option<identity::ports::Session>, identity::ports::IdentityError> {
            Ok(None)
        }

        async fn revoke(
            &self,
            _tenant: vocab::TenantId,
            _session_id: identity::ports::SessionId,
        ) -> Result<(), identity::ports::IdentityError> {
            Ok(())
        }
    }

    struct UnusedRefreshStore;

    impl identity::ports::RefreshTokenStore for UnusedRefreshStore {
        async fn insert(
            &self,
            _record: identity::ports::RefreshTokenRecord,
        ) -> Result<(), identity::ports::IdentityError> {
            Err(identity_storage_error(
                "runtime test refresh store must not be called",
            ))
        }

        async fn find_by_hash(
            &self,
            _tenant: vocab::TenantId,
            _hash: identity::ports::RefreshTokenHash,
        ) -> Result<Option<identity::ports::RefreshTokenRecord>, identity::ports::IdentityError>
        {
            Ok(None)
        }

        async fn rotate(
            &self,
            _rotation: identity::ports::RefreshRotation,
        ) -> Result<bool, identity::ports::IdentityError> {
            Err(identity_storage_error(
                "runtime test refresh store must not be called",
            ))
        }

        async fn revoke_lineage(
            &self,
            _tenant: vocab::TenantId,
            _lineage_id: identity::ports::RefreshTokenId,
        ) -> Result<(), identity::ports::IdentityError> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct TestSigner;

    impl diport::Signer for TestSigner {
        async fn sign(
            &self,
            _req: diport::SignRequest,
        ) -> Result<diport::Signature, diport::SignerError> {
            Ok(diport::Signature::new(vec![0x5a; 64]))
        }

        async fn shutdown(&self) -> Result<(), diport::SignerError> {
            Ok(())
        }
    }

    struct DelegatingAuditAdminRepo {
        repo: Arc<audit::ports::DynAuditRepo<'static>>,
    }

    impl audit::ports::AuditAdminRepo for DelegatingAuditAdminRepo {
        async fn list_tenant(
            &self,
            tenant: vocab::TenantId,
            page: audit::ports::AuditPage,
        ) -> Result<audit::ports::AuditListResult, audit::ports::AuditError> {
            use audit::ports::AuditRepo as _;

            self.repo.list(tenant, page).await
        }
    }

    #[allow(clippy::expect_used)]
    fn test_identity_domain_with_audit_role(
        tenant: vocab::TenantId,
    ) -> identity::IdentityDomain<TestSigner> {
        let audit_role = identity::ports::Role::hydrate(
            "audit-reader",
            "Audit reader",
            &[vocab::AUDIT_READ_PERMISSION.to_string()],
        )
        .expect("audit role");
        let roles = Arc::from(identity::ports::DynRoleRepo::new_box(StaticRoleRepo::new(
            vec![audit_role],
        )));
        let bindings = Arc::from(identity::ports::DynRoleBindingLifecycle::new_box(
            StaticRoleBindings::new(vec![(
                tenant,
                "11111111-2222-4333-8444-555555555555".to_string(),
                "audit-reader".to_string(),
            )]),
        ));
        let issuer = Arc::new(
            authn::JwtIssuer::new(
                Arc::new(TestSigner),
                Box::new(SystemClock),
                authn::JwtIssuerConfig {
                    key: diport::KeyId::new("runtime-test-key"),
                    alg: authn::JwtAlg::Es256,
                    purpose: diport::SigningPurpose::new("runtime-test"),
                    issuer: "https://issuer.test".to_string(),
                    audience: "rss-test".to_string(),
                    ttl: Duration::from_secs(900),
                },
            )
            .expect("jwt issuer"),
        );
        let refresh = Arc::new(identity::RefreshService::new(
            identity::ports::DynRefreshTokenStore::new_box(UnusedRefreshStore),
            issuer,
            Box::new(SystemClock),
            Duration::from_secs(900),
        ));
        let login = Arc::new(identity::LoginService::new(
            Arc::from(identity::ports::DynCredentialRepo::new_box(
                UnusedCredentialRepo,
            )),
            Arc::from(identity::ports::DynSessionLifecycle::new_box(
                UnusedSessionLifecycle,
            )),
            Arc::clone(&refresh),
            Box::new(SystemClock),
            Duration::from_secs(900),
        ));
        let rbac_admin = Arc::new(identity::RbacAdminService::new(
            Arc::clone(&roles),
            Arc::clone(&bindings),
            Box::new(SystemClock),
        ));
        identity::IdentityDomain::new(
            login,
            refresh,
            rbac_admin,
            roles,
            bindings,
            Arc::from(identity::ports::DynPolicyRepo::new_box(EmptyPolicyRepo)),
            Arc::new(SystemClock),
        )
    }

    #[allow(clippy::expect_used)]
    fn test_audit_repo() -> Arc<audit::ports::DynAuditRepo<'static>> {
        let hasher = audit::ports::AuditChainHasher::new(
            RustCryptoMacVerifier,
            MacKey::from_bytes(vec![0x5a; 32]),
        )
        .expect("audit chain hasher");
        Arc::from(audit::ports::DynAuditRepo::new_box(
            audit::InMemAuditRepo::new(hasher),
        ))
    }

    fn test_audit_admin_repo(
        repo: Arc<audit::ports::DynAuditRepo<'static>>,
    ) -> Arc<audit::ports::DynAuditAdminRepo<'static>> {
        Arc::from(audit::ports::DynAuditAdminRepo::new_box(
            DelegatingAuditAdminRepo { repo },
        ))
    }

    #[allow(clippy::expect_used)]
    async fn append_sensitive_audit_record(
        repo: &Arc<audit::ports::DynAuditRepo<'static>>,
        tenant: vocab::TenantId,
    ) {
        use audit::ports::AuditRepo as _;

        repo.append(audit::ports::AuditRecord {
            tenant,
            actor: ids::UserId::parse("11111111-2222-4333-8444-555555555555").expect("actor"),
            actor_kind: vocab::PrincipalKind::Admin,
            action: vocab::Action::parse("audit:read").expect("action"),
            resource: audit::ports::ResourceRef::new(
                "session",
                "99999999-8888-4777-8666-555555555555",
            ),
            outcome: audit::ports::AuditOutcome::Success,
            recorded_at: SystemTime::UNIX_EPOCH,
        })
        .await
        .expect("append audit record");
    }

    #[allow(clippy::expect_used)]
    fn runtime_test_provider() -> Arc<OidcProvider> {
        use p256::ecdsa::SigningKey;

        let key = SigningKey::from_slice(&[7u8; 32]).expect("signing key");
        Arc::new(
            provider_from_b64(
                "https://issuer.test",
                "rss-test",
                "admin,superAdmin",
                Some(&B64.encode(key.verifying_key().to_encoded_point(false).as_bytes())),
                Some(&B64.encode([9u8; 32])),
                Some("cell-a.svc-a"),
                Box::new(SystemClock),
            )
            .expect("provider"),
        )
    }

    #[allow(clippy::expect_used)]
    fn runtime_test_jwt(kind: &str, tenant: Option<vocab::TenantId>) -> String {
        use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};

        let key = SigningKey::from_slice(&[7u8; 32]).expect("signing key");
        let header = B64.encode(br#"{"alg":"ES256"}"#);
        let tenant_claim = tenant
            .map(|tenant| format!(r#","tenant_id":"{tenant}""#))
            .unwrap_or_default();
        let payload = format!(
            r#"{{"sub":"11111111-2222-4333-8444-555555555555","exp":4102444800,"iss":"https://issuer.test","aud":"rss-test","kind":"{kind}"{tenant_claim}}}"#
        );
        let body = B64.encode(payload.as_bytes());
        let signing_input = format!("{header}.{body}");
        let sig: Signature = key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", B64.encode(sig.to_bytes()))
    }

    fn extract_admin_router(assembled: Vec<AssembledListener>) -> anyhow::Result<axum::Router> {
        assembled
            .into_iter()
            .find_map(|assembled| {
                let (listener, routes) = assembled.into_parts();
                (listener == ListenerKind::Admin).then(|| routes.into_router_for_test())
            })
            .context("admin router")
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn assembled_admin_audit_read_uses_identity_authorizer_and_masks_sensitive_fields()
    -> anyhow::Result<()> {
        use tower::ServiceExt as _;

        let tenant =
            vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant");
        let audit_repo = test_audit_repo();
        append_sensitive_audit_record(&audit_repo, tenant).await;
        let identity_domain = test_identity_domain_with_audit_role(tenant);
        let audit_domain = audit::AuditDomain::new(
            Arc::clone(&audit_repo),
            Some(test_audit_admin_repo(Arc::clone(&audit_repo))),
            TracingAuthAuditSink,
            Arc::new(SystemClock),
        );
        let domains: [&dyn bootstrap::Domain; 2] = [&identity_domain, &audit_domain];
        let mut registry = bootstrap::compose(&domains)?;
        let app = extract_admin_router(assemble_authed_routers(
            &mut registry,
            runtime_test_provider(),
            httpserve::AuditSinkHandle::new(TracingAuthAuditSink),
            Arc::new(SystemClock),
            identity_domain.primary_authorizer(),
        )?)?;

        let scoped_response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::GET)
                    .uri(generated::http::audit_v1::SPEC.path)
                    .header(
                        axum::http::header::AUTHORIZATION,
                        format!("Bearer {}", runtime_test_jwt("admin", Some(tenant))),
                    )
                    .body(axum::body::Body::empty())?,
            )
            .await?;
        assert_eq!(scoped_response.status(), axum::http::StatusCode::OK);
        let scoped_body = axum::body::to_bytes(scoped_response.into_body(), usize::MAX).await?;
        let scoped_json: serde_json::Value = serde_json::from_slice(&scoped_body)?;
        assert_eq!(scoped_json["data"][0]["actor"], "<redacted>");
        assert_eq!(scoped_json["data"][0]["resourceId"], "<redacted>");

        let target_response = app
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::GET)
                    .uri(format!(
                        "{}?tenantId={tenant}",
                        generated::http::audit_v1::SPEC.path
                    ))
                    .header(
                        axum::http::header::AUTHORIZATION,
                        format!("Bearer {}", runtime_test_jwt("superAdmin", None)),
                    )
                    .body(axum::body::Body::empty())?,
            )
            .await?;
        assert_eq!(target_response.status(), axum::http::StatusCode::OK);
        let target_body = axum::body::to_bytes(target_response.into_body(), usize::MAX).await?;
        let target_json: serde_json::Value = serde_json::from_slice(&target_body)?;
        assert_eq!(target_json["data"][0]["actor"], "<redacted>");
        assert_eq!(target_json["data"][0]["resourceId"], "<redacted>");
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn finalize_listener_routes_injects_primary_authorizer_into_admin_listener() {
        use axum::extract::Extension;
        use axum::response::IntoResponse as _;
        use tower::ServiceExt as _;

        let admin =
            httpserve::UnfinalizedRoutes::empty()
                .nest_group::<httpserve::Admin, anyhow::Error>("/admin", |rb| {
                    Ok(rb.mount(
                        httpserve::Route {
                            method: Method::GET,
                            path: "/probe",
                            contract_id: generated::http::audit_v1::SPEC.contract_id,
                        },
                        axum::routing::get(
                            |Extension(authorizer): Extension<
                                Arc<dyn httpserve::RouteAuthorizer>,
                            >| async move {
                                match authorizer
                                    .authorize(httpserve::RouteAuthorizationRequest {
                                        contract_id: generated::http::audit_v1::SPEC.contract_id,
                                        permission: vocab::AUDIT_READ_PERMISSION,
                                        tenant_id: Some(
                                            vocab::TenantId::parse(
                                                "00000000-0000-4000-8000-000000000001",
                                            )
                                            .expect("tenant"),
                                        ),
                                        principal_kind: vocab::PrincipalKind::Admin,
                                        principal_id: "admin-subject".to_string(),
                                        resource: None,
                                    })
                                    .await
                                {
                                    httpserve::RouteAuthorizationDecision::Allow
                                    | httpserve::RouteAuthorizationDecision::AllowWithProjection(
                                        _,
                                    ) => axum::http::StatusCode::NO_CONTENT.into_response(),
                                    httpserve::RouteAuthorizationDecision::Deny => {
                                        axum::http::StatusCode::FORBIDDEN.into_response()
                                    }
                                }
                            },
                        ),
                    ))
                })
                .expect("admin route");
        let plan = AuthPlan::new(ListenerKind::Admin, AuthScheme::Jwt).expect("admin jwt plan");
        let routes = finalize_listener_auth(
            ListenerKind::Admin,
            admin,
            plan,
            httpserve::AuditSinkHandle::new(TracingAuthAuditSink),
            Arc::new(SystemClock),
            allow_authorizer(),
            AuthScheme::Jwt,
        )
        .expect("finalize admin listener")
        .layer(axum::middleware::from_fn(
            |mut req: axum::extract::Request, next: axum::middleware::Next| async move {
                req.extensions_mut().insert(httpserve::Authenticated::new(
                    primitives::RequiredScheme::Jwt,
                    vocab::PrincipalKind::Admin,
                    "admin-subject",
                    Some(
                        vocab::TenantId::parse("00000000-0000-4000-8000-000000000001")
                            .expect("tenant"),
                    ),
                ));
                next.run(req).await
            },
        ));

        let response = routes
            .into_router_for_test()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/admin/probe")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("oneshot");

        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
    }

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_string()).collect()
    }

    #[test]
    fn settings_config_value_maintenance_args_default_to_both() -> anyhow::Result<()> {
        let parsed = parse_settings_config_value_maintenance_args(&args(&[
            "settings-config-values",
            "maintenance",
            "--operator-service-token",
            "opaque-token",
            "--operator-tenant",
            "00000000-0000-4000-8000-000000000001",
        ]))?;
        assert_eq!(parsed.operator_service_token, "opaque-token");
        assert_eq!(
            parsed.operator_tenant,
            vocab::TenantId::parse("00000000-0000-4000-8000-000000000001")?
        );
        assert_eq!(parsed.options.batch_size(), 500);
        assert_eq!(parsed.options.max_rows(), None);
        assert!(!parsed.options.dry_run());
        Ok(())
    }

    #[test]
    fn settings_config_value_maintenance_args_parse_flags() -> anyhow::Result<()> {
        let parsed = parse_settings_config_value_maintenance_args(&args(&[
            "settings-config-values",
            "maintenance",
            "--operator-service-token",
            "opaque-token",
            "--operator-tenant",
            "00000000-0000-4000-8000-000000000001",
            "--operation",
            "backfill",
            "--tenant",
            "00000000-0000-4000-8000-000000000001",
            "--batch-size",
            "7",
            "--max-rows",
            "9",
            "--dry-run",
        ]))?;
        assert_eq!(parsed.operator_service_token, "opaque-token");
        assert_eq!(parsed.options.batch_size(), 7);
        assert_eq!(parsed.options.max_rows(), Some(9));
        assert!(parsed.options.tenant_opt().is_some());
        assert!(parsed.options.dry_run());
        Ok(())
    }

    #[test]
    fn settings_config_value_maintenance_args_fail_closed() {
        assert!(
            parse_settings_config_value_maintenance_args(&args(&[
                "settings-config-values",
                "maintenance",
                "--operator-service-token",
                "opaque-token",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--bogus",
            ]))
            .is_err()
        );
        assert!(
            parse_settings_config_value_maintenance_args(&args(&[
                "settings-config-values",
                "maintenance",
                "--operator-service-token",
                "opaque-token",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--operation",
                "decrypt",
            ]))
            .is_err()
        );
        assert!(
            parse_settings_config_value_maintenance_args(&args(&[
                "settings-config-values",
                "maintenance",
                "--operator-service-token",
                "opaque-token",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
                "--batch-size",
                "0",
            ]))
            .is_err()
        );
        assert!(
            parse_settings_config_value_maintenance_args(&args(&[
                "settings-config-values",
                "maintenance",
            ]))
            .is_err()
        );
        assert!(
            parse_settings_config_value_maintenance_args(&args(&[
                "settings-config-values",
                "maintenance",
                "--operator-service-token",
                "",
                "--operator-tenant",
                "00000000-0000-4000-8000-000000000001",
            ]))
            .is_err()
        );
        assert!(
            parse_settings_config_value_maintenance_args(&args(&[
                "settings-config-values",
                "maintenance",
                "--operator-service-token",
                "opaque-token",
            ]))
            .is_err()
        );
        assert!(
            parse_settings_config_value_maintenance_args(&args(&[
                "settings-config-values",
                "maintenance",
                "--operator-subject",
                "ops@example.com",
            ]))
            .is_err()
        );
    }

    struct StubPdp {
        result: Result<diport::VerifiedClaims, diport::PdpError>,
    }

    impl diport::Pdp for StubPdp {
        async fn verify(
            &self,
            _raw: &diport::RawCredential,
        ) -> Result<diport::VerifiedClaims, diport::PdpError> {
            self.result.clone()
        }
    }

    fn stub_pdp(
        result: Result<diport::VerifiedClaims, diport::PdpError>,
    ) -> Box<diport::DynPdp<'static>> {
        diport::DynPdp::new_box(StubPdp { result })
    }

    #[tokio::test]
    async fn settings_config_value_maintenance_operator_subject_comes_from_verified_service_token()
    -> anyhow::Result<()> {
        let pdp = stub_pdp(Ok(diport::VerifiedClaims::new(
            "verified-operator",
            None,
            Some("ignored".to_owned()),
        )));
        let subject = verified_config_value_maintenance_operator_subject(
            "opaque-token",
            vocab::TenantId::parse("00000000-0000-4000-8000-000000000001")?,
            &pdp,
        )
        .await?;

        assert_eq!(subject, "verified-operator");
        Ok(())
    }

    #[tokio::test]
    async fn settings_config_value_maintenance_operator_token_failure_is_fail_closed()
    -> anyhow::Result<()> {
        let pdp = stub_pdp(Err(diport::PdpError::InvalidSignature));
        let result = verified_config_value_maintenance_operator_subject(
            "opaque-token",
            vocab::TenantId::parse("00000000-0000-4000-8000-000000000001")?,
            &pdp,
        )
        .await;

        assert!(result.is_err());
        Ok(())
    }

    /// settings 域产物：`configs_ready` + `keyprovider_ready` 两条探针、resources / workers 空。
    ///
    /// 直测 [`settings_module_result`]（脱离 vault env / 真实 pg），覆盖 `wire_settings` 的探针 emission
    /// 契约——该路径在 integration Ok 分支（需 vault+pg）外不可达，故抽出后单测以满足新增覆盖。
    #[test]
    #[allow(clippy::expect_used)]
    fn settings_module_result_emits_single_configs_ready_probe() {
        let readiness = Arc::new(PgDbReadiness::new());
        let keyprovider_ready = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let result = settings_module_result(readiness, keyprovider_ready)
            .expect("settings_module_result ok");
        assert_eq!(
            result.probes.len(),
            2,
            "settings 暴露 configs_ready + keyprovider_ready"
        );
        assert_eq!(result.probes[0].0.as_str(), CONFIGS_READY_PROBE_NAME);
        assert_eq!(result.probes[1].0.as_str(), KEYPROVIDER_READY_PROBE_NAME);
        assert!(result.resources.is_empty(), "settings 今无 detached 资源");
        assert!(
            result.workers.is_empty(),
            "纯 module result helper 不创建后台 worker"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn session_sweeper_interval_defaults_and_parses_env() {
        let default = build_session_sweeper_interval_from(|_| None);
        assert_eq!(default, DEFAULT_SESSION_SWEEP_INTERVAL);

        let parsed = build_session_sweeper_interval_from(|name| {
            (name == SESSION_SWEEP_INTERVAL_ENV).then(|| "120000".to_string())
        });
        assert_eq!(parsed, Duration::from_millis(120_000));

        let invalid = build_session_sweeper_interval_from(|name| {
            (name == SESSION_SWEEP_INTERVAL_ENV).then(|| "not-a-number".to_string())
        });
        assert_eq!(invalid, DEFAULT_SESSION_SWEEP_INTERVAL);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn identity_maintenance_module_emits_session_sweeper_probe_and_worker() {
        struct NoopResource;
        impl diport::ManagedResource for NoopResource {
            fn name(&self) -> &str {
                "noop-session-sweeper"
            }

            async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
                Ok(())
            }
        }

        let health = Arc::new(SessionSweeperHealth::healthy());
        let worker: bootstrap::WorkerSpec =
            Box::new(|_| diport::DynManagedResource::new_box(NoopResource));
        let result =
            session_sweeper_module_result(worker, health).expect("session sweeper module result");
        assert_eq!(result.probes.len(), 1);
        assert_eq!(result.probes[0].0.as_str(), SESSION_SWEEPER_PROBE_NAME);
        assert!(result.resources.is_empty());
        assert_eq!(
            result.workers.len(),
            1,
            "session sweeper must be registered as a managed worker"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: 静态回归守卫切分当前源码；缺目标函数时测试应硬失败。
    fn session_sweeper_worker_cancellation_races_inflight_sweep() {
        let source = include_str!("lib.rs");
        let function = source
            .split("fn spawn_session_sweeper(")
            .nth(1)
            .and_then(|rest| rest.split("fn session_sweeper_module_result(").next())
            .expect("spawn_session_sweeper source slice");
        assert!(
            function.contains("deleted = sweeper.sweep_expired()")
                && function.contains("() = worker_token.cancelled() => break"),
            "session sweeper worker must race cancellation against an in-flight sweep"
        );
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

    /// RedisReadyProbe：`true → Healthy("ready")` / `false → Unhealthy("down")`（fail-closed）。
    #[test]
    fn redis_ready_probe_maps_flag_to_health() {
        use bootstrap::HealthProbe;
        use std::sync::atomic::{AtomicBool, Ordering};

        let flag = Arc::new(AtomicBool::new(true));
        let probe = RedisReadyProbe::new(Arc::clone(&flag));
        let ready = probe.check();
        assert_eq!(ready.status(), HealthStatus::Healthy);
        assert_eq!(ready.detail(), "ready");
        assert_eq!(ready.name().as_str(), REDIS_READY_PROBE_NAME);

        flag.store(false, Ordering::Release);
        let down = probe.check();
        assert_eq!(down.status(), HealthStatus::Unhealthy);
        assert_eq!(down.detail(), "down");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn runtime_replay_guard_expires_seen_nonce() {
        let guard = RuntimeServiceTokenReplayGuard::default();
        let expired = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        let future = SystemTime::UNIX_EPOCH + Duration::from_secs(4_102_444_800);
        guard
            .check_and_record("nonce-a", expired)
            .expect("first record");
        guard
            .check_and_record("nonce-a", future)
            .expect("expired nonce pruned before second record");
        assert!(matches!(
            guard.check_and_record("nonce-a", future),
            Err(diport::ServiceTokenReplayError::Replayed)
        ));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn mtls_source_health_probe_is_unhealthy_before_bind() {
        use bootstrap::HealthProbe;

        let slot = Arc::new(MtlsHealthSlot::new());
        let probe = MtlsSourceHealthProbe::new(
            mtls_probe_name(ListenerKind::Internal).expect("probe name"),
            slot,
        );
        let check = probe.check();
        assert_eq!(check.status(), HealthStatus::Unhealthy);
        assert_eq!(check.detail(), "not-bound");
        assert_eq!(check.name().as_str(), MTLS_SOURCE_READY_PROBE_NAME);
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

    #[allow(clippy::panic)]
    #[test]
    fn pg_migrator_config_requires_dedicated_credentials() {
        let result = build_pg_migrator_config_from(|name| match name {
            "RSS_PG_HOST" => Some("postgres".to_string()),
            "RSS_PG_PORT" => Some("5432".to_string()),
            "RSS_PG_DATABASE" => Some("rss".to_string()),
            "RSS_PG_USERNAME" => Some("rss_app".to_string()),
            "RSS_PG_PASSWORD" => Some("app_pw".to_string()),
            _ => None,
        });
        match result {
            Ok(_) => panic!("missing migrator username should fail"),
            Err(err) => assert!(err.to_string().contains("RSS_PG_MIGRATOR_USERNAME")),
        }
    }

    #[allow(clippy::panic)]
    #[test]
    fn pg_migrator_config_uses_dedicated_credentials() {
        let cfg = match build_pg_migrator_config_from(|name| match name {
            "RSS_PG_HOST" => Some("postgres".to_string()),
            "RSS_PG_PORT" => Some("5432".to_string()),
            "RSS_PG_DATABASE" => Some("rss".to_string()),
            "RSS_PG_USERNAME" => Some("rss_app".to_string()),
            "RSS_PG_PASSWORD" => Some("app_pw".to_string()),
            "RSS_PG_MIGRATOR_USERNAME" => Some("postgres".to_string()),
            "RSS_PG_MIGRATOR_PASSWORD" => Some("owner_pw".to_string()),
            "RSS_PG_SSL_MODE" => Some("disable".to_string()),
            _ => None,
        }) {
            Ok(cfg) => cfg,
            Err(err) => panic!("migrator config: {err}"),
        };
        let debug = format!("{cfg:?}");
        assert!(debug.contains("postgres"));
        assert!(!debug.contains("rss_app"));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn auth_scheme_per_listener() {
        assert_eq!(
            auth_scheme_from(ListenerKind::Primary, |_| None).unwrap(),
            AuthScheme::Jwt
        );
        assert_eq!(
            auth_scheme_from(ListenerKind::Admin, |_| None).unwrap(),
            AuthScheme::Jwt
        );
        assert_eq!(
            auth_scheme_from(ListenerKind::Internal, |_| None).unwrap(),
            AuthScheme::Mtls
        );
        assert_eq!(
            auth_scheme_from(ListenerKind::Health, |_| None).unwrap(),
            AuthScheme::NoAuth
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn internal_service_token_requires_explicit_transition_flag() {
        let scheme = auth_scheme_from(ListenerKind::Internal, |name| {
            (name == INTERNAL_AUTH_SCHEME_ENV)
                .then(|| INTERNAL_AUTH_SCHEME_SERVICE_TOKEN.to_string())
        })
        .expect("explicit service-token transition is accepted");
        assert_eq!(scheme, AuthScheme::ServiceToken);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn internal_auth_scheme_rejects_unknown_value() {
        let err = auth_scheme_from(ListenerKind::Internal, |name| {
            (name == INTERNAL_AUTH_SCHEME_ENV).then(|| "mtls-or-token".to_string())
        })
        .expect_err("unknown internal auth scheme must fail-fast");
        assert!(
            err.to_string().contains(INTERNAL_AUTH_SCHEME_ENV),
            "error should name env var: {err}"
        );
    }

    #[test]
    fn required_scheme_maps_and_health_is_none() {
        assert_eq!(
            required_scheme_for_auth_scheme(AuthScheme::Jwt),
            Some(RequiredScheme::Jwt)
        );
        assert_eq!(
            required_scheme_for_auth_scheme(AuthScheme::Mtls),
            Some(RequiredScheme::Mtls)
        );
        assert_eq!(
            required_scheme_for_auth_scheme(AuthScheme::ServiceToken),
            Some(RequiredScheme::ServiceToken)
        );
        assert_eq!(required_scheme_for_auth_scheme(AuthScheme::NoAuth), None);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn mtls_allow_set_from_csv_rejects_empty_and_wildcard() {
        let err = mtls_allow_set_from_csv("spiffe://example.org/ns/rss/sa/internal,")
            .expect_err("trailing comma must not be ignored");
        assert!(
            err.to_string().contains(INTERNAL_MTLS_SPIFFE_ALLOW_SET_ENV),
            "error should name env var: {err}"
        );

        let err = mtls_allow_set_from_csv("spiffe://example.org/ns/rss/sa/*")
            .expect_err("wildcard spiffe ids must fail");
        assert!(
            err.to_string().contains(INTERNAL_MTLS_SPIFFE_ALLOW_SET_ENV),
            "error should name env var: {err}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn mtls_allow_set_from_env_requires_config_for_internal_mtls() {
        let err = mtls_allow_set_from_env(ListenerKind::Internal, |_| None)
            .expect_err("mTLS allow-set must be configured");
        assert!(
            err.to_string().contains(INTERNAL_MTLS_SPIFFE_ALLOW_SET_ENV),
            "error should name env var: {err}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn domain_transport_required_domains_must_be_non_empty() {
        let err = build_domain_transport_targets_from(bootstrap::Topology::DurableShared, |_| None)
            .expect_err("missing required domains must fail");
        assert!(
            err.to_string()
                .contains(DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV),
            "error should name env var: {err}"
        );

        let err = build_domain_transport_targets_from(bootstrap::Topology::DurableShared, |name| {
            (name == DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV).then(String::new)
        })
        .expect_err("empty required domain entry must fail");
        assert!(
            err.to_string()
                .contains(DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV),
            "error should name env var: {err}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn domain_transport_per_domain_allow_set_is_required() {
        let err = build_domain_transport_targets_from(bootstrap::Topology::DurableShared, |name| {
            match name {
                DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV => Some("identity".to_string()),
                "RSS_IDENTITY_DOMAIN_TRANSPORT_URL" => {
                    Some("https://identity.internal/rpc".to_string())
                }
                DOMAIN_TRANSPORT_LOCAL_SPIFFE_ID_ENV => {
                    Some("spiffe://example.org/ns/rss/sa/runtime".to_string())
                }
                _ => None,
            }
        })
        .expect_err("remote target requires exact server SPIFFE allow-set");
        assert!(
            err.to_string()
                .contains("RSS_IDENTITY_DOMAIN_TRANSPORT_MTLS_SPIFFE_ALLOW_SET"),
            "error should name per-domain allow-set env: {err}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn domain_transport_isolated_topology_forbids_shared_fallback() {
        let err =
            build_domain_transport_targets_from(bootstrap::Topology::DurableIsolated, |name| {
                match name {
                    DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV => Some("identity".to_string()),
                    DOMAIN_TRANSPORT_SHARED_URL_ENV => {
                        Some("https://gateway.internal/rpc".to_string())
                    }
                    _ => None,
                }
            })
            .expect_err("isolated topology must not use shared domain transport fallback");
        assert!(
            format!("{err:#}").contains(DOMAIN_TRANSPORT_SHARED_URL_ENV),
            "error should name shared fallback env: {err}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn domain_transport_targets_build_typed_outbound_mtls_policy() {
        let targets =
            build_domain_transport_targets_from(bootstrap::Topology::DurableShared, |name| {
                match name {
                    DOMAIN_TRANSPORT_REQUIRED_DOMAINS_ENV => Some("identity".to_string()),
                    DOMAIN_TRANSPORT_SHARED_URL_ENV => {
                        Some("https://gateway.internal/rpc".to_string())
                    }
                    DOMAIN_TRANSPORT_LOCAL_SPIFFE_ID_ENV => {
                        Some("spiffe://example.org/ns/rss/sa/runtime".to_string())
                    }
                    "RSS_IDENTITY_DOMAIN_TRANSPORT_MTLS_SPIFFE_ALLOW_SET" => {
                        Some("spiffe://example.org/ns/rss/sa/identity".to_string())
                    }
                    _ => None,
                }
            })
            .expect("valid domain transport target config");
        assert_eq!(targets.len(), 1);
    }

    #[derive(Clone)]
    struct NoopRuntimeDomainTransport {
        ready: Arc<std::sync::atomic::AtomicBool>,
    }

    impl distributed::DomainTransport for NoopRuntimeDomainTransport {
        fn dispatch(
            &self,
            _request: distributed::DomainRequest,
        ) -> Pin<
            Box<
                dyn Future<
                        Output = Result<
                            distributed::DomainResponse,
                            distributed::DomainTransportError,
                        >,
                    > + Send
                    + '_,
            >,
        > {
            Box::pin(async {
                Ok(distributed::DomainResponse::new(
                    204,
                    Vec::new(),
                    Vec::new(),
                ))
            })
        }
    }

    impl ManagedResource for NoopRuntimeDomainTransport {
        fn name(&self) -> &str {
            "domain-http-transport"
        }

        async fn shutdown(&self) -> Result<(), ShutdownError> {
            Ok(())
        }
    }

    impl RuntimeDomainTransport for NoopRuntimeDomainTransport {
        fn readiness(&self) -> httpd::DomainHttpReadiness {
            if self.ready.load(std::sync::atomic::Ordering::Acquire) {
                httpd::DomainHttpReadiness::Ready
            } else {
                httpd::DomainHttpReadiness::MtlsSourceUnavailable
            }
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn domain_transport_runtime_exports_dispatch_resource_and_readyz() {
        let ready = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let runtime = DomainTransportRuntime::new(NoopRuntimeDomainTransport {
            ready: Arc::clone(&ready),
        });
        let _dispatch = runtime.dispatch_handle();
        let module = runtime
            .module_result()
            .expect("domain transport module result");

        assert_eq!(module.resources.len(), 1);
        assert_eq!(module.resources[0].name(), "domain-http-transport");
        assert_eq!(module.probes.len(), 1);
        let healthy = module.probes[0].1.check();
        assert_eq!(healthy.name().as_str(), DOMAIN_TRANSPORT_READY_PROBE_NAME);
        assert_eq!(healthy.status(), HealthStatus::Healthy);
        assert_eq!(healthy.detail(), "ready");

        ready.store(false, std::sync::atomic::Ordering::Release);
        let unhealthy = module.probes[0].1.check();
        assert_eq!(unhealthy.status(), HealthStatus::Unhealthy);
        assert_eq!(unhealthy.detail(), "mtls-source-unavailable");
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

    #[tokio::test]
    async fn build_redis_runtime_deps_missing_url_fails_fast() {
        let result = build_redis_runtime_deps(|_| None).await;
        assert!(
            matches!(&result, Err(e) if format!("{e:#}").contains("RSS_REDIS_URL")),
            "缺 redis url env 须 fail-fast 且错误含变量名"
        );
    }

    #[tokio::test]
    async fn build_redis_runtime_deps_rejects_plaintext_by_default() {
        let result = build_redis_runtime_deps(|name| {
            (name == "RSS_REDIS_URL").then(|| "redis://127.0.0.1:6379/0".to_string())
        })
        .await;
        let err = result.err().map(|e| format!("{e:#}")).unwrap_or_default();
        assert!(err.contains("RSS_REDIS_URL"), "{err}");
        assert!(err.contains("rediss://"), "{err}");
    }

    #[tokio::test]
    async fn build_redis_runtime_deps_rejects_non_loopback_plaintext_even_with_opt_in() {
        let result = build_redis_runtime_deps(|name| match name {
            "RSS_REDIS_URL" => Some("redis://cache.internal:6379/0".to_string()),
            REDIS_ALLOW_PLAINTEXT_ENV => Some("true".to_string()),
            _ => None,
        })
        .await;
        let err = result.err().map(|e| format!("{e:#}")).unwrap_or_default();
        assert!(err.contains("loopback"), "{err}");
    }

    #[tokio::test]
    async fn build_redis_runtime_deps_rejects_invalid_plaintext_opt_in() {
        let result = build_redis_runtime_deps(|name| match name {
            "RSS_REDIS_URL" => Some("rediss://cache.internal:6379/0".to_string()),
            REDIS_ALLOW_PLAINTEXT_ENV => Some("enabled".to_string()),
            _ => None,
        })
        .await;
        let err = result.err().map(|e| format!("{e:#}")).unwrap_or_default();
        assert!(err.contains(REDIS_ALLOW_PLAINTEXT_ENV), "{err}");
    }

    #[test]
    fn plaintext_endpoint_policy_accepts_dev_container_explicitly() {
        let policy = plaintext_endpoint_policy_from(
            |name| (name == REDIS_ALLOW_PLAINTEXT_ENV).then(|| "dev-container".to_string()),
            REDIS_ALLOW_PLAINTEXT_ENV,
        );
        assert!(
            matches!(policy, Ok(PlaintextEndpointPolicy::AllowDevContainer)),
            "dev-container 是 demo compose 明文策略的唯一非 loopback opt-in"
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

        let result = build_redis_runtime_deps(|name| match name {
            "RSS_REDIS_URL" => Some(format!("redis://{addr}")),
            REDIS_ALLOW_PLAINTEXT_ENV => Some("true".to_string()),
            _ => None,
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
        let deps = build_redis_runtime_deps(|name| match name {
            "RSS_REDIS_URL" => Some(url.clone()),
            REDIS_ALLOW_PLAINTEXT_ENV => Some("true".to_string()),
            _ => None,
        })
        .await;
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
                Some("cell-a.svc-a"),
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
            allow_authorizer(),
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
            "RSS_PG_USERNAME" => Some("rss_app".to_string()),
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
        assert!(debug.contains("rss_app"), "serving user 示例为 rss_app");
        assert!(!debug.contains("s3cr3t"), "password 不在 debug 输出中");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_audit_admin_config_absent_is_none() {
        let cfg = build_pg_audit_admin_config_from(full_pg_get).expect("optional admin config");
        assert!(cfg.is_none());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_audit_admin_config_requires_pair() {
        let missing_password = build_pg_audit_admin_config_from(|k| match k {
            "RSS_PG_AUDIT_ADMIN_USERNAME" => Some("rss_audit_admin".to_string()),
            _ => full_pg_get(k),
        })
        .expect_err("missing password must fail");
        assert!(
            missing_password
                .to_string()
                .contains("RSS_PG_AUDIT_ADMIN_PASSWORD")
        );

        let missing_username = build_pg_audit_admin_config_from(|k| match k {
            "RSS_PG_AUDIT_ADMIN_PASSWORD" => Some("admin_pw".to_string()),
            _ => full_pg_get(k),
        })
        .expect_err("missing username must fail");
        assert!(
            missing_username
                .to_string()
                .contains("RSS_PG_AUDIT_ADMIN_USERNAME")
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_audit_admin_config_happy() {
        let cfg = build_pg_audit_admin_config_from(|k| match k {
            "RSS_PG_AUDIT_ADMIN_USERNAME" => Some("rss_audit_admin".to_string()),
            "RSS_PG_AUDIT_ADMIN_PASSWORD" => Some("admin_pw".to_string()),
            _ => full_pg_get(k),
        })
        .expect("admin config ok")
        .expect("configured");
        let debug = format!("{cfg:?}");
        assert!(debug.contains("rss_audit_admin"));
        assert!(!debug.contains("admin_pw"));
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

    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_applies_ssl_root_cert_path() {
        let ca = write_temp_file("pg-root-ca.pem", b"test ca");
        let cfg = build_pg_config_from(|name| {
            if name == PG_SSL_ROOT_CERT_PATH_ENV {
                Some(ca.display().to_string())
            } else {
                full_pg_get(name)
            }
        })
        .expect("valid pg config with root cert");
        let debug = format!("{cfg:?}");
        assert!(
            debug.contains("pg-root-ca.pem"),
            "root cert path must be captured in PgConfig: {debug}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_migrator_config_applies_ssl_root_cert_path() {
        let ca = write_temp_file("pg-migrator-root-ca.pem", b"test ca");
        let cfg = build_pg_migrator_config_from(|name| match name {
            "RSS_PG_MIGRATOR_USERNAME" => Some("rss_migrator".to_string()),
            "RSS_PG_MIGRATOR_PASSWORD" => Some("migrator-secret".to_string()),
            PG_SSL_ROOT_CERT_PATH_ENV => Some(ca.display().to_string()),
            _ => full_pg_get(name),
        })
        .expect("valid pg migrator config with root cert");
        let debug = format!("{cfg:?}");
        assert!(
            debug.contains("pg-migrator-root-ca.pem"),
            "root cert path must be shared by serving and migrator configs: {debug}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_rejects_empty_ssl_root_cert_path() {
        let err = build_pg_config_from(|name| {
            if name == PG_SSL_ROOT_CERT_PATH_ENV {
                Some("  ".to_string())
            } else {
                full_pg_get(name)
            }
        })
        .expect_err("empty root cert path is explicit misconfiguration");
        assert!(
            format!("{err:#}").contains(PG_SSL_ROOT_CERT_PATH_ENV),
            "error must identify env var: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_rejects_missing_ssl_root_cert_path() {
        let missing = unique_temp_path("missing-pg-root-ca.pem");
        let err = build_pg_config_from(|name| {
            if name == PG_SSL_ROOT_CERT_PATH_ENV {
                Some(missing.display().to_string())
            } else {
                full_pg_get(name)
            }
        })
        .expect_err("missing root cert path must fail before connect");
        assert!(
            format!("{err:#}").contains(PG_SSL_ROOT_CERT_PATH_ENV),
            "error must identify env var: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_rejects_non_file_ssl_root_cert_path() {
        let dir = create_temp_dir("pg-root-ca-dir");
        let err = build_pg_config_from(|name| {
            if name == PG_SSL_ROOT_CERT_PATH_ENV {
                Some(dir.display().to_string())
            } else {
                full_pg_get(name)
            }
        })
        .expect_err("directory root cert path must fail before connect");
        assert!(
            format!("{err:#}").contains(PG_SSL_ROOT_CERT_PATH_ENV),
            "error must identify env var: {err:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)]
    fn build_pg_config_rejects_unreadable_ssl_root_cert_path() {
        use std::os::unix::fs::PermissionsExt;

        let unreadable = write_unreadable_temp_file("unreadable-pg-root-ca.pem", b"test ca");
        let err = build_pg_config_from(|name| {
            if name == PG_SSL_ROOT_CERT_PATH_ENV {
                Some(unreadable.display().to_string())
            } else {
                full_pg_get(name)
            }
        })
        .expect_err("unreadable root cert path must fail before connect");
        let mut permissions = std::fs::metadata(&unreadable)
            .expect("metadata unreadable temp file")
            .permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&unreadable, permissions).expect("restore temp file permissions");
        assert!(
            format!("{err:#}").contains(PG_SSL_ROOT_CERT_PATH_ENV),
            "error must identify env var: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn legacy_config_plaintext_policy_defaults_to_deny() {
        let policy = legacy_config_plaintext_policy_from(|_| None).expect("policy");
        assert_eq!(policy, LegacyConfigPlaintextPolicy::Deny);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn legacy_config_plaintext_policy_allows_explicit_temporary_values() {
        for raw in ["true", "1", "yes", " TRUE "] {
            let policy = legacy_config_plaintext_policy_from(|n| {
                (n == SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES_ENV).then(|| raw.to_string())
            })
            .expect("policy");
            assert_eq!(
                policy,
                LegacyConfigPlaintextPolicy::AllowTemporary,
                "{SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES_ENV}={raw:?}"
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn legacy_config_plaintext_policy_denies_explicit_false_values() {
        for raw in ["false", "0", "no", " FALSE "] {
            let policy = legacy_config_plaintext_policy_from(|n| {
                (n == SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES_ENV).then(|| raw.to_string())
            })
            .expect("policy");
            assert_eq!(
                policy,
                LegacyConfigPlaintextPolicy::Deny,
                "{SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES_ENV}={raw:?}"
            );
        }
    }

    #[test]
    fn legacy_config_plaintext_policy_rejects_invalid_value() {
        let result = legacy_config_plaintext_policy_from(|n| {
            (n == SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES_ENV).then(|| "enabled".to_string())
        });
        let err = result.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            err.contains(SETTINGS_ALLOW_LEGACY_PLAINTEXT_CONFIG_VALUES_ENV),
            "error must identify env var: {err}"
        );
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

    #[test]
    fn build_redis_readiness_interval_uses_redis_env_not_pg_env() {
        let d = build_redis_readiness_interval_from(|n| match n {
            "RSS_PG_READINESS_SAMPLE_INTERVAL_SECS" => Some("300".to_string()),
            "RSS_REDIS_READINESS_SAMPLE_INTERVAL_SECS" => Some("7".to_string()),
            _ => None,
        });
        assert_eq!(d, Duration::from_secs(7));
    }

    #[test]
    fn build_redis_readiness_interval_rejects_pg_sized_upper_bound() {
        let d = build_redis_readiness_interval_from(|n| {
            (n == "RSS_REDIS_READINESS_SAMPLE_INTERVAL_SECS").then(|| "300".to_string())
        });
        assert_eq!(d, DEFAULT_REDIS_READINESS_INTERVAL);
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
        let addr = listener_addr_from(ListenerKind::Primary, |name| match name {
            "RSS_PRIMARY_LISTEN_ADDR" => Some("0.0.0.0:8080".to_string()),
            LISTENER_ALLOW_PLAINTEXT_ENV => Some("dev-container".to_string()),
            _ => None,
        })
        .expect("valid dev-container listener addr");
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn listener_plaintext_default_rejects_loopback() {
        let err = listener_addr_from(ListenerKind::Health, |name| {
            (name == "RSS_HEALTH_LISTEN_ADDR").then(|| "127.0.0.1:8083".to_string())
        })
        .expect_err("plaintext listener needs explicit opt-in even on loopback");
        assert!(
            format!("{err:#}").contains(LISTENER_ALLOW_PLAINTEXT_ENV),
            "error must identify plaintext opt-in env: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn listener_plaintext_default_rejects_non_loopback() {
        let err = listener_addr_from(ListenerKind::Primary, |name| {
            (name == "RSS_PRIMARY_LISTEN_ADDR").then(|| "0.0.0.0:8080".to_string())
        })
        .expect_err("non-loopback plaintext listener must fail closed by default");
        assert!(
            format!("{err:#}").contains(LISTENER_ALLOW_PLAINTEXT_ENV),
            "error must identify plaintext opt-in env: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn listener_plaintext_true_allows_loopback_only() {
        let loopback = listener_addr_from(ListenerKind::Health, |name| match name {
            "RSS_HEALTH_LISTEN_ADDR" => Some("127.0.0.1:8083".to_string()),
            LISTENER_ALLOW_PLAINTEXT_ENV => Some("true".to_string()),
            _ => None,
        })
        .expect("explicit loopback opt-in should allow loopback bind");
        assert!(loopback.ip().is_loopback());

        let err = listener_addr_from(ListenerKind::Health, |name| match name {
            "RSS_HEALTH_LISTEN_ADDR" => Some("10.0.0.8:8083".to_string()),
            LISTENER_ALLOW_PLAINTEXT_ENV => Some("true".to_string()),
            _ => None,
        })
        .expect_err("loopback opt-in must reject fixed non-loopback addresses");
        assert!(format!("{err:#}").contains("loopback"), "{err:#}");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn listener_plaintext_dev_container_allows_only_loopback_or_unspecified() {
        for raw in ["0.0.0.0:8080", "[::]:8080", "127.0.0.1:8080"] {
            let addr = listener_addr_from(ListenerKind::Primary, |name| match name {
                "RSS_PRIMARY_LISTEN_ADDR" => Some(raw.to_string()),
                LISTENER_ALLOW_PLAINTEXT_ENV => Some("dev-container".to_string()),
                _ => None,
            })
            .expect("dev-container policy allows compose wildcard and loopback binds");
            assert!(addr.ip().is_unspecified() || addr.ip().is_loopback());
        }

        let err = listener_addr_from(ListenerKind::Primary, |name| match name {
            "RSS_PRIMARY_LISTEN_ADDR" => Some("10.0.0.8:8080".to_string()),
            LISTENER_ALLOW_PLAINTEXT_ENV => Some("dev-container".to_string()),
            _ => None,
        })
        .expect_err("dev-container policy must not allow arbitrary non-loopback binds");
        assert!(
            format!("{err:#}").contains("dev-container"),
            "error should mention dev-container policy: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn listener_plaintext_invalid_opt_in_fails_fast() {
        let err = listener_addr_from(ListenerKind::Health, |name| match name {
            "RSS_HEALTH_LISTEN_ADDR" => Some("127.0.0.1:8083".to_string()),
            LISTENER_ALLOW_PLAINTEXT_ENV => Some("enabled".to_string()),
            _ => None,
        })
        .expect_err("invalid plaintext opt-in should fail");
        assert!(
            format!("{err:#}").contains(LISTENER_ALLOW_PLAINTEXT_ENV),
            "error must identify opt-in env: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn internal_mtls_listener_is_not_plaintext() {
        let addr = listener_addr_from(ListenerKind::Internal, |name| {
            (name == "RSS_INTERNAL_LISTEN_ADDR").then(|| "0.0.0.0:8081".to_string())
        })
        .expect("default Internal listener is mTLS and not gated as plaintext");
        assert!(addr.ip().is_unspecified());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn internal_service_token_listener_is_plaintext_and_requires_opt_in() {
        let err = listener_addr_from(ListenerKind::Internal, |name| match name {
            "RSS_INTERNAL_LISTEN_ADDR" => Some("0.0.0.0:8081".to_string()),
            "RSS_INTERNAL_AUTH_SCHEME" => Some("service-token".to_string()),
            _ => None,
        })
        .expect_err("Internal service-token mode is plaintext and must be gated");
        assert!(
            format!("{err:#}").contains(LISTENER_ALLOW_PLAINTEXT_ENV),
            "error must identify plaintext opt-in env: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn internal_service_token_non_loopback_requires_migration_ticket() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000);
        let err = listener_addr_from_at(
            ListenerKind::Internal,
            |name| match name {
                "RSS_INTERNAL_LISTEN_ADDR" => Some("0.0.0.0:8081".to_string()),
                INTERNAL_AUTH_SCHEME_ENV => Some(INTERNAL_AUTH_SCHEME_SERVICE_TOKEN.to_string()),
                LISTENER_ALLOW_PLAINTEXT_ENV => Some("dev-container".to_string()),
                _ => None,
            },
            now,
        )
        .expect_err("wildcard Internal service-token listener needs a migration ticket");
        assert!(
            format!("{err:#}").contains(INTERNAL_SERVICE_TOKEN_MIGRATION_TICKET_ENV),
            "error should name migration ticket env: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn internal_service_token_migration_ticket_must_not_be_expired() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000);
        let err = listener_addr_from_at(
            ListenerKind::Internal,
            |name| match name {
                "RSS_INTERNAL_LISTEN_ADDR" => Some("0.0.0.0:8081".to_string()),
                INTERNAL_AUTH_SCHEME_ENV => Some(INTERNAL_AUTH_SCHEME_SERVICE_TOKEN.to_string()),
                LISTENER_ALLOW_PLAINTEXT_ENV => Some("dev-container".to_string()),
                INTERNAL_SERVICE_TOKEN_MIGRATION_TICKET_ENV => Some("SEC-1500".to_string()),
                INTERNAL_SERVICE_TOKEN_MIGRATION_EXPIRES_AT_UNIX_ENV => Some("1000".to_string()),
                _ => None,
            },
            now,
        )
        .expect_err("expired migration ticket must fail startup");
        assert!(
            format!("{err:#}").contains(INTERNAL_SERVICE_TOKEN_MIGRATION_EXPIRES_AT_UNIX_ENV),
            "error should name migration expiry env: {err:#}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn internal_service_token_non_loopback_accepts_unexpired_migration_ticket() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000);
        let addr = listener_addr_from_at(
            ListenerKind::Internal,
            |name| match name {
                "RSS_INTERNAL_LISTEN_ADDR" => Some("0.0.0.0:8081".to_string()),
                INTERNAL_AUTH_SCHEME_ENV => Some(INTERNAL_AUTH_SCHEME_SERVICE_TOKEN.to_string()),
                LISTENER_ALLOW_PLAINTEXT_ENV => Some("dev-container".to_string()),
                INTERNAL_SERVICE_TOKEN_MIGRATION_TICKET_ENV => Some("SEC-1500".to_string()),
                INTERNAL_SERVICE_TOKEN_MIGRATION_EXPIRES_AT_UNIX_ENV => Some("3000".to_string()),
                _ => None,
            },
            now,
        )
        .expect("unexpired migration ticket allows explicit transition");
        assert!(addr.ip().is_unspecified());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn internal_service_token_loopback_does_not_require_migration_ticket() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000);
        let addr = listener_addr_from_at(
            ListenerKind::Internal,
            |name| match name {
                "RSS_INTERNAL_LISTEN_ADDR" => Some("127.0.0.1:8081".to_string()),
                INTERNAL_AUTH_SCHEME_ENV => Some(INTERNAL_AUTH_SCHEME_SERVICE_TOKEN.to_string()),
                LISTENER_ALLOW_PLAINTEXT_ENV => Some("true".to_string()),
                _ => None,
            },
            now,
        )
        .expect("loopback service-token listener remains a local test migration path");
        assert!(addr.ip().is_loopback());
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

    #[allow(clippy::expect_used)]
    fn test_health_assembled() -> AssembledListener {
        let (listener, routes) =
            health_listener(test_reporter(), noop_metrics()).expect("health listener");
        AssembledListener::plain(listener, routes)
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
        let listeners = vec![test_health_assembled(), test_health_assembled()];
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
        let listeners = vec![test_health_assembled()];
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
        let source = include_str!("lib.rs");
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
