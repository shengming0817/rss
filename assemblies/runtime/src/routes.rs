//! Runtime listener route finalization and auth wiring.

use crate::auth_bridge;

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use oidc::OidcProvider;
use primitives::{
    AuthPlan, AuthScheme, HealthCheck, HealthStatus, ListenerKind, ProbeName, RequiredScheme,
};
use ratelimit::GovernorLimiter;

/// Internal listener auth mode. Default is mTLS; `service-token` is loopback local-test only.
pub(crate) const INTERNAL_AUTH_SCHEME_ENV: &str = "RSS_INTERNAL_AUTH_SCHEME";
const INTERNAL_AUTH_SCHEME_MTLS: &str = "mtls";
pub(crate) const INTERNAL_AUTH_SCHEME_SERVICE_TOKEN: &str = "service-token";
/// Comma-separated exact SPIFFE IDs accepted on the Internal mTLS listener.
pub(crate) const INTERNAL_MTLS_SPIFFE_ALLOW_SET_ENV: &str = "RSS_INTERNAL_MTLS_SPIFFE_ALLOW_SET";

pub(crate) fn auth_scheme_from(
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
                "internal listener using local-test service-token auth; mTLS is the production default"
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

pub(crate) fn required_scheme_for_auth_scheme(scheme: AuthScheme) -> Option<RequiredScheme> {
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
    pub(crate) listener: ListenerKind,
    pub(crate) scheme: AuthScheme,
    pub(crate) routes: httpserve::AuthenticatedRoutes,
    pub(crate) mtls_health: Option<Arc<MtlsHealthSlot>>,
}

impl AssembledListener {
    pub fn listener(&self) -> ListenerKind {
        self.listener
    }

    pub fn auth_scheme(&self) -> AuthScheme {
        self.scheme
    }

    pub fn into_parts(self) -> (ListenerKind, httpserve::AuthenticatedRoutes) {
        (self.listener, self.routes)
    }

    pub(crate) fn plain(listener: ListenerKind, routes: httpserve::AuthenticatedRoutes) -> Self {
        Self {
            listener,
            scheme: AuthScheme::NoAuth,
            routes,
            mtls_health: None,
        }
    }
}

pub(crate) struct MtlsHealthSlot {
    config: Mutex<Option<httpd::MtlsServerConfig>>,
}

impl MtlsHealthSlot {
    pub(crate) fn new() -> Self {
        Self {
            config: Mutex::new(None),
        }
    }

    pub(crate) fn set(&self, config: httpd::MtlsServerConfig) -> anyhow::Result<()> {
        let mut guard = self
            .config
            .lock()
            .map_err(|_| anyhow::anyhow!("mtls health slot lock poisoned"))?;
        *guard = Some(config);
        Ok(())
    }

    pub(crate) fn check(&self) -> (HealthStatus, &'static str) {
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

pub(crate) struct MtlsSourceHealthProbe {
    name: ProbeName,
    slot: Arc<MtlsHealthSlot>,
}

impl MtlsSourceHealthProbe {
    pub(crate) fn new(name: ProbeName, slot: Arc<MtlsHealthSlot>) -> Self {
        Self { name, slot }
    }
}

impl bootstrap::HealthProbe for MtlsSourceHealthProbe {
    fn check(&self) -> HealthCheck {
        let (status, detail) = self.slot.check();
        HealthCheck::new(self.name.clone(), status, detail)
    }
}

pub(crate) const MTLS_SOURCE_READY_PROBE_NAME: &str = "mtls_source_ready";

pub(crate) fn mtls_probe_name(listener: ListenerKind) -> anyhow::Result<ProbeName> {
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

fn mtls_route_authorizer_from(
    listener: ListenerKind,
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<Arc<dyn httpserve::RouteAuthorizer>> {
    let allow_set = mtls_allow_set_from_env(listener, get)?;
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
    assemble_authed_routers_from(
        registry,
        provider,
        audit_sink,
        audit_clock,
        primary_authorizer,
        |name| std::env::var(name).ok(),
    )
}

pub(crate) fn assemble_authed_routers_from(
    registry: &mut bootstrap::Registry,
    provider: Arc<OidcProvider>,
    audit_sink: httpserve::AuditSinkHandle,
    audit_clock: Arc<dyn diport::Clock>,
    primary_authorizer: Arc<dyn httpserve::RouteAuthorizer>,
    get: impl Fn(&str) -> Option<String> + Copy,
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
        let scheme = auth_scheme_from(listener, get).context("resolve listener auth scheme")?;
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
        let authed = finalize_listener_auth_from(
            listener,
            routes,
            plan,
            audit_sink.clone(),
            audit_clock.clone(),
            primary_authorizer.clone(),
            get,
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
            scheme,
            routes: wired,
            mtls_health,
        });
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) fn finalize_listener_auth(
    listener: ListenerKind,
    routes: httpserve::UnfinalizedRoutes,
    plan: AuthPlan,
    audit_sink: httpserve::AuditSinkHandle,
    audit_clock: Arc<dyn diport::Clock>,
    primary_authorizer: Arc<dyn httpserve::RouteAuthorizer>,
) -> anyhow::Result<httpserve::AuthenticatedRoutes> {
    finalize_listener_auth_from(
        listener,
        routes,
        plan,
        audit_sink,
        audit_clock,
        primary_authorizer,
        |name| std::env::var(name).ok(),
    )
}

fn finalize_listener_auth_from(
    listener: ListenerKind,
    routes: httpserve::UnfinalizedRoutes,
    plan: AuthPlan,
    audit_sink: httpserve::AuditSinkHandle,
    audit_clock: Arc<dyn diport::Clock>,
    primary_authorizer: Arc<dyn httpserve::RouteAuthorizer>,
    get: impl Fn(&str) -> Option<String> + Copy,
) -> anyhow::Result<httpserve::AuthenticatedRoutes> {
    let scheme = plan.scheme();
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
            mtls_route_authorizer_from(listener, get)?,
        )
        .map_err(Into::into);
    }
    httpserve::finalize_auth_with_audit(routes, plan, audit_sink, audit_clock).map_err(Into::into)
}

pub(crate) fn mtls_allow_set_from_csv(raw: &str) -> anyhow::Result<authn::MtlsAllowSet> {
    mtls_allow_set_from_csv_for_env(raw, INTERNAL_MTLS_SPIFFE_ALLOW_SET_ENV)
}

pub(crate) fn mtls_allow_set_from_csv_for_env(
    raw: &str,
    env: &str,
) -> anyhow::Result<authn::MtlsAllowSet> {
    let mut ids = Vec::new();
    for part in raw.split(',') {
        let trimmed = part.trim();
        anyhow::ensure!(!trimmed.is_empty(), "{env} must not contain empty entries");
        ids.push(trimmed.to_owned());
    }
    authn::MtlsAllowSet::new(ids).map_err(|e| anyhow::anyhow!("{env} invalid: {e}"))
}

pub(crate) fn mtls_allow_set_from_env(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listeners::health_listener;
    use crate::{SystemClock, TracingAuthAuditSink, provider_from_b64};

    use std::future::Future;
    use std::pin::Pin;

    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::routing::get;
    use base64::Engine as _;
    use httpserve::{PrimaryRoute, Route, RoutePermission, RouteResourceScope};
    use tower::ServiceExt as _;

    const B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE_NO_PAD;

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

    #[allow(clippy::expect_used)]
    fn runtime_test_provider() -> Arc<oidc::OidcProvider> {
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
    fn test_reporter() -> Arc<bootstrap::HealthReporter> {
        let mut reg = bootstrap::compose(&[]).expect("compose");
        Arc::new(reg.take_health_reporter())
    }

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
                Box::new(SystemClock),
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

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn assemble_authed_routers_smoke_segregates_listeners_and_finalizes_auth() {
        let mut registry = bootstrap::Registry::new();
        registry
            .route_group::<httpserve::Primary>("/api/v1/p", |rb| {
                Ok(rb.mount_primary(
                    PrimaryRoute::permission(
                        Method::GET,
                        "/private",
                        "runtime.smoke.primary",
                        RoutePermission {
                            permission: vocab::RoutePermissionId::AuditRead,
                            scope: RouteResourceScope::None,
                        },
                    ),
                    get(|| async { "primary" }),
                ))
            })
            .expect("primary route group");
        registry
            .route_group::<httpserve::Admin>("/admin", |rb| {
                Ok(rb.mount(
                    Route {
                        method: Method::GET,
                        path: "/probe",
                        contract_id: "runtime.smoke.admin",
                    },
                    get(|| async { "admin" }),
                ))
            })
            .expect("admin route group");
        registry
            .route_group::<httpserve::Internal>("/internal", |rb| {
                Ok(rb.mount(
                    Route {
                        method: Method::GET,
                        path: "/probe",
                        contract_id: "runtime.smoke.internal",
                    },
                    get(|| async { "internal" }),
                ))
            })
            .expect("internal route group");

        let listeners = assemble_authed_routers_from(
            &mut registry,
            runtime_test_provider(),
            httpserve::AuditSinkHandle::new(TracingAuthAuditSink),
            Arc::new(SystemClock),
            allow_authorizer(),
            |name| {
                (name == INTERNAL_MTLS_SPIFFE_ALLOW_SET_ENV)
                    .then(|| "spiffe://example.org/ns/rss/sa/internal".to_string())
            },
        )
        .expect("assemble listeners");
        let (health_listener_kind, health_routes) =
            health_listener(test_reporter(), noop_metrics()).expect("health listener");
        assert_eq!(health_listener_kind, ListenerKind::Health);

        let mut primary = None;
        let mut admin = None;
        let mut internal = None;
        let mut unexpected = Vec::new();
        for assembled in listeners {
            let (listener, routes) = assembled.into_parts();
            match listener {
                ListenerKind::Primary => primary = Some(routes.into_router_for_test()),
                ListenerKind::Admin => admin = Some(routes.into_router_for_test()),
                ListenerKind::Internal => internal = Some(routes.into_router_for_test()),
                other => unexpected.push(other),
            }
        }
        assert!(
            unexpected.is_empty(),
            "unexpected listeners from assemble: {unexpected:?}"
        );
        let primary = primary.expect("primary listener");
        let admin = admin.expect("admin listener");
        let internal = internal.expect("internal listener");
        let health = health_routes.into_router_for_test();

        async fn status(router: axum::Router, uri: &str) -> StatusCode {
            router
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("oneshot")
                .status()
        }

        assert_eq!(
            status(primary.clone(), "/api/v1/p/private").await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(admin.clone(), "/admin/probe").await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(internal.clone(), "/internal/probe").await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(health.clone(), "/health/v1/healthz").await,
            StatusCode::OK
        );

        for path in ["/admin/probe", "/internal/probe", "/health/v1/healthz"] {
            assert_eq!(status(primary.clone(), path).await, StatusCode::NOT_FOUND);
        }
        for path in ["/api/v1/p/private", "/internal/probe"] {
            assert_eq!(status(admin.clone(), path).await, StatusCode::NOT_FOUND);
        }
        for path in ["/api/v1/p/private", "/admin/probe"] {
            assert_eq!(status(internal.clone(), path).await, StatusCode::NOT_FOUND);
        }
        for path in ["/api/v1/p/private", "/admin/probe", "/internal/probe"] {
            assert_eq!(status(health.clone(), path).await, StatusCode::NOT_FOUND);
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn finalize_listener_routes_injects_primary_authorizer_into_admin_listener() {
        use axum::extract::Extension;
        use axum::response::IntoResponse as _;

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
        )
        .expect("finalize admin listener")
        .layer(axum::middleware::from_fn(
            |mut req: axum::extract::Request, next: axum::middleware::Next| async move {
                req.extensions_mut().insert(httpserve::Authenticated::new(
                    RequiredScheme::Jwt,
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
                Request::builder()
                    .uri("/admin/probe")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("admin probe");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
