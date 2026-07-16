//! Runtime listener route finalization and auth wiring.

use crate::{SPIFFE_ENDPOINT_SOCKET_ENV, auth_bridge, config::SnapshotConfig};

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

/// Resolve one listener's auth policy exclusively from the captured serving generation.
pub(crate) fn auth_scheme(
    config: SnapshotConfig<'_>,
    listener: ListenerKind,
) -> anyhow::Result<AuthScheme> {
    auth_scheme_from_value(listener, config.value(INTERNAL_AUTH_SCHEME_ENV))
}

pub(crate) fn auth_scheme_from_value(
    listener: ListenerKind,
    internal_auth_scheme: Option<&str>,
) -> anyhow::Result<AuthScheme> {
    Ok(match listener {
        ListenerKind::Primary | ListenerKind::Admin => AuthScheme::Jwt,
        ListenerKind::Internal => internal_auth_scheme_from_value(internal_auth_scheme)?,
        ListenerKind::Health => AuthScheme::NoAuth,
        _ => anyhow::bail!("unknown ListenerKind {listener:?}; refusing to infer an auth scheme"),
    })
}

fn internal_auth_scheme_from_value(raw: Option<&str>) -> anyhow::Result<AuthScheme> {
    let Some(raw) = raw else {
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
            "{INTERNAL_AUTH_SCHEME_ENV} has an unsupported value (expected '{INTERNAL_AUTH_SCHEME_MTLS}' or '{INTERNAL_AUTH_SCHEME_SERVICE_TOKEN}')"
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
    pub(crate) transport: ListenerTransport,
}

/// Transport material resolved during route assembly from the same captured generation.
///
/// The mTLS variant makes the allow-set, SPIFFE endpoint, and readiness slot indivisible, so the
/// launch phase cannot bind mTLS and then fall back to an ambient configuration source.
pub(crate) enum ListenerTransport {
    Plaintext,
    Mtls {
        allow_set: authn::MtlsAllowSet,
        spiffe_endpoint: String,
        health: Arc<MtlsHealthSlot>,
    },
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
            transport: ListenerTransport::Plaintext,
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

fn mtls_route_authorizer(allow_set: authn::MtlsAllowSet) -> Arc<dyn httpserve::RouteAuthorizer> {
    Arc::new(MtlsRouteAuthorizer { allow_set })
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
/// Primary listener：从 Registry 一次性取得 authorizer，再由
/// `finalize_primary_auth_with_audit(routes, plan, ..., primary_authorizer)` 注入
/// `RouteAuthorizer`；Admin listener 也注入同一 Authorizer 供 field projection 消费；其它非 Primary
/// listener：`finalize_auth_with_audit(routes, plan, ...)`。三者均消费
/// `UnfinalizedRoutes` 产 `AuthenticatedRoutes` 并注入 AuthPlan 与 framework 中间件。随后据
/// `required_scheme` 叠外层 `verify_bridge`（`NoAuth` listener 无桥）
/// → 叠 rate-limit（[`httpserve::rate_limit`]，outer 于验签桥；peer-IP keyed per-request）。
/// 产出 `AuthenticatedRoutes` 经 `into_make_service` 交给 launch phase 绑 socket + serve——bind 点
/// 天生只能消费已认证 router（ROUTE-AUTH-FUNNEL-01/02：未跑 finalize_auth 的 router 无 bindable 出口）。
///
/// 层序（外→内）：body-limit（httpserve sealed_router，最外防护）→ rate-limit（本函数 verify-bridge 后叠）
/// → 验签桥 → trace → enforce → handler。rate-limit outer 于验签桥保证限流在 auth 计算前生效
/// （INVARIANT RATELIMIT-BEFORE-AUTH-01：组合根在 verify-bridge 后 .layer ⇒ outer 于桥）。
///
/// Health listener 由 [`health_listener`] 单独构造、**不经本函数、不叠限流**——探针不限速（k8s
/// liveness/readiness 在高负载下不应被限流触发级联重启），有意设计。
///
/// 借 `&mut Registry`，一次性消费 Primary authorizer 并 drain `finalize_routes`；registry 的探针在此后仍存活，组合根经
/// [`bootstrap::Registry::take_health_reporter`] 取出探针装入 `Arc<HealthReporter>`（`Send + Sync`）注入
/// Health listener 的 readyz handler（每请求 `report`，[`health_listener`]）；整体非 `Sync` 的 `Registry`
/// 无法进 axum handler 闭包。
pub(crate) fn assemble_authed_routers(
    config: SnapshotConfig<'_>,
    registry: &mut bootstrap::Registry,
    provider: Arc<OidcProvider>,
    audit_sink: httpserve::AuditSinkHandle,
    audit_clock: Arc<dyn diport::Clock>,
) -> anyhow::Result<Vec<AssembledListener>> {
    let internal_scheme = auth_scheme(config, ListenerKind::Internal)
        .context("resolve captured Internal auth scheme")?;
    assemble_authed_routers_with_resolved_internal_auth(
        registry,
        provider,
        audit_sink,
        audit_clock,
        internal_scheme,
        config.value(INTERNAL_MTLS_SPIFFE_ALLOW_SET_ENV),
        config.value(SPIFFE_ENDPOINT_SOCKET_ENV),
    )
}

/// Explicit-value assembly core for integration tests that cannot mint [`SnapshotConfig`].
///
/// Production must enter through [`assemble_authed_routers`]. This boundary accepts only the
/// three raw values owned by route/listener transport assembly; it cannot accept an ambient reader
/// and therefore cannot introduce late environment reads.
#[cfg(feature = "integration")]
pub fn assemble_authed_routers_from_values(
    registry: &mut bootstrap::Registry,
    provider: Arc<OidcProvider>,
    audit_sink: httpserve::AuditSinkHandle,
    audit_clock: Arc<dyn diport::Clock>,
    internal_auth_scheme: Option<&str>,
    internal_mtls_allow_set: Option<&str>,
    spiffe_endpoint: Option<&str>,
) -> anyhow::Result<Vec<AssembledListener>> {
    let internal_scheme = auth_scheme_from_value(ListenerKind::Internal, internal_auth_scheme)
        .context("resolve explicit Internal auth scheme")?;
    assemble_authed_routers_with_resolved_internal_auth(
        registry,
        provider,
        audit_sink,
        audit_clock,
        internal_scheme,
        internal_mtls_allow_set,
        spiffe_endpoint,
    )
}

fn assemble_authed_routers_with_resolved_internal_auth(
    registry: &mut bootstrap::Registry,
    provider: Arc<OidcProvider>,
    audit_sink: httpserve::AuditSinkHandle,
    audit_clock: Arc<dyn diport::Clock>,
    internal_scheme: AuthScheme,
    internal_mtls_allow_set: Option<&str>,
    spiffe_endpoint: Option<&str>,
) -> anyhow::Result<Vec<AssembledListener>> {
    crate::modules_gen::register_framework_routes(registry).context("register framework routes")?;
    let primary_authorizer = registry
        .take_primary_authorizer()
        .context("take Primary route authorizer")?;
    // 默认限流配额（owner=组合根，可调）：10 req/s，burst 20。peer-IP keyed（见 #1106 / RealIP follow-up）。
    // 共享跨所有 listener——统一 per-IP 预算，避免分散 listener 各自独立 bucket 使 burst 预算 N 倍膨胀。
    //
    // 已知限制（multi-instance）：in-mem `GovernorLimiter` 是 per-instance 独立桶，N 副本部署下
    // 每实例独立配额（全局视图 ≈ N × 单实例率）；全局一致限流须 redis-distributed provider（future）。
    // 叠加 peer-IP-after-proxy 退化（RealIP follow-up），本限流当前为单实例 best-effort 防护。
    let rate_limiter = Arc::new(GovernorLimiter::new(default_rate_quota()));
    let mut out = Vec::new();
    let finalized_routes = registry.finalize_routes().context("finalize_routes")?;
    bootstrap::validate_framework_serving(
        &finalized_routes,
        crate::modules_gen::FRAMEWORK_HTTP_ROUTES,
    )
    .context("validate framework serving")?;
    for (listener, routes) in finalized_routes {
        let scheme = if listener == ListenerKind::Internal {
            internal_scheme
        } else {
            auth_scheme_from_value(listener, None).context("resolve listener auth scheme")?
        };
        let plan = AuthPlan::new(listener, scheme).context("build auth plan")?;
        let transport = if scheme == AuthScheme::Mtls {
            let allow_set = mtls_allow_set_from_value(listener, internal_mtls_allow_set)?;
            let spiffe_endpoint = mtls_spiffe_endpoint_from_value(spiffe_endpoint)?;
            let slot = Arc::new(MtlsHealthSlot::new());
            let probe_name = mtls_probe_name(listener)?;
            registry
                .probe(
                    probe_name.clone(),
                    Box::new(MtlsSourceHealthProbe::new(probe_name, slot.clone())),
                )
                .context("register mtls source health probe")?;
            ListenerTransport::Mtls {
                allow_set,
                spiffe_endpoint,
                health: slot,
            }
        } else {
            ListenerTransport::Plaintext
        };
        let mtls_authorizer = match &transport {
            ListenerTransport::Mtls { allow_set, .. } => Some(allow_set.clone()),
            ListenerTransport::Plaintext => None,
        };
        let authed = finalize_listener_auth_with_mtls(
            listener,
            routes,
            plan,
            audit_sink.clone(),
            audit_clock.clone(),
            primary_authorizer.clone(),
            mtls_authorizer,
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
            transport,
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
    finalize_listener_auth_with_mtls(
        listener,
        routes,
        plan,
        audit_sink,
        audit_clock,
        primary_authorizer,
        None,
    )
}

fn finalize_listener_auth_with_mtls(
    listener: ListenerKind,
    routes: httpserve::UnfinalizedRoutes,
    plan: AuthPlan,
    audit_sink: httpserve::AuditSinkHandle,
    audit_clock: Arc<dyn diport::Clock>,
    primary_authorizer: Arc<dyn httpserve::RouteAuthorizer>,
    mtls_allow_set: Option<authn::MtlsAllowSet>,
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
        let allow_set = mtls_allow_set.ok_or_else(|| {
            anyhow::anyhow!("mTLS listener {listener:?} is missing its captured allow-set")
        })?;
        return httpserve::finalize_auth_with_audit_and_authorizer(
            routes,
            plan,
            audit_sink,
            audit_clock,
            mtls_route_authorizer(allow_set),
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

pub(crate) fn mtls_allow_set_from_value(
    listener: ListenerKind,
    raw: Option<&str>,
) -> anyhow::Result<authn::MtlsAllowSet> {
    anyhow::ensure!(
        listener == ListenerKind::Internal,
        "mTLS listener config is only wired for Internal"
    );
    let raw = raw.ok_or_else(|| {
        anyhow::anyhow!("missing required env var: {INTERNAL_MTLS_SPIFFE_ALLOW_SET_ENV}")
    })?;
    mtls_allow_set_from_csv(raw)
}

fn mtls_spiffe_endpoint_from_value(raw: Option<&str>) -> anyhow::Result<String> {
    let raw = raw
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {SPIFFE_ENDPOINT_SOCKET_ENV}"))?;
    let endpoint = raw.trim();
    anyhow::ensure!(
        !endpoint.is_empty(),
        "{SPIFFE_ENDPOINT_SOCKET_ENV} must be a non-empty explicit endpoint"
    );
    anyhow::ensure!(
        endpoint == raw
            && !endpoint.chars().any(char::is_control)
            && !endpoint.chars().any(char::is_whitespace),
        "{SPIFFE_ENDPOINT_SOCKET_ENV} must not contain whitespace or control characters"
    );
    Ok(raw.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RuntimeConfigSnapshot, test_snapshot};
    use crate::listeners::health_listener;
    use crate::{SystemClock, TracingAuthAuditSink, provider_from_b64};

    use std::future::Future;
    use std::pin::Pin;

    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::routing::get;
    use base64::Engine as _;
    use httpserve::{
        TestPrimaryRoute as PrimaryRoute, TestRoute as Route,
        TestRoutePermission as RoutePermission, TestRouteResourceScope as RouteResourceScope,
    };
    use tower::ServiceExt as _;

    const B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::URL_SAFE_NO_PAD;

    #[allow(clippy::expect_used)]
    fn test_config(
        entries: impl IntoIterator<Item = (&'static str, &'static str)>,
    ) -> RuntimeConfigSnapshot {
        let entries = entries.into_iter().collect::<Vec<_>>();
        test_snapshot(&entries).expect("capture test serving config")
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

    #[derive(Clone, Default)]
    struct RouteMetaCapture(Arc<Mutex<Option<(vocab::HttpRouteEvidence, Method)>>>);

    struct RouteMetaDomain {
        capture: RouteMetaCapture,
    }

    impl bootstrap::Domain for RouteMetaDomain {
        fn init(&self, registry: &mut bootstrap::Registry) -> Result<(), bootstrap::KernelError> {
            let capture = self.capture.clone();
            registry.route_group::<httpserve::Primary>("/api/v1/identity", move |router| {
                let endpoint = httpserve::GeneratedPrimaryEndpoint::new(
                    generated::http::identity_v1::login::ROUTE,
                    route_meta_capture_handler,
                )?
                .with_state(capture);
                Ok(router.mount(endpoint)?)
            })?;
            Ok(())
        }
    }

    async fn route_meta_capture_handler(
        _: httpserve::ContractMarker<generated::http::identity_v1::login::RouteMarker>,
        axum::extract::State(capture): axum::extract::State<RouteMetaCapture>,
        axum::extract::Extension(meta): axum::extract::Extension<httpserve::RouteMeta>,
    ) -> StatusCode {
        let Ok(mut slot) = capture.0.lock() else {
            return StatusCode::INTERNAL_SERVER_ERROR;
        };
        *slot = Some((*meta.evidence(), meta.method().clone()));
        StatusCode::CREATED
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
            auth_scheme_from_value(ListenerKind::Primary, None).unwrap(),
            AuthScheme::Jwt
        );
        assert_eq!(
            auth_scheme_from_value(ListenerKind::Admin, None).unwrap(),
            AuthScheme::Jwt
        );
        assert_eq!(
            auth_scheme_from_value(ListenerKind::Internal, None).unwrap(),
            AuthScheme::Mtls
        );
        assert_eq!(
            auth_scheme_from_value(ListenerKind::Health, None).unwrap(),
            AuthScheme::NoAuth
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn internal_service_token_requires_explicit_transition_flag() {
        let scheme = auth_scheme_from_value(
            ListenerKind::Internal,
            Some(INTERNAL_AUTH_SCHEME_SERVICE_TOKEN),
        )
        .expect("explicit service-token transition is accepted");
        assert_eq!(scheme, AuthScheme::ServiceToken);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn internal_auth_scheme_rejects_unknown_value() {
        const SECRET_FRAGMENT: &str = "auth-secret-bait";
        let err = auth_scheme_from_value(ListenerKind::Internal, Some(SECRET_FRAGMENT))
            .expect_err("unknown internal auth scheme must fail-fast");
        let error = err.to_string();
        assert!(
            error.contains(INTERNAL_AUTH_SCHEME_ENV),
            "error should name env var: {err}"
        );
        assert!(
            !error.contains(SECRET_FRAGMENT),
            "auth errors must not expose configured values"
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
    fn mtls_allow_set_from_value_requires_config_for_internal_mtls() {
        let err = mtls_allow_set_from_value(ListenerKind::Internal, None)
            .expect_err("mTLS allow-set must be configured");
        assert!(
            err.to_string().contains(INTERNAL_MTLS_SPIFFE_ALLOW_SET_ENV),
            "error should name env var: {err}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn mtls_spiffe_endpoint_requires_a_nonempty_captured_value_without_echoing_it() {
        for raw in [None, Some(""), Some("   \t")] {
            let err = mtls_spiffe_endpoint_from_value(raw)
                .expect_err("Internal mTLS must require an explicit SPIFFE endpoint");
            assert!(err.to_string().contains(SPIFFE_ENDPOINT_SOCKET_ENV));
        }

        const SECRET_BAIT: &str = "unix:///tenant-secret/spire.sock";
        assert_eq!(
            mtls_spiffe_endpoint_from_value(Some("unix:///run/spire/agent.sock"))
                .expect("explicit endpoint"),
            "unix:///run/spire/agent.sock"
        );
        let padded = format!(" {SECRET_BAIT} ");
        let err = mtls_spiffe_endpoint_from_value(Some(&padded))
            .expect_err("leading or trailing whitespace must be rejected");
        assert!(!err.to_string().contains(SECRET_BAIT));
        let invalid = format!("{SECRET_BAIT}\ninner");
        let err = mtls_spiffe_endpoint_from_value(Some(&invalid))
            .expect_err("control characters must be rejected");
        assert!(!err.to_string().contains(SECRET_BAIT));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn route_assembly_requires_endpoint_only_for_internal_mtls() {
        fn internal_registry() -> bootstrap::Registry {
            let mut registry = bootstrap::Registry::new();
            registry
                .route_group::<httpserve::Internal>("/internal", |rb| {
                    Ok(rb.mount_raw_for_test(
                        Route {
                            method: Method::GET,
                            path: "/internal/probe",
                            contract_id: "runtime.mtls.endpoint",
                        },
                        get(|| async { "internal" }),
                    )?)
                })
                .expect("internal route group");
            registry
                .register_primary_authorizer(allow_authorizer())
                .expect("Primary authorizer registered");
            registry
        }

        let mut mtls_registry = internal_registry();
        let mtls_snapshot = test_config([(
            INTERNAL_MTLS_SPIFFE_ALLOW_SET_ENV,
            "spiffe://example.org/ns/rss/sa/internal",
        )]);
        let error = assemble_authed_routers(
            mtls_snapshot.view(),
            &mut mtls_registry,
            runtime_test_provider(),
            httpserve::AuditSinkHandle::new(TracingAuthAuditSink),
            Arc::new(SystemClock),
        )
        .err()
        .expect("mTLS route assembly must fail without a captured SPIFFE endpoint");
        assert!(error.to_string().contains(SPIFFE_ENDPOINT_SOCKET_ENV));

        let mut plaintext_registry = internal_registry();
        let plaintext_snapshot =
            test_config([(INTERNAL_AUTH_SCHEME_ENV, INTERNAL_AUTH_SCHEME_SERVICE_TOKEN)]);
        let listeners = assemble_authed_routers(
            plaintext_snapshot.view(),
            &mut plaintext_registry,
            runtime_test_provider(),
            httpserve::AuditSinkHandle::new(TracingAuthAuditSink),
            Arc::new(SystemClock),
        )
        .expect("service-token Internal assembly must not require a SPIFFE endpoint");
        assert!(listeners.iter().any(|listener| {
            listener.listener == ListenerKind::Internal
                && matches!(listener.transport, ListenerTransport::Plaintext)
        }));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn assemble_without_primary_authorizer_fails_closed() {
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
        let snapshot = test_config([]);
        let error = assemble_authed_routers(
            snapshot.view(),
            &mut registry,
            provider,
            httpserve::AuditSinkHandle::new(TracingAuthAuditSink),
            Arc::new(SystemClock),
        )
        .err()
        .expect("missing Primary authorizer must fail closed");
        assert!(
            error.to_string().contains("take Primary route authorizer"),
            "error preserves safe assembly context: {error}"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn assemble_authed_routers_smoke_segregates_listeners_and_finalizes_auth() {
        let mut registry = bootstrap::Registry::new();
        registry
            .route_group::<httpserve::Primary>("/api/v1/p", |rb| {
                Ok(rb.mount_primary_raw_for_test(
                    PrimaryRoute::permission(
                        Method::GET,
                        "/api/v1/p/private",
                        "runtime.smoke.primary",
                        RoutePermission {
                            permission: vocab::RoutePermissionId::AuditRead,
                            scope: RouteResourceScope::None,
                        },
                    ),
                    get(|| async { "primary" }),
                )?)
            })
            .expect("primary route group");
        registry
            .route_group::<httpserve::Admin>("/admin", |rb| {
                Ok(rb.mount_raw_for_test(
                    Route {
                        method: Method::GET,
                        path: "/admin/probe",
                        contract_id: "runtime.smoke.admin",
                    },
                    get(|| async { "admin" }),
                )?)
            })
            .expect("admin route group");
        registry
            .route_group::<httpserve::Internal>("/internal", |rb| {
                Ok(rb.mount_raw_for_test(
                    Route {
                        method: Method::GET,
                        path: "/internal/probe",
                        contract_id: "runtime.smoke.internal",
                    },
                    get(|| async { "internal" }),
                )?)
            })
            .expect("internal route group");
        registry
            .register_primary_authorizer(allow_authorizer())
            .expect("Primary authorizer registered");

        let snapshot = test_config([
            (
                INTERNAL_MTLS_SPIFFE_ALLOW_SET_ENV,
                "spiffe://example.org/ns/rss/sa/internal",
            ),
            (SPIFFE_ENDPOINT_SOCKET_ENV, "unix:///run/spire/test.sock"),
        ]);
        let listeners = assemble_authed_routers(
            snapshot.view(),
            &mut registry,
            runtime_test_provider(),
            httpserve::AuditSinkHandle::new(TracingAuthAuditSink),
            Arc::new(SystemClock),
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
            if assembled.listener() == ListenerKind::Internal {
                let carried = match &assembled.transport {
                    ListenerTransport::Mtls {
                        allow_set,
                        spiffe_endpoint,
                        ..
                    } => Some((allow_set, spiffe_endpoint)),
                    ListenerTransport::Plaintext => None,
                };
                assert!(
                    carried.is_some(),
                    "Internal mTLS auth must carry its resolved transport config"
                );
                if let Some((allow_set, spiffe_endpoint)) = carried {
                    let expected =
                        authn::SpiffeId::parse("spiffe://example.org/ns/rss/sa/internal")
                            .expect("valid expected SPIFFE ID");
                    assert!(allow_set.allows(&expected));
                    assert_eq!(spiffe_endpoint, "unix:///run/spire/test.sock");
                }
            }
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
    async fn compose_finalize_auth_propagates_exact_generated_route_evidence_to_handler() {
        let capture = RouteMetaCapture::default();
        let domain = RouteMetaDomain {
            capture: capture.clone(),
        };
        let mut registry = bootstrap::compose(&[&domain]).expect("compose evidence domain");
        let mut listeners = registry
            .finalize_routes()
            .expect("finalize registry routes");
        assert_eq!(listeners.len(), 1, "one Primary listener must be finalized");
        let (listener, routes) = listeners.pop().expect("Primary routes");
        assert_eq!(listener, ListenerKind::Primary);

        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt).expect("Primary JWT plan");
        let authed = finalize_listener_auth(
            listener,
            routes,
            plan,
            httpserve::AuditSinkHandle::new(TracingAuthAuditSink),
            Arc::new(SystemClock),
            allow_authorizer(),
        )
        .expect("finalize runtime auth");
        let response = authed
            .into_router_for_test()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(generated::http::identity_v1::login::SPEC.route.path())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("route response");
        assert_eq!(response.status(), StatusCode::CREATED);

        let observed = capture
            .0
            .lock()
            .expect("route meta capture lock")
            .clone()
            .expect("handler observed RouteMeta");
        assert_eq!(
            observed.0,
            generated::http::identity_v1::login::SPEC.route,
            "handler must receive the exact generated evidence value"
        );
        assert_eq!(observed.1, Method::POST);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn finalize_listener_routes_injects_primary_authorizer_into_admin_listener() {
        use axum::extract::Extension;
        use axum::response::IntoResponse as _;

        let admin =
            httpserve::UnfinalizedRoutes::empty()
                .nest_group::<httpserve::Admin, anyhow::Error>("/admin", |rb| {
                    Ok(rb.mount_raw_for_test(
                        Route {
                            method: Method::GET,
                            path: "/admin/probe",
                            contract_id: generated::http::audit_v1::list_entries::SPEC
                                .route
                                .contract_id(),
                        },
                        axum::routing::get(
                            |Extension(authorizer): Extension<
                                Arc<dyn httpserve::RouteAuthorizer>,
                            >| async move {
                                match authorizer
                                    .authorize(httpserve::RouteAuthorizationRequest {
                                        contract_id: generated::http::audit_v1::list_entries::SPEC
                                            .route
                                            .contract_id(),
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
                                    ) => axum::http::StatusCode::OK.into_response(),
                                    httpserve::RouteAuthorizationDecision::Deny => {
                                        axum::http::StatusCode::FORBIDDEN.into_response()
                                    }
                                }
                            },
                        ),
                    )?)
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
        assert_eq!(response.status(), StatusCode::OK);
    }
}
