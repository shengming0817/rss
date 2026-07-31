//! Runtime listener route finalization and auth wiring.

use crate::auth_bridge::{self, ProfileBinding};
use crate::config::SnapshotConfig;
use crate::phase::SPIFFE_ENDPOINT_SOCKET_ENV;
use crate::plan::{ListenerExecutionPlan, ListenerExecutionSpec};

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use primitives::{AuthPlan, AuthScheme, HealthCheck, HealthStatus, ListenerKind, ProbeName};
use ratelimit::GovernorLimiter;

/// Comma-separated exact SPIFFE IDs accepted on the Internal mTLS listener.
pub(crate) const INTERNAL_MTLS_SPIFFE_ALLOW_SET_ENV: &str = "RSS_INTERNAL_MTLS_SPIFFE_ALLOW_SET";

/// Active verifier set for one captured configuration generation.
///
/// Fields are private and typed by profile. Route assembly validates exact presence against the
/// selected listeners before constructing any `AuthPlan`.
pub(crate) struct TokenProviderBindings {
    rss_access: Option<Arc<oidc::OidcProvider<diport::RssAccessProfile>>>,
    rss_access_grants: Option<Arc<identity::AuthGrantValidationService>>,
    federated_access: Option<Arc<oidc::OidcProvider<diport::FederatedAccessProfile>>>,
    service_token: Option<Arc<oidc::OidcProvider<diport::ServiceTokenProfile>>>,
}

impl TokenProviderBindings {
    pub(crate) const fn new(
        rss_access: Option<Arc<oidc::OidcProvider<diport::RssAccessProfile>>>,
        rss_access_grants: Option<Arc<identity::AuthGrantValidationService>>,
        federated_access: Option<Arc<oidc::OidcProvider<diport::FederatedAccessProfile>>>,
        service_token: Option<Arc<oidc::OidcProvider<diport::ServiceTokenProfile>>>,
    ) -> Self {
        Self {
            rss_access,
            rss_access_grants,
            federated_access,
            service_token,
        }
    }

    fn validate_exact_presence(&self, plan: &ListenerExecutionPlan) -> anyhow::Result<()> {
        let requires = |scheme| {
            plan.listeners()
                .iter()
                .any(|listener| listener.auth_scheme() == scheme)
        };
        anyhow::ensure!(
            self.rss_access.is_some() == requires(AuthScheme::RssAccessToken),
            "RSS access provider presence does not match RuntimePlan"
        );
        anyhow::ensure!(
            self.rss_access_grants.is_some() == requires(AuthScheme::RssAccessToken),
            "RSS access grant validator presence does not match RuntimePlan"
        );
        anyhow::ensure!(
            self.federated_access.is_some() == requires(AuthScheme::FederatedAccessToken),
            "federated access provider presence does not match RuntimePlan"
        );
        anyhow::ensure!(
            self.service_token.is_some() == requires(AuthScheme::ServiceToken),
            "service-token provider presence does not match RuntimePlan"
        );
        Ok(())
    }

    fn profile_binding(&self, scheme: AuthScheme) -> anyhow::Result<ProfileBinding> {
        match scheme {
            AuthScheme::RssAccessToken => self
                .rss_access
                .as_ref()
                .zip(self.rss_access_grants.as_ref())
                .map(|(provider, grants)| ProfileBinding::RssAccess {
                    provider: Arc::clone(provider),
                    grants: Arc::clone(grants),
                })
                .context("RSS access listener selected without its verifier and grant validator"),
            AuthScheme::FederatedAccessToken => self
                .federated_access
                .as_ref()
                .map(|provider| ProfileBinding::FederatedAccess(Arc::clone(provider)))
                .context("federated listener selected without federated provider"),
            AuthScheme::ServiceToken => self
                .service_token
                .as_ref()
                .map(|provider| ProfileBinding::ServiceToken(Arc::clone(provider)))
                .context("service-token listener selected without service-token provider"),
            AuthScheme::NoAuth | AuthScheme::Mtls => {
                anyhow::bail!("listener auth scheme has no token profile binding")
            }
            _ => anyhow::bail!("unknown listener auth scheme; refusing provider inference"),
        }
    }
}

enum ListenerAuthBinding {
    Token(ProfileBinding),
    Mtls,
}

impl ListenerAuthBinding {
    const fn scheme(&self) -> AuthScheme {
        match self {
            Self::Token(binding) => binding.auth_scheme(),
            Self::Mtls => AuthScheme::Mtls,
        }
    }
}

pub(crate) struct AssembledListener {
    spec: ListenerExecutionSpec,
    routes: httpserve::AuthenticatedRoutes,
    transport: ListenerTransport,
}

/// The exact, plan-ordered listener set accepted by launch.
///
/// Private fields and the absence of a `Vec` conversion keep launch membership coupled to the
/// consuming plan finalizer.
pub(crate) struct FinalizedListenerSet {
    listeners: Vec<AssembledListener>,
}

/// Linear proof that route finalization drained the registry's health probes exactly once.
///
/// The private field prevents construction outside this module. Deliberately omitting `Clone` and
/// `Copy` keeps the proof coupled to the finalized listener set until the launch executor consumes
/// it.
pub(crate) struct FinalizedProbeReceipt {
    _private: (),
}

/// Route finalization output kept indivisible until the `Finalized` phase state is constructed.
pub(crate) struct FinalizedListenerPlan {
    listeners: FinalizedListenerSet,
    probe_receipt: FinalizedProbeReceipt,
    health_reporter: Arc<bootstrap::HealthReporter>,
}

/// Transport material resolved during route assembly from the same captured generation.
///
/// The mTLS variant makes the allow-set, SPIFFE endpoint, and readiness slot indivisible, so the
/// launch phase cannot bind mTLS and then fall back to an ambient configuration source.
pub(crate) enum ListenerTransport {
    Plaintext,
    #[cfg(feature = "integration")]
    InventoryJourneyPlaintext,
    Mtls {
        allow_set: authn::MtlsAllowSet,
        spiffe_endpoint: String,
        health: Arc<MtlsHealthSlot>,
    },
}

impl AssembledListener {
    #[cfg(test)]
    pub(crate) fn listener(&self) -> ListenerKind {
        self.spec.kind()
    }

    #[cfg(test)]
    pub(crate) fn auth_scheme(&self) -> AuthScheme {
        self.spec.auth_scheme()
    }

    #[cfg(any(test, feature = "integration"))]
    pub(crate) fn into_parts(self) -> (ListenerKind, httpserve::AuthenticatedRoutes) {
        (self.spec.kind(), self.routes)
    }

    pub(crate) fn into_launch_parts(
        self,
    ) -> (
        String,
        ListenerKind,
        AuthScheme,
        httpserve::AuthenticatedRoutes,
        ListenerTransport,
    ) {
        (
            self.spec.id().to_owned(),
            self.spec.kind(),
            self.spec.auth_scheme(),
            self.routes,
            self.transport,
        )
    }

    #[cfg(test)]
    pub(crate) fn health_for_test(
        reporter: Arc<bootstrap::HealthReporter>,
        metrics: Arc<dyn diport::MetricsExporter>,
    ) -> anyhow::Result<Self> {
        finalize_health_spec(ListenerExecutionSpec::health_for_test(), reporter, metrics)
    }
}

impl FinalizedListenerSet {
    pub(crate) fn into_listeners(self) -> Vec<AssembledListener> {
        self.listeners
    }

    #[cfg(test)]
    pub(crate) fn for_test(listeners: Vec<AssembledListener>) -> Self {
        Self { listeners }
    }

    #[cfg(feature = "integration")]
    pub(crate) fn for_inventory_journey(
        admin: httpserve::AuthenticatedRoutes,
    ) -> anyhow::Result<(Self, FinalizedProbeReceipt)> {
        let mut admin = Some(admin);
        struct JourneyMetrics;
        impl diport::MetricsExporter for JourneyMetrics {
            fn render(&self) -> String {
                "# inventory-journey\n".to_owned()
            }
        }
        let reporter = Arc::new(bootstrap::Registry::new().take_health_reporter());
        let metrics: Arc<dyn diport::MetricsExporter> = Arc::new(JourneyMetrics);
        let mut listeners = Vec::new();
        for kind in [
            assembly_schema::AssemblyListenerKind::Admin,
            assembly_schema::AssemblyListenerKind::Health,
            assembly_schema::AssemblyListenerKind::Internal,
            assembly_schema::AssemblyListenerKind::Primary,
        ] {
            let spec = crate::plan::fixture_listener_spec(kind)?;
            let routes = if kind == assembly_schema::AssemblyListenerKind::Admin {
                admin
                    .take()
                    .context("Admin journey route already consumed")?
            } else {
                finalize_health_fixture(Arc::clone(&reporter), Arc::clone(&metrics))?
            };
            listeners.push(AssembledListener {
                spec,
                routes,
                transport: ListenerTransport::InventoryJourneyPlaintext,
            });
        }
        Ok((Self { listeners }, FinalizedProbeReceipt { _private: () }))
    }
}

impl FinalizedListenerPlan {
    pub(crate) fn into_parts(
        self,
    ) -> (
        FinalizedListenerSet,
        FinalizedProbeReceipt,
        Arc<bootstrap::HealthReporter>,
    ) {
        (self.listeners, self.probe_receipt, self.health_reporter)
    }
}

impl FinalizedProbeReceipt {
    #[cfg(test)]
    pub(crate) const fn for_test() -> Self {
        Self { _private: () }
    }
}

pub(crate) struct MtlsHealthSlot {
    config: Mutex<Option<httpd::MtlsServerConfig>>,
}

pub(crate) struct MtlsHealthCommit<'slot> {
    guard: std::sync::MutexGuard<'slot, Option<httpd::MtlsServerConfig>>,
    config: Option<httpd::MtlsServerConfig>,
}

impl MtlsHealthCommit<'_> {
    pub(crate) fn commit(mut self) {
        *self.guard = self.config.take();
    }
}

impl MtlsHealthSlot {
    pub(crate) fn new() -> Self {
        Self {
            config: Mutex::new(None),
        }
    }

    pub(crate) fn prepare_commit(
        &self,
        config: httpd::MtlsServerConfig,
    ) -> anyhow::Result<MtlsHealthCommit<'_>> {
        let guard = self
            .config
            .lock()
            .map_err(|_| anyhow::anyhow!("mtls health slot lock poisoned"))?;
        Ok(MtlsHealthCommit {
            guard,
            config: Some(config),
        })
    }

    #[cfg(test)]
    #[allow(clippy::panic)] // reason: deliberately poison the mutex to exercise fail-closed preflight.
    pub(crate) fn poison_for_test(&self) {
        let _poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = self.config.lock().unwrap_or_else(|_| unreachable!());
            panic!("poison mTLS health slot for preflight test");
        }));
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

pub(crate) fn build_runtime_rate_limiter() -> Arc<GovernorLimiter> {
    Arc::new(GovernorLimiter::new(default_rate_quota()))
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
/// 层序（外→内）：security headers → request-id → correlation → 全请求 server budget → body-limit
/// → rate-limit（本函数 verify-bridge 后叠）→ 验签桥 → trace → enforce → handler。rate-limit outer 于验签桥保证限流在 auth 计算前生效
/// （INVARIANT RATELIMIT-BEFORE-AUTH-01：组合根在 verify-bridge 后 .layer ⇒ outer 于桥）。
///
/// Health is produced only from the consumed plan entry and does not receive token bridges or
/// rate limiting, so liveness/readiness probes remain isolated from authenticated traffic.
///
/// 借 `&mut Registry`，一次性消费 Primary authorizer 并 drain `finalize_routes`；registry 的探针在此后仍存活，组合根经
/// [`bootstrap::Registry::take_health_reporter`] 取出探针装入 `Arc<HealthReporter>`（`Send + Sync`）注入
/// Health listener 的 readyz handler（每请求 `report`）；整体非 `Sync` 的 `Registry`
/// 无法进 axum handler 闭包。
pub(crate) struct FinalizeListenerPlanInputs<'config, 'borrow> {
    pub(crate) execution_plan: ListenerExecutionPlan,
    pub(crate) config: SnapshotConfig<'config>,
    pub(crate) registry: &'borrow mut bootstrap::Registry,
    pub(crate) providers: &'borrow TokenProviderBindings,
    pub(crate) audit_sink: httpserve::AuditSinkHandle,
    pub(crate) audit_clock: Arc<dyn diport::Clock>,
    pub(crate) rate_limiter: Arc<GovernorLimiter>,
    pub(crate) metrics: Arc<dyn diport::MetricsExporter>,
    pub(crate) framework_routes: crate::runtime_inventory::RuntimeInventoryRoutes,
}

pub(crate) fn finalize_listener_plan(
    inputs: FinalizeListenerPlanInputs<'_, '_>,
) -> anyhow::Result<FinalizedListenerPlan> {
    let FinalizeListenerPlanInputs {
        execution_plan,
        config,
        registry,
        providers,
        audit_sink,
        audit_clock,
        rate_limiter,
        metrics,
        framework_routes,
    } = inputs;
    providers.validate_exact_presence(&execution_plan)?;
    let internal_mtls_allow_set = config.value(INTERNAL_MTLS_SPIFFE_ALLOW_SET_ENV);
    let spiffe_endpoint = config.value(SPIFFE_ENDPOINT_SOCKET_ENV);
    crate::modules_gen::register_framework_routes(&framework_routes, registry)
        .context("register framework routes")?;
    let primary_authorizer = registry
        .take_primary_authorizer()
        .context("take Primary route authorizer")?;
    // 默认限流配额（owner=组合根，可调）：10 req/s，burst 20。peer-IP keyed（见 #1106 / RealIP follow-up）。
    // 共享跨所有 listener——统一 per-IP 预算，避免分散 listener 各自独立 bucket 使 burst 预算 N 倍膨胀。
    //
    // 已知限制（multi-instance）：in-mem `GovernorLimiter` 是 per-instance 独立桶，N 副本部署下
    // 每实例独立配额（全局视图 ≈ N × 单实例率）；全局一致限流须 redis-distributed provider（future）。
    // 叠加 peer-IP-after-proxy 退化（RealIP follow-up），本限流当前为单实例 best-effort 防护。
    let mut live_routes = registry.finalize_routes().context("finalize_routes")?;
    bootstrap::validate_framework_serving(&live_routes, crate::modules_gen::FRAMEWORK_HTTP_ROUTES)
        .context("validate framework serving")?;
    for (listener, _) in &live_routes {
        anyhow::ensure!(
            execution_plan
                .listeners()
                .iter()
                .any(|spec| spec.kind() == *listener && spec.kind() != ListenerKind::Health),
            "live listener {listener:?} is not declared by RuntimePlan"
        );
    }

    let mut finalized = Vec::with_capacity(execution_plan.listeners().len());
    let mut health = None;
    for (plan_index, spec) in execution_plan.into_listeners().into_iter().enumerate() {
        let listener = spec.kind();
        let scheme = spec.auth_scheme();
        if listener == ListenerKind::Health {
            anyhow::ensure!(
                scheme == AuthScheme::NoAuth && spec.domains().is_empty(),
                "Health RuntimePlan entry must be NoAuth and domain-free"
            );
            anyhow::ensure!(
                health.replace((plan_index, spec)).is_none(),
                "RuntimePlan declares Health listener more than once"
            );
            continue;
        }
        anyhow::ensure!(
            scheme != AuthScheme::NoAuth,
            "non-Health RuntimePlan listener cannot use NoAuth"
        );
        let routes = match live_routes
            .iter()
            .position(|(live_listener, _)| *live_listener == listener)
        {
            Some(index) => live_routes.swap_remove(index).1,
            None if spec.domains().is_empty() => httpserve::UnfinalizedRoutes::empty(),
            None => anyhow::bail!(
                "RuntimePlan listener {listener:?} declares domains but produced no live routes"
            ),
        };
        finalized.push((
            plan_index,
            finalize_non_health_spec(
                spec,
                routes,
                registry,
                providers,
                &audit_sink,
                &audit_clock,
                &primary_authorizer,
                &rate_limiter,
                internal_mtls_allow_set,
                spiffe_endpoint,
            )?,
        ));
    }
    anyhow::ensure!(
        live_routes.is_empty(),
        "live route finalization left undeclared listener routes"
    );

    let (health_index, health_spec) =
        health.context("RuntimePlan does not declare the required Health listener")?;
    let health_reporter = Arc::new(registry.take_health_reporter());
    let probe_receipt = FinalizedProbeReceipt { _private: () };
    let health = finalize_health_spec(health_spec, Arc::clone(&health_reporter), metrics)?;
    finalized.push((health_index, health));
    finalized.sort_by_key(|(plan_index, _)| *plan_index);
    Ok(FinalizedListenerPlan {
        listeners: FinalizedListenerSet {
            listeners: finalized
                .into_iter()
                .map(|(_, listener)| listener)
                .collect(),
        },
        probe_receipt,
        health_reporter,
    })
}

#[allow(clippy::too_many_arguments)]
fn finalize_non_health_spec(
    spec: ListenerExecutionSpec,
    routes: httpserve::UnfinalizedRoutes,
    registry: &mut bootstrap::Registry,
    providers: &TokenProviderBindings,
    audit_sink: &httpserve::AuditSinkHandle,
    audit_clock: &Arc<dyn diport::Clock>,
    primary_authorizer: &Arc<dyn httpserve::RouteAuthorizer>,
    rate_limiter: &Arc<GovernorLimiter>,
    internal_mtls_allow_set: Option<&str>,
    spiffe_endpoint: Option<&str>,
) -> anyhow::Result<AssembledListener> {
    let listener = spec.kind();
    let scheme = spec.auth_scheme();
    let binding = match scheme {
        AuthScheme::RssAccessToken
        | AuthScheme::FederatedAccessToken
        | AuthScheme::ServiceToken => {
            ListenerAuthBinding::Token(providers.profile_binding(scheme)?)
        }
        AuthScheme::Mtls => ListenerAuthBinding::Mtls,
        AuthScheme::NoAuth => anyhow::bail!("non-Health listener cannot use NoAuth"),
        _ => anyhow::bail!("unknown RuntimePlan auth scheme; refusing auth inference"),
    };
    anyhow::ensure!(
        binding.scheme() == scheme,
        "RuntimePlan auth scheme does not match selected provider binding"
    );
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
        #[cfg(feature = "integration")]
        ListenerTransport::InventoryJourneyPlaintext => None,
    };
    let authed = finalize_listener_auth_with_mtls(
        listener,
        routes,
        plan,
        audit_sink.clone(),
        Arc::clone(audit_clock),
        Arc::clone(primary_authorizer),
        mtls_authorizer,
    )
    .context("finalize_auth")?;
    let wired = match binding {
        ListenerAuthBinding::Token(profile) => auth_bridge::apply_verify_bridge(authed, profile),
        ListenerAuthBinding::Mtls => auth_bridge::apply_mtls_verify_bridge(authed),
    };
    let wired = wired.layer(axum::middleware::from_fn_with_state(
        Arc::clone(rate_limiter),
        httpserve::rate_limit::<GovernorLimiter>,
    ));
    tracing::info!(
        plan_id = spec.id(),
        listener = ?listener,
        auth_scheme = ?scheme,
        verify_bridge = true,
        "listener auth wiring assembled"
    );
    Ok(AssembledListener {
        spec,
        routes: wired,
        transport,
    })
}

fn finalize_health_spec(
    spec: ListenerExecutionSpec,
    reporter: Arc<bootstrap::HealthReporter>,
    metrics: Arc<dyn diport::MetricsExporter>,
) -> anyhow::Result<AssembledListener> {
    anyhow::ensure!(
        spec.kind() == ListenerKind::Health
            && spec.auth_scheme() == AuthScheme::NoAuth
            && spec.domains().is_empty(),
        "Health RuntimePlan entry must be Health + NoAuth and domain-free"
    );
    let routes = httpserve::health::routes(move || reporter.report(), move || metrics.render());
    let plan = AuthPlan::new(spec.kind(), spec.auth_scheme()).context("build Health auth plan")?;
    Ok(AssembledListener {
        spec,
        routes: httpserve::finalize_auth(routes, plan).context("finalize_auth Health")?,
        transport: ListenerTransport::Plaintext,
    })
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
    crate::phase::required_spiffe_endpoint_from_value(raw)
}

#[cfg(feature = "integration")]
pub(crate) fn finalize_rss_fixture_listener(
    registry: &mut bootstrap::Registry,
    provider: Arc<oidc::OidcProvider<diport::RssAccessProfile>>,
    grants: Arc<identity::AuthGrantValidationService>,
    audit_sink: httpserve::AuditSinkHandle,
    audit_clock: Arc<dyn diport::Clock>,
    kind: assembly_schema::AssemblyListenerKind,
) -> anyhow::Result<httpserve::AuthenticatedRoutes> {
    let spec = crate::plan::fixture_listener_spec(kind)?;
    anyhow::ensure!(
        matches!(spec.kind(), ListenerKind::Primary | ListenerKind::Admin)
            && spec.auth_scheme() == AuthScheme::RssAccessToken,
        "RSS integration fixture requires a plan-declared RSS access listener"
    );
    finalize_access_fixture_listener(
        registry,
        spec,
        TokenProviderBindings::new(Some(provider), Some(grants), None, None),
        audit_sink,
        audit_clock,
    )
}

#[cfg(feature = "integration")]
pub(crate) fn finalize_federated_fixture_listener(
    registry: &mut bootstrap::Registry,
    provider: Arc<oidc::OidcProvider<diport::FederatedAccessProfile>>,
    audit_sink: httpserve::AuditSinkHandle,
    audit_clock: Arc<dyn diport::Clock>,
    kind: assembly_schema::AssemblyListenerKind,
) -> anyhow::Result<httpserve::AuthenticatedRoutes> {
    let spec = crate::plan::fixture_listener_spec(kind)?.into_federated_access_fixture()?;
    finalize_access_fixture_listener(
        registry,
        spec,
        TokenProviderBindings::new(None, None, Some(provider), None),
        audit_sink,
        audit_clock,
    )
}

#[cfg(feature = "integration")]
fn finalize_access_fixture_listener(
    registry: &mut bootstrap::Registry,
    spec: crate::plan::ListenerExecutionSpec,
    providers: TokenProviderBindings,
    audit_sink: httpserve::AuditSinkHandle,
    audit_clock: Arc<dyn diport::Clock>,
) -> anyhow::Result<httpserve::AuthenticatedRoutes> {
    let primary_authorizer = registry
        .take_primary_authorizer()
        .context("take Primary route authorizer")?;
    let mut live_routes = registry.finalize_routes().context("finalize_routes")?;
    bootstrap::validate_framework_serving(&live_routes, &[])
        .context("validate framework serving")?;
    let index = live_routes
        .iter()
        .position(|(listener, _)| *listener == spec.kind())
        .context("selected RuntimePlan listener produced no live routes")?;
    let routes = live_routes.swap_remove(index).1;
    anyhow::ensure!(
        live_routes.is_empty(),
        "integration fixture contains live routes for an unselected listener"
    );
    let rate_limiter = build_runtime_rate_limiter();
    finalize_non_health_spec(
        spec,
        routes,
        registry,
        &providers,
        &audit_sink,
        &audit_clock,
        &primary_authorizer,
        &rate_limiter,
        None,
        None,
    )
    .map(|listener| listener.into_parts().1)
}

#[cfg(feature = "integration")]
pub(crate) fn finalize_health_fixture(
    reporter: Arc<bootstrap::HealthReporter>,
    metrics: Arc<dyn diport::MetricsExporter>,
) -> anyhow::Result<httpserve::AuthenticatedRoutes> {
    finalize_health_spec(
        crate::plan::fixture_listener_spec(assembly_schema::AssemblyListenerKind::Health)?,
        reporter,
        metrics,
    )
    .map(|listener| listener.into_parts().1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_snapshot;
    use crate::support::{SystemClock, TracingAuthAuditSink};
    use crate::{
        KeyedEs256StaticKey, RssAccessStaticProviderConfig, rss_access_provider_from_static_config,
    };

    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::routing::get;
    use base64::Engine as _;
    use httpserve::{
        TestPrimaryRoute as PrimaryRoute, TestRoute as Route,
        TestRoutePermission as RoutePermission, TestRouteResourceScope as RouteResourceScope,
    };
    use std::future::Future;
    use std::pin::Pin;
    use std::time::Duration;
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

    struct CurrentGrantValidator;

    impl identity::ports::AuthGrantValidator for CurrentGrantValidator {
        async fn is_current(
            &self,
            _scope: identity::ports::TenantRepoScope,
            _input: &authn::AccessGrantValidationInput,
            _observed_at: std::time::SystemTime,
        ) -> Result<bool, identity::ports::IdentityError> {
            Ok(true)
        }
    }

    fn runtime_test_grants() -> Arc<identity::AuthGrantValidationService> {
        Arc::new(identity::AuthGrantValidationService::new(
            identity::ports::DynAuthGrantValidator::new_arc(CurrentGrantValidator),
            Box::new(SystemClock),
        ))
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
                let endpoint = httpserve::GeneratedPrimaryEndpoint::new_producer(
                    generated::http::identity_v1::login::PRODUCER,
                    route_meta_capture_handler,
                )?
                .with_state(capture);
                Ok(router.mount(endpoint)?)
            })?;
            Ok(())
        }
    }

    async fn route_meta_capture_handler(
        _: httpserve::ProducerMarker<generated::http::identity_v1::login::RouteMarker>,
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
    fn runtime_test_provider() -> Arc<oidc::OidcProvider<diport::RssAccessProfile>> {
        use p256::ecdsa::SigningKey;

        let key = SigningKey::from_slice(&[7u8; 32]).expect("signing key");
        let public_key_b64 = B64.encode(key.verifying_key().to_encoded_point(false).as_bytes());
        let keys = [KeyedEs256StaticKey {
            key_id: "runtime-test-rss",
            sec1_b64url: &public_key_b64,
        }];
        Arc::new(
            rss_access_provider_from_static_config(RssAccessStaticProviderConfig {
                issuer: "https://issuer.test",
                audience: "rss-test",
                keys: &keys,
                retirement_schedule: None,
                clock: Box::new(SystemClock),
            })
            .expect("provider"),
        )
    }

    #[allow(clippy::expect_used)]
    fn runtime_test_federated_provider() -> Arc<oidc::OidcProvider<diport::FederatedAccessProfile>>
    {
        use p256::ecdsa::SigningKey;

        let key = SigningKey::from_slice(&[8u8; 32]).expect("federated signing key");
        let public_key = key.verifying_key().to_encoded_point(false);
        let keys = oidc::AccessStaticKeySource::builder()
            .add_es256_sec1("runtime-test-federated", public_key.as_bytes())
            .expect("federated public key")
            .build();
        let permissions =
            oidc::FederatedPermissionUniverse::try_new([vocab::GrantPermission::route(
                vocab::RoutePermissionId::RuntimeInventoryRead,
            )])
            .expect("non-empty federated permission universe");
        let config = oidc::VerifierConfigBuilder::<diport::FederatedAccessProfile>::new(
            "https://federated.issuer.test",
            "federated-test",
            permissions,
        )
        .keys_static(keys)
        .trust_kind("admin")
        .build()
        .expect("federated provider config");
        Arc::new(oidc::OidcProvider::new(config, Box::new(SystemClock)))
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

    #[allow(clippy::expect_used)]
    fn runtime_test_service_provider() -> Arc<oidc::OidcProvider<diport::ServiceTokenProfile>> {
        let keys = oidc::ServiceTokenKeySource::builder()
            .add_hs256_secret("runtime-test-service", &[0x55; 32])
            .expect("service-token key")
            .build();
        let replay_store = diport::DynServiceTokenReplayStore::new_arc(TestReplayStore);
        let config = oidc::VerifierConfigBuilder::<diport::ServiceTokenProfile>::new(
            "https://service.issuer.test",
            "service-test",
        )
        .keys_hs256(keys)
        .replay_store(replay_store, Duration::from_secs(5))
        .build()
        .expect("service-token provider config");
        Arc::new(oidc::OidcProvider::new(config, Box::new(SystemClock)))
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn primary_and_admin_selections_derive_the_exact_typed_profile_bindings() {
        let providers = TokenProviderBindings::new(
            Some(runtime_test_provider()),
            Some(runtime_test_grants()),
            Some(runtime_test_federated_provider()),
            None,
        );
        for expected_scheme in [AuthScheme::RssAccessToken, AuthScheme::FederatedAccessToken] {
            let binding = providers
                .profile_binding(expected_scheme)
                .expect("selected typed provider");
            assert_eq!(binding.auth_scheme(), expected_scheme);
            assert!(matches!(
                binding,
                ProfileBinding::RssAccess { .. } | ProfileBinding::FederatedAccess(_)
            ));
        }
    }

    fn assemble_test_plan(
        registry: &mut bootstrap::Registry,
        values: &[(&str, &str)],
        providers: &TokenProviderBindings,
    ) -> anyhow::Result<FinalizedListenerSet> {
        let live = registry.route_groups();
        if !live
            .iter()
            .any(|(listener, _)| *listener == ListenerKind::Primary)
        {
            registry.route_group::<httpserve::Primary>("/test-primary", Ok)?;
        }
        if !live
            .iter()
            .any(|(listener, _)| *listener == ListenerKind::Admin)
        {
            registry.route_group::<httpserve::Admin>("/test-admin", Ok)?;
        }
        let snapshot = test_snapshot(values)?;
        let framework_routes =
            crate::runtime_inventory::RuntimeInventoryRoutes::unpublished_fixture(snapshot.view())?;
        let execution_plan =
            crate::plan::RuntimePlan::bundled(snapshot.view())?.listener_execution_plan();
        finalize_listener_plan(FinalizeListenerPlanInputs {
            execution_plan,
            config: snapshot.view(),
            registry,
            providers,
            audit_sink: httpserve::AuditSinkHandle::new(TracingAuthAuditSink),
            audit_clock: Arc::new(SystemClock),
            rate_limiter: build_runtime_rate_limiter(),
            metrics: noop_metrics(),
            framework_routes,
        })
        .map(|plan| plan.into_parts().0)
    }

    fn assemble_rss_mtls_test(
        registry: &mut bootstrap::Registry,
        internal_mtls_allow_set: Option<&str>,
        spiffe_endpoint: Option<&str>,
    ) -> anyhow::Result<FinalizedListenerSet> {
        let mut values = vec![
            ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
            ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
        ];
        if let Some(allow_set) = internal_mtls_allow_set {
            values.push((INTERNAL_MTLS_SPIFFE_ALLOW_SET_ENV, allow_set));
        }
        if let Some(endpoint) = spiffe_endpoint {
            values.push((SPIFFE_ENDPOINT_SOCKET_ENV, endpoint));
        }
        let providers = TokenProviderBindings::new(
            Some(runtime_test_provider()),
            Some(runtime_test_grants()),
            None,
            None,
        );
        assemble_test_plan(registry, &values, &providers)
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn bundled_plan_finalizes_exact_four_listeners_and_keeps_internal_empty_router() {
        let mut registry = bootstrap::Registry::new();
        registry
            .register_primary_authorizer(allow_authorizer())
            .expect("Primary authorizer registered");

        let listeners = assemble_rss_mtls_test(
            &mut registry,
            Some("spiffe://example.org/ns/rss/sa/internal"),
            Some("unix:///run/spire/test.sock"),
        )
        .expect("finalize bundled listener plan")
        .into_listeners();
        let actual = listeners
            .iter()
            .map(|listener| (listener.listener(), listener.auth_scheme()))
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            vec![
                (ListenerKind::Admin, AuthScheme::RssAccessToken),
                (ListenerKind::Health, AuthScheme::NoAuth),
                (ListenerKind::Internal, AuthScheme::Mtls),
                (ListenerKind::Primary, AuthScheme::RssAccessToken),
            ]
        );
        let internal = listeners
            .iter()
            .find(|listener| listener.listener() == ListenerKind::Internal)
            .expect("Internal listener");
        assert!(matches!(internal.transport, ListenerTransport::Mtls { .. }));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn listener_finalizer_rejects_declared_missing_and_live_health_routes_before_launch() {
        fn snapshot() -> crate::config::RuntimeConfigSnapshot {
            test_snapshot(&[
                ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
                ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
                ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
                (
                    INTERNAL_MTLS_SPIFFE_ALLOW_SET_ENV,
                    "spiffe://example.org/ns/rss/sa/internal",
                ),
                (SPIFFE_ENDPOINT_SOCKET_ENV, "unix:///run/spire/test.sock"),
            ])
            .expect("listener snapshot")
        }

        let providers = TokenProviderBindings::new(
            Some(runtime_test_provider()),
            Some(runtime_test_grants()),
            None,
            None,
        );
        let mut missing = bootstrap::Registry::new();
        missing
            .register_primary_authorizer(allow_authorizer())
            .expect("Primary authorizer");
        let config = snapshot();
        let framework_routes =
            crate::runtime_inventory::RuntimeInventoryRoutes::unpublished_fixture(config.view())
                .expect("inventory fixture");
        let error = finalize_listener_plan(FinalizeListenerPlanInputs {
            execution_plan: crate::plan::RuntimePlan::bundled(config.view())
                .expect("RuntimePlan")
                .listener_execution_plan(),
            config: config.view(),
            registry: &mut missing,
            providers: &providers,
            audit_sink: httpserve::AuditSinkHandle::new(TracingAuthAuditSink),
            audit_clock: Arc::new(SystemClock),
            rate_limiter: build_runtime_rate_limiter(),
            metrics: noop_metrics(),
            framework_routes,
        })
        .err()
        .expect("declared Primary without live routes must fail");
        assert!(error.to_string().contains("produced no live routes"));

        let mut manual_health = bootstrap::Registry::new();
        manual_health
            .route_group::<httpserve::Primary>("/primary", Ok)
            .expect("Primary group");
        manual_health
            .route_group::<httpserve::Admin>("/admin", Ok)
            .expect("Admin group");
        manual_health
            .route_group::<httpserve::Health>("/manual-health", Ok)
            .expect("manual Health group");
        manual_health
            .register_primary_authorizer(allow_authorizer())
            .expect("Primary authorizer");
        let config = snapshot();
        let framework_routes =
            crate::runtime_inventory::RuntimeInventoryRoutes::unpublished_fixture(config.view())
                .expect("inventory fixture");
        let error = finalize_listener_plan(FinalizeListenerPlanInputs {
            execution_plan: crate::plan::RuntimePlan::bundled(config.view())
                .expect("RuntimePlan")
                .listener_execution_plan(),
            config: config.view(),
            registry: &mut manual_health,
            providers: &providers,
            audit_sink: httpserve::AuditSinkHandle::new(TracingAuthAuditSink),
            audit_clock: Arc::new(SystemClock),
            rate_limiter: build_runtime_rate_limiter(),
            metrics: noop_metrics(),
            framework_routes,
        })
        .err()
        .expect("manual live Health routes must fail");
        assert!(error.to_string().contains("not declared by RuntimePlan"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn provider_presence_is_an_exact_projection_of_plan_auth() {
        let rss = test_snapshot(&[
            ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
            ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
        ])
        .expect("RSS plan snapshot");
        let rss_plan = crate::plan::RuntimePlan::bundled(rss.view())
            .expect("RSS RuntimePlan")
            .listener_execution_plan();
        assert!(
            TokenProviderBindings::new(
                Some(runtime_test_provider()),
                Some(runtime_test_grants()),
                None,
                None,
            )
            .validate_exact_presence(&rss_plan)
            .is_ok()
        );
        assert!(
            TokenProviderBindings::new(
                Some(runtime_test_provider()),
                Some(runtime_test_grants()),
                Some(runtime_test_federated_provider()),
                None,
            )
            .validate_exact_presence(&rss_plan)
            .is_err()
        );

        let service = test_snapshot(&[
            ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
            ("RSS_INTERNAL_AUTH_SCHEME", "service-token"),
        ])
        .expect("service-token plan snapshot");
        let service_plan = crate::plan::RuntimePlan::bundled(service.view())
            .expect("service-token RuntimePlan")
            .listener_execution_plan();
        assert!(
            TokenProviderBindings::new(
                Some(runtime_test_provider()),
                Some(runtime_test_grants()),
                None,
                None,
            )
            .validate_exact_presence(&service_plan)
            .is_err()
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn federated_and_service_token_plans_finalize_through_typed_provider_bridges() {
        let mut federated_registry = bootstrap::Registry::new();
        federated_registry
            .register_primary_authorizer(allow_authorizer())
            .expect("Federated Primary authorizer");
        let federated_providers =
            TokenProviderBindings::new(None, None, Some(runtime_test_federated_provider()), None);
        let federated = assemble_test_plan(
            &mut federated_registry,
            &[
                ("RSS_PRIMARY_TOKEN_PROFILE", "federated-access"),
                ("RSS_ADMIN_TOKEN_PROFILE", "federated-access"),
                ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
                (
                    INTERNAL_MTLS_SPIFFE_ALLOW_SET_ENV,
                    "spiffe://example.org/ns/rss/sa/internal",
                ),
                (SPIFFE_ENDPOINT_SOCKET_ENV, "unix:///run/spire/test.sock"),
            ],
            &federated_providers,
        )
        .expect("Federated listener plan finalizes");
        let federated_schemes = federated
            .into_listeners()
            .into_iter()
            .map(|listener| (listener.listener(), listener.auth_scheme()))
            .collect::<Vec<_>>();
        assert!(
            federated_schemes.contains(&(ListenerKind::Primary, AuthScheme::FederatedAccessToken))
        );
        assert!(
            federated_schemes.contains(&(ListenerKind::Admin, AuthScheme::FederatedAccessToken))
        );

        let mut service_registry = bootstrap::Registry::new();
        service_registry
            .register_primary_authorizer(allow_authorizer())
            .expect("ServiceToken Primary authorizer");
        let service_providers = TokenProviderBindings::new(
            Some(runtime_test_provider()),
            Some(runtime_test_grants()),
            None,
            Some(runtime_test_service_provider()),
        );
        let service = assemble_test_plan(
            &mut service_registry,
            &[
                ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
                ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
                ("RSS_INTERNAL_AUTH_SCHEME", "service-token"),
            ],
            &service_providers,
        )
        .expect("ServiceToken listener plan finalizes");
        let internal = service
            .into_listeners()
            .into_iter()
            .find(|listener| listener.listener() == ListenerKind::Internal)
            .expect("ServiceToken Internal listener");
        assert_eq!(internal.auth_scheme(), AuthScheme::ServiceToken);
        assert!(matches!(internal.transport, ListenerTransport::Plaintext));
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

    struct HealthyProbe;

    impl bootstrap::HealthProbe for HealthyProbe {
        fn check(&self) -> HealthCheck {
            HealthCheck::new(
                ProbeName::parse("healthy-before-mtls")
                    .unwrap_or_else(|_| unreachable!("static probe name")),
                HealthStatus::Healthy,
                "ready",
            )
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn health_reporter_captures_mtls_probe_before_health_routes_finalize() {
        let mut registry = bootstrap::Registry::new();
        registry
            .register_primary_authorizer(allow_authorizer())
            .expect("Primary authorizer");
        let healthy_name =
            ProbeName::parse("healthy-before-mtls").expect("static healthy probe name");
        registry
            .probe(healthy_name, Box::new(HealthyProbe))
            .expect("healthy probe");

        let health = assemble_rss_mtls_test(
            &mut registry,
            Some("spiffe://example.org/ns/rss/sa/internal"),
            Some("unix:///run/spire/test.sock"),
        )
        .expect("finalize plan with mTLS probe")
        .into_listeners()
        .into_iter()
        .find(|listener| listener.listener() == ListenerKind::Health)
        .expect("Health listener");
        let (_, routes) = health.into_parts();
        let response = routes
            .into_router_for_test()
            .oneshot(
                Request::builder()
                    .uri("/health/v1/readyz")
                    .body(Body::empty())
                    .expect("readyz request"),
            )
            .await
            .expect("readyz response");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("readyz body");
        let body = std::str::from_utf8(&body).expect("readyz JSON");
        assert!(
            body.contains(MTLS_SOURCE_READY_PROBE_NAME),
            "Health reporter must retain the pre-bind mTLS probe: {body}"
        );
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
    fn route_assembly_requires_endpoint_for_internal_mtls() {
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
        let error = assemble_rss_mtls_test(
            &mut mtls_registry,
            Some("spiffe://example.org/ns/rss/sa/internal"),
            None,
        )
        .err()
        .expect("mTLS route assembly must fail without a captured SPIFFE endpoint");
        assert!(error.to_string().contains(SPIFFE_ENDPOINT_SOCKET_ENV));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn assemble_without_primary_authorizer_fails_closed() {
        let mut registry = bootstrap::compose(&[]).expect("compose empty");
        let error = assemble_rss_mtls_test(
            &mut registry,
            Some("spiffe://example.org/ns/rss/sa/internal"),
            Some("unix:///run/spire/test.sock"),
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
    async fn listener_plan_finalizer_smoke_segregates_listeners_and_finalizes_auth() {
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

        let listeners = assemble_rss_mtls_test(
            &mut registry,
            Some("spiffe://example.org/ns/rss/sa/internal"),
            Some("unix:///run/spire/test.sock"),
        )
        .expect("assemble listeners");
        let mut primary = None;
        let mut admin = None;
        let mut internal = None;
        let mut health = None;
        let mut unexpected = Vec::new();
        for assembled in listeners.into_listeners() {
            if assembled.listener() == ListenerKind::Internal {
                let carried = match &assembled.transport {
                    ListenerTransport::Mtls {
                        allow_set,
                        spiffe_endpoint,
                        ..
                    } => Some((allow_set, spiffe_endpoint)),
                    ListenerTransport::Plaintext => None,
                    #[cfg(feature = "integration")]
                    ListenerTransport::InventoryJourneyPlaintext => None,
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
                ListenerKind::Health => health = Some(routes.into_router_for_test()),
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
        let health = health.expect("health listener");

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

        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::RssAccessToken)
            .expect("Primary JWT plan");
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
                                        federated_permissions: None,
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
        let plan =
            AuthPlan::new(ListenerKind::Admin, AuthScheme::RssAccessToken).expect("admin jwt plan");
        let routes = finalize_listener_auth(
            ListenerKind::Admin,
            admin,
            plan,
            httpserve::AuditSinkHandle::new(TracingAuthAuditSink),
            Arc::new(SystemClock),
            allow_authorizer(),
        )
        .expect("finalize admin listener with primary authorizer");

        // 验签桥范式：请求携 Authenticated 证据。RssAccessToken 证据仅 User 可通过
        // AUTH-EVIDENCE-REQUIRE-01（Admin kind 会被滤成无证据 → 401）。
        // User 证据过桥后，注入的 primary authorizer 放行 → 200（#1710 + AUTH-EVIDENCE）。
        let mut request = Request::builder()
            .uri("/admin/probe")
            .body(Body::empty())
            .expect("request");
        request
            .extensions_mut()
            .insert(httpserve::Authenticated::new(
                RequiredScheme::RssAccessToken,
                vocab::PrincipalKind::User,
                "admin-subject",
                Some(
                    vocab::TenantId::parse("00000000-0000-4000-8000-000000000001").expect("tenant"),
                ),
            ));

        let response = routes
            .into_router_for_test()
            .oneshot(request)
            .await
            .expect("admin probe");
        assert_eq!(response.status(), StatusCode::OK);
    }
}
