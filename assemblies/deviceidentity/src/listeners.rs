//! Closed three-listener finalization and all-sockets-before-serve launch adapter.

use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::sync::Arc;

use anyhow::Context as _;
use httpd::HttpServer;
use primitives::{AuthPlan, AuthScheme, ListenerKind};

pub(crate) struct FinalizedListenerSet {
    primary: httpserve::RateLimitedRoutes,
    internal: httpserve::RateLimitedRoutes,
    health: httpserve::HealthRoutes,
}

pub(crate) fn finalize<S>(
    components: identity_composition::DevicePolicyCandidateComponents,
    write_admission: primitives::WriteAdmission,
    verifier: crate::auth_bridge::FederatedVerifier,
    limiter: Arc<S>,
    audit_sink: httpserve::AuditSinkHandle,
    reporter: Arc<bootstrap::HealthReporter>,
    metrics: Arc<dyn diport::MetricsExporter>,
    trusted_proxy_config: httpserve::TrustedProxyConfig,
) -> anyhow::Result<FinalizedListenerSet>
where
    S: diport::RateLimiter + Send + Sync + 'static,
{
    let binding = components.binding();
    let status = components.status();
    let primary = httpserve::UnfinalizedRoutes::with_mutation_admission(write_admission)
        .nest_group::<httpserve::Primary, _>("/api/v2/identity", |router| {
            identity::register_device_candidate_routes(router, Arc::clone(&binding), status)
        })
        .context("mount exact device candidate Primary routes")?;
    let primary = httpserve::finalize_primary_auth_with_audit(
        primary,
        AuthPlan::new(ListenerKind::Primary, AuthScheme::FederatedAccessToken)?,
        audit_sink,
        Arc::new(crate::runtime::ProcessClock),
        binding,
    )
    .context("finalize deviceidentity Primary auth")?;
    let primary = with_rate_limit(
        crate::auth_bridge::apply(primary, verifier),
        Arc::clone(&limiter),
        trusted_proxy_config,
    );
    let internal = httpserve::finalize_auth(
        httpserve::UnfinalizedRoutes::empty(),
        AuthPlan::new(ListenerKind::Internal, AuthScheme::Mtls)?,
    )
    .context("finalize empty deviceidentity Internal router")?;
    let internal = with_rate_limit(internal, limiter, httpserve::TrustedProxyConfig::disabled());
    let report = Arc::clone(&reporter);
    let health = httpserve::health::routes(move || report.report(), move || metrics.render());
    let health = httpserve::finalize_health(health, AuthPlan::none(ListenerKind::Health)?)
        .context("finalize deviceidentity Health routes")?;
    Ok(FinalizedListenerSet {
        primary,
        internal,
        health,
    })
}

fn with_rate_limit<S>(
    routes: httpserve::AuthenticatedRoutes,
    limiter: Arc<S>,
    trusted_proxy_config: httpserve::TrustedProxyConfig,
) -> httpserve::RateLimitedRoutes
where
    S: diport::RateLimiter + Send + Sync + 'static,
{
    httpserve::with_client_rate_limit(routes, limiter, trusted_proxy_config)
}

pub(crate) struct LaunchAdapter {
    listeners: FinalizedListenerSet,
    primary: SocketAddr,
    internal: SocketAddr,
    health: SocketAddr,
    budget: httpserve::ServerRequestBudget,
    internal_mtls: httpd::MtlsServerConfig,
    inventory_publisher: runtimeexec::inventory::InventoryPublisher,
}

impl LaunchAdapter {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        listeners: FinalizedListenerSet,
        primary: SocketAddr,
        internal: SocketAddr,
        health: SocketAddr,
        budget: std::time::Duration,
        internal_mtls: httpd::MtlsServerConfig,
        inventory_publisher: runtimeexec::inventory::InventoryPublisher,
    ) -> anyhow::Result<Self> {
        let millis = NonZeroU64::new(u64::try_from(budget.as_millis())?)
            .context("request budget must be non-zero")?;
        Ok(Self {
            listeners,
            primary,
            internal,
            health,
            budget: httpserve::ServerRequestBudget::from_millis(millis),
            internal_mtls,
            inventory_publisher,
        })
    }
}

struct PreparedListener {
    bound: httpd::BoundHttpServer,
    service: httpserve::ServerService,
}

struct PreparedMtlsListener {
    bound: httpd::BoundHttpServer,
    service: httpserve::ServerService,
    mtls: httpd::MtlsServerConfig,
}

pub(crate) struct PreparedListeners {
    primary: PreparedListener,
    internal: PreparedMtlsListener,
    health: PreparedListener,
    inventory_publisher: runtimeexec::inventory::InventoryPublisher,
}

pub(crate) struct ListenerInventory {
    pub(crate) primary: SocketAddr,
    pub(crate) internal: SocketAddr,
    pub(crate) health: SocketAddr,
}

impl runtimeexec::LaunchAdapter<Arc<bootstrap::HealthReporter>> for LaunchAdapter {
    type Prepared = PreparedListeners;
    type Inventory = ListenerInventory;

    async fn prepare(
        self,
        _receipt: Arc<bootstrap::HealthReporter>,
        _transaction: &mut runtimeexec::LaunchTransaction<'_>,
    ) -> anyhow::Result<Self::Prepared> {
        let primary = HttpServer::bind("deviceidentity-primary", self.primary).await?;
        let internal = HttpServer::bind("deviceidentity-internal", self.internal).await?;
        let health = HttpServer::bind("deviceidentity-health", self.health).await?;
        Ok(PreparedListeners {
            primary: PreparedListener {
                bound: primary,
                service: self.listeners.primary.into_server_service(self.budget),
            },
            internal: PreparedMtlsListener {
                bound: internal,
                service: self.listeners.internal.into_server_service(self.budget),
                mtls: self.internal_mtls,
            },
            health: PreparedListener {
                bound: health,
                service: self.listeners.health.into_server_service(self.budget),
            },
            inventory_publisher: self.inventory_publisher,
        })
    }

    fn activate(
        prepared: Self::Prepared,
        mut registrar: runtimeexec::LaunchRegistrar<'_>,
    ) -> anyhow::Result<runtimeexec::Activated<Self::Inventory>> {
        let inventory = ListenerInventory {
            primary: prepared.primary.bound.local_addr(),
            internal: prepared.internal.bound.local_addr(),
            health: prepared.health.bound.local_addr(),
        };
        prepared.inventory_publisher.publish(Vec::from([
            runtimeexec::inventory::BoundListenerObservation::from_bound(
                "primary-main",
                assembly_schema::AssemblyListenerKind::Primary,
                assembly_schema::ListenerAuth::FederatedAccessToken,
                runtimeexec::inventory::InventoryEndpointScheme::Http,
                inventory.primary,
            ),
            runtimeexec::inventory::BoundListenerObservation::from_bound(
                "internal-main",
                assembly_schema::AssemblyListenerKind::Internal,
                assembly_schema::ListenerAuth::Mtls,
                runtimeexec::inventory::InventoryEndpointScheme::Https,
                inventory.internal,
            ),
            runtimeexec::inventory::BoundListenerObservation::from_bound(
                "health-main",
                assembly_schema::AssemblyListenerKind::Health,
                assembly_schema::ListenerAuth::NoAuth,
                runtimeexec::inventory::InventoryEndpointScheme::Http,
                inventory.health,
            ),
        ]))?;
        register(prepared.primary, &mut registrar);
        register_mtls(prepared.internal, &mut registrar);
        register(prepared.health, &mut registrar);
        registrar.complete(inventory)
    }
}

fn register(listener: PreparedListener, registrar: &mut runtimeexec::LaunchRegistrar<'_>) {
    registrar
        .register_listener_with_token(move |token| listener.bound.serve(listener.service, token));
}

fn register_mtls(listener: PreparedMtlsListener, registrar: &mut runtimeexec::LaunchRegistrar<'_>) {
    registrar.register_listener_with_token(move |token| {
        listener
            .bound
            .serve_mtls(listener.service, listener.mtls, token)
    });
}
