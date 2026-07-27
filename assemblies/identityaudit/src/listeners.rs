//! Closed three-listener finalization and all-sockets-before-serve adapter.

use std::net::SocketAddr;
use std::num::{NonZeroU32, NonZeroU64};
use std::sync::Arc;

use anyhow::Context as _;
use diport::DynManagedResource;
use httpd::HttpServer;
use primitives::{AuthPlan, AuthScheme, ListenerKind};
use ratelimit::{GovernorLimiter, QuotaConfig};

pub(crate) fn rate_limiter() -> Arc<GovernorLimiter> {
    let rate = NonZeroU32::new(10).unwrap_or_else(|| unreachable!("non-zero literal"));
    let burst = NonZeroU32::new(20).unwrap_or_else(|| unreachable!("non-zero literal"));
    Arc::new(GovernorLimiter::new(QuotaConfig::per_second(rate, burst)))
}

fn auth_plan(kind: ListenerKind) -> anyhow::Result<AuthPlan> {
    match kind {
        ListenerKind::Primary | ListenerKind::Admin => {
            AuthPlan::new(kind, AuthScheme::RssAccessToken).context("build RSS listener auth plan")
        }
        ListenerKind::Health => AuthPlan::none(kind).context("build Health auth plan"),
        _ => anyhow::bail!("identityaudit admits only Primary, Admin and Health"),
    }
}

pub(crate) struct FinalizedListenerSet {
    primary: httpserve::AuthenticatedRoutes,
    admin: httpserve::AuthenticatedRoutes,
    health: httpserve::AuthenticatedRoutes,
}

pub(crate) struct FinalizedProbeReceipt {
    reporter: Arc<bootstrap::HealthReporter>,
}

impl FinalizedProbeReceipt {
    pub(crate) fn readiness(&self) -> Arc<bootstrap::HealthReporter> {
        Arc::clone(&self.reporter)
    }
}

pub(crate) struct FinalizeInputs {
    pub(crate) verifier: crate::auth_bridge::RssAccessVerifier,
    pub(crate) limiter: Arc<GovernorLimiter>,
    pub(crate) metrics: Arc<dyn diport::MetricsExporter>,
    pub(crate) audit_sink: httpserve::AuditSinkHandle,
    pub(crate) audit_clock: Arc<dyn diport::Clock>,
    pub(crate) reporter: Arc<bootstrap::HealthReporter>,
}

pub(crate) fn finalize(
    registry: &mut bootstrap::Registry,
    inputs: FinalizeInputs,
) -> anyhow::Result<(FinalizedListenerSet, FinalizedProbeReceipt)> {
    let authorizer = registry
        .take_primary_authorizer()
        .context("take Identity route authorizer")?;
    let mut live = registry
        .finalize_routes()
        .context("finalize identityaudit routes")?;
    bootstrap::validate_framework_serving(&live, crate::modules_gen::FRAMEWORK_HTTP_ROUTES)
        .context("validate identityaudit framework route exact set")?;
    let primary = take_routes(&mut live, ListenerKind::Primary)?;
    let admin = take_routes(&mut live, ListenerKind::Admin)?;
    anyhow::ensure!(
        live.is_empty(),
        "identityaudit produced undeclared listener routes"
    );

    let primary = httpserve::finalize_primary_auth_with_audit(
        primary,
        auth_plan(ListenerKind::Primary)?,
        inputs.audit_sink.clone(),
        Arc::clone(&inputs.audit_clock),
        Arc::clone(&authorizer),
    )
    .context("finalize identityaudit Primary auth")?;
    let admin = httpserve::finalize_auth_with_audit_and_authorizer(
        admin,
        auth_plan(ListenerKind::Admin)?,
        inputs.audit_sink,
        inputs.audit_clock,
        authorizer,
    )
    .context("finalize identityaudit Admin auth")?;
    let primary = with_access_layers(
        primary,
        inputs.verifier.clone(),
        Arc::clone(&inputs.limiter),
    );
    let admin = with_access_layers(admin, inputs.verifier, inputs.limiter);

    let reporter = inputs.reporter;
    let report = Arc::clone(&reporter);
    let health =
        httpserve::health::routes(move || report.report(), move || inputs.metrics.render());
    let health = httpserve::finalize_auth(health, auth_plan(ListenerKind::Health)?)
        .context("finalize identityaudit Health auth")?;
    Ok((
        FinalizedListenerSet {
            primary,
            admin,
            health,
        },
        FinalizedProbeReceipt { reporter },
    ))
}

fn take_routes(
    routes: &mut Vec<(ListenerKind, httpserve::UnfinalizedRoutes)>,
    kind: ListenerKind,
) -> anyhow::Result<httpserve::UnfinalizedRoutes> {
    let index = routes
        .iter()
        .position(|(candidate, _)| *candidate == kind)
        .with_context(|| format!("identityaudit {kind:?} routes are missing"))?;
    Ok(routes.swap_remove(index).1)
}

fn with_access_layers(
    routes: httpserve::AuthenticatedRoutes,
    verifier: crate::auth_bridge::RssAccessVerifier,
    limiter: Arc<GovernorLimiter>,
) -> httpserve::AuthenticatedRoutes {
    crate::auth_bridge::apply(routes, verifier).layer(axum::middleware::from_fn_with_state(
        limiter,
        httpserve::rate_limit::<GovernorLimiter>,
    ))
}

pub(crate) struct LaunchAdapter {
    listeners: FinalizedListenerSet,
    primary: SocketAddr,
    admin: SocketAddr,
    health: SocketAddr,
    budget: httpserve::ServerRequestBudget,
    inventory_publisher: runtimeexec::inventory::InventoryPublisher,
}

impl LaunchAdapter {
    pub(crate) fn new(
        listeners: FinalizedListenerSet,
        primary: SocketAddr,
        admin: SocketAddr,
        health: SocketAddr,
        budget: std::time::Duration,
        inventory_publisher: runtimeexec::inventory::InventoryPublisher,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            listeners,
            primary,
            admin,
            health,
            budget: server_request_budget(budget)?,
            inventory_publisher,
        })
    }
}

fn server_request_budget(
    budget: std::time::Duration,
) -> anyhow::Result<httpserve::ServerRequestBudget> {
    let millis = u64::try_from(budget.as_millis()).context("request budget too large")?;
    let millis = NonZeroU64::new(millis).context("request budget must be non-zero")?;
    Ok(httpserve::ServerRequestBudget::from_millis(millis))
}

struct PreparedListener {
    bound: httpd::BoundHttpServer,
    service: httpserve::ServerMakeService,
}

pub(crate) struct PreparedListeners {
    primary: PreparedListener,
    admin: PreparedListener,
    health: PreparedListener,
}

pub(crate) struct PreparedLaunchListeners {
    listeners: PreparedListeners,
    inventory_publisher: runtimeexec::inventory::InventoryPublisher,
}

#[derive(Clone, Copy)]
pub(crate) struct ListenerInventory {
    pub(crate) primary: SocketAddr,
    pub(crate) admin: SocketAddr,
    pub(crate) health: SocketAddr,
}

impl runtimeexec::LaunchAdapter<FinalizedProbeReceipt> for LaunchAdapter {
    type Prepared = PreparedLaunchListeners;
    type Inventory = ListenerInventory;

    async fn prepare(
        self,
        _receipt: FinalizedProbeReceipt,
        _transaction: &mut runtimeexec::LaunchTransaction<'_>,
    ) -> anyhow::Result<Self::Prepared> {
        let listeners = prepare_listeners(
            self.listeners,
            self.primary,
            self.admin,
            self.health,
            self.budget,
        )
        .await?;
        Ok(PreparedLaunchListeners {
            listeners,
            inventory_publisher: self.inventory_publisher,
        })
    }

    fn activate(
        prepared: Self::Prepared,
        mut registrar: runtimeexec::LaunchRegistrar<'_>,
    ) -> anyhow::Result<runtimeexec::Activated<Self::Inventory>> {
        let PreparedLaunchListeners {
            listeners: prepared,
            inventory_publisher,
        } = prepared;
        let observations = bound_listener_observations(&prepared);
        let inventory = ListenerInventory {
            primary: prepared.primary.bound.local_addr(),
            admin: prepared.admin.bound.local_addr(),
            health: prepared.health.bound.local_addr(),
        };
        inventory_publisher
            .publish(observations)
            .context("publish exact identityaudit listener inventory")?;
        register(prepared.primary, &mut registrar);
        register(prepared.admin, &mut registrar);
        register(prepared.health, &mut registrar);
        registrar.complete(inventory)
    }
}

fn bound_listener_observations(
    prepared: &PreparedListeners,
) -> Vec<runtimeexec::inventory::BoundListenerObservation> {
    Vec::from([
        runtimeexec::inventory::BoundListenerObservation::from_bound(
            "primary-main",
            assembly_schema::AssemblyListenerKind::Primary,
            assembly_schema::ListenerAuth::RssAccessToken,
            runtimeexec::inventory::InventoryEndpointScheme::Http,
            prepared.primary.bound.local_addr(),
        ),
        runtimeexec::inventory::BoundListenerObservation::from_bound(
            "admin-main",
            assembly_schema::AssemblyListenerKind::Admin,
            assembly_schema::ListenerAuth::RssAccessToken,
            runtimeexec::inventory::InventoryEndpointScheme::Http,
            prepared.admin.bound.local_addr(),
        ),
        runtimeexec::inventory::BoundListenerObservation::from_bound(
            "health-main",
            assembly_schema::AssemblyListenerKind::Health,
            assembly_schema::ListenerAuth::NoAuth,
            runtimeexec::inventory::InventoryEndpointScheme::Http,
            prepared.health.bound.local_addr(),
        ),
    ])
}

async fn prepare_listeners(
    listeners: FinalizedListenerSet,
    primary_address: SocketAddr,
    admin_address: SocketAddr,
    health_address: SocketAddr,
    budget: httpserve::ServerRequestBudget,
) -> anyhow::Result<PreparedListeners> {
    let primary = HttpServer::bind("identityaudit-primary", primary_address)
        .await
        .context("bind identityaudit Primary")?;
    let admin = HttpServer::bind("identityaudit-admin", admin_address)
        .await
        .context("bind identityaudit Admin")?;
    let health = HttpServer::bind("identityaudit-health", health_address)
        .await
        .context("bind identityaudit Health")?;
    Ok(PreparedListeners {
        primary: PreparedListener {
            bound: primary,
            service: listeners.primary.into_make_service(budget),
        },
        admin: PreparedListener {
            bound: admin,
            service: listeners.admin.into_make_service(budget),
        },
        health: PreparedListener {
            bound: health,
            service: listeners.health.into_make_service(budget),
        },
    })
}

fn register(listener: PreparedListener, registrar: &mut runtimeexec::LaunchRegistrar<'_>) {
    registrar.register_listener_with_token(move |token| {
        DynManagedResource::new_box(listener.bound.serve(listener.service, token))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use diport::RateLimiter as _;

    fn empty_listener_set() -> anyhow::Result<FinalizedListenerSet> {
        let routes = || {
            httpserve::finalize_auth(
                httpserve::UnfinalizedRoutes::empty(),
                AuthPlan::none(ListenerKind::Health)?,
            )
            .map_err(anyhow::Error::from)
        };
        Ok(FinalizedListenerSet {
            primary: routes()?,
            admin: routes()?,
            health: routes()?,
        })
    }

    fn free_address() -> std::io::Result<SocketAddr> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        drop(listener);
        Ok(address)
    }

    #[test]
    fn listener_auth_profiles_are_closed() -> anyhow::Result<()> {
        assert_eq!(
            auth_plan(ListenerKind::Primary)?.scheme(),
            AuthScheme::RssAccessToken
        );
        assert_eq!(
            auth_plan(ListenerKind::Admin)?.scheme(),
            AuthScheme::RssAccessToken
        );
        assert_eq!(
            auth_plan(ListenerKind::Health)?.scheme(),
            AuthScheme::NoAuth
        );
        assert!(auth_plan(ListenerKind::Internal).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn runtime_inventory_admin_pairs_rss_user_bridge_with_identity_durable_authorizer()
    -> anyhow::Result<()> {
        let tenant = vocab::TenantId::parse("00000000-0000-4000-8000-000000001797")?;
        let mut bindings = vec![identity_composition::test_support::binding()?];
        let (mut registry, _output) = bootstrap::compose_bindings(&mut bindings)?;
        let registered = registry.take_primary_authorizer()?;
        assert_eq!(
            auth_plan(ListenerKind::Admin)?.scheme(),
            AuthScheme::RssAccessToken,
            "production Admin listener must retain the RSS User-only verifier"
        );

        let request = httpserve::RouteAuthorizationRequest {
            contract_id: generated::http::runtime_v1::inventory::SPEC
                .route
                .contract_id(),
            permission: vocab::RoutePermissionId::RuntimeInventoryRead,
            tenant_id: Some(tenant),
            principal_kind: vocab::PrincipalKind::User,
            principal_id: "unbound-rss-user".to_string(),
            resource: None,
        };
        assert_eq!(
            registered.authorize(request).await,
            httpserve::RouteAuthorizationDecision::Deny
        );
        Ok(())
    }

    #[test]
    fn launch_adapter_rejects_invalid_request_budgets() -> anyhow::Result<()> {
        assert!(server_request_budget(std::time::Duration::ZERO).is_err());
        assert!(server_request_budget(std::time::Duration::MAX).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn all_listener_sockets_are_bound_before_preparation_succeeds() -> anyhow::Result<()> {
        assert!(matches!(
            rate_limiter()
                .check(diport::RateLimitKey::new("coverage-client"))
                .await?,
            diport::RateLimitDecision::Allowed
        ));
        let zero = "127.0.0.1:0".parse()?;
        let budget = httpserve::ServerRequestBudget::from_millis(
            NonZeroU64::new(1_000).ok_or_else(|| anyhow::anyhow!("non-zero literal"))?,
        );
        let prepared = prepare_listeners(empty_listener_set()?, zero, zero, zero, budget).await?;
        let addresses = [
            prepared.primary.bound.local_addr(),
            prepared.admin.bound.local_addr(),
            prepared.health.bound.local_addr(),
        ];
        assert!(addresses.iter().all(|address| address.port() != 0));
        assert_ne!(addresses[0], addresses[1]);
        assert_ne!(addresses[0], addresses[2]);
        assert_ne!(addresses[1], addresses[2]);
        Ok(())
    }

    #[tokio::test]
    async fn later_bind_failure_rolls_back_earlier_listener() -> anyhow::Result<()> {
        let primary = free_address()?;
        let occupied_admin = std::net::TcpListener::bind("127.0.0.1:0")?;
        let admin = occupied_admin.local_addr()?;
        let health = free_address()?;
        let budget = httpserve::ServerRequestBudget::from_millis(
            NonZeroU64::new(1_000).ok_or_else(|| anyhow::anyhow!("non-zero literal"))?,
        );

        let error = prepare_listeners(empty_listener_set()?, primary, admin, health, budget)
            .await
            .err()
            .ok_or_else(|| anyhow::anyhow!("occupied Admin listener unexpectedly bound"))?;
        assert!(error.to_string().contains("Admin"));
        let rebound = std::net::TcpListener::bind(primary)?;
        assert_eq!(rebound.local_addr()?, primary);
        Ok(())
    }

    #[test]
    fn route_and_probe_receipts_are_move_only_and_fail_closed() -> anyhow::Result<()> {
        let mut routes = vec![
            (ListenerKind::Primary, httpserve::UnfinalizedRoutes::empty()),
            (ListenerKind::Admin, httpserve::UnfinalizedRoutes::empty()),
        ];
        let _primary = take_routes(&mut routes, ListenerKind::Primary)?;
        assert_eq!(routes.len(), 1);
        let _admin = take_routes(&mut routes, ListenerKind::Admin)?;
        assert!(routes.is_empty());
        assert!(take_routes(&mut routes, ListenerKind::Health).is_err());

        let mut registry = bootstrap::compose(&[])?;
        let reporter = Arc::new(registry.take_health_reporter());
        let receipt = FinalizedProbeReceipt {
            reporter: Arc::clone(&reporter),
        };
        assert!(Arc::ptr_eq(&receipt.readiness(), &reporter));
        Ok(())
    }
}
