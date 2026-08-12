//! Closed three-listener finalization and all-sockets-before-serve adapter.

use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::sync::Arc;

use anyhow::Context as _;
use diport::DynManagedResource;
use httpd::HttpServer;
use primitives::{AuthPlan, AuthScheme, ListenerKind};
#[cfg(any(test, feature = "test-support"))]
use ratelimit::GovernorLimiter;

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn rate_limiter() -> Arc<GovernorLimiter> {
    let quota = diport::RateLimitQuota::try_new(10, 20)
        .unwrap_or_else(|_| unreachable!("valid test quota"));
    Arc::new(GovernorLimiter::new(quota))
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
    primary: httpserve::RateLimitedRoutes,
    admin: httpserve::RateLimitedRoutes,
    health: httpserve::HealthRoutes,
}

pub(crate) struct FinalizedProbeReceipt {
    reporter: Arc<bootstrap::HealthReporter>,
}

impl FinalizedProbeReceipt {
    pub(crate) fn readiness(&self) -> Arc<bootstrap::HealthReporter> {
        Arc::clone(&self.reporter)
    }
}

pub(crate) struct FinalizeInputs<S> {
    pub(crate) verifier: crate::auth_bridge::RssAccessVerifier,
    pub(crate) limiter: Arc<S>,
    pub(crate) trusted_proxy_config: httpserve::TrustedProxyConfig,
    pub(crate) metrics: Arc<dyn diport::MetricsExporter>,
    pub(crate) audit_sink: httpserve::AuditSinkHandle,
    pub(crate) audit_clock: Arc<dyn diport::Clock>,
    pub(crate) reporter: Arc<bootstrap::HealthReporter>,
}

pub(crate) fn finalize<S>(
    registry: &mut bootstrap::Registry,
    inputs: FinalizeInputs<S>,
) -> anyhow::Result<(FinalizedListenerSet, FinalizedProbeReceipt)>
where
    S: diport::RateLimiter + Send + Sync + 'static,
{
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
        inputs.trusted_proxy_config.clone(),
    );
    let admin = with_access_layers(
        admin,
        inputs.verifier,
        inputs.limiter,
        inputs.trusted_proxy_config,
    );

    let reporter = inputs.reporter;
    let report = Arc::clone(&reporter);
    let health =
        httpserve::health::routes(move || report.report(), move || inputs.metrics.render());
    let health = httpserve::finalize_health(health, auth_plan(ListenerKind::Health)?)
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

fn with_access_layers<S>(
    routes: httpserve::AuthenticatedRoutes,
    verifier: crate::auth_bridge::RssAccessVerifier,
    limiter: Arc<S>,
    trusted_proxy_config: httpserve::TrustedProxyConfig,
) -> httpserve::RateLimitedRoutes
where
    S: diport::RateLimiter + Send + Sync + 'static,
{
    httpserve::with_client_rate_limit(
        crate::auth_bridge::apply(routes, verifier),
        limiter,
        trusted_proxy_config,
    )
}

pub(crate) struct LaunchAdapter {
    listeners: FinalizedListenerSet,
    primary: SocketAddr,
    admin: SocketAddr,
    health: SocketAddr,
    budget: httpserve::ServerRequestBudget,
    inventory_publisher: runtimeexec::inventory::InventoryPublisher,
    frontend: Option<crate::config::ServingFrontendConfig>,
}

impl LaunchAdapter {
    pub(crate) fn new(
        listeners: FinalizedListenerSet,
        primary: SocketAddr,
        admin: SocketAddr,
        health: SocketAddr,
        budget: std::time::Duration,
        inventory_publisher: runtimeexec::inventory::InventoryPublisher,
        frontend: Option<crate::config::ServingFrontendConfig>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            listeners,
            primary,
            admin,
            health,
            budget: server_request_budget(budget)?,
            inventory_publisher,
            frontend,
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
    service: httpserve::ServerService,
}

struct PreparedMtlsListener {
    bound: httpd::BoundHttpServer,
    service: httpserve::ServerService,
    mtls: httpd::MtlsServerConfig,
}

pub(crate) struct PreparedListeners {
    primary: PreparedListener,
    admin: PreparedListener,
    health: PreparedListener,
    primary_front: Option<PreparedMtlsListener>,
    admin_front: Option<PreparedMtlsListener>,
    health_front: Option<PreparedListener>,
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
        transaction: &mut runtimeexec::LaunchTransaction<'_>,
    ) -> anyhow::Result<Self::Prepared> {
        let listeners = prepare_listeners(
            self.listeners,
            self.primary,
            self.admin,
            self.health,
            self.budget,
        )
        .await?;
        let listeners = prepare_frontends(listeners, self.frontend, transaction).await?;
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
        let primary_bound = prepared
            .primary_front
            .as_ref()
            .map_or(&prepared.primary.bound, |front| &front.bound);
        let admin_bound = prepared
            .admin_front
            .as_ref()
            .map_or(&prepared.admin.bound, |front| &front.bound);
        let health_bound = prepared
            .health_front
            .as_ref()
            .map_or(&prepared.health.bound, |front| &front.bound);
        let edge_scheme = if prepared.primary_front.is_some() {
            runtimeexec::inventory::InventoryEndpointScheme::Https
        } else {
            runtimeexec::inventory::InventoryEndpointScheme::Http
        };
        let observations = Vec::from([
            runtimeexec::inventory::BoundListenerObservation::from_bound(
                "primary-main",
                assembly_schema::AssemblyListenerKind::Primary,
                assembly_schema::ListenerAuth::RssAccessToken,
                edge_scheme,
                prepared
                    .primary_front
                    .as_ref()
                    .map_or(&prepared.primary.bound, |front| &front.bound)
                    .local_addr(),
            ),
            runtimeexec::inventory::BoundListenerObservation::from_bound(
                "admin-main",
                assembly_schema::AssemblyListenerKind::Admin,
                assembly_schema::ListenerAuth::RssAccessToken,
                edge_scheme,
                prepared
                    .admin_front
                    .as_ref()
                    .map_or(&prepared.admin.bound, |front| &front.bound)
                    .local_addr(),
            ),
            runtimeexec::inventory::BoundListenerObservation::from_bound(
                "health-main",
                assembly_schema::AssemblyListenerKind::Health,
                assembly_schema::ListenerAuth::NoAuth,
                runtimeexec::inventory::InventoryEndpointScheme::Http,
                prepared
                    .health_front
                    .as_ref()
                    .map_or(&prepared.health.bound, |front| &front.bound)
                    .local_addr(),
            ),
        ]);
        let primary = primary_bound.local_addr();
        let admin = admin_bound.local_addr();
        let health = health_bound.local_addr();
        let inventory = ListenerInventory {
            primary,
            admin,
            health,
        };
        inventory_publisher
            .publish(observations)
            .context("publish exact identityaudit listener inventory")?;
        register(prepared.primary, &mut registrar);
        register(prepared.admin, &mut registrar);
        register(prepared.health, &mut registrar);
        if let Some(front) = prepared.primary_front {
            register_mtls(front, &mut registrar);
        }
        if let Some(front) = prepared.admin_front {
            register_mtls(front, &mut registrar);
        }
        if let Some(front) = prepared.health_front {
            register(front, &mut registrar);
        }
        registrar.complete(inventory)
    }
}

#[cfg(feature = "test-support")]
pub(crate) struct InventoryJourneyHttpResult {
    pub(crate) status: reqwest::StatusCode,
    pub(crate) body: Vec<u8>,
    pub(crate) serving_address: SocketAddr,
}

/// Exercise the production bind, listener-inventory publication and activation funnel with
/// kernel-assigned ports. The returned address is the exact Admin socket minted by activation.
#[cfg(feature = "test-support")]
pub(crate) async fn serve_inventory_journey(
    admin: httpserve::AuthenticatedRoutes,
    reporter: Arc<bootstrap::HealthReporter>,
    inventory_publisher: runtimeexec::inventory::InventoryPublisher,
    bearer: String,
) -> anyhow::Result<InventoryJourneyHttpResult> {
    struct JourneyMetrics;
    impl diport::MetricsExporter for JourneyMetrics {
        fn render(&self) -> String {
            "# inventory-journey\n".to_owned()
        }
    }
    let companion = || {
        let reporter = Arc::clone(&reporter);
        let metrics: Arc<dyn diport::MetricsExporter> = Arc::new(JourneyMetrics);
        httpserve::finalize_health(
            httpserve::health::routes(move || reporter.report(), move || metrics.render()),
            auth_plan(ListenerKind::Health)?,
        )
        .map_err(anyhow::Error::from)
    };
    let business = || {
        httpserve::finalize_auth(
            httpserve::UnfinalizedRoutes::empty(),
            auth_plan(ListenerKind::Admin)?,
        )
        .map_err(anyhow::Error::from)
    };
    let adapter = LaunchAdapter::new(
        FinalizedListenerSet {
            primary: httpserve::with_client_rate_limit(
                business()?,
                rate_limiter(),
                httpserve::TrustedProxyConfig::disabled(),
            ),
            admin: httpserve::with_client_rate_limit(
                admin,
                rate_limiter(),
                httpserve::TrustedProxyConfig::disabled(),
            ),
            health: companion()?,
        },
        "127.0.0.1:0".parse()?,
        "127.0.0.1:0".parse()?,
        "127.0.0.1:0".parse()?,
        std::time::Duration::from_secs(1),
        inventory_publisher,
        None,
    )?;
    let (completion, controlled) = runtimeexec::test_support::controlled();
    let launch = runtimeexec::LaunchPlan::new(
        adapter,
        FinalizedProbeReceipt { reporter },
        move |inventory: ListenerInventory| async move {
            let result = async {
                let response = reqwest::Client::new()
                    .get(format!(
                        "http://{}{}",
                        inventory.admin,
                        generated::http::runtime_v1::inventory::PATH
                    ))
                    .bearer_auth(bearer)
                    .send()
                    .await?;
                let status = response.status();
                let body = response.bytes().await?.to_vec();
                Ok(InventoryJourneyHttpResult {
                    status,
                    body,
                    serving_address: inventory.admin,
                })
            }
            .await;
            completion.complete(result)
        },
        None,
        runtimeexec::LaunchLifecycleBatches::new(
            runtimeexec::ProviderLifecycleBatch::from_provider_output(
                bootstrap::DomainModuleResult::default(),
            ),
            runtimeexec::DomainLifecycleBatch::from_domain_output(
                bootstrap::DomainModuleResult::default(),
            ),
            Some(bootstrap::ExpectedWorkerInventory::closed([])?),
        ),
        crate::runtime::total_drain_budget()?,
    );
    controlled.run(launch).await
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
            service: listeners.primary.into_server_service(budget),
        },
        admin: PreparedListener {
            bound: admin,
            service: listeners.admin.into_server_service(budget),
        },
        health: PreparedListener {
            bound: health,
            service: listeners.health.into_server_service(budget),
        },
        primary_front: None,
        admin_front: None,
        health_front: None,
    })
}

async fn prepare_frontends(
    mut listeners: PreparedListeners,
    frontend: Option<crate::config::ServingFrontendConfig>,
    transaction: &mut runtimeexec::LaunchTransaction<'_>,
) -> anyhow::Result<PreparedListeners> {
    let Some(frontend) = frontend else {
        return Ok(listeners);
    };
    let primary_bound = HttpServer::bind(
        "identityaudit-primary-mtls",
        SocketAddr::new(frontend.pod_ip, frontend.primary_port),
    )
    .await
    .context("bind identityaudit Primary mTLS frontend")?;
    let admin_bound = HttpServer::bind(
        "identityaudit-admin-mtls",
        SocketAddr::new(frontend.pod_ip, frontend.admin_port),
    )
    .await
    .context("bind identityaudit Admin mTLS frontend")?;
    let health_bound = HttpServer::bind(
        "identityaudit-health-front",
        SocketAddr::new(frontend.pod_ip, frontend.health_port),
    )
    .await
    .context("bind identityaudit Health frontend")?;
    #[cfg(feature = "test-support")]
    let use_test_mtls = std::env::var_os("RSS_IDENTITYAUDIT_TEST_MTLS").is_some();
    #[cfg(not(feature = "test-support"))]
    let use_test_mtls = false;
    let mtls = if use_test_mtls {
        #[cfg(feature = "test-support")]
        {
            httpd::MtlsServerConfig::for_test(frontend.allow_set.clone())
                .context("prepare hermetic identityaudit mTLS frontend")?
        }
        #[cfg(not(feature = "test-support"))]
        unreachable!()
    } else {
        httpd::MtlsServerConfig::from_spire(frontend.allow_set, Some(&frontend.spiffe_endpoint))
            .await
            .context("prepare identityaudit SPIFFE mTLS frontend")?
            .stage_with(|resource| transaction.stage_resource(resource))
    };
    listeners.primary_front = Some(PreparedMtlsListener {
        bound: primary_bound,
        service: listeners.primary.service.clone(),
        mtls: mtls.clone(),
    });
    listeners.admin_front = Some(PreparedMtlsListener {
        bound: admin_bound,
        service: listeners.admin.service.clone(),
        mtls,
    });
    listeners.health_front = Some(PreparedListener {
        bound: health_bound,
        service: listeners.health.service.clone(),
    });
    Ok(listeners)
}

fn register(listener: PreparedListener, registrar: &mut runtimeexec::LaunchRegistrar<'_>) {
    registrar.register_listener_with_token(move |token| {
        DynManagedResource::new_box(listener.bound.serve(listener.service, token))
    });
}

fn register_mtls(listener: PreparedMtlsListener, registrar: &mut runtimeexec::LaunchRegistrar<'_>) {
    registrar.register_listener_with_token(move |token| {
        DynManagedResource::new_box(listener.bound.serve_mtls(
            listener.service,
            listener.mtls,
            token,
        ))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use diport::RateLimiter as _;

    fn empty_listener_set() -> anyhow::Result<FinalizedListenerSet> {
        let business = || {
            httpserve::finalize_auth(
                httpserve::UnfinalizedRoutes::empty(),
                auth_plan(ListenerKind::Admin)?,
            )
            .map_err(anyhow::Error::from)
        };
        let health = || {
            httpserve::finalize_health(
                httpserve::UnfinalizedRoutes::empty(),
                AuthPlan::none(ListenerKind::Health)?,
            )
            .map_err(anyhow::Error::from)
        };
        Ok(FinalizedListenerSet {
            primary: httpserve::with_client_rate_limit(
                business()?,
                rate_limiter(),
                httpserve::TrustedProxyConfig::disabled(),
            ),
            admin: httpserve::with_client_rate_limit(
                business()?,
                rate_limiter(),
                httpserve::TrustedProxyConfig::disabled(),
            ),
            health: health()?,
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
        let tenant = rss_request_context::TenantId::parse("00000000-0000-4000-8000-000000001797")?;
        let mut bindings = vec![identity_composition::test_support::binding()?];
        let (mut registry, _output) = bootstrap::compose_bindings(&mut bindings)?;
        registry
            .register_primary_authorizer(identity_composition::test_support::root_authorizer())?;
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
            principal_kind: rss_request_context::PrincipalKind::User,
            principal_id: "unbound-rss-user".to_string(),
            federated_permissions: None,
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
