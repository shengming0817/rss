//! Private listener finalization and all-sockets-before-serve launch adapter.

use std::future::Future;
use std::net::SocketAddr;
use std::num::{NonZeroU32, NonZeroU64};
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Context as _;
use diport::DynManagedResource;
use httpd::HttpServer;
use primitives::{AuthPlan, AuthScheme, ListenerKind};
use ratelimit::{GovernorLimiter, QuotaConfig};

use crate::auth_bridge::{self, FederatedVerifier};

pub(crate) struct FederatedPermissionAuthorizer;

impl httpserve::RouteAuthorizer for FederatedPermissionAuthorizer {
    fn authorize<'a>(
        &'a self,
        request: httpserve::RouteAuthorizationRequest,
    ) -> Pin<Box<dyn Future<Output = httpserve::RouteAuthorizationDecision> + Send + 'a>> {
        Box::pin(async move {
            let exact_pair = matches!(
                (request.contract_id, request.permission),
                (
                    generated::http::settings_v1::CONTRACT_ID,
                    vocab::RoutePermissionId::SettingsConfigPublish,
                ) | (
                    generated::http::settings_v5::CONTRACT_ID,
                    vocab::RoutePermissionId::SettingsConfigDelete,
                ) | (
                    generated::http::settings_v6::CONTRACT_ID,
                    vocab::RoutePermissionId::SettingsConfigRollback,
                ) | (
                    generated::http::runtime_v1::inventory::CONTRACT_ID,
                    vocab::RoutePermissionId::RuntimeInventoryRead,
                )
            );
            let exact_grant = request
                .federated_permissions
                .as_deref()
                .is_some_and(|permissions| {
                    permissions
                        .iter()
                        .any(|grant| grant.matches_route(request.permission))
                });
            let tenant_shape = request.permission == vocab::RoutePermissionId::RuntimeInventoryRead
                || request.tenant_id.is_some();
            if exact_pair && exact_grant && tenant_shape {
                httpserve::RouteAuthorizationDecision::Allow
            } else {
                httpserve::RouteAuthorizationDecision::Deny
            }
        })
    }
}

pub(crate) fn rate_limiter() -> Arc<GovernorLimiter> {
    let per_second =
        NonZeroU32::new(10).unwrap_or_else(|| unreachable!("literal rate is non-zero"));
    let burst = NonZeroU32::new(20).unwrap_or_else(|| unreachable!("literal burst is non-zero"));
    Arc::new(GovernorLimiter::new(QuotaConfig::per_second(
        per_second, burst,
    )))
}

fn primary_auth_plan() -> anyhow::Result<AuthPlan> {
    AuthPlan::new(ListenerKind::Primary, AuthScheme::FederatedAccessToken)
        .context("build settingsonly Primary auth plan")
}

fn health_auth_plan() -> anyhow::Result<AuthPlan> {
    AuthPlan::none(ListenerKind::Health).context("build settingsonly Health auth plan")
}

fn admin_auth_plan() -> anyhow::Result<AuthPlan> {
    AuthPlan::new(ListenerKind::Admin, AuthScheme::FederatedAccessToken)
        .context("build settingsonly Admin auth plan")
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

pub(crate) fn finalize(
    registry: &mut bootstrap::Registry,
    verifier: FederatedVerifier,
    limiter: Arc<GovernorLimiter>,
    metrics: Arc<dyn diport::MetricsExporter>,
    audit_sink: httpserve::AuditSinkHandle,
    reporter: Arc<bootstrap::HealthReporter>,
    framework_routes: &impl bootstrap::FrameworkRoutes,
) -> anyhow::Result<(FinalizedListenerSet, FinalizedProbeReceipt)> {
    registry
        .register_primary_authorizer(Arc::new(FederatedPermissionAuthorizer))
        .context("register settingsonly federated permission authorizer")?;
    crate::modules_gen::register_framework_routes(framework_routes, registry)
        .context("register settingsonly framework routes")?;
    let primary_authorizer = registry
        .take_primary_authorizer()
        .context("take settingsonly federated permission authorizer")?;
    let mut routes = registry
        .finalize_routes()
        .context("finalize settings routes")?;
    bootstrap::validate_framework_serving(&routes, crate::modules_gen::FRAMEWORK_HTTP_ROUTES)
        .context("validate settingsonly framework serving")?;
    anyhow::ensure!(
        routes.len() == 2,
        "settingsonly requires exactly Primary and Admin live listeners"
    );
    let primary = take_routes(&mut routes, ListenerKind::Primary)?;
    let admin = take_routes(&mut routes, ListenerKind::Admin)?;
    anyhow::ensure!(
        routes.is_empty(),
        "settingsonly produced extra live listeners"
    );
    let clock: Arc<dyn diport::Clock> = Arc::new(crate::SystemClock);
    let primary = httpserve::finalize_primary_auth_with_audit(
        primary,
        primary_auth_plan()?,
        audit_sink.clone(),
        Arc::clone(&clock),
        primary_authorizer,
    )
    .context("finalize settingsonly Primary auth")?;
    let admin = httpserve::finalize_auth_with_audit_and_authorizer(
        admin,
        admin_auth_plan()?,
        audit_sink,
        clock,
        Arc::new(FederatedPermissionAuthorizer),
    )
    .context("finalize settingsonly Admin auth")?;
    let primary = with_access_layers(primary, verifier.clone(), Arc::clone(&limiter));
    let admin = with_access_layers(admin, verifier, limiter);

    let health_reporter = Arc::clone(&reporter);
    let health =
        httpserve::health::routes(move || health_reporter.report(), move || metrics.render());
    let health = httpserve::finalize_auth(health, health_auth_plan()?)
        .context("finalize settingsonly Health auth")?;
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
        .with_context(|| format!("settingsonly {kind:?} routes are missing"))?;
    Ok(routes.swap_remove(index).1)
}

fn with_access_layers(
    routes: httpserve::AuthenticatedRoutes,
    verifier: FederatedVerifier,
    limiter: Arc<GovernorLimiter>,
) -> httpserve::AuthenticatedRoutes {
    auth_bridge::apply(routes, verifier).layer(axum::middleware::from_fn_with_state(
        limiter,
        httpserve::rate_limit::<GovernorLimiter>,
    ))
}

pub(crate) struct LaunchAdapter {
    listeners: FinalizedListenerSet,
    primary_addr: SocketAddr,
    admin_addr: SocketAddr,
    health_addr: SocketAddr,
    inventory_publisher: runtimeexec::inventory::InventoryPublisher,
    request_budget: httpserve::ServerRequestBudget,
    frontend: Option<crate::config::ServingFrontendConfig>,
    #[cfg(feature = "test-support")]
    activation_gate: Option<SocketAddr>,
}

impl LaunchAdapter {
    pub(crate) fn new(
        listeners: FinalizedListenerSet,
        primary_addr: SocketAddr,
        admin_addr: SocketAddr,
        health_addr: SocketAddr,
        request_budget: std::time::Duration,
        inventory_publisher: runtimeexec::inventory::InventoryPublisher,
        frontend: Option<crate::config::ServingFrontendConfig>,
    ) -> anyhow::Result<Self> {
        let millis = u64::try_from(request_budget.as_millis())
            .context("settingsonly request budget is too large")?;
        let millis = NonZeroU64::new(millis)
            .context("settingsonly request budget must be at least one millisecond")?;
        Ok(Self {
            listeners,
            primary_addr,
            admin_addr,
            health_addr,
            inventory_publisher,
            request_budget: httpserve::ServerRequestBudget::from_millis(millis),
            frontend,
            #[cfg(feature = "test-support")]
            activation_gate: None,
        })
    }

    /// Test-only barrier after every socket is prepared but before either listener is activated.
    #[cfg(feature = "test-support")]
    pub(crate) fn with_activation_gate(mut self, address: SocketAddr) -> Self {
        self.activation_gate = Some(address);
        self
    }
}

pub(crate) struct PreparedListeners {
    primary: PreparedListener,
    admin: PreparedListener,
    health: PreparedListener,
    primary_front: Option<PreparedMtlsListener>,
    admin_front: Option<PreparedMtlsListener>,
    health_front: Option<PreparedListener>,
    inventory_publisher: runtimeexec::inventory::InventoryPublisher,
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

pub(crate) struct ListenerInventory {
    pub(crate) primary: SocketAddr,
    pub(crate) admin: SocketAddr,
    pub(crate) health: SocketAddr,
}

impl runtimeexec::LaunchAdapter<FinalizedProbeReceipt> for LaunchAdapter {
    type Prepared = PreparedListeners;
    type Inventory = ListenerInventory;

    async fn prepare(
        self,
        _probe_receipt: FinalizedProbeReceipt,
        transaction: &mut runtimeexec::LaunchTransaction<'_>,
    ) -> anyhow::Result<Self::Prepared> {
        let Self {
            listeners,
            primary_addr,
            admin_addr,
            health_addr,
            inventory_publisher,
            request_budget,
            frontend,
            #[cfg(feature = "test-support")]
            activation_gate,
        } = self;
        let primary = HttpServer::bind("settingsonly-primary", primary_addr)
            .await
            .context("bind settingsonly Primary listener")?;
        let admin = HttpServer::bind("settingsonly-admin", admin_addr)
            .await
            .context("bind settingsonly Admin listener")?;
        let health = HttpServer::bind("settingsonly-health", health_addr)
            .await
            .context("bind settingsonly Health listener")?;
        #[cfg(feature = "test-support")]
        if let Some(address) = activation_gate {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

            let mut gate = tokio::net::TcpStream::connect(address)
                .await
                .context("connect settingsonly activation gate")?;
            gate.write_all(&[1])
                .await
                .context("report settingsonly listeners prepared")?;
            let mut release = [0_u8; 1];
            gate.read_exact(&mut release)
                .await
                .context("wait for settingsonly activation release")?;
        }
        let primary_service = listeners.primary.into_server_service(request_budget);
        let admin_service = listeners.admin.into_server_service(request_budget);
        let health_service = listeners.health.into_server_service(request_budget);
        let (primary_front, admin_front, health_front) = if let Some(frontend) = frontend {
            let primary_address = SocketAddr::new(frontend.pod_ip, frontend.primary_port);
            let admin_address = SocketAddr::new(frontend.pod_ip, frontend.admin_port);
            let primary_bound = HttpServer::bind("settingsonly-primary-mtls", primary_address)
                .await
                .context("bind settingsonly Primary mTLS frontend")?;
            let admin_bound = HttpServer::bind("settingsonly-admin-mtls", admin_address)
                .await
                .context("bind settingsonly Admin mTLS frontend")?;
            let health_bound = HttpServer::bind(
                "settingsonly-health-front",
                SocketAddr::new(frontend.pod_ip, frontend.health_port),
            )
            .await
            .context("bind settingsonly Health frontend")?;
            let prepared = httpd::MtlsServerConfig::from_spire(
                frontend.allow_set,
                Some(&frontend.spiffe_endpoint),
            )
            .await
            .context("prepare settingsonly SPIFFE mTLS frontend")?;
            let mtls = prepared.stage_with(|resource| transaction.stage_resource(resource));
            (
                Some(PreparedMtlsListener {
                    bound: primary_bound,
                    service: primary_service.clone(),
                    mtls: mtls.clone(),
                }),
                Some(PreparedMtlsListener {
                    bound: admin_bound,
                    service: admin_service.clone(),
                    mtls,
                }),
                Some(PreparedListener {
                    bound: health_bound,
                    service: health_service.clone(),
                }),
            )
        } else {
            (None, None, None)
        };
        Ok(PreparedListeners {
            primary: PreparedListener {
                bound: primary,
                service: primary_service,
            },
            admin: PreparedListener {
                bound: admin,
                service: admin_service,
            },
            health: PreparedListener {
                bound: health,
                service: health_service,
            },
            primary_front,
            admin_front,
            health_front,
            inventory_publisher,
        })
    }

    fn activate(
        prepared: Self::Prepared,
        mut registrar: runtimeexec::LaunchRegistrar<'_>,
    ) -> anyhow::Result<runtimeexec::Activated<Self::Inventory>> {
        let primary_bound = prepared
            .primary_front
            .as_ref()
            .map_or(&prepared.primary.bound, |front| &front.bound);
        let admin_bound = prepared
            .admin_front
            .as_ref()
            .map_or(&prepared.admin.bound, |front| &front.bound);
        let edge_scheme = if prepared.primary_front.is_some() {
            runtimeexec::inventory::InventoryEndpointScheme::Https
        } else {
            runtimeexec::inventory::InventoryEndpointScheme::Http
        };
        let health_bound = prepared
            .health_front
            .as_ref()
            .map_or(&prepared.health.bound, |front| &front.bound);
        prepared.inventory_publisher.publish(Vec::from([
            runtimeexec::inventory::BoundListenerObservation::from_bound(
                "primary-main",
                assembly_schema::AssemblyListenerKind::Primary,
                assembly_schema::ListenerAuth::FederatedAccessToken,
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
                assembly_schema::ListenerAuth::FederatedAccessToken,
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
        ]))?;
        let primary = primary_bound.local_addr();
        let admin = admin_bound.local_addr();
        let health = health_bound.local_addr();
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
        registrar.complete(ListenerInventory {
            primary,
            admin,
            health,
        })
    }
}

#[cfg(feature = "test-support")]
pub(crate) struct InventoryJourneyHttpResult {
    pub(crate) status: reqwest::StatusCode,
    pub(crate) body: Vec<u8>,
    pub(crate) serving_address: SocketAddr,
}

/// Drive an inventory request through the production listener bind, publish and activation
/// funnel. All configured ports are zero so the published Admin endpoint can only come from the
/// socket actually bound by [`LaunchAdapter`].
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
        httpserve::finalize_auth(
            httpserve::health::routes(move || reporter.report(), move || metrics.render()),
            health_auth_plan()?,
        )
        .map_err(anyhow::Error::from)
    };
    let adapter = LaunchAdapter::new(
        FinalizedListenerSet {
            primary: companion()?,
            admin,
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
        ),
        crate::runtime::total_drain_budget()?,
    );
    controlled.run(launch).await
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
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;
    use httpserve::RouteAuthorizer as _;

    struct CountedResource {
        name: &'static str,
        shutdowns: Arc<AtomicUsize>,
        transcript: Arc<Mutex<Vec<&'static str>>>,
    }

    impl diport::ManagedResource for CountedResource {
        fn name(&self) -> &str {
            self.name
        }

        async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
            self.transcript
                .lock()
                .map_err(|_| diport::ShutdownError::new(std::io::Error::other("poisoned")))?
                .push(self.name);
            Ok(())
        }
    }

    fn counted_resource(
        name: &'static str,
        shutdowns: &Arc<AtomicUsize>,
        transcript: &Arc<Mutex<Vec<&'static str>>>,
    ) -> Box<DynManagedResource<'static>> {
        DynManagedResource::new_box(CountedResource {
            name,
            shutdowns: Arc::clone(shutdowns),
            transcript: Arc::clone(transcript),
        })
    }

    #[tokio::test]
    async fn federated_authorizer_requires_exact_contract_permission_and_verified_grant()
    -> anyhow::Result<()> {
        let grant =
            |permission| Some(vec![vocab::GrantPermission::route(permission)].into_boxed_slice());
        let request = |contract_id, permission, permissions| httpserve::RouteAuthorizationRequest {
            contract_id,
            permission,
            tenant_id: None,
            principal_kind: vocab::PrincipalKind::User,
            principal_id: "operator".to_owned(),
            resource: None,
            federated_permissions: permissions,
        };
        assert_eq!(
            FederatedPermissionAuthorizer
                .authorize(request(
                    generated::http::runtime_v1::inventory::CONTRACT_ID,
                    vocab::RoutePermissionId::RuntimeInventoryRead,
                    grant(vocab::RoutePermissionId::RuntimeInventoryRead),
                ))
                .await,
            httpserve::RouteAuthorizationDecision::Allow
        );
        for (contract, permission) in [
            (
                generated::http::settings_v1::CONTRACT_ID,
                vocab::RoutePermissionId::SettingsConfigPublish,
            ),
            (
                generated::http::settings_v5::CONTRACT_ID,
                vocab::RoutePermissionId::SettingsConfigDelete,
            ),
            (
                generated::http::settings_v6::CONTRACT_ID,
                vocab::RoutePermissionId::SettingsConfigRollback,
            ),
        ] {
            let mut authorized = request(contract, permission, grant(permission));
            authorized.tenant_id = Some(vocab::TenantId::parse(
                "00000000-0000-4000-8000-000000001836",
            )?);
            assert_eq!(
                FederatedPermissionAuthorizer.authorize(authorized).await,
                httpserve::RouteAuthorizationDecision::Allow,
                "{contract} must accept only its exact typed route grant"
            );
        }
        for denied in [
            request(
                generated::http::runtime_v1::inventory::CONTRACT_ID,
                vocab::RoutePermissionId::RuntimeInventoryRead,
                None,
            ),
            request(
                generated::http::runtime_v1::inventory::CONTRACT_ID,
                vocab::RoutePermissionId::SettingsConfigGet,
                grant(vocab::RoutePermissionId::SettingsConfigGet),
            ),
            request(
                "settings.config.get",
                vocab::RoutePermissionId::RuntimeInventoryRead,
                grant(vocab::RoutePermissionId::RuntimeInventoryRead),
            ),
        ] {
            assert_eq!(
                FederatedPermissionAuthorizer.authorize(denied).await,
                httpserve::RouteAuthorizationDecision::Deny
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn second_bind_failure_releases_first_socket_without_ready() -> anyhow::Result<()> {
        let primary_reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
        let primary = primary_reservation.local_addr()?;
        drop(primary_reservation);
        let occupied_health = std::net::TcpListener::bind("127.0.0.1:0")?;
        let health = occupied_health.local_addr()?;

        let primary_routes = httpserve::finalize_primary_auth(
            httpserve::UnfinalizedRoutes::empty(),
            primary_auth_plan()?,
            Arc::new(FederatedPermissionAuthorizer),
        )?;
        let health_routes =
            httpserve::finalize_auth(httpserve::UnfinalizedRoutes::empty(), health_auth_plan()?)?;
        let admin_routes =
            httpserve::finalize_auth(httpserve::UnfinalizedRoutes::empty(), admin_auth_plan()?)?;
        let admin_reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
        let admin = admin_reservation.local_addr()?;
        drop(admin_reservation);
        let adapter = LaunchAdapter::new(
            FinalizedListenerSet {
                primary: primary_routes,
                admin: admin_routes,
                health: health_routes,
            },
            primary,
            admin,
            health,
            Duration::from_secs(1),
            inventory_publisher()?,
            None,
        )?;
        let ready = Arc::new(AtomicUsize::new(0));
        let ready_hook = Arc::clone(&ready);
        let provider_one = Arc::new(AtomicUsize::new(0));
        let provider_two = Arc::new(AtomicUsize::new(0));
        let domain_one = Arc::new(AtomicUsize::new(0));
        let transcript = Arc::new(Mutex::new(Vec::new()));
        let mut provider_output = bootstrap::DomainModuleResult::default();
        provider_output.resources.push(counted_resource(
            "provider-one",
            &provider_one,
            &transcript,
        ));
        provider_output.resources.push(counted_resource(
            "provider-two",
            &provider_two,
            &transcript,
        ));
        let mut domain_output = bootstrap::DomainModuleResult::default();
        domain_output
            .resources
            .push(counted_resource("domain-one", &domain_one, &transcript));
        let plan = runtimeexec::LaunchPlan::new(
            adapter,
            FinalizedProbeReceipt {
                reporter: Arc::new(bootstrap::Registry::new().take_health_reporter()),
            },
            move |_| async move {
                ready_hook.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            None,
            runtimeexec::LaunchLifecycleBatches::new(
                runtimeexec::ProviderLifecycleBatch::from_provider_output(provider_output),
                runtimeexec::DomainLifecycleBatch::from_domain_output(domain_output),
            ),
            crate::runtime::total_drain_budget()?,
        );
        assert!(runtimeexec::launch(plan).await.is_err());
        assert_eq!(ready.load(Ordering::SeqCst), 0);
        assert_eq!(provider_one.load(Ordering::SeqCst), 1);
        assert_eq!(provider_two.load(Ordering::SeqCst), 1);
        assert_eq!(domain_one.load(Ordering::SeqCst), 1);
        assert_eq!(
            *transcript.lock().map_err(|_| anyhow::anyhow!("poisoned"))?,
            ["domain-one", "provider-two", "provider-one"]
        );
        let rebound = tokio::net::TcpListener::bind(primary).await?;
        drop(rebound);
        Ok(())
    }

    fn inventory_publisher() -> anyhow::Result<runtimeexec::inventory::InventoryPublisher> {
        let plan = crate::plan::SettingsOnlyPlan::bundled()?;
        let bindings = crate::providers_gen::PROVIDER_CATALOG
            .iter()
            .map(|provider| {
                runtimeexec::inventory::ProviderProbeBinding::new(
                    provider.role().as_str(),
                    Vec::new(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let seed = plan.into_inventory_seed_fixture(bindings)?;
        let reporter = Arc::new(bootstrap::Registry::new().take_health_reporter());
        Ok(runtimeexec::inventory::inventory_channel(seed, reporter).0)
    }
}
