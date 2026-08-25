//! Runtime-specific listener preparation and activation for the shared launch kernel.

use crate::{config::SnapshotConfig, listeners, routes};

use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use diport::DynManagedResource;
use httpd::HttpServer;
use primitives::{AuthScheme, ListenerKind};

pub(crate) const HTTP_SERVER_REQUEST_BUDGET_ENV: &str = "RSS_HTTP_SERVER_REQUEST_BUDGET_MS";
const TOTAL_DRAIN_BUDGET: Duration = Duration::from_secs(20);

pub(crate) fn total_drain_budget() -> anyhow::Result<runtimeexec::TotalDrainBudget> {
    runtimeexec::TotalDrainBudget::new(TOTAL_DRAIN_BUDGET)
}

pub(crate) fn server_request_budget(
    config: SnapshotConfig<'_>,
) -> anyhow::Result<httpserve::ServerRequestBudget> {
    let raw = config
        .value(HTTP_SERVER_REQUEST_BUDGET_ENV)
        .ok_or_else(|| {
            anyhow::anyhow!("missing required env var: {HTTP_SERVER_REQUEST_BUDGET_ENV}")
        })?;
    let millis = raw.parse::<u64>().with_context(|| {
        format!("{HTTP_SERVER_REQUEST_BUDGET_ENV} must be a non-zero u64 millisecond value")
    })?;
    let millis = NonZeroU64::new(millis).ok_or_else(|| {
        anyhow::anyhow!("{HTTP_SERVER_REQUEST_BUDGET_ENV} must be greater than zero")
    })?;
    Ok(httpserve::ServerRequestBudget::from_millis(millis))
}

pub(crate) struct RuntimeLaunchAdapter<R, P = runtimeexec::inventory::InventoryPublisher> {
    listeners: routes::FinalizedListenerSet,
    budget: httpserve::ServerRequestBudget,
    addr_resolver: R,
    inventory_publisher: P,
}

impl<R> RuntimeLaunchAdapter<R, runtimeexec::inventory::InventoryPublisher> {
    pub(crate) fn new(
        listeners: routes::FinalizedListenerSet,
        budget: httpserve::ServerRequestBudget,
        addr_resolver: R,
        inventory_publisher: runtimeexec::inventory::InventoryPublisher,
    ) -> Self {
        Self {
            listeners,
            budget,
            addr_resolver,
            inventory_publisher,
        }
    }
}

trait InventoryPublication: Send {
    fn publish(
        self,
        listeners: Vec<runtimeexec::inventory::BoundListenerObservation>,
    ) -> Result<(), runtimeexec::inventory::InventoryError>;
}

impl InventoryPublication for runtimeexec::inventory::InventoryPublisher {
    fn publish(
        self,
        listeners: Vec<runtimeexec::inventory::BoundListenerObservation>,
    ) -> Result<(), runtimeexec::inventory::InventoryError> {
        runtimeexec::inventory::InventoryPublisher::publish(self, listeners)
    }
}

#[cfg(any(test, feature = "integration"))]
pub(crate) struct NoopInventoryPublication;

#[cfg(any(test, feature = "integration"))]
impl InventoryPublication for NoopInventoryPublication {
    fn publish(
        self,
        _: Vec<runtimeexec::inventory::BoundListenerObservation>,
    ) -> Result<(), runtimeexec::inventory::InventoryError> {
        Ok(())
    }
}

#[cfg(any(test, feature = "integration"))]
impl<R> RuntimeLaunchAdapter<R, NoopInventoryPublication> {
    pub(crate) fn without_inventory(
        set: routes::FinalizedListenerSet,
        budget: httpserve::ServerRequestBudget,
        addr_resolver: R,
    ) -> Self {
        Self {
            listeners: set,
            budget,
            addr_resolver,
            inventory_publisher: NoopInventoryPublication,
        }
    }
}

pub(crate) struct PreparedRuntimeListeners {
    listeners: BoundListenerSet,
}

pub(crate) struct RuntimeListenerInventory {
    listener_count: usize,
    #[cfg(feature = "integration")]
    admin: Option<SocketAddr>,
}

impl<R, P> runtimeexec::LaunchAdapter<Arc<bootstrap::HealthReporter>> for RuntimeLaunchAdapter<R, P>
where
    R: Fn(ListenerKind, AuthScheme) -> anyhow::Result<SocketAddr> + Send + Sync,
    P: InventoryPublication,
{
    type Prepared = PreparedRuntimeListeners;
    type Inventory = RuntimeListenerInventory;

    async fn prepare(
        self,
        probe_receipt: Arc<bootstrap::HealthReporter>,
        transaction: &mut runtimeexec::LaunchTransaction<'_>,
    ) -> anyhow::Result<Self::Prepared> {
        let Self {
            listeners,
            budget,
            addr_resolver,
            inventory_publisher,
        } = self;
        let _probe_receipt = probe_receipt;
        let listeners = BoundListenerSet::prepare(
            listeners.into_listeners(),
            budget,
            &addr_resolver,
            transaction,
        )
        .await?;
        listeners.preflight_activation()?;
        inventory_publisher
            .publish(listeners.inventory_observations())
            .context("publish bound runtime inventory")?;
        Ok(PreparedRuntimeListeners { listeners })
    }

    fn activate(
        prepared: Self::Prepared,
        mut registrar: runtimeexec::LaunchRegistrar<'_>,
    ) -> anyhow::Result<runtimeexec::Activated<Self::Inventory>> {
        let inventory = prepared.listeners.activate(&mut registrar);
        registrar.complete(inventory)
    }
}

pub(crate) fn log_ready(inventory: RuntimeListenerInventory) -> anyhow::Result<()> {
    tracing::info!(
        listener_count = inventory.listener_count,
        "all listeners bound; server ready"
    );
    Ok(())
}

/// Fully prepared listener set. Private fields make partial activation unrepresentable outside this
/// module: every socket and transport must prepare successfully before the set can be consumed.
struct BoundListenerSet {
    non_health: Vec<BoundListener>,
    health: Vec<BoundListener>,
}

struct BoundListener {
    id: String,
    listener: ListenerKind,
    scheme: AuthScheme,
    bound: httpd::BoundHttpServer,
    svc: httpserve::ServerService,
    transport: PreparedListenerTransport,
}

enum PreparedListenerTransport {
    Plaintext,
    Mtls {
        config: httpd::MtlsServerConfig,
        health: std::sync::Arc<routes::MtlsHealthSlot>,
    },
}

impl BoundListenerSet {
    fn inventory_observations(&self) -> Vec<runtimeexec::inventory::BoundListenerObservation> {
        self.non_health
            .iter()
            .chain(&self.health)
            .map(BoundListener::inventory_observation)
            .collect()
    }

    async fn prepare<R, P>(
        listeners: Vec<routes::AssembledListener>,
        budget: httpserve::ServerRequestBudget,
        addr_resolver: &R,
        transaction: &mut P,
    ) -> anyhow::Result<Self>
    where
        R: Fn(ListenerKind, AuthScheme) -> anyhow::Result<SocketAddr>,
        P: PreparationRegistrar,
    {
        let mut non_health = Vec::with_capacity(listeners.len());
        let mut health = Vec::new();
        for listener in listeners {
            let listener =
                BoundListener::prepare(listener, budget, addr_resolver, transaction).await?;
            if listener.listener == ListenerKind::Health {
                health.push(listener);
            } else {
                non_health.push(listener);
            }
        }
        Ok(Self { non_health, health })
    }

    fn preflight_activation(&self) -> anyhow::Result<()> {
        let mut commits = Vec::new();
        for listener in self.non_health.iter().chain(&self.health) {
            if let Some(commit) = listener.prepare_readiness_commit()? {
                commits.push(commit);
            }
        }
        for commit in commits {
            commit.commit();
        }
        Ok(())
    }

    fn activate<R>(self, registrar: &mut R) -> RuntimeListenerInventory
    where
        R: ListenerRegistrar,
    {
        let listener_count = self.non_health.len() + self.health.len();
        #[cfg(feature = "integration")]
        let admin = self
            .non_health
            .iter()
            .chain(&self.health)
            .find(|listener| listener.listener == ListenerKind::Admin)
            .map(|listener| listener.bound.local_addr());
        for listener in self.non_health.into_iter().chain(self.health) {
            listener.activate(registrar);
        }
        RuntimeListenerInventory {
            listener_count,
            #[cfg(feature = "integration")]
            admin,
        }
    }
}

#[cfg(feature = "integration")]
pub(crate) struct InventoryJourneyHttpResult {
    pub(crate) status: reqwest::StatusCode,
    pub(crate) body: Vec<u8>,
    pub(crate) serving_address: SocketAddr,
}

/// Exercise the production runtime bind, inventory publication and activation funnel using
/// kernel-assigned ports, then query the exact activated Admin socket.
#[cfg(feature = "integration")]
pub(crate) async fn serve_inventory_journey(
    admin: httpserve::AuthenticatedRoutes,
    inventory_publisher: runtimeexec::inventory::InventoryPublisher,
    bearer: String,
) -> anyhow::Result<InventoryJourneyHttpResult> {
    let (listeners, receipt) = routes::FinalizedListenerSet::for_inventory_journey(admin)?;
    let adapter = RuntimeLaunchAdapter::new(
        listeners,
        httpserve::ServerRequestBudget::from_millis(
            NonZeroU64::new(1_000).context("non-zero journey request budget")?,
        ),
        |_, _| "127.0.0.1:0".parse().map_err(anyhow::Error::from),
        inventory_publisher,
    );
    let (completion, controlled) = runtimeexec::test_support::controlled();
    let launch = runtimeexec::LaunchPlan::new(
        adapter,
        receipt,
        move |inventory: RuntimeListenerInventory| async move {
            let result = async {
                let serving_address = inventory
                    .admin
                    .context("runtime activation did not mint an Admin socket")?;
                let response = reqwest::Client::new()
                    .get(format!(
                        "http://{serving_address}{}",
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
                    serving_address,
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
        total_drain_budget()?,
    );
    controlled.run(launch).await
}

trait ListenerRegistrar {
    fn register_with_token<F>(&mut self, make: F)
    where
        F: FnOnce(tokio_util::sync::CancellationToken) -> httpd::ListenerTaskRegistration;
}

trait PreparationRegistrar {
    fn stage_resource(&mut self, resource: Box<DynManagedResource<'static>>);
}

impl PreparationRegistrar for runtimeexec::LaunchTransaction<'_> {
    fn stage_resource(&mut self, resource: Box<DynManagedResource<'static>>) {
        runtimeexec::LaunchTransaction::stage_resource(self, resource);
    }
}

impl ListenerRegistrar for runtimeexec::LaunchRegistrar<'_> {
    fn register_with_token<F>(&mut self, make: F)
    where
        F: FnOnce(tokio_util::sync::CancellationToken) -> httpd::ListenerTaskRegistration,
    {
        runtimeexec::LaunchRegistrar::register_listener_with_token(self, make);
    }
}

impl BoundListener {
    #[allow(clippy::cognitive_complexity)]
    async fn prepare<R, P>(
        listener: routes::AssembledListener,
        budget: httpserve::ServerRequestBudget,
        addr_resolver: &R,
        transaction: &mut P,
    ) -> anyhow::Result<Self>
    where
        R: Fn(ListenerKind, AuthScheme) -> anyhow::Result<SocketAddr>,
        P: PreparationRegistrar,
    {
        let (id, listener, scheme, routes, transport) = listener.into_launch_parts();
        let transport = resolve_listener_transport(listener, scheme, transport)?;
        let name = listeners::listener_name(listener);
        let addr = addr_resolver(listener, scheme)?;
        let bound = HttpServer::bind(name, addr)
            .await
            .with_context(|| format!("bind {name} listener at {addr}"))?;
        tracing::info!(listener = ?listener, name, addr = %bound.local_addr(), "listener bound");
        let transport = match transport {
            ResolvedListenerTransport::Mtls(material) => {
                let prepared = mtls_config(listener, material.allow_set, &material.spiffe_endpoint)
                    .await
                    .with_context(|| format!("build {name} mTLS config"))?;
                let mtls = prepared.stage_with(|lifecycle| {
                    transaction.stage_resource(lifecycle);
                });
                PreparedListenerTransport::Mtls {
                    config: mtls,
                    health: material.health,
                }
            }
            ResolvedListenerTransport::Plaintext => PreparedListenerTransport::Plaintext,
        };
        Ok(Self {
            id,
            listener,
            scheme,
            bound,
            svc: routes.into_server_service(budget),
            transport,
        })
    }

    fn prepare_readiness_commit(&self) -> anyhow::Result<Option<routes::MtlsHealthCommit<'_>>> {
        match &self.transport {
            PreparedListenerTransport::Plaintext => Ok(None),
            PreparedListenerTransport::Mtls { config, health } => {
                health.prepare_commit(config.clone()).map(Some)
            }
        }
    }

    fn activate<R>(self, registrar: &mut R)
    where
        R: ListenerRegistrar,
    {
        let Self {
            id: _,
            listener,
            scheme,
            bound,
            svc,
            transport,
        } = self;
        match transport {
            PreparedListenerTransport::Mtls { config, health: _ } => {
                registrar.register_with_token(move |token| bound.serve_mtls(svc, config, token));
            }
            PreparedListenerTransport::Plaintext => {
                if listener == ListenerKind::Internal && scheme == AuthScheme::ServiceToken {
                    tracing::warn!(
                        listener = ?listener,
                        "binding local-test Internal service-token listener; mTLS is the production default"
                    );
                }
                registrar.register_with_token(move |token| bound.serve(svc, token));
            }
        }
    }

    fn inventory_observation(&self) -> runtimeexec::inventory::BoundListenerObservation {
        let kind = match self.listener {
            ListenerKind::Primary => assembly_schema::AssemblyListenerKind::Primary,
            ListenerKind::Internal => assembly_schema::AssemblyListenerKind::Internal,
            ListenerKind::Health => assembly_schema::AssemblyListenerKind::Health,
            ListenerKind::Admin => assembly_schema::AssemblyListenerKind::Admin,
            _ => unreachable!("closed runtime listener kind"),
        };
        let auth = match self.scheme {
            AuthScheme::NoAuth => assembly_schema::ListenerAuth::NoAuth,
            AuthScheme::RssAccessToken => assembly_schema::ListenerAuth::RssAccessToken,
            AuthScheme::FederatedAccessToken => assembly_schema::ListenerAuth::FederatedAccessToken,
            AuthScheme::Mtls => assembly_schema::ListenerAuth::Mtls,
            AuthScheme::ServiceToken => assembly_schema::ListenerAuth::ServiceToken,
            _ => unreachable!("closed runtime listener auth scheme"),
        };
        let endpoint_scheme = match self.transport {
            PreparedListenerTransport::Plaintext => {
                runtimeexec::inventory::InventoryEndpointScheme::Http
            }
            PreparedListenerTransport::Mtls { .. } => {
                runtimeexec::inventory::InventoryEndpointScheme::Https
            }
        };
        runtimeexec::inventory::BoundListenerObservation::from_bound(
            self.id.clone(),
            kind,
            auth,
            endpoint_scheme,
            self.bound.local_addr(),
        )
    }
}

struct MtlsLaunchMaterial {
    allow_set: authn::MtlsAllowSet,
    spiffe_endpoint: String,
    health: std::sync::Arc<routes::MtlsHealthSlot>,
}

enum ResolvedListenerTransport {
    Plaintext,
    Mtls(MtlsLaunchMaterial),
}

fn resolve_listener_transport(
    listener: ListenerKind,
    scheme: AuthScheme,
    transport: routes::ListenerTransport,
) -> anyhow::Result<ResolvedListenerTransport> {
    match transport {
        routes::ListenerTransport::Mtls {
            allow_set,
            spiffe_endpoint,
            health,
        } => {
            anyhow::ensure!(
                scheme == AuthScheme::Mtls,
                "listener {listener:?} carries mTLS transport with non-mTLS auth {scheme:?}"
            );
            anyhow::ensure!(
                listener == ListenerKind::Internal,
                "mTLS listener config is only wired for Internal"
            );
            Ok(ResolvedListenerTransport::Mtls(MtlsLaunchMaterial {
                allow_set,
                spiffe_endpoint,
                health,
            }))
        }
        routes::ListenerTransport::Plaintext => {
            anyhow::ensure!(
                scheme != AuthScheme::Mtls,
                "listener {listener:?} has mTLS auth without captured mTLS transport material"
            );
            Ok(ResolvedListenerTransport::Plaintext)
        }
        #[cfg(feature = "integration")]
        routes::ListenerTransport::InventoryJourneyPlaintext => {
            Ok(ResolvedListenerTransport::Plaintext)
        }
    }
}

async fn mtls_config(
    listener: ListenerKind,
    allow_set: authn::MtlsAllowSet,
    spiffe_endpoint: &str,
) -> anyhow::Result<httpd::MtlsServerPreparation> {
    anyhow::ensure!(
        listener == ListenerKind::Internal,
        "mTLS listener config is only wired for Internal"
    );
    httpd::MtlsServerConfig::from_spire(allow_set, Some(spiffe_endpoint))
        .await
        .context("build Internal listener mTLS config from captured SPIFFE endpoint")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::generic_test_snapshot;

    use primitives::{HealthCheck, HealthStatus, ProbeName};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    fn listener_receipt<T>(
        _receipt: T,
    ) -> anyhow::Result<runtimeexec::LaunchProbeReceipt<Arc<bootstrap::HealthReporter>>> {
        let mut registry = bootstrap::Registry::new();
        runtimeexec::ListenerLifecycleRegistration::install(&mut registry)
    }

    struct NoopProbe;

    impl bootstrap::HealthProbe for NoopProbe {
        fn check(&self) -> HealthCheck {
            HealthCheck::new(
                ProbeName::parse("launch-test").unwrap_or_else(|_| unreachable!()),
                HealthStatus::Healthy,
                "ok",
            )
        }
    }

    #[allow(clippy::expect_used)] // reason: test fixture bootstrap must compose or the test setup is invalid.
    fn test_reporter() -> Arc<bootstrap::HealthReporter> {
        let mut reg = bootstrap::compose(&[]).expect("compose");
        Arc::new(reg.take_health_reporter())
    }

    #[allow(clippy::expect_used)]
    fn healthy_test_reporter() -> Arc<bootstrap::HealthReporter> {
        let mut reg = bootstrap::compose(&[]).expect("compose");
        let name = ProbeName::parse("launch-test").expect("static probe name");
        reg.probe(name, Box::new(NoopProbe))
            .expect("register healthy launch probe");
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

    #[allow(clippy::expect_used)] // reason: test fixture health listener must assemble or the test setup is invalid.
    fn test_health_assembled() -> routes::AssembledListener {
        routes::AssembledListener::health_for_test(test_reporter(), noop_metrics())
            .expect("health listener")
    }

    #[allow(clippy::expect_used)]
    fn healthy_test_health_assembled() -> routes::AssembledListener {
        routes::AssembledListener::health_for_test(healthy_test_reporter(), noop_metrics())
            .expect("healthy health listener")
    }

    fn ephemeral_addr(_l: ListenerKind, _scheme: AuthScheme) -> anyhow::Result<SocketAddr> {
        "127.0.0.1:0".parse::<SocketAddr>().map_err(Into::into)
    }

    fn test_budget() -> httpserve::ServerRequestBudget {
        httpserve::ServerRequestBudget::for_test()
    }

    struct TestRegistrar {
        stack: bootstrap::shutdown::ShutdownStack,
    }

    impl TestRegistrar {
        fn new() -> Self {
            Self {
                stack: bootstrap::shutdown::ShutdownStack::new(
                    tokio_util::sync::CancellationToken::new(),
                ),
            }
        }

        fn registered_names(&self) -> Vec<&str> {
            self.stack.registered_names().collect()
        }

        async fn shutdown(self) -> anyhow::Result<()> {
            let failures = self.stack.shutdown().await;
            anyhow::ensure!(
                failures.is_empty(),
                "listener test cleanup reported {} failure(s)",
                failures.len()
            );
            Ok(())
        }
    }

    impl ListenerRegistrar for TestRegistrar {
        fn register_with_token<F>(&mut self, make: F)
        where
            F: FnOnce(tokio_util::sync::CancellationToken) -> httpd::ListenerTaskRegistration,
        {
            let _status = self
                .stack
                .register_managed_task_with_token(|token| make(token).into_managed());
        }
    }

    impl PreparationRegistrar for TestRegistrar {
        fn stage_resource(&mut self, resource: Box<DynManagedResource<'static>>) {
            self.stack.register_detached(resource);
        }
    }

    struct CountingResource {
        name: &'static str,
        shutdowns: Arc<AtomicUsize>,
    }

    impl diport::ManagedResource for CountingResource {
        fn name(&self) -> &str {
            self.name
        }

        async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn counting_resource(
        name: &'static str,
        shutdowns: &Arc<AtomicUsize>,
    ) -> Box<DynManagedResource<'static>> {
        DynManagedResource::new_box(CountingResource {
            name,
            shutdowns: Arc::clone(shutdowns),
        })
    }

    fn lifecycle_batches(
        provider: bootstrap::DomainModuleResult,
        domain: bootstrap::DomainModuleResult,
    ) -> runtimeexec::LaunchLifecycleBatches {
        runtimeexec::LaunchLifecycleBatches::new(
            runtimeexec::ProviderLifecycleBatch::from_provider_output(provider),
            runtimeexec::DomainLifecycleBatch::from_domain_output(domain),
            Some(
                bootstrap::ExpectedWorkerInventory::closed([])
                    .unwrap_or_else(|error| unreachable!("empty inventory: {error}")),
            ),
        )
    }

    #[allow(clippy::expect_used)]
    async fn bound_listener_for_test(
        listener: ListenerKind,
        transport: PreparedListenerTransport,
    ) -> BoundListener {
        let (_, _, _, routes, _) = test_health_assembled().into_launch_parts();
        let name = listeners::listener_name(listener);
        let bound = HttpServer::bind(name, "127.0.0.1:0".parse().expect("ephemeral address"))
            .await
            .expect("bind listener fixture");
        BoundListener {
            id: format!("{:?}-test", listener).to_ascii_lowercase(),
            listener,
            scheme: AuthScheme::NoAuth,
            bound,
            svc: routes.into_server_service(test_budget()),
            transport,
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn server_request_budget_is_required_non_zero_and_snapshot_backed() {
        let missing = generic_test_snapshot(&[]).expect("capture empty config");
        let error = server_request_budget(missing.view()).expect_err("budget is mandatory");
        assert!(error.to_string().contains(HTTP_SERVER_REQUEST_BUDGET_ENV));

        for raw in ["0", "not-a-number"] {
            let snapshot = generic_test_snapshot(&[(HTTP_SERVER_REQUEST_BUDGET_ENV, raw)])
                .expect("capture invalid budget");
            let error = server_request_budget(snapshot.view()).expect_err("invalid budget");
            assert!(error.to_string().contains(HTTP_SERVER_REQUEST_BUDGET_ENV));
        }

        let snapshot = generic_test_snapshot(&[(HTTP_SERVER_REQUEST_BUDGET_ENV, "2500")])
            .expect("capture valid budget");
        assert_eq!(
            server_request_budget(snapshot.view())
                .expect("valid budget")
                .millis()
                .get(),
            2500
        );
    }

    async fn activate_listeners<R>(
        listeners: Vec<routes::AssembledListener>,
        addr_resolver: R,
    ) -> anyhow::Result<(RuntimeListenerInventory, TestRegistrar)>
    where
        R: Fn(ListenerKind, AuthScheme) -> anyhow::Result<SocketAddr> + Send + Sync,
    {
        let mut registrar = TestRegistrar::new();
        let prepared =
            BoundListenerSet::prepare(listeners, test_budget(), &addr_resolver, &mut registrar)
                .await?;
        prepared.preflight_activation()?;
        let inventory = prepared.activate(&mut registrar);
        Ok((inventory, registrar))
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: direct async test assertion for clean listener launch.
    async fn adapter_binds_all_listeners_and_drains_clean() {
        let (inventory, registrar) = activate_listeners(
            vec![test_health_assembled(), test_health_assembled()],
            ephemeral_addr,
        )
        .await
        .expect("adapter binds 2 listeners");

        assert_eq!(inventory.listener_count, 2);
        assert_eq!(registrar.registered_names(), ["http-health", "http-health"]);
        registrar.shutdown().await.expect("drain listeners cleanly");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn activated_health_listener_serves_request_id_then_drains_and_releases_socket() {
        let reservation = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve Health address");
        let addr = reservation.local_addr().expect("reserved Health address");
        drop(reservation);

        let (_, registrar) = activate_listeners(
            vec![healthy_test_health_assembled()],
            move |listener, scheme| {
                assert_eq!(listener, ListenerKind::Health);
                assert_eq!(scheme, AuthScheme::NoAuth);
                Ok(addr)
            },
        )
        .await
        .expect("activate real Health listener");

        let client = reqwest::Client::new();
        let response = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match client
                    .get(format!("http://{addr}/health/v1/readyz"))
                    .send()
                    .await
                {
                    Ok(response) => break response,
                    Err(_) => tokio::task::yield_now().await,
                }
            }
        })
        .await
        .expect("Health listener must accept a request before timeout");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert!(
            response.headers().get("x-request-id").is_some(),
            "production launch path must preserve request-id middleware"
        );
        let liveness = client
            .get(format!("http://{addr}/health/v1/healthz"))
            .send()
            .await
            .expect("Health liveness request");
        assert_eq!(liveness.status(), reqwest::StatusCode::OK);
        registrar.shutdown().await.expect("drain Health listener");

        let after = reqwest::Client::new()
            .get(format!("http://{addr}/health/v1/healthz"))
            .send()
            .await;
        assert!(after.is_err(), "drained listener must reject new requests");
        let rebound = tokio::net::TcpListener::bind(addr)
            .await
            .expect("graceful drain must release Health socket");
        drop(rebound);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn activated_health_listener_serves_metrics_exposition_over_real_socket() {
        let reservation = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve Health address");
        let addr = reservation.local_addr().expect("reserved Health address");
        drop(reservation);
        let metrics: Arc<dyn diport::MetricsExporter> =
            Arc::new(FixedMetrics("rss_launch_e2e_total 7\n"));
        let listener = routes::AssembledListener::health_for_test(test_reporter(), metrics)
            .expect("metrics Health listener");

        let (_, registrar) = activate_listeners(vec![listener], move |_, _| Ok(addr))
            .await
            .expect("activate metrics listener");
        let response = reqwest::Client::new()
            .get(format!("http://{addr}/health/v1/metrics"))
            .send()
            .await
            .expect("metrics request over real socket");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("text/plain; version=0.0.4; charset=utf-8")
        );
        let body = response.text().await.expect("metrics response body");
        assert!(body.contains("rss_launch_e2e_total"));
        registrar.shutdown().await.expect("drain metrics listener");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn activated_health_listener_empty_probe_readyz_fails_closed_over_real_socket() {
        let reservation = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve Health address");
        let addr = reservation.local_addr().expect("reserved Health address");
        drop(reservation);

        let (_, registrar) =
            activate_listeners(vec![test_health_assembled()], move |_, _| Ok(addr))
                .await
                .expect("activate empty-probe Health listener");
        let response = reqwest::Client::new()
            .get(format!("http://{addr}/health/v1/readyz"))
            .send()
            .await
            .expect("empty-probe readyz request");
        assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        registrar
            .shutdown()
            .await
            .expect("drain empty-probe Health listener");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn bound_listener_set_activates_through_test_registrar() {
        let bound = BoundListenerSet::prepare(
            vec![healthy_test_health_assembled()],
            test_budget(),
            &ephemeral_addr,
            &mut TestRegistrar::new(),
        )
        .await
        .expect("prepare Health listener set");
        let addr = bound.health[0].bound.local_addr();
        let mut registrar = TestRegistrar::new();

        bound
            .preflight_activation()
            .expect("preflight fully prepared Health set");
        let _inventory = bound.activate(&mut registrar);
        assert_eq!(registrar.registered_names(), ["http-health"]);
        let response = reqwest::Client::new()
            .get(format!("http://{addr}/health/v1/readyz"))
            .send()
            .await
            .expect("readyz over funnel-served socket");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        registrar
            .shutdown()
            .await
            .expect("test registrar must drain the listener cleanly");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn activation_registers_non_health_before_health() {
        let non_health =
            bound_listener_for_test(ListenerKind::Internal, PreparedListenerTransport::Plaintext)
                .await;
        let health =
            bound_listener_for_test(ListenerKind::Health, PreparedListenerTransport::Plaintext)
                .await;
        let prepared = BoundListenerSet {
            non_health: vec![non_health],
            health: vec![health],
        };
        let mut registrar = TestRegistrar::new();

        let inventory = prepared.activate(&mut registrar);

        assert_eq!(inventory.listener_count, 2);
        assert_eq!(
            registrar.registered_names(),
            ["http-internal", "http-health"]
        );
        registrar.shutdown().await.expect("drain ordered listeners");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn preflight_failure_releases_every_prepared_socket_without_activation() {
        let allow_set = authn::MtlsAllowSet::new(["spiffe://example.org/ns/rss/sa/internal"])
            .expect("allow-set");
        let config = httpd::MtlsServerConfig::for_test(allow_set).expect("hermetic mTLS config");
        let first_health = Arc::new(routes::MtlsHealthSlot::new());
        let failed_health = Arc::new(routes::MtlsHealthSlot::new());
        failed_health.poison_for_test();

        let first = bound_listener_for_test(
            ListenerKind::Internal,
            PreparedListenerTransport::Mtls {
                config: config.clone(),
                health: Arc::clone(&first_health),
            },
        )
        .await;
        let second = bound_listener_for_test(
            ListenerKind::Internal,
            PreparedListenerTransport::Mtls {
                config,
                health: Arc::clone(&failed_health),
            },
        )
        .await;
        let addresses = [first.bound.local_addr(), second.bound.local_addr()];
        let prepared = BoundListenerSet {
            non_health: vec![first, second],
            health: Vec::new(),
        };

        let error = prepared
            .preflight_activation()
            .expect_err("poisoned second readiness slot must fail preflight");
        assert!(error.to_string().contains("slot lock poisoned"));
        assert_eq!(
            first_health.check().1,
            "not-bound",
            "validation failure must not partially publish an earlier readiness slot"
        );
        assert_eq!(failed_health.check().1, "slot-poisoned");
        drop(prepared);

        for address in addresses {
            let rebound = tokio::net::TcpListener::bind(address)
                .await
                .expect("failed preflight must release every prepared socket");
            drop(rebound);
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: direct async test assertion and poisoned test mutex handling.
    async fn adapter_prepare_passes_assembled_scheme_to_addr_resolver() {
        let listener = test_health_assembled();
        let resolved = Arc::new(Mutex::new(None));
        let seen = Arc::clone(&resolved);

        let (_, registrar) = activate_listeners(vec![listener], move |listener, scheme| {
            assert_eq!(listener, ListenerKind::Health);
            *seen.lock().expect("scheme lock") = Some(scheme);
            "127.0.0.1:0".parse::<SocketAddr>().map_err(Into::into)
        })
        .await
        .expect("adapter binds listener");

        assert_eq!(
            *resolved.lock().expect("scheme lock"),
            Some(AuthScheme::NoAuth)
        );
        registrar.shutdown().await.expect("drain listener");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: direct async test assertion for resolver error propagation.
    async fn adapter_prepare_addr_resolver_failure_propagates() {
        let err = activate_listeners(vec![test_health_assembled()], |_, _| {
            anyhow::bail!("no addr configured for listener")
        })
        .await
        .err()
        .expect("addr resolver failure must propagate");
        assert!(err.to_string().contains("no addr configured"));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn canonical_launch_composes_runtime_adapter_ready_and_single_drain() {
        let reservation = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve canonical Health address");
        let addr = reservation.local_addr().expect("canonical local address");
        drop(reservation);

        let ready_calls = Arc::new(AtomicUsize::new(0));
        let ready_calls_for_hook = Arc::clone(&ready_calls);
        let trace_shutdowns = Arc::new(AtomicUsize::new(0));
        let provider_shutdowns = Arc::new(AtomicUsize::new(0));
        let domain_shutdowns = Arc::new(AtomicUsize::new(0));
        let adapter = RuntimeLaunchAdapter::without_inventory(
            routes::FinalizedListenerSet::for_test(vec![healthy_test_health_assembled()]),
            test_budget(),
            move |listener, scheme| {
                assert_eq!(listener, ListenerKind::Health);
                assert_eq!(scheme, AuthScheme::NoAuth);
                Ok(addr)
            },
        );
        let launch_plan = runtimeexec::LaunchPlan::new(
            adapter,
            listener_receipt(routes::FinalizedProbeReceipt::for_test())
                .expect("listener probe install"),
            move |inventory: RuntimeListenerInventory| async move {
                assert_eq!(inventory.listener_count, 1);
                ready_calls_for_hook.fetch_add(1, Ordering::SeqCst);
                anyhow::bail!("stop after deterministic ready observation")
            },
            Some(counting_resource("trace", &trace_shutdowns)),
            lifecycle_batches(
                bootstrap::DomainModuleResult::from_parts(
                    [],
                    [counting_resource("provider", &provider_shutdowns)],
                    [],
                ),
                bootstrap::DomainModuleResult::from_parts(
                    [],
                    [counting_resource("domain", &domain_shutdowns)],
                    [],
                ),
            ),
            total_drain_budget().expect("valid runtime drain budget"),
        );

        let error = runtimeexec::launch(launch_plan)
            .await
            .err()
            .expect("ready hook ends canonical launch before signal polling");

        assert_eq!(
            error.to_string(),
            "stop after deterministic ready observation"
        );
        assert_eq!(ready_calls.load(Ordering::SeqCst), 1);
        assert_eq!(trace_shutdowns.load(Ordering::SeqCst), 1);
        assert_eq!(provider_shutdowns.load(Ordering::SeqCst), 1);
        assert_eq!(domain_shutdowns.load(Ordering::SeqCst), 1);
        let rebound = tokio::net::TcpListener::bind(addr)
            .await
            .expect("canonical drain must release Health socket");
        drop(rebound);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn canonical_launch_partial_bind_failure_drains_modules_once_and_releases_port() {
        let first_reservation = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve first listener address");
        let first_addr = first_reservation.local_addr().expect("first local address");
        drop(first_reservation);
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("occupy second listener address");
        let occupied_addr = occupied.local_addr().expect("occupied local address");
        let addresses = [first_addr, occupied_addr];
        let next_addr = Arc::new(AtomicUsize::new(0));
        let resolver_index = Arc::clone(&next_addr);
        let ready_calls = Arc::new(AtomicUsize::new(0));
        let ready_calls_for_hook = Arc::clone(&ready_calls);
        let trace_shutdowns = Arc::new(AtomicUsize::new(0));
        let provider_shutdowns = Arc::new(AtomicUsize::new(0));
        let domain_shutdowns = Arc::new(AtomicUsize::new(0));
        let adapter = RuntimeLaunchAdapter::without_inventory(
            routes::FinalizedListenerSet::for_test(vec![
                test_health_assembled(),
                test_health_assembled(),
            ]),
            test_budget(),
            move |_, _| {
                let index = resolver_index.fetch_add(1, Ordering::SeqCst);
                addresses
                    .get(index)
                    .copied()
                    .context("unexpected listener address request")
            },
        );
        let launch_plan = runtimeexec::LaunchPlan::new(
            adapter,
            listener_receipt(routes::FinalizedProbeReceipt::for_test())
                .expect("listener probe install"),
            move |_: RuntimeListenerInventory| async move {
                ready_calls_for_hook.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            Some(counting_resource("trace", &trace_shutdowns)),
            lifecycle_batches(
                bootstrap::DomainModuleResult::from_parts(
                    [],
                    [counting_resource("provider", &provider_shutdowns)],
                    [],
                ),
                bootstrap::DomainModuleResult::from_parts(
                    [],
                    [counting_resource("domain", &domain_shutdowns)],
                    [],
                ),
            ),
            total_drain_budget().expect("valid runtime drain budget"),
        );
        let err = runtimeexec::launch(launch_plan)
            .await
            .err()
            .expect("second bind must fail");

        assert!(format!("{err:#}").contains("bind http-health listener"));
        assert_eq!(next_addr.load(Ordering::SeqCst), 2);
        assert_eq!(ready_calls.load(Ordering::SeqCst), 0);
        assert_eq!(trace_shutdowns.load(Ordering::SeqCst), 1);
        assert_eq!(provider_shutdowns.load(Ordering::SeqCst), 1);
        assert_eq!(domain_shutdowns.load(Ordering::SeqCst), 1);
        let rebound = tokio::net::TcpListener::bind(first_addr)
            .await
            .expect("partial-bind listener port must be released by canonical drain");
        drop(rebound);
        drop(occupied);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[allow(clippy::expect_used)]
    async fn health_is_not_served_before_every_listener_is_bound() {
        let health_reservation = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve Health listener address");
        let health_addr = health_reservation
            .local_addr()
            .expect("Health local address");
        drop(health_reservation);
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("occupy later listener address");
        let occupied_addr = occupied.local_addr().expect("occupied local address");

        let resolver_index = Arc::new(AtomicUsize::new(0));
        let second_resolver_reached = Arc::new(tokio::sync::Notify::new());
        let release_second_resolver = Arc::new((Mutex::new(false), Condvar::new()));
        let launch = {
            let resolver_index = Arc::clone(&resolver_index);
            let second_resolver_reached = Arc::clone(&second_resolver_reached);
            let release_second_resolver = Arc::clone(&release_second_resolver);
            tokio::spawn(activate_listeners(
                vec![healthy_test_health_assembled(), test_health_assembled()],
                move |_, _| {
                    let index = resolver_index.fetch_add(1, Ordering::SeqCst);
                    if index == 1 {
                        second_resolver_reached.notify_one();
                        tokio::task::block_in_place(|| {
                            let (released, wake) = &*release_second_resolver;
                            let mut released = released.lock().expect("release lock");
                            while !*released {
                                released = wake.wait(released).expect("release wait");
                            }
                        });
                    }
                    [health_addr, occupied_addr]
                        .get(index)
                        .copied()
                        .context("unexpected listener address request")
                },
            ))
        };

        second_resolver_reached.notified().await;
        let premature_response = tokio::time::timeout(
            Duration::from_millis(300),
            reqwest::Client::new()
                .get(format!("http://{health_addr}/health/v1/healthz"))
                .send(),
        )
        .await;

        {
            let (released, wake) = &*release_second_resolver;
            *released.lock().expect("release lock") = true;
            wake.notify_one();
        }
        let error = launch
            .await
            .expect("launch task must not panic")
            .err()
            .expect("later listener bind must fail");
        assert!(format!("{error:#}").contains("bind http-health listener"));
        assert!(
            !matches!(premature_response, Ok(Ok(_))),
            "Health must not serve before every listener socket and transport is ready: \
             {premature_response:?}"
        );
        drop(occupied);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn mtls_launch_material_preserves_exact_allow_set_and_endpoint() -> anyhow::Result<()> {
        let allow_set = authn::MtlsAllowSet::new([
            "spiffe://example.org/ns/rss/sa/internal-a",
            "spiffe://example.org/ns/rss/sa/internal-b",
        ])
        .expect("allow-set");
        let health = Arc::new(routes::MtlsHealthSlot::new());
        let material = resolve_listener_transport(
            ListenerKind::Internal,
            AuthScheme::Mtls,
            routes::ListenerTransport::Mtls {
                allow_set,
                spiffe_endpoint: "unix:///run/spire/exact-agent.sock".to_owned(),
                health,
            },
        )
        .expect("matching mTLS transport");

        let material = match material {
            ResolvedListenerTransport::Mtls(material) => material,
            ResolvedListenerTransport::Plaintext => {
                anyhow::bail!("mTLS transport unexpectedly resolved as plaintext")
            }
        };
        let ids = material
            .allow_set
            .iter()
            .map(authn::SpiffeId::as_str)
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            [
                "spiffe://example.org/ns/rss/sa/internal-a",
                "spiffe://example.org/ns/rss/sa/internal-b"
            ]
        );
        assert_eq!(
            material.spiffe_endpoint,
            "unix:///run/spire/exact-agent.sock"
        );
        Ok(())
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn listener_scheme_transport_mismatches_fail_closed_before_bind() {
        let allow_set = authn::MtlsAllowSet::new(["spiffe://example.org/ns/rss/sa/internal"])
            .expect("allow-set");
        let error = resolve_listener_transport(
            ListenerKind::Internal,
            AuthScheme::ServiceToken,
            routes::ListenerTransport::Mtls {
                allow_set,
                spiffe_endpoint: "unix:///run/spire/agent.sock".to_owned(),
                health: Arc::new(routes::MtlsHealthSlot::new()),
            },
        )
        .err()
        .expect("mTLS transport with non-mTLS scheme must fail");
        assert!(error.to_string().contains("non-mTLS auth"));

        let error = resolve_listener_transport(
            ListenerKind::Internal,
            AuthScheme::Mtls,
            routes::ListenerTransport::Plaintext,
        )
        .err()
        .expect("mTLS scheme without mTLS transport must fail");
        assert!(
            error
                .to_string()
                .contains("without captured mTLS transport")
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn bound_mtls_activation_preflights_readiness_then_registers_and_drains() {
        let allow_set = authn::MtlsAllowSet::new(["spiffe://example.org/ns/rss/sa/internal"])
            .expect("allow-set");
        let mtls = httpd::MtlsServerConfig::for_test(allow_set).expect("hermetic mTLS config");
        let health = Arc::new(routes::MtlsHealthSlot::new());
        let (_, _, _, routes, _) = test_health_assembled().into_launch_parts();
        let bound = HttpServer::bind(
            "http-internal",
            "127.0.0.1:0".parse().expect("ephemeral address"),
        )
        .await
        .expect("bind hermetic mTLS listener");
        let mut registrar = TestRegistrar::new();

        assert_eq!(
            health.check().1,
            "not-bound",
            "socket and transport preparation must not publish readiness"
        );
        let bound = BoundListenerSet {
            non_health: vec![BoundListener {
                id: "internal-main".to_owned(),
                listener: ListenerKind::Internal,
                scheme: AuthScheme::Mtls,
                bound,
                svc: routes.into_server_service(test_budget()),
                transport: PreparedListenerTransport::Mtls {
                    config: mtls,
                    health: Arc::clone(&health),
                },
            }],
            health: Vec::new(),
        };
        bound.preflight_activation().expect("preflight mTLS set");
        let _inventory = bound.activate(&mut registrar);

        assert_ne!(health.check().1, "not-bound", "readiness slot must be set");
        assert_eq!(registrar.registered_names(), ["http-internal"]);
        registrar
            .shutdown()
            .await
            .expect("mTLS resource must drain");
    }
}
