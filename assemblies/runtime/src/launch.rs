//! Runtime launch phase: listener serving plus LIFO shutdown registration.

use crate::{config::SnapshotConfig, listeners, routes};

use std::future::Future;
use std::net::SocketAddr;
use std::num::NonZeroU64;

use anyhow::Context as _;
use bootstrap::DomainModuleResult;
#[cfg(test)]
use bootstrap::WorkerSpec;
use bootstrap::shutdown::ShutdownStack;
use diport::DynManagedResource;
use httpd::HttpServer;
use primitives::{AuthScheme, ListenerKind};
use tokio_util::sync::CancellationToken;

pub(crate) const HTTP_SERVER_REQUEST_BUDGET_ENV: &str = "RSS_HTTP_SERVER_REQUEST_BUDGET_MS";

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

/// Resources owned by the launch phase, grouped by lifecycle dependency.
pub(crate) struct LaunchPlanParts {
    pub(crate) listeners: routes::FinalizedListenerSet,
    pub(crate) trace_exporter: Option<Box<DynManagedResource<'static>>>,
    pub(crate) pg_runtime_module: DomainModuleResult,
    pub(crate) domain_module: DomainModuleResult,
}

/// Launch plan consumed by [`launch`] to register shutdown resources and serve listeners.
pub(crate) struct LaunchPlan {
    listeners: routes::FinalizedListenerSet,
    trace_exporter: Option<Box<DynManagedResource<'static>>>,
    pg_runtime_module: DomainModuleResult,
    domain_module: DomainModuleResult,
}

impl LaunchPlan {
    pub(crate) fn new(parts: LaunchPlanParts) -> Self {
        Self {
            listeners: parts.listeners,
            trace_exporter: parts.trace_exporter,
            pg_runtime_module: parts.pg_runtime_module,
            domain_module: parts.domain_module,
        }
    }

    fn listener_count(&self) -> usize {
        self.listeners.len()
    }

    fn register(self, stack: &mut ShutdownStack) -> anyhow::Result<Vec<routes::AssembledListener>> {
        let Self {
            listeners,
            trace_exporter,
            pg_runtime_module,
            domain_module,
        } = self;

        // Trace exporter registers first so LIFO drains it last, after shutdown-period spans stop.
        if let Some(exporter) = trace_exporter {
            stack.register_detached(exporter);
        }
        // PG guards outlive their sampler and all downstream workers.
        let pg_result = Self::register_module_output(stack, pg_runtime_module);
        // Event infra lives in domain_module.resources and outlives all module workers.
        let domain_result = Self::register_module_output(stack, domain_module);
        // Both owned output batches must cross into the async shutdown stack before validation can
        // return an error; otherwise a later batch would be synchronously dropped on an earlier
        // validation failure.
        pg_result?;
        domain_result?;

        Ok(listeners.into_listeners())
    }

    /// Registers one lifecycle output batch through the common resources-then-workers funnel.
    fn register_module_output(
        stack: &mut ShutdownStack,
        output: DomainModuleResult,
    ) -> anyhow::Result<()> {
        let DomainModuleResult {
            probes,
            resources,
            workers,
        } = output;
        for resource in resources {
            stack.register_detached(resource);
        }
        for worker in workers {
            stack.register_with_token(worker);
        }
        anyhow::ensure!(
            probes.is_empty(),
            "launch lifecycle output still contains undrained probes"
        );
        Ok(())
    }
}

/// Production launch entry: bind listeners, wait for SIGTERM/SIGINT, then drain resources.
pub(crate) async fn launch(
    config: SnapshotConfig<'_>,
    budget: httpserve::ServerRequestBudget,
    plan: LaunchPlan,
) -> anyhow::Result<()> {
    launch_until(
        plan,
        budget,
        move |listener, scheme| listeners::listener_addr_for_scheme(config, listener, scheme),
        wait_for_shutdown_signal(),
    )
    .await
}

/// Testable launch core with injected address resolver and shutdown trigger.
pub(crate) async fn launch_until<R, S>(
    plan: LaunchPlan,
    budget: httpserve::ServerRequestBudget,
    addr_resolver: R,
    shutdown: S,
) -> anyhow::Result<()>
where
    R: Fn(ListenerKind, AuthScheme) -> anyhow::Result<SocketAddr>,
    S: Future<Output = anyhow::Result<()>>,
{
    launch_until_observed(plan, budget, addr_resolver, shutdown, |_| {}).await
}

// reason: bind loop + registration + drain logging is one launch phase; splitting would hide the startup/drain order.
#[allow(clippy::cognitive_complexity)]
async fn launch_until_observed<R, S, O>(
    plan: LaunchPlan,
    budget: httpserve::ServerRequestBudget,
    addr_resolver: R,
    shutdown: S,
    observe_ready_stack: O,
) -> anyhow::Result<()>
where
    R: Fn(ListenerKind, AuthScheme) -> anyhow::Result<SocketAddr>,
    S: Future<Output = anyhow::Result<()>>,
    O: FnOnce(&ShutdownStack),
{
    let listener_count = plan.listener_count();
    let mut stack = ShutdownStack::new(CancellationToken::new());
    let launch_result = async {
        let listeners = plan.register(&mut stack)?;
        anyhow::ensure!(
            listener_count > 0,
            "no listener has routes to serve (refusing to start with zero bound sockets)"
        );
        let bound = BoundListenerSet::prepare(listeners, budget, &addr_resolver).await?;
        bound.activate(&mut stack)?;
        observe_ready_stack(&stack);
        tracing::info!(listener_count, "all listeners bound; server ready");
        shutdown.await
    }
    .await;

    if launch_result.is_ok() {
        tracing::info!("draining listeners (graceful)");
    } else {
        tracing::warn!("launch lifecycle failed; draining registered resources");
    }
    let drain_result = report_shutdown_failures(stack.shutdown().await);
    preserve_launch_error(launch_result, drain_result)
}

fn preserve_launch_error(
    launch_result: anyhow::Result<()>,
    drain_result: anyhow::Result<()>,
) -> anyhow::Result<()> {
    match (launch_result, drain_result) {
        (Ok(()), drain_result) => drain_result,
        (Err(launch_error), Ok(())) => Err(launch_error),
        (Err(launch_error), Err(drain_error)) => {
            tracing::error!(
                cleanup_error = %drain_error,
                "launch failed and cleanup also failed; preserving primary launch error"
            );
            Err(launch_error)
        }
    }
}

/// Fully prepared listener set. Private fields make partial activation unrepresentable outside this
/// module: every socket and transport must prepare successfully before the set can be consumed.
struct BoundListenerSet {
    non_health: Vec<BoundListener>,
    health: Vec<BoundListener>,
}

struct BoundListener {
    listener: ListenerKind,
    scheme: AuthScheme,
    bound: httpd::BoundHttpServer,
    svc: httpserve::ServerMakeService,
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
    async fn prepare<R>(
        listeners: Vec<routes::AssembledListener>,
        budget: httpserve::ServerRequestBudget,
        addr_resolver: &R,
    ) -> anyhow::Result<Self>
    where
        R: Fn(ListenerKind, AuthScheme) -> anyhow::Result<SocketAddr>,
    {
        let mut non_health = Vec::with_capacity(listeners.len());
        let mut health = Vec::new();
        for listener in listeners {
            let listener = BoundListener::prepare(listener, budget, addr_resolver).await?;
            if listener.listener == ListenerKind::Health {
                health.push(listener);
            } else {
                non_health.push(listener);
            }
        }
        Ok(Self { non_health, health })
    }

    fn activate(self, stack: &mut ShutdownStack) -> anyhow::Result<()> {
        for listener in self.non_health.iter().chain(&self.health) {
            listener.preflight_activation()?;
        }
        for listener in self.non_health.into_iter().chain(self.health) {
            listener.activate(stack);
        }
        Ok(())
    }
}

impl BoundListener {
    #[allow(clippy::cognitive_complexity)]
    async fn prepare<R>(
        listener: routes::AssembledListener,
        budget: httpserve::ServerRequestBudget,
        addr_resolver: &R,
    ) -> anyhow::Result<Self>
    where
        R: Fn(ListenerKind, AuthScheme) -> anyhow::Result<SocketAddr>,
    {
        let (listener, scheme, routes, transport) = listener.into_launch_parts();
        let transport = resolve_listener_transport(listener, scheme, transport)?;
        let name = listeners::listener_name(listener);
        let addr = addr_resolver(listener, scheme)?;
        let bound = HttpServer::bind(name, addr)
            .await
            .with_context(|| format!("bind {name} listener at {addr}"))?;
        tracing::info!(listener = ?listener, name, addr = %bound.local_addr(), "listener bound");
        let transport = match transport {
            ResolvedListenerTransport::Mtls(material) => {
                let mtls = mtls_config(listener, material.allow_set, &material.spiffe_endpoint)
                    .await
                    .with_context(|| format!("build {name} mTLS config"))?;
                PreparedListenerTransport::Mtls {
                    config: mtls,
                    health: material.health,
                }
            }
            ResolvedListenerTransport::Plaintext => PreparedListenerTransport::Plaintext,
        };
        Ok(Self {
            listener,
            scheme,
            bound,
            svc: routes.into_make_service(budget),
            transport,
        })
    }

    fn preflight_activation(&self) -> anyhow::Result<()> {
        match &self.transport {
            PreparedListenerTransport::Plaintext => Ok(()),
            PreparedListenerTransport::Mtls { config, health } => health.set(config.clone()),
        }
    }

    fn activate(self, stack: &mut ShutdownStack) {
        let Self {
            listener,
            scheme,
            bound,
            svc,
            transport,
        } = self;
        match transport {
            PreparedListenerTransport::Mtls { config, health: _ } => {
                stack.register_with_token(move |token| {
                    DynManagedResource::new_box(bound.serve_mtls(svc, config, token))
                });
            }
            PreparedListenerTransport::Plaintext => {
                if listener == ListenerKind::Internal && scheme == AuthScheme::ServiceToken {
                    tracing::warn!(
                        listener = ?listener,
                        "binding local-test Internal service-token listener; mTLS is the production default"
                    );
                }
                stack.register_with_token(move |token| {
                    DynManagedResource::new_box(bound.serve(svc, token))
                });
            }
        }
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
    }
}

async fn mtls_config(
    listener: ListenerKind,
    allow_set: authn::MtlsAllowSet,
    spiffe_endpoint: &str,
) -> anyhow::Result<httpd::MtlsServerConfig> {
    anyhow::ensure!(
        listener == ListenerKind::Internal,
        "mTLS listener config is only wired for Internal"
    );
    httpd::MtlsServerConfig::from_spire(allow_set, Some(spiffe_endpoint))
        .await
        .context("build Internal listener mTLS config from captured SPIFFE endpoint")
}

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

// reason: cfg(unix) branch installs two signal streams and selects one; this is a tight OS-signal boundary.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_snapshot;

    use diport::{ManagedResource, ShutdownError};
    use primitives::{HealthCheck, HealthStatus, ProbeName};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;
    use tracing_subscriber::prelude::*;

    #[derive(Clone)]
    struct ErrorEventCounter(Arc<AtomicUsize>);

    impl<S> tracing_subscriber::Layer<S> for ErrorEventCounter
    where
        S: tracing::Subscriber,
    {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() == tracing::Level::ERROR {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    struct NamedResource {
        name: &'static str,
    }

    impl ManagedResource for NamedResource {
        fn name(&self) -> &str {
            self.name
        }

        fn shutdown_timeout(&self) -> Duration {
            Duration::from_secs(5)
        }

        async fn shutdown(&self) -> Result<(), ShutdownError> {
            Ok(())
        }
    }

    fn resource(name: &'static str) -> Box<DynManagedResource<'static>> {
        DynManagedResource::new_box(NamedResource { name })
    }

    struct RecordingResource {
        name: &'static str,
        shutdowns: Arc<AtomicUsize>,
        fail_shutdown: bool,
    }

    impl ManagedResource for RecordingResource {
        fn name(&self) -> &str {
            self.name
        }

        fn shutdown_timeout(&self) -> Duration {
            Duration::from_secs(5)
        }

        async fn shutdown(&self) -> Result<(), ShutdownError> {
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
            if self.fail_shutdown {
                return Err(ShutdownError::new(std::io::Error::other(
                    "recorded cleanup failure",
                )));
            }
            Ok(())
        }
    }

    fn recording_resource(
        name: &'static str,
        shutdowns: Arc<AtomicUsize>,
    ) -> Box<DynManagedResource<'static>> {
        DynManagedResource::new_box(RecordingResource {
            name,
            shutdowns,
            fail_shutdown: false,
        })
    }

    fn failing_recording_resource(
        name: &'static str,
        shutdowns: Arc<AtomicUsize>,
    ) -> Box<DynManagedResource<'static>> {
        DynManagedResource::new_box(RecordingResource {
            name,
            shutdowns,
            fail_shutdown: true,
        })
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

    fn worker(name: &'static str) -> WorkerSpec {
        Box::new(move |_token| resource(name))
    }

    fn pg_runtime_module(audit_guard: bool) -> DomainModuleResult {
        let mut resources = vec![resource("pg-store")];
        if audit_guard {
            resources.push(resource("pg-audit"));
        }
        DomainModuleResult {
            resources,
            workers: vec![worker("pg-sampler")],
            ..DomainModuleResult::default()
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

    #[test]
    #[allow(clippy::expect_used)]
    fn server_request_budget_is_required_non_zero_and_snapshot_backed() {
        let missing = test_snapshot(&[]).expect("capture empty config");
        let error = server_request_budget(missing.view()).expect_err("budget is mandatory");
        assert!(error.to_string().contains(HTTP_SERVER_REQUEST_BUDGET_ENV));

        for raw in ["0", "not-a-number"] {
            let snapshot = test_snapshot(&[(HTTP_SERVER_REQUEST_BUDGET_ENV, raw)])
                .expect("capture invalid budget");
            let error = server_request_budget(snapshot.view()).expect_err("invalid budget");
            assert!(error.to_string().contains(HTTP_SERVER_REQUEST_BUDGET_ENV));
        }

        let snapshot = test_snapshot(&[(HTTP_SERVER_REQUEST_BUDGET_ENV, "2500")])
            .expect("capture valid budget");
        assert_eq!(
            server_request_budget(snapshot.view())
                .expect("valid budget")
                .millis()
                .get(),
            2500
        );
    }

    fn minimal_plan(listeners: Vec<routes::AssembledListener>) -> LaunchPlan {
        LaunchPlan::new(LaunchPlanParts {
            listeners: routes::FinalizedListenerSet::for_test(listeners),
            trace_exporter: None,
            pg_runtime_module: pg_runtime_module(false),
            domain_module: DomainModuleResult::default(),
        })
    }

    fn full_plan(trace: bool, audit_guard: bool) -> LaunchPlan {
        LaunchPlan::new(LaunchPlanParts {
            listeners: routes::FinalizedListenerSet::for_test(vec![test_health_assembled()]),
            trace_exporter: trace.then(|| resource("trace-exporter")),
            pg_runtime_module: pg_runtime_module(audit_guard),
            domain_module: DomainModuleResult {
                resources: vec![
                    resource("domain-resource-a"),
                    resource("domain-resource-b"),
                    resource("event-infra-a"),
                    resource("event-infra-b"),
                ],
                workers: vec![worker("domain-worker-a"), worker("domain-worker-b")],
                ..DomainModuleResult::default()
            },
        })
    }

    #[allow(clippy::expect_used)] // reason: direct test assertion path for clean launch and poisoned test mutexes.
    async fn registered_names(plan: LaunchPlan) -> Vec<String> {
        let names = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&names);
        launch_until_observed(
            plan,
            test_budget(),
            ephemeral_addr,
            std::future::ready(anyhow::Ok(())),
            move |stack| {
                *captured.lock().expect("registered names lock") =
                    stack.registered_names().map(str::to_owned).collect();
            },
        )
        .await
        .expect("launch drains clean");
        Arc::try_unwrap(names)
            .expect("only observer holds names")
            .into_inner()
            .expect("registered names lock")
    }

    #[tokio::test]
    async fn launch_plan_registers_shutdown_resources_in_lifo_dependency_order() {
        let names = registered_names(full_plan(true, true)).await;
        assert_eq!(
            names,
            [
                "trace-exporter",
                "pg-store",
                "pg-audit",
                "pg-sampler",
                "domain-resource-a",
                "domain-resource-b",
                "event-infra-a",
                "event-infra-b",
                "domain-worker-a",
                "domain-worker-b",
                "http-health",
            ]
        );
        let drain = names.iter().rev().map(String::as_str).collect::<Vec<_>>();
        assert_eq!(
            drain,
            [
                "http-health",
                "domain-worker-b",
                "domain-worker-a",
                "event-infra-b",
                "event-infra-a",
                "domain-resource-b",
                "domain-resource-a",
                "pg-sampler",
                "pg-audit",
                "pg-store",
                "trace-exporter",
            ]
        );
    }

    #[tokio::test]
    async fn launch_plan_omits_optional_trace_and_audit_without_placeholders() {
        let names = registered_names(full_plan(false, false)).await;
        assert_eq!(
            names,
            [
                "pg-store",
                "pg-sampler",
                "domain-resource-a",
                "domain-resource-b",
                "event-infra-a",
                "event-infra-b",
                "domain-worker-a",
                "domain-worker-b",
                "http-health",
            ]
        );
        assert!(!names.iter().any(|name| name.contains("trace")));
        assert!(!names.iter().any(|name| name.contains("audit")));
    }

    #[test]
    #[allow(clippy::expect_used)] // reason: direct test assertion for expected error branch.
    fn report_shutdown_failures_ok_when_empty_err_when_failures() {
        use bootstrap::shutdown::{ResourceShutdownError, ShutdownFailureKind};

        assert!(report_shutdown_failures(Vec::new()).is_ok());

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
        let err = report_shutdown_failures(failures).expect_err("non-empty failures -> Err");
        assert!(err.to_string().contains("2 listener failure"));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: direct async test assertion for clean listener launch.
    async fn launch_plan_binds_all_listeners_and_drains_clean() {
        let plan = minimal_plan(vec![test_health_assembled(), test_health_assembled()]);
        launch_until(
            plan,
            test_budget(),
            ephemeral_addr,
            std::future::ready(anyhow::Ok(())),
        )
        .await
        .expect("launch_until binds 2 listeners + drains clean");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn default_launch_serves_request_id_then_drains_and_releases_socket() {
        let reservation = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve Health address");
        let addr = reservation.local_addr().expect("reserved Health address");
        drop(reservation);

        let request = async move {
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
                .context("Health liveness request")?;
            assert_eq!(liveness.status(), reqwest::StatusCode::OK);
            anyhow::Ok(())
        };

        launch_until(
            minimal_plan(vec![healthy_test_health_assembled()]),
            test_budget(),
            move |listener, scheme| {
                assert_eq!(listener, ListenerKind::Health);
                assert_eq!(scheme, AuthScheme::NoAuth);
                Ok(addr)
            },
            request,
        )
        .await
        .expect("real Health request then graceful drain");

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
    async fn default_launch_serves_metrics_exposition_over_real_socket() {
        let reservation = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve Health address");
        let addr = reservation.local_addr().expect("reserved Health address");
        drop(reservation);
        let metrics: Arc<dyn diport::MetricsExporter> =
            Arc::new(FixedMetrics("rss_launch_e2e_total 7\n"));
        let listener = routes::AssembledListener::health_for_test(test_reporter(), metrics)
            .expect("metrics Health listener");

        launch_until(
            minimal_plan(vec![listener]),
            test_budget(),
            move |_, _| Ok(addr),
            async move {
                let response = reqwest::Client::new()
                    .get(format!("http://{addr}/health/v1/metrics"))
                    .send()
                    .await
                    .context("metrics request over real socket")?;
                assert_eq!(response.status(), reqwest::StatusCode::OK);
                assert_eq!(
                    response
                        .headers()
                        .get("content-type")
                        .and_then(|value| value.to_str().ok()),
                    Some("text/plain; version=0.0.4; charset=utf-8")
                );
                let body = response.text().await.context("metrics response body")?;
                assert!(body.contains("rss_launch_e2e_total"));
                anyhow::Ok(())
            },
        )
        .await
        .expect("metrics request then graceful drain");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn default_launch_empty_probe_readyz_fails_closed_over_real_socket() {
        let reservation = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve Health address");
        let addr = reservation.local_addr().expect("reserved Health address");
        drop(reservation);

        launch_until(
            minimal_plan(vec![test_health_assembled()]),
            test_budget(),
            move |_, _| Ok(addr),
            async move {
                let response = reqwest::Client::new()
                    .get(format!("http://{addr}/health/v1/readyz"))
                    .send()
                    .await
                    .context("empty-probe readyz request")?;
                assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
                anyhow::Ok(())
            },
        )
        .await
        .expect("empty-probe request then graceful drain");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn bound_listener_set_activates_through_shutdown_stack_funnel() {
        let bound = BoundListenerSet::prepare(
            vec![healthy_test_health_assembled()],
            test_budget(),
            &ephemeral_addr,
        )
        .await
        .expect("prepare Health listener set");
        let addr = bound.health[0].bound.local_addr();
        let mut stack = ShutdownStack::new(CancellationToken::new());

        bound
            .activate(&mut stack)
            .expect("activate fully prepared Health set");
        assert_eq!(
            stack.registered_names().collect::<Vec<_>>(),
            ["http-health"]
        );
        let response = reqwest::Client::new()
            .get(format!("http://{addr}/health/v1/readyz"))
            .send()
            .await
            .expect("readyz over funnel-served socket");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert!(
            stack.shutdown().await.is_empty(),
            "ShutdownStack funnel must drain the listener cleanly"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: direct async test assertion for fail-fast listener validation.
    async fn launch_plan_empty_listeners_errs() {
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let mut plan = minimal_plan(Vec::new());
        plan.domain_module.resources.push(recording_resource(
            "recorded-domain",
            Arc::clone(&shutdowns),
        ));
        let err = launch_until(
            plan,
            test_budget(),
            ephemeral_addr,
            std::future::ready(anyhow::Ok(())),
        )
        .await
        .expect_err("empty listeners must fail fast");
        assert!(err.to_string().contains("zero bound sockets"));
        assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: direct async test assertion and poisoned test mutex handling.
    async fn launch_until_passes_assembled_scheme_to_addr_resolver() {
        let listener = test_health_assembled();
        let resolved = Arc::new(Mutex::new(None));
        let seen = Arc::clone(&resolved);

        launch_until(
            minimal_plan(vec![listener]),
            test_budget(),
            move |listener, scheme| {
                assert_eq!(listener, ListenerKind::Health);
                *seen.lock().expect("scheme lock") = Some(scheme);
                "127.0.0.1:0".parse::<SocketAddr>().map_err(Into::into)
            },
            std::future::ready(anyhow::Ok(())),
        )
        .await
        .expect("launch_until binds listener");

        assert_eq!(
            *resolved.lock().expect("scheme lock"),
            Some(AuthScheme::NoAuth)
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: direct async test assertion for resolver error propagation.
    async fn launch_until_addr_resolver_failure_propagates() {
        let err = launch_until(
            minimal_plan(vec![test_health_assembled()]),
            test_budget(),
            |_, _| anyhow::bail!("no addr configured for listener"),
            std::future::ready(anyhow::Ok(())),
        )
        .await
        .expect_err("addr resolver failure must propagate");
        assert!(err.to_string().contains("no addr configured"));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn launch_plan_partial_bind_failure_drains_resources_once_and_releases_port() {
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
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let mut plan = minimal_plan(vec![test_health_assembled(), test_health_assembled()]);
        plan.domain_module.resources.push(recording_resource(
            "recorded-domain",
            Arc::clone(&shutdowns),
        ));

        let err = launch_until(
            plan,
            test_budget(),
            move |_, _| {
                let index = resolver_index.fetch_add(1, Ordering::SeqCst);
                addresses
                    .get(index)
                    .copied()
                    .context("unexpected listener address request")
            },
            std::future::pending::<anyhow::Result<()>>(),
        )
        .await
        .expect_err("second bind must fail");

        assert!(format!("{err:#}").contains("bind http-health listener"));
        assert_eq!(next_addr.load(Ordering::SeqCst), 2);
        assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
        let rebound = tokio::net::TcpListener::bind(first_addr)
            .await
            .expect("partial-start listener port must be released by drain");
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
            tokio::spawn(launch_until(
                minimal_plan(vec![
                    healthy_test_health_assembled(),
                    test_health_assembled(),
                ]),
                test_budget(),
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
                std::future::pending::<anyhow::Result<()>>(),
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
            .expect_err("later listener bind must fail");
        assert!(format!("{error:#}").contains("bind http-health listener"));
        assert!(
            !matches!(premature_response, Ok(Ok(_))),
            "Health must not serve before every listener socket and transport is ready: \
             {premature_response:?}"
        );
        drop(occupied);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn launch_plan_shutdown_trigger_error_preserves_error_and_drains_once() {
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let mut plan = minimal_plan(vec![test_health_assembled()]);
        plan.domain_module.resources.push(recording_resource(
            "recorded-domain",
            Arc::clone(&shutdowns),
        ));

        let err = launch_until(
            plan,
            test_budget(),
            ephemeral_addr,
            std::future::ready(Err(anyhow::anyhow!("shutdown trigger failed"))),
        )
        .await
        .expect_err("shutdown trigger failure must remain primary");

        assert!(format!("{err:#}").contains("shutdown trigger failed"));
        assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn launch_plan_preserves_primary_error_when_cleanup_also_fails() {
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let cleanup_error_events = Arc::new(AtomicUsize::new(0));
        let subscriber = tracing_subscriber::registry()
            .with(ErrorEventCounter(Arc::clone(&cleanup_error_events)));
        let _subscriber_guard = tracing::subscriber::set_default(subscriber);
        let mut plan = minimal_plan(vec![test_health_assembled()]);
        plan.domain_module
            .resources
            .push(failing_recording_resource(
                "failing-domain",
                Arc::clone(&shutdowns),
            ));

        let err = launch_until(
            plan,
            test_budget(),
            ephemeral_addr,
            std::future::ready(Err(anyhow::anyhow!("primary shutdown trigger failure"))),
        )
        .await
        .expect_err("primary launch error must be preserved");

        assert_eq!(err.to_string(), "primary shutdown trigger failure");
        assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
        assert!(
            cleanup_error_events.load(Ordering::SeqCst) > 0,
            "cleanup failure must be reported while the primary error is preserved"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn launch_plan_partial_registration_failure_drains_registered_resources_once() {
        let trace_shutdowns = Arc::new(AtomicUsize::new(0));
        let pg_shutdowns = Arc::new(AtomicUsize::new(0));
        let domain_shutdowns = Arc::new(AtomicUsize::new(0));
        let probe_name = ProbeName::parse("leftover-probe").expect("valid probe name");
        let plan = LaunchPlan::new(LaunchPlanParts {
            listeners: routes::FinalizedListenerSet::for_test(vec![test_health_assembled()]),
            trace_exporter: Some(recording_resource(
                "trace-exporter",
                Arc::clone(&trace_shutdowns),
            )),
            pg_runtime_module: DomainModuleResult {
                probes: vec![(probe_name, Box::new(NoopProbe))],
                resources: vec![recording_resource(
                    "pg-owned-resource",
                    Arc::clone(&pg_shutdowns),
                )],
                ..DomainModuleResult::default()
            },
            domain_module: DomainModuleResult {
                resources: vec![recording_resource(
                    "domain-owned-resource",
                    Arc::clone(&domain_shutdowns),
                )],
                ..DomainModuleResult::default()
            },
        });

        let err = launch_until(
            plan,
            test_budget(),
            ephemeral_addr,
            std::future::ready(anyhow::Ok(())),
        )
        .await
        .expect_err("leftover probe must fail registration");

        assert!(format!("{err:#}").contains("undrained probes"));
        assert_eq!(trace_shutdowns.load(Ordering::SeqCst), 1);
        assert_eq!(pg_shutdowns.load(Ordering::SeqCst), 1);
        assert_eq!(domain_shutdowns.load(Ordering::SeqCst), 1);
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
        let (_, routes) = test_health_assembled().into_parts();
        let bound = HttpServer::bind(
            "http-internal",
            "127.0.0.1:0".parse().expect("ephemeral address"),
        )
        .await
        .expect("bind hermetic mTLS listener");
        let mut stack = ShutdownStack::new(CancellationToken::new());

        assert_eq!(
            health.check().1,
            "not-bound",
            "socket and transport preparation must not publish readiness"
        );
        BoundListenerSet {
            non_health: vec![BoundListener {
                listener: ListenerKind::Internal,
                scheme: AuthScheme::Mtls,
                bound,
                svc: routes.into_make_service(test_budget()),
                transport: PreparedListenerTransport::Mtls {
                    config: mtls,
                    health: Arc::clone(&health),
                },
            }],
            health: Vec::new(),
        }
        .activate(&mut stack)
        .expect("preflight and activate mTLS set");

        assert_ne!(health.check().1, "not-bound", "readiness slot must be set");
        assert_eq!(
            stack.registered_names().collect::<Vec<_>>(),
            ["http-internal"]
        );
        assert!(
            stack.shutdown().await.is_empty(),
            "mTLS resource must drain"
        );
    }
}
