//! Runtime launch phase: listener serving plus LIFO shutdown registration.

use crate::{SPIFFE_ENDPOINT_SOCKET_ENV, listeners, routes};

use std::future::Future;
use std::net::SocketAddr;

use anyhow::Context as _;
use bootstrap::DomainModuleResult;
#[cfg(test)]
use bootstrap::WorkerSpec;
use bootstrap::shutdown::ShutdownStack;
use diport::DynManagedResource;
use httpd::HttpServer;
use primitives::{AuthScheme, ListenerKind};
use tokio_util::sync::CancellationToken;

/// Resources owned by the launch phase, grouped by lifecycle dependency.
pub(crate) struct LaunchPlanParts {
    pub(crate) listeners: Vec<routes::AssembledListener>,
    pub(crate) trace_exporter: Option<Box<DynManagedResource<'static>>>,
    pub(crate) pg_runtime_module: DomainModuleResult,
    pub(crate) domain_module: DomainModuleResult,
}

/// Launch plan consumed by [`launch`] to register shutdown resources and serve listeners.
pub(crate) struct LaunchPlan {
    listeners: Vec<routes::AssembledListener>,
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
        Self::register_module_output(stack, pg_runtime_module)?;
        // Event infra lives in domain_module.resources and outlives all module workers.
        Self::register_module_output(stack, domain_module)?;

        Ok(listeners)
    }

    /// Registers one lifecycle output batch through the common resources-then-workers funnel.
    fn register_module_output(
        stack: &mut ShutdownStack,
        output: DomainModuleResult,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            output.probes.is_empty(),
            "launch lifecycle output still contains undrained probes"
        );
        for resource in output.resources {
            stack.register_detached(resource);
        }
        for worker in output.workers {
            stack.register_with_token(worker);
        }
        Ok(())
    }
}

/// Production launch entry: bind listeners, wait for SIGTERM/SIGINT, then drain resources.
pub(crate) async fn launch(plan: LaunchPlan) -> anyhow::Result<()> {
    launch_until(
        plan,
        listeners::listener_addr_for_scheme,
        wait_for_shutdown_signal(),
    )
    .await
}

/// Testable launch core with injected address resolver and shutdown trigger.
pub(crate) async fn launch_until<R, S>(
    plan: LaunchPlan,
    addr_resolver: R,
    shutdown: S,
) -> anyhow::Result<()>
where
    R: Fn(ListenerKind, AuthScheme) -> anyhow::Result<SocketAddr>,
    S: Future<Output = anyhow::Result<()>>,
{
    launch_until_observed(plan, addr_resolver, shutdown, |_| {}).await
}

// reason: bind loop + registration + drain logging is one launch phase; splitting would hide the startup/drain order.
#[allow(clippy::cognitive_complexity)]
async fn launch_until_observed<R, S, O>(
    plan: LaunchPlan,
    addr_resolver: R,
    shutdown: S,
    observe_ready_stack: O,
) -> anyhow::Result<()>
where
    R: Fn(ListenerKind, AuthScheme) -> anyhow::Result<SocketAddr>,
    S: Future<Output = anyhow::Result<()>>,
    O: FnOnce(&ShutdownStack),
{
    anyhow::ensure!(
        plan.listener_count() > 0,
        "no listener has routes to serve (refusing to start with zero bound sockets)"
    );
    let listener_count = plan.listener_count();
    let mut stack = ShutdownStack::new(CancellationToken::new());
    let listeners = plan.register(&mut stack)?;
    for listener in listeners {
        bind_and_register(&mut stack, listener, &addr_resolver).await?;
    }
    observe_ready_stack(&stack);
    tracing::info!(listener_count, "all listeners bound; server ready");

    shutdown.await?;
    tracing::info!("draining listeners (graceful)");
    report_shutdown_failures(stack.shutdown().await)
}

/// Bind one listener socket and register the serve task through the shutdown token funnel.
// reason: this is the per-listener assembly junction; keeping bind, auth-scheme selection, and
// plaintext/mTLS ShutdownStack registration together makes fail-fast startup order explicit.
#[allow(clippy::cognitive_complexity)]
async fn bind_and_register<R>(
    stack: &mut ShutdownStack,
    listener: routes::AssembledListener,
    addr_resolver: &R,
) -> anyhow::Result<()>
where
    R: Fn(ListenerKind, AuthScheme) -> anyhow::Result<SocketAddr>,
{
    let routes::AssembledListener {
        listener,
        scheme,
        routes,
        mtls_health,
    } = listener;
    let name = listeners::listener_name(listener);
    let addr = addr_resolver(listener, scheme)?;
    let bound = HttpServer::bind(name, addr)
        .await
        .with_context(|| format!("bind {name} listener at {addr}"))?;
    tracing::info!(listener = ?listener, name, addr = %bound.local_addr(), "listener bound");
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
                    "binding local-test Internal service-token listener; mTLS is the production default"
                );
            }
            stack.register_with_token(move |token| {
                DynManagedResource::new_box(bound.serve(svc, token))
            });
        }
    }
    Ok(())
}

async fn mtls_config_from_env(listener: ListenerKind) -> anyhow::Result<httpd::MtlsServerConfig> {
    let allow_set = routes::mtls_allow_set_from_env(listener, |name| std::env::var(name).ok())?;
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
    use crate::listeners::health_listener;

    use diport::{ManagedResource, ShutdownError};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

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
        let (listener, routes) =
            health_listener(test_reporter(), noop_metrics()).expect("health listener");
        routes::AssembledListener::plain(listener, routes)
    }

    fn ephemeral_addr(_l: ListenerKind, _scheme: AuthScheme) -> anyhow::Result<SocketAddr> {
        "127.0.0.1:0".parse::<SocketAddr>().map_err(Into::into)
    }

    fn minimal_plan(listeners: Vec<routes::AssembledListener>) -> LaunchPlan {
        LaunchPlan::new(LaunchPlanParts {
            listeners,
            trace_exporter: None,
            pg_runtime_module: pg_runtime_module(false),
            domain_module: DomainModuleResult::default(),
        })
    }

    fn full_plan(trace: bool, audit_guard: bool) -> LaunchPlan {
        LaunchPlan::new(LaunchPlanParts {
            listeners: vec![test_health_assembled()],
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
    async fn launch_until_binds_all_listeners_and_drains_clean() {
        let plan = minimal_plan(vec![test_health_assembled(), test_health_assembled()]);
        launch_until(plan, ephemeral_addr, std::future::ready(anyhow::Ok(())))
            .await
            .expect("launch_until binds 2 listeners + drains clean");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: direct async test assertion for fail-fast listener validation.
    async fn launch_until_empty_listeners_errs() {
        let err = launch_until(
            minimal_plan(Vec::new()),
            ephemeral_addr,
            std::future::ready(anyhow::Ok(())),
        )
        .await
        .expect_err("empty listeners must fail fast");
        assert!(err.to_string().contains("zero bound sockets"));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: direct async test assertion and poisoned test mutex handling.
    async fn launch_until_passes_assembled_scheme_to_addr_resolver() {
        let listener = test_health_assembled();
        let resolved = Arc::new(Mutex::new(None));
        let seen = Arc::clone(&resolved);

        launch_until(
            minimal_plan(vec![listener]),
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
            |_, _| anyhow::bail!("no addr configured for listener"),
            std::future::ready(anyhow::Ok(())),
        )
        .await
        .expect_err("addr resolver failure must propagate");
        assert!(err.to_string().contains("no addr configured"));
    }
}
