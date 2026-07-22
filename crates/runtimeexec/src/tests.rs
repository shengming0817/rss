#![allow(clippy::expect_used)]
// reason: lifecycle tests use expect for direct assertion failures and poisoned test mutexes.

use super::*;

use std::future::{Future, ready};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bootstrap::{DomainModuleResult, HealthProbe};
use diport::{DynManagedResource, ManagedResource, ShutdownError};
use primitives::{HealthCheck, HealthStatus, ProbeName};
use static_assertions::assert_not_impl_any;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::prelude::*;

#[derive(Clone)]
struct Transcript(Arc<Mutex<Vec<&'static str>>>);

impl Transcript {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }

    fn record(&self, event: &'static str) {
        self.0.lock().expect("transcript lock").push(event);
    }

    fn snapshot(&self) -> Vec<&'static str> {
        self.0.lock().expect("transcript lock").clone()
    }
}

struct RecordingResource {
    name: &'static str,
    transcript: Transcript,
    fail: bool,
}

impl ManagedResource for RecordingResource {
    fn name(&self) -> &str {
        self.name
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.transcript.record(self.name);
        if self.fail {
            return Err(ShutdownError::new(std::io::Error::other(
                "recorded shutdown failure",
            )));
        }
        Ok(())
    }
}

fn resource(name: &'static str, transcript: &Transcript) -> Box<DynManagedResource<'static>> {
    DynManagedResource::new_box(RecordingResource {
        name,
        transcript: transcript.clone(),
        fail: false,
    })
}

fn failing_resource(
    name: &'static str,
    transcript: &Transcript,
) -> Box<DynManagedResource<'static>> {
    DynManagedResource::new_box(RecordingResource {
        name,
        transcript: transcript.clone(),
        fail: true,
    })
}

fn worker(name: &'static str, transcript: &Transcript) -> bootstrap::WorkerSpec {
    let transcript = transcript.clone();
    Box::new(move |token: CancellationToken| {
        assert!(
            !token.is_cancelled(),
            "worker token must be live at registration"
        );
        resource(name, &transcript)
    })
}

struct ProbeReceipt;

struct FakeAdapter {
    listener_names: Vec<&'static str>,
    transcript: Transcript,
    fail_prepare: bool,
}

struct PreparedFake {
    listener_names: Vec<&'static str>,
    transcript: Transcript,
}

struct ReadyInventory {
    listener_count: usize,
}

impl LaunchAdapter<ProbeReceipt> for FakeAdapter {
    type Prepared = PreparedFake;
    type Inventory = ReadyInventory;

    fn prepare(
        self,
        _receipt: ProbeReceipt,
        _transaction: &mut LaunchTransaction<'_>,
    ) -> impl Future<Output = anyhow::Result<Self::Prepared>> + Send {
        if self.fail_prepare {
            return ready(Err(anyhow::anyhow!("prepare failed")));
        }
        ready(Ok(PreparedFake {
            listener_names: self.listener_names,
            transcript: self.transcript,
        }))
    }

    fn activate(
        prepared: Self::Prepared,
        mut registrar: LaunchRegistrar<'_>,
    ) -> anyhow::Result<Activated<Self::Inventory>> {
        let listener_count = prepared.listener_names.len();
        for name in prepared.listener_names {
            let transcript = prepared.transcript.clone();
            registrar.register_listener_with_token(move |_token| resource(name, &transcript));
        }
        registrar.complete(ReadyInventory { listener_count })
    }
}

struct CancellationObservedResource {
    token: CancellationToken,
    shutdowns: Arc<AtomicUsize>,
    cancelled_at_shutdown: Arc<AtomicBool>,
    shutdown_done: Arc<Notify>,
}

impl ManagedResource for CancellationObservedResource {
    fn name(&self) -> &str {
        "cancellation-observed"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.cancelled_at_shutdown
            .store(self.token.is_cancelled(), Ordering::SeqCst);
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        self.shutdown_done.notify_one();
        Ok(())
    }
}

struct CancellationAdapter {
    activated: Arc<Notify>,
    shutdowns: Arc<AtomicUsize>,
    cancelled_at_shutdown: Arc<AtomicBool>,
    shutdown_done: Arc<Notify>,
}

struct PrepareOwnedAdapter {
    prepare_started: Arc<Notify>,
    shutdown_started: Arc<Notify>,
    release_shutdown: Arc<Notify>,
    shutdowns: Arc<AtomicUsize>,
    shutdown_done: Arc<Notify>,
}

struct PrepareOwnedResource {
    shutdown_started: Arc<Notify>,
    release_shutdown: Arc<Notify>,
    shutdowns: Arc<AtomicUsize>,
    shutdown_done: Arc<Notify>,
}

impl ManagedResource for PrepareOwnedResource {
    fn name(&self) -> &str {
        "prepare-owned"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.shutdown_started.notify_one();
        self.release_shutdown.notified().await;
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        self.shutdown_done.notify_one();
        Ok(())
    }
}

impl LaunchAdapter<ProbeReceipt> for PrepareOwnedAdapter {
    type Prepared = ();
    type Inventory = ();

    fn prepare(
        self,
        _receipt: ProbeReceipt,
        transaction: &mut LaunchTransaction<'_>,
    ) -> impl Future<Output = anyhow::Result<Self::Prepared>> + Send {
        transaction.stage_resource(DynManagedResource::new_box(PrepareOwnedResource {
            shutdown_started: self.shutdown_started,
            release_shutdown: self.release_shutdown,
            shutdowns: self.shutdowns,
            shutdown_done: self.shutdown_done,
        }));
        self.prepare_started.notify_one();
        std::future::pending::<anyhow::Result<()>>()
    }

    fn activate(
        _prepared: Self::Prepared,
        registrar: LaunchRegistrar<'_>,
    ) -> anyhow::Result<Activated<Self::Inventory>> {
        registrar.complete(())
    }
}

struct StagedOnlyAdapter {
    transcript: Transcript,
}

impl LaunchAdapter<ProbeReceipt> for StagedOnlyAdapter {
    type Prepared = ();
    type Inventory = ();

    fn prepare(
        self,
        _receipt: ProbeReceipt,
        transaction: &mut LaunchTransaction<'_>,
    ) -> impl Future<Output = anyhow::Result<Self::Prepared>> + Send {
        transaction.stage_resource(resource("staged-only", &self.transcript));
        ready(Ok(()))
    }

    fn activate(
        _prepared: Self::Prepared,
        registrar: LaunchRegistrar<'_>,
    ) -> anyhow::Result<Activated<Self::Inventory>> {
        registrar.complete(())
    }
}

struct FailingPrepareAdapter {
    transcript: Transcript,
}

impl LaunchAdapter<ProbeReceipt> for FailingPrepareAdapter {
    type Prepared = ();
    type Inventory = ();

    fn prepare(
        self,
        _receipt: ProbeReceipt,
        transaction: &mut LaunchTransaction<'_>,
    ) -> impl Future<Output = anyhow::Result<Self::Prepared>> + Send {
        transaction.stage_resource(failing_resource("staged-failure", &self.transcript));
        ready(Err(anyhow::anyhow!("prepare primary")))
    }

    fn activate(
        _prepared: Self::Prepared,
        registrar: LaunchRegistrar<'_>,
    ) -> anyhow::Result<Activated<Self::Inventory>> {
        registrar.complete(())
    }
}

struct PreparedCancellationAdapter(CancellationAdapter);

impl LaunchAdapter<ProbeReceipt> for CancellationAdapter {
    type Prepared = PreparedCancellationAdapter;
    type Inventory = ();

    fn prepare(
        self,
        _receipt: ProbeReceipt,
        _transaction: &mut LaunchTransaction<'_>,
    ) -> impl Future<Output = anyhow::Result<Self::Prepared>> + Send {
        ready(Ok(PreparedCancellationAdapter(self)))
    }

    fn activate(
        prepared: Self::Prepared,
        mut registrar: LaunchRegistrar<'_>,
    ) -> anyhow::Result<Activated<Self::Inventory>> {
        let CancellationAdapter {
            activated,
            shutdowns,
            cancelled_at_shutdown,
            shutdown_done,
        } = prepared.0;
        registrar.register_listener_with_token(move |token| {
            activated.notify_one();
            DynManagedResource::new_box(CancellationObservedResource {
                token,
                shutdowns,
                cancelled_at_shutdown,
                shutdown_done,
            })
        });
        registrar.complete(())
    }
}

struct GatedShutdownResource {
    name: &'static str,
    transcript: Transcript,
    started: Option<Arc<Notify>>,
    release: Option<Arc<Notify>>,
    done: Option<Arc<Notify>>,
}

impl ManagedResource for GatedShutdownResource {
    fn name(&self) -> &str {
        self.name
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.transcript.record(self.name);
        if let Some(started) = &self.started {
            started.notify_one();
        }
        if let Some(release) = &self.release {
            release.notified().await;
        }
        if let Some(done) = &self.done {
            done.notify_one();
        }
        Ok(())
    }
}

fn gated_resource(
    name: &'static str,
    transcript: &Transcript,
    started: Option<Arc<Notify>>,
    release: Option<Arc<Notify>>,
    done: Option<Arc<Notify>>,
) -> Box<DynManagedResource<'static>> {
    DynManagedResource::new_box(GatedShutdownResource {
        name,
        transcript: transcript.clone(),
        started,
        release,
        done,
    })
}

fn module(
    resources: Vec<Box<DynManagedResource<'static>>>,
    workers: Vec<bootstrap::WorkerSpec>,
) -> DomainModuleResult {
    DomainModuleResult {
        probes: Vec::new(),
        resources,
        workers,
    }
}

fn lifecycle_batches(
    provider: DomainModuleResult,
    domain: DomainModuleResult,
) -> LaunchLifecycleBatches {
    LaunchLifecycleBatches::new(
        ProviderLifecycleBatch::from_provider_output(provider),
        DomainLifecycleBatch::from_domain_output(domain),
    )
}

fn plan<H>(
    transcript: &Transcript,
    listener_names: Vec<&'static str>,
    fail_prepare: bool,
    provider_module: DomainModuleResult,
    domain_module: DomainModuleResult,
    on_ready: H,
) -> LaunchPlan<FakeAdapter, ProbeReceipt, H>
where
    H: FnOnce(ReadyInventory) -> anyhow::Result<()>,
{
    LaunchPlan::new(
        FakeAdapter {
            listener_names,
            transcript: transcript.clone(),
            fail_prepare,
        },
        ProbeReceipt,
        on_ready,
        Some(resource("trace", transcript)),
        lifecycle_batches(provider_module, domain_module),
    )
}

#[tokio::test]
async fn executor_drains_in_exact_dependency_lifo_order() {
    let transcript = Transcript::new();
    let ready_transcript = transcript.clone();
    let launch = plan(
        &transcript,
        vec!["listener-a", "listener-b"],
        false,
        module(
            vec![resource("provider-resource", &transcript)],
            vec![worker("provider-worker", &transcript)],
        ),
        module(
            vec![resource("domain-resource", &transcript)],
            vec![worker("domain-worker", &transcript)],
        ),
        move |inventory| {
            assert_eq!(inventory.listener_count, 2);
            ready_transcript.record("ready");
            Ok(())
        },
    );

    let _outputs = launch_until(launch, async { Ok(()) })
        .await
        .expect("launch and drain cleanly");

    assert_eq!(
        transcript.snapshot(),
        vec![
            "ready",
            "listener-b",
            "listener-a",
            "domain-worker",
            "domain-resource",
            "provider-worker",
            "provider-resource",
            "trace",
        ]
    );
}

#[tokio::test]
async fn executor_rejects_zero_listeners_after_registering_and_drains_owned_resources() {
    let transcript = Transcript::new();
    let ready_transcript = transcript.clone();
    let launch = plan(
        &transcript,
        Vec::new(),
        false,
        module(vec![resource("provider", &transcript)], Vec::new()),
        module(vec![resource("domain", &transcript)], Vec::new()),
        move |_| {
            ready_transcript.record("ready");
            Ok(())
        },
    );

    let error = launch_until(launch, async { Ok(()) })
        .await
        .err()
        .expect("zero listeners must fail");

    assert!(error.to_string().contains("no listener"));
    assert_eq!(transcript.snapshot(), vec!["domain", "provider", "trace"]);
}

#[tokio::test]
async fn executor_rejects_adapter_that_claims_listener_without_activating_one() {
    let transcript = Transcript::new();
    let ready_transcript = transcript.clone();
    let launch = LaunchPlan::new(
        FakeAdapter {
            listener_names: Vec::new(),
            transcript: transcript.clone(),
            fail_prepare: false,
        },
        ProbeReceipt,
        move |_| {
            ready_transcript.record("ready");
            Ok(())
        },
        None,
        lifecycle_batches(DomainModuleResult::default(), DomainModuleResult::default()),
    );

    let error = launch_until(launch, async { Ok(()) })
        .await
        .err()
        .expect("an adapter cannot self-attest a non-empty activation");

    assert!(error.to_string().contains("no listener"));
    assert!(transcript.snapshot().is_empty(), "ready hook must not run");
}

#[tokio::test]
async fn staged_prepare_resource_does_not_count_as_an_activated_listener() {
    let transcript = Transcript::new();
    let launch = LaunchPlan::new(
        StagedOnlyAdapter {
            transcript: transcript.clone(),
        },
        ProbeReceipt,
        |()| Ok(()),
        None,
        lifecycle_batches(DomainModuleResult::default(), DomainModuleResult::default()),
    );

    let error = launch_until(launch, async { Ok(()) })
        .await
        .err()
        .expect("staged resources cannot mint listener activation proof");

    assert!(error.to_string().contains("no listener"));
    assert_eq!(transcript.snapshot(), ["staged-only"]);
}

#[tokio::test]
async fn staged_shutdown_failure_preserves_prepare_primary_error() {
    let transcript = Transcript::new();
    let launch = LaunchPlan::new(
        FailingPrepareAdapter {
            transcript: transcript.clone(),
        },
        ProbeReceipt,
        |()| Ok(()),
        None,
        lifecycle_batches(DomainModuleResult::default(), DomainModuleResult::default()),
    );

    let error = launch_until(launch, async { Ok(()) })
        .await
        .err()
        .expect("prepare and staged cleanup both fail");

    assert_eq!(error.to_string(), "prepare primary");
    assert_eq!(transcript.snapshot(), ["staged-failure"]);
}

struct LeftoverProbe;

impl HealthProbe for LeftoverProbe {
    fn check(&self) -> HealthCheck {
        HealthCheck::new(
            ProbeName::parse("leftover").expect("valid probe name"),
            HealthStatus::Healthy,
            "leftover",
        )
    }
}

#[tokio::test]
async fn leftover_probe_still_transfers_and_drains_later_module_resources() {
    let transcript = Transcript::new();
    let mut provider = module(vec![resource("provider", &transcript)], Vec::new());
    provider.probes.push((
        ProbeName::parse("leftover").expect("valid probe name"),
        Box::new(LeftoverProbe),
    ));
    let launch = plan(
        &transcript,
        vec!["listener"],
        false,
        provider,
        module(vec![resource("domain", &transcript)], Vec::new()),
        |_| Ok(()),
    );

    let error = launch_until(launch, async { Ok(()) })
        .await
        .err()
        .expect("leftover probe must fail");

    assert!(error.to_string().contains("undrained probes"));
    assert_eq!(transcript.snapshot(), vec!["domain", "provider", "trace"]);
}

#[tokio::test]
async fn prepare_failure_skips_activation_and_ready_hook_then_drains() {
    let transcript = Transcript::new();
    let ready_transcript = transcript.clone();
    let launch = plan(
        &transcript,
        vec!["listener"],
        true,
        module(vec![resource("provider", &transcript)], Vec::new()),
        DomainModuleResult::default(),
        move |_| {
            ready_transcript.record("ready");
            Ok(())
        },
    );

    let error = launch_until(launch, async { Ok(()) })
        .await
        .err()
        .expect("prepare must fail");

    assert_eq!(error.to_string(), "prepare failed");
    assert_eq!(transcript.snapshot(), vec!["provider", "trace"]);
}

#[tokio::test]
async fn ready_hook_failure_drains_activated_listener_and_preserves_error() {
    let transcript = Transcript::new();
    let launch = plan(
        &transcript,
        vec!["listener"],
        false,
        module(vec![resource("provider", &transcript)], Vec::new()),
        DomainModuleResult::default(),
        |_| Err(anyhow::anyhow!("ready publication failed")),
    );

    let error = launch_until(launch, async { Ok(()) })
        .await
        .err()
        .expect("ready hook must fail");

    assert_eq!(error.to_string(), "ready publication failed");
    assert_eq!(transcript.snapshot(), vec!["listener", "provider", "trace"]);
}

#[tokio::test]
async fn shutdown_trigger_failure_drains_and_preserves_error() {
    let transcript = Transcript::new();
    let launch = plan(
        &transcript,
        vec!["listener"],
        false,
        module(vec![resource("provider", &transcript)], Vec::new()),
        DomainModuleResult::default(),
        |_| Ok(()),
    );

    let error = launch_until(launch, async { Err(anyhow::anyhow!("signal failed")) })
        .await
        .err()
        .expect("signal failure must propagate");

    assert_eq!(error.to_string(), "signal failed");
    assert_eq!(transcript.snapshot(), vec!["listener", "provider", "trace"]);
}

#[tokio::test]
async fn launch_error_remains_primary_when_cleanup_also_fails() {
    let transcript = Transcript::new();
    let launch = plan(
        &transcript,
        vec!["listener"],
        false,
        module(
            vec![failing_resource("failing-provider", &transcript)],
            Vec::new(),
        ),
        DomainModuleResult::default(),
        |_| Err(anyhow::anyhow!("primary launch failure")),
    );

    let error = launch_until(launch, async { Ok(()) })
        .await
        .err()
        .expect("launch and cleanup fail");

    assert_eq!(error.to_string(), "primary launch failure");
    assert_eq!(
        transcript.snapshot(),
        vec!["listener", "failing-provider", "trace"]
    );
}

#[tokio::test]
async fn cleanup_failure_is_returned_after_successful_shutdown_trigger() {
    let transcript = Transcript::new();
    let launch = plan(
        &transcript,
        vec!["listener"],
        false,
        module(
            vec![
                failing_resource("failing-provider-a", &transcript),
                failing_resource("failing-provider-b", &transcript),
            ],
            Vec::new(),
        ),
        module(
            vec![failing_resource("failing-domain", &transcript)],
            Vec::new(),
        ),
        |_| Ok(()),
    );

    let error = launch_until(launch, async { Ok(()) })
        .await
        .err()
        .expect("cleanup failure must propagate");

    assert!(error.to_string().contains("3 runtime resource failure"));
    assert_eq!(
        transcript.snapshot(),
        vec![
            "listener",
            "failing-domain",
            "failing-provider-b",
            "failing-provider-a",
            "trace",
        ],
        "cleanup must continue after each failure and preserve exact LIFO order"
    );
}

#[tokio::test]
async fn abort_during_execute_transfers_stack_and_drains_exactly_once() {
    let activated = Arc::new(Notify::new());
    let shutdowns = Arc::new(AtomicUsize::new(0));
    let cancelled_at_shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_done = Arc::new(Notify::new());
    let launch = LaunchPlan::new(
        CancellationAdapter {
            activated: Arc::clone(&activated),
            shutdowns: Arc::clone(&shutdowns),
            cancelled_at_shutdown: Arc::clone(&cancelled_at_shutdown),
            shutdown_done: Arc::clone(&shutdown_done),
        },
        ProbeReceipt,
        |()| Ok(()),
        None,
        lifecycle_batches(DomainModuleResult::default(), DomainModuleResult::default()),
    );

    let task = tokio::spawn(launch_until(
        launch,
        std::future::pending::<anyhow::Result<()>>(),
    ));
    activated.notified().await;
    task.abort();
    let join_error = task.await.err().expect("launch task must be aborted");
    assert!(join_error.is_cancelled());

    tokio::time::timeout(Duration::from_secs(2), shutdown_done.notified())
        .await
        .expect("background drain must finish after launch cancellation");
    assert!(
        cancelled_at_shutdown.load(Ordering::SeqCst),
        "ShutdownStack must broadcast cancellation before resource shutdown"
    );
    assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
    tokio::task::yield_now().await;
    assert_eq!(shutdowns.load(Ordering::SeqCst), 1, "drain is single-shot");
}

#[tokio::test]
async fn abort_during_prepare_awaits_resources_created_by_prepare() {
    let prepare_started = Arc::new(Notify::new());
    let shutdown_started = Arc::new(Notify::new());
    let release_shutdown = Arc::new(Notify::new());
    let shutdowns = Arc::new(AtomicUsize::new(0));
    let shutdown_done = Arc::new(Notify::new());
    let launch = LaunchPlan::new(
        PrepareOwnedAdapter {
            prepare_started: Arc::clone(&prepare_started),
            shutdown_started: Arc::clone(&shutdown_started),
            release_shutdown: Arc::clone(&release_shutdown),
            shutdowns: Arc::clone(&shutdowns),
            shutdown_done: Arc::clone(&shutdown_done),
        },
        ProbeReceipt,
        |()| Ok(()),
        None,
        lifecycle_batches(DomainModuleResult::default(), DomainModuleResult::default()),
    );

    let task = tokio::spawn(launch_until(
        launch,
        std::future::pending::<anyhow::Result<()>>(),
    ));
    prepare_started.notified().await;
    task.abort();
    let join_error = task.await.err().expect("launch must be aborted");
    assert!(join_error.is_cancelled());

    tokio::time::timeout(Duration::from_millis(200), shutdown_started.notified())
        .await
        .expect("background drain must begin staged resource shutdown");
    assert_eq!(
        shutdowns.load(Ordering::SeqCst),
        0,
        "drain must remain blocked until staged resource shutdown completes"
    );
    release_shutdown.notify_one();
    tokio::time::timeout(Duration::from_millis(200), shutdown_done.notified())
        .await
        .expect("prepare-created resource must be owned and awaited by the launch transaction");
    assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn abort_while_finish_waits_does_not_interrupt_remaining_lifo_drain() {
    let transcript = Transcript::new();
    let gate_started = Arc::new(Notify::new());
    let release_gate = Arc::new(Notify::new());
    let earlier_done = Arc::new(Notify::new());
    let provider_module = module(
        vec![
            gated_resource(
                "earlier",
                &transcript,
                None,
                None,
                Some(Arc::clone(&earlier_done)),
            ),
            gated_resource(
                "gate",
                &transcript,
                Some(Arc::clone(&gate_started)),
                Some(Arc::clone(&release_gate)),
                None,
            ),
        ],
        Vec::new(),
    );
    let launch = LaunchPlan::new(
        FakeAdapter {
            listener_names: vec!["listener"],
            transcript: transcript.clone(),
            fail_prepare: false,
        },
        ProbeReceipt,
        |_| Ok(()),
        None,
        lifecycle_batches(provider_module, DomainModuleResult::default()),
    );

    let task = tokio::spawn(launch_until(launch, ready(Ok(()))));
    gate_started.notified().await;
    task.abort();
    let join_error = task.await.err().expect("finish waiter must be aborted");
    assert!(join_error.is_cancelled());
    release_gate.notify_one();

    tokio::time::timeout(Duration::from_secs(2), earlier_done.notified())
        .await
        .expect("detached drain task must continue through the remaining LIFO stack");
    assert_eq!(transcript.snapshot(), vec!["listener", "gate", "earlier"]);
}

#[derive(Clone, Default)]
struct ErrorFieldRecorder(Arc<Mutex<Vec<String>>>);

impl<S> tracing_subscriber::Layer<S> for ErrorFieldRecorder
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct Visitor<'a>(&'a mut Vec<String>);

        impl tracing::field::Visit for Visitor<'_> {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if matches!(field.name(), "error" | "cleanup_error") {
                    self.0.push(value.to_owned());
                }
            }

            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if matches!(field.name(), "error" | "cleanup_error") {
                    self.0.push(format!("{value:?}"));
                }
            }
        }

        let mut fields = self.0.lock().expect("error field recorder lock");
        event.record(&mut Visitor(&mut fields));
    }
}

#[test]
fn shutdown_error_logs_strip_url_credentials() {
    const LEAK_MARKER: &str = "launch-log-leak-marker";
    let recorder = ErrorFieldRecorder::default();
    let subscriber = tracing_subscriber::registry().with(recorder.clone());
    let failure = bootstrap::shutdown::ResourceShutdownError {
        name: format!("postgres://runtime:{LEAK_MARKER}@db.internal/app"),
        kind: bootstrap::shutdown::ShutdownFailureKind::Failed(ShutdownError::new(
            std::io::Error::other("redacted source"),
        )),
    };

    tracing::subscriber::with_default(subscriber, || {
        let _ = report_shutdown_failures(vec![failure]);
        let result = preserve_launch_error(
            Err(anyhow::anyhow!("primary launch failure")),
            Err(anyhow::anyhow!(
                "cleanup postgres://runtime:{LEAK_MARKER}@db.internal/app"
            )),
        );
        assert_eq!(
            result
                .err()
                .expect("primary failure must remain primary")
                .to_string(),
            "primary launch failure"
        );
    });

    let fields = recorder.0.lock().expect("error field recorder lock");
    assert_eq!(fields.len(), 2);
    assert!(fields.iter().all(|field| !field.contains(LEAK_MARKER)));
    assert!(fields.iter().all(|field| field.contains("<redacted>")));
}

assert_not_impl_any!(RuntimeOutputs: Clone, Copy);
