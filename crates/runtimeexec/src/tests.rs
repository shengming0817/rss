//! INVARIANT: RUNTIMEEXEC-LAUNCH-OWNERSHIP-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "executor_drains_in_exact_dependency_lifo_order + signal_installer_failure_drains_lifecycle_batches_once_in_lifo_order + executor_rejects_zero_listeners_after_registering_and_drains_owned_resources + abort_during_execute_transfers_stack_and_drains_exactly_once + total_drain_budget_bounds_multiple_hanging_resources", anti_vacuity = "executor_drains_in_exact_dependency_lifo_order + abort_during_execute_transfers_stack_and_drains_exactly_once" } -- LaunchTransaction and StartupTransaction behavior own cancellation transfer, non-empty readiness, exact-once LIFO drain, primary-error preservation, and one total shutdown budget. Cross-file second launch/signal/shutdown owners remain forbidden by `RUNTIME-LIFECYCLE-BYPASS-01`.
//!
#![allow(clippy::expect_used, clippy::panic)]
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

fn test_listener_receipt<T>(assembly_receipt: T) -> LaunchProbeReceipt<T> {
    let mut registry = bootstrap::Registry::default();
    ListenerLifecycleRegistration::install(&mut registry)
        .map(|receipt| receipt.map_for_test(assembly_receipt))
        .expect("listener probe installation must succeed")
}

fn listener_probe_status(reporter: &bootstrap::HealthReporter) -> HealthStatus {
    reporter
        .report()
        .checks()
        .iter()
        .find(|check| check.name().as_str() == "runtime-listeners")
        .expect("runtime listener probe must be installed")
        .status()
}

fn listener_probe_detail(reporter: &bootstrap::HealthReporter) -> &'static str {
    reporter
        .report()
        .checks()
        .iter()
        .find(|check| check.name().as_str() == "runtime-listeners")
        .expect("runtime listener probe must be installed")
        .detail()
}

#[tokio::test]
async fn required_managed_worker_completion_is_terminal_for_the_executor() {
    let token = CancellationToken::new();
    let (start, status) = diport::ManagedTask::prepare("required-worker", Duration::from_secs(1));
    let task = start.spawn(token, |_| async { Ok(()) });
    let exit = wait_for_worker_exit(vec![status]).await;
    assert_eq!(exit.name, "required-worker");
    assert_eq!(exit.exit, diport::TaskExit::Completed);
    assert!(
        unexpected_worker_exit(exit)
            .to_string()
            .contains("exited unexpectedly")
    );
    drop(task);
}

#[tokio::test]
async fn listener_probe_is_installed_sealed_and_terminal_sticky() {
    let mut registry = bootstrap::Registry::default();
    let receipt =
        ListenerLifecycleRegistration::install(&mut registry).expect("listener probe install");
    let reporter = Arc::clone(receipt.assembly_receipt());
    assert_eq!(listener_probe_status(&reporter), HealthStatus::Unhealthy);

    let (_assembly, listener_receipt) = receipt.into_parts();
    let root = CancellationToken::new();
    let mut stack = ShutdownStack::new(root.clone());
    let transaction = LaunchTransaction { stack: &mut stack };
    let mut registrar = transaction.commit(listener_receipt);
    registrar.register_listener_with_token(|token| {
        bound_listener("listener-probe-test").spawn(
            token,
            Duration::from_secs(1),
            |_listener, worker_token| async move {
                worker_token.cancelled().await;
                Ok(())
            },
        )
    });
    assert_eq!(listener_probe_status(&reporter), HealthStatus::Unhealthy);
    let _activated = registrar
        .complete(())
        .expect("non-empty listener group seals");
    assert_eq!(listener_probe_status(&reporter), HealthStatus::Healthy);

    root.cancel();
    assert!(stack.shutdown().await.is_empty());
    assert_eq!(listener_probe_status(&reporter), HealthStatus::Unhealthy);
    assert_eq!(listener_probe_detail(&reporter), "listener cancelled");
}

#[test]
#[allow(clippy::panic)]
fn production_panic_hook_redacts_payload() {
    const CHILD_ENV: &str = "RSS_RUNTIMEEXEC_PANIC_HOOK_CHILD";
    const SECRET: &str = "runtime-task-plain-panic-secret";
    if std::env::var_os(CHILD_ENV).is_some() {
        install_redacted_panic_hook();
        panic!("{SECRET}");
    }

    let output = std::process::Command::new(std::env::current_exe().expect("current test binary"))
        .args([
            "--exact",
            "tests::production_panic_hook_redacts_payload",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .output()
        .expect("spawn panic-hook child");
    assert!(!output.status.success(), "child must panic");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("payload redacted"), "{stderr}");
    assert!(!stderr.contains(SECRET), "{stderr}");
}

#[test]
#[allow(clippy::panic)]
fn structured_panic_observation_never_writes_plaintext_after_activation() {
    const CHILD_ENV: &str = "RSS_RUNTIMEEXEC_STRUCTURED_PANIC_CHILD";
    const SECRET: &str = "runtime-structured-panic-secret";
    if std::env::var_os(CHILD_ENV).is_some() {
        install_redacted_panic_hook();
        tracing_subscriber::fmt()
            .json()
            .with_writer(std::io::stderr)
            .try_init()
            .expect("subscriber");
        activate_structured_panic_observation();
        panic!("{SECRET}");
    }

    let output = std::process::Command::new(std::env::current_exe().expect("current test binary"))
        .args([
            "--exact",
            "tests::structured_panic_observation_never_writes_plaintext_after_activation",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .output()
        .expect("spawn structured panic child");
    assert!(!output.status.success(), "child must panic");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains(SECRET), "{stderr}");
    for line in stderr.lines().filter(|line| line.starts_with('{')) {
        let parsed = serde_json::from_str::<serde_json::Value>(line);
        assert!(parsed.is_ok(), "panic observation must be JSON: {line}");
    }
    assert!(stderr.contains("payload redacted"), "{stderr}");
    assert!(
        !stderr
            .lines()
            .any(|line| line == "process task or thread panicked; payload redacted"),
        "structured generation must not contain plaintext lines: {stderr}"
    );
}

#[test]
fn managed_worker_panic_uses_the_same_structured_dispatcher() {
    const CHILD_ENV: &str = "RSS_RUNTIMEEXEC_MANAGED_PANIC_CHILD";
    const SECRET: &str = "runtime-managed-worker-panic-secret";
    if std::env::var_os(CHILD_ENV).is_some() {
        install_redacted_panic_hook();
        tracing_subscriber::fmt()
            .json()
            .with_writer(std::io::stderr)
            .try_init()
            .expect("subscriber");
        activate_structured_panic_observation();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let worker = eventexec::ManagedBlockingWorker::spawn(
                "managed-panic-test",
                CancellationToken::new(),
                Arc::new(eventexec::WorkerHealth::starting()),
                eventing::lifecycle::ShutdownBudget::new(Duration::from_secs(1))
                    .expect("positive shutdown budget"),
                |_token| -> Result<(), ShutdownError> { panic!("{SECRET}") },
            );
            assert!(worker.shutdown().await.is_err());
        });
        return;
    }

    let output = std::process::Command::new(std::env::current_exe().expect("current test binary"))
        .args([
            "--exact",
            "tests::managed_worker_panic_uses_the_same_structured_dispatcher",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .output()
        .expect("spawn managed panic child");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("managed_blocking_worker"), "{stderr}");
    assert!(stderr.contains("payload redacted"), "{stderr}");
    assert!(!stderr.contains(SECRET), "{stderr}");
    assert!(stderr.lines().all(|line| line.starts_with('{')), "{stderr}");
}

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

struct HangingResource {
    name: &'static str,
    entered: Arc<AtomicUsize>,
}

impl ManagedResource for HangingResource {
    fn name(&self) -> &str {
        self.name
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        std::future::pending().await
    }

    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}

fn hanging_resource(
    name: &'static str,
    entered: &Arc<AtomicUsize>,
) -> Box<DynManagedResource<'static>> {
    DynManagedResource::new_box(HangingResource {
        name,
        entered: Arc::clone(entered),
    })
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

fn listener_registration(
    name: &'static str,
    transcript: &Transcript,
    token: CancellationToken,
) -> listenerlifecycle::ListenerTaskRegistration {
    let transcript = transcript.clone();
    bound_listener(name).spawn(
        token,
        diport::DEFAULT_SHUTDOWN_TIMEOUT,
        move |_listener, task_token| async move {
            task_token.cancelled().await;
            transcript.record(name);
            Ok(())
        },
    )
}

fn bound_listener(name: &'static str) -> listenerlifecycle::BoundTcpListener {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test listener");
    listener
        .set_nonblocking(true)
        .expect("set test listener nonblocking");
    let listener = tokio::net::TcpListener::from_std(listener).expect("adopt test listener");
    listenerlifecycle::BoundTcpListener::new(name, listener).expect("read test listener address")
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
    bootstrap::WorkerSpec::observational_deferred(name, move |token: CancellationToken| {
        assert!(
            !token.is_cancelled(),
            "worker token must be live at registration"
        );
        resource(name, &transcript)
    })
}

struct ProbeReceipt;

fn test_drain_budget() -> TotalDrainBudget {
    TotalDrainBudget::new(Duration::from_secs(2)).expect("valid test drain budget")
}

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

#[derive(Clone, Copy)]
enum EarlyListenerExit {
    Completed,
    Failed,
    Panicked,
}

struct EarlyExitAdapter {
    exit: EarlyListenerExit,
}

impl LaunchAdapter<ProbeReceipt> for EarlyExitAdapter {
    type Prepared = Self;
    type Inventory = ();

    fn prepare(
        self,
        _receipt: ProbeReceipt,
        _transaction: &mut LaunchTransaction<'_>,
    ) -> impl Future<Output = anyhow::Result<Self::Prepared>> + Send {
        ready(Ok(self))
    }

    fn activate(
        prepared: Self::Prepared,
        mut registrar: LaunchRegistrar<'_>,
    ) -> anyhow::Result<Activated<Self::Inventory>> {
        registrar.register_listener_with_token(move |token| {
            bound_listener("early-exit-listener").spawn(
                token,
                diport::DEFAULT_SHUTDOWN_TIMEOUT,
                move |_listener, _managed_token| async move {
                    match prepared.exit {
                        EarlyListenerExit::Completed => Ok(()),
                        EarlyListenerExit::Failed => Err(ShutdownError::new(
                            std::io::Error::other("listener-plaintext-secret"),
                        )),
                        EarlyListenerExit::Panicked => {
                            panic!("listener-plaintext-panic-secret")
                        }
                    }
                },
            )
        });
        registrar.complete(())
    }
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
            registrar.register_listener_with_token(move |token| {
                listener_registration(name, &transcript, token)
            });
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
            bound_listener("cancellation-observed").spawn(
                token,
                diport::DEFAULT_SHUTDOWN_TIMEOUT,
                move |_listener, task_token| async move {
                    task_token.cancelled().await;
                    cancelled_at_shutdown.store(true, Ordering::SeqCst);
                    shutdowns.fetch_add(1, Ordering::SeqCst);
                    shutdown_done.notify_one();
                    Ok(())
                },
            )
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
    DomainModuleResult::from_parts([], resources, workers)
}

fn lifecycle_batches(
    provider: DomainModuleResult,
    domain: DomainModuleResult,
) -> LaunchLifecycleBatches {
    let expected = bootstrap::ExpectedWorkerInventory::closed(
        provider
            .workers()
            .chain(domain.workers())
            .map(bootstrap::WorkerSpec::descriptor)
            .filter(|descriptor| descriptor.lane != bootstrap::WorkerAdmissionLane::Observational),
    )
    .expect("test worker inventory is closed");
    LaunchLifecycleBatches::new(
        ProviderLifecycleBatch::from_provider_output(provider),
        DomainLifecycleBatch::from_domain_output(domain),
        Some(expected),
    )
}

fn plan<H>(
    transcript: &Transcript,
    listener_names: Vec<&'static str>,
    fail_prepare: bool,
    provider_module: DomainModuleResult,
    domain_module: DomainModuleResult,
    on_ready: H,
) -> LaunchPlan<
    FakeAdapter,
    ProbeReceipt,
    impl FnOnce(ReadyInventory) -> std::future::Ready<anyhow::Result<()>>,
>
where
    H: FnOnce(ReadyInventory) -> anyhow::Result<()>,
{
    LaunchPlan::new(
        FakeAdapter {
            listener_names,
            transcript: transcript.clone(),
            fail_prepare,
        },
        test_listener_receipt(ProbeReceipt),
        move |inventory| ready(on_ready(inventory)),
        Some(resource("trace", transcript)),
        lifecycle_batches(provider_module, domain_module),
        test_drain_budget(),
    )
}

#[tokio::test]
async fn executor_drains_in_exact_dependency_lifo_order() {
    let transcript = Transcript::new();
    let ready_transcript = transcript.clone();
    let mut interleaved_provider = DomainModuleResult::default();
    interleaved_provider.push_worker(worker("provider-worker", &transcript));
    interleaved_provider.push_resource(resource("provider-resource", &transcript));
    let launch = plan(
        &transcript,
        vec!["listener-a", "listener-b"],
        false,
        interleaved_provider,
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

    let _outputs = launch_until(launch, || Ok(async { Ok(()) }))
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
async fn module_worker_cancellation_waits_for_listener_lifo_drain() {
    let transcript = Transcript::new();
    let listener_started = Arc::new(Notify::new());
    let release_listener = Arc::new(Notify::new());
    let worker_token = Arc::new(Mutex::new(None::<CancellationToken>));
    let worker_token_capture = Arc::clone(&worker_token);
    let worker_cancelled_at_shutdown = Arc::new(AtomicBool::new(false));
    let worker_shutdowns = Arc::new(AtomicUsize::new(0));
    let worker_shutdown_done = Arc::new(Notify::new());
    let worker_cancelled_capture = Arc::clone(&worker_cancelled_at_shutdown);
    let worker_shutdowns_capture = Arc::clone(&worker_shutdowns);
    let worker_done_capture = Arc::clone(&worker_shutdown_done);

    let mut stack = bootstrap::shutdown::ShutdownStack::new(CancellationToken::new());
    register_lifecycle_outputs(
        &mut stack,
        None,
        lifecycle_batches(
            module(
                Vec::new(),
                vec![bootstrap::WorkerSpec::observational_deferred(
                    "crates.runtimeexec.src.tests.02",
                    move |token| {
                        *worker_token_capture.lock().expect("worker token capture") =
                            Some(token.clone());
                        DynManagedResource::new_box(CancellationObservedResource {
                            token,
                            shutdowns: worker_shutdowns_capture,
                            cancelled_at_shutdown: worker_cancelled_capture,
                            shutdown_done: worker_done_capture,
                        })
                    },
                )],
            ),
            DomainModuleResult::default(),
        ),
        true,
    )
    .expect("register module worker");
    stack.register_with_token({
        let transcript = transcript.clone();
        let listener_started = Arc::clone(&listener_started);
        let release_listener = Arc::clone(&release_listener);
        move |_token| {
            gated_resource(
                "listener",
                &transcript,
                Some(listener_started),
                Some(release_listener),
                None,
            )
        }
    });

    let drain = tokio::spawn(async move { stack.shutdown().await });
    listener_started.notified().await;
    let module_token = worker_token
        .lock()
        .expect("worker token read")
        .clone()
        .expect("module worker received a token");
    assert!(
        !module_token.is_cancelled(),
        "module worker admission must stay live until listeners finish their LIFO drain"
    );

    release_listener.notify_one();
    let failures = drain.await.expect("drain task");
    assert!(failures.is_empty());
    assert!(worker_cancelled_at_shutdown.load(Ordering::SeqCst));
    assert_eq!(worker_shutdowns.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn phase_one_module_worker_cancels_before_listener_lifo_drain() {
    let transcript = Transcript::new();
    let listener_started = Arc::new(Notify::new());
    let release_listener = Arc::new(Notify::new());
    let worker_token = Arc::new(Mutex::new(None::<CancellationToken>));
    let worker_token_capture = Arc::clone(&worker_token);
    let worker_cancelled_at_shutdown = Arc::new(AtomicBool::new(false));
    let worker_shutdowns = Arc::new(AtomicUsize::new(0));

    let mut stack = bootstrap::shutdown::ShutdownStack::new(CancellationToken::new());
    register_lifecycle_outputs(
        &mut stack,
        None,
        lifecycle_batches(
            module(
                Vec::new(),
                vec![bootstrap::WorkerSpec::observational_phase_one(
                    "crates.runtimeexec.src.tests.03",
                    {
                        let shutdowns = Arc::clone(&worker_shutdowns);
                        let cancelled_at_shutdown = Arc::clone(&worker_cancelled_at_shutdown);
                        move |token| {
                            *worker_token_capture.lock().expect("worker token capture") =
                                Some(token.clone());
                            DynManagedResource::new_box(CancellationObservedResource {
                                token,
                                shutdowns,
                                cancelled_at_shutdown,
                                shutdown_done: Arc::new(Notify::new()),
                            })
                        }
                    },
                )],
            ),
            DomainModuleResult::default(),
        ),
        true,
    )
    .expect("register phase-one module worker");
    stack.register_with_token({
        let transcript = transcript.clone();
        let listener_started = Arc::clone(&listener_started);
        let release_listener = Arc::clone(&release_listener);
        move |_token| {
            gated_resource(
                "listener",
                &transcript,
                Some(listener_started),
                Some(release_listener),
                None,
            )
        }
    });

    let drain = tokio::spawn(async move { stack.shutdown().await });
    listener_started.notified().await;
    let module_token = worker_token
        .lock()
        .expect("worker token read")
        .clone()
        .expect("module worker received a token");
    assert!(
        module_token.is_cancelled(),
        "phase-one worker must stop admission before listener LIFO drain completes"
    );
    assert_eq!(
        worker_shutdowns.load(Ordering::SeqCst),
        0,
        "phase-one cancel must not bypass LIFO join ordering"
    );

    release_listener.notify_one();
    let failures = drain.await.expect("drain task");
    assert!(failures.is_empty());
    assert!(worker_cancelled_at_shutdown.load(Ordering::SeqCst));
    assert_eq!(worker_shutdowns.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn signal_installer_failure_drains_lifecycle_batches_once_in_lifo_order() {
    let transcript = Transcript::new();
    let ready_transcript = transcript.clone();
    let launch = plan(
        &transcript,
        vec!["listener"],
        false,
        module(
            vec![failing_resource("provider-resource", &transcript)],
            vec![worker("provider-worker", &transcript)],
        ),
        module(
            vec![resource("domain-resource", &transcript)],
            vec![worker("domain-worker", &transcript)],
        ),
        move |_| {
            ready_transcript.record("ready");
            Ok(())
        },
    );

    let error = launch_until(
        launch,
        || -> anyhow::Result<std::future::Ready<anyhow::Result<()>>> {
            Err(anyhow::anyhow!("install signal source failed"))
        },
    )
    .await
    .err()
    .expect("signal installer failure must propagate after drain");

    assert_eq!(error.to_string(), "install signal source failed");
    assert_eq!(
        transcript.snapshot(),
        vec![
            "domain-worker",
            "domain-resource",
            "provider-worker",
            "provider-resource",
            "trace",
        ],
        "installer failure must drain every accepted lifecycle exactly once in LIFO order"
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

    let error = launch_until(launch, || Ok(async { Ok(()) }))
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
        test_listener_receipt(ProbeReceipt),
        move |_| {
            ready({
                ready_transcript.record("ready");
                Ok(())
            })
        },
        None,
        lifecycle_batches(DomainModuleResult::default(), DomainModuleResult::default()),
        test_drain_budget(),
    );

    let error = launch_until(launch, || Ok(async { Ok(()) }))
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
        test_listener_receipt(ProbeReceipt),
        |()| ready(Ok(())),
        None,
        lifecycle_batches(DomainModuleResult::default(), DomainModuleResult::default()),
        test_drain_budget(),
    );

    let error = launch_until(launch, || Ok(async { Ok(()) }))
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
        test_listener_receipt(ProbeReceipt),
        |()| ready(Ok(())),
        None,
        lifecycle_batches(DomainModuleResult::default(), DomainModuleResult::default()),
        test_drain_budget(),
    );

    let error = launch_until(launch, || Ok(async { Ok(()) }))
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
    provider.push_probe((
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

    let error = launch_until(launch, || Ok(async { Ok(()) }))
        .await
        .err()
        .expect("leftover probe must fail");

    assert!(error.to_string().contains("undrained probes"));
    assert_eq!(transcript.snapshot(), vec!["domain", "provider", "trace"]);
}

#[tokio::test]
async fn leftover_probe_rejects_output_before_worker_factory_activation() {
    let worker_transcript = Transcript::new();
    let launch_transcript = Transcript::new();
    let factory_calls = Arc::new(AtomicUsize::new(0));
    let factory_calls_capture = Arc::clone(&factory_calls);
    let domain_factory_calls = Arc::clone(&factory_calls);
    let domain_worker_transcript = Transcript::new();
    let mut provider = DomainModuleResult::default();
    provider.push_probe((
        ProbeName::parse("leftover").expect("valid probe name"),
        Box::new(LeftoverProbe),
    ));
    provider.push_worker(bootstrap::WorkerSpec::observational_deferred(
        "crates.runtimeexec.src.tests.leftover",
        move |_| {
            factory_calls_capture.fetch_add(1, Ordering::SeqCst);
            resource("worker", &worker_transcript)
        },
    ));
    let launch = plan(
        &launch_transcript,
        vec!["listener"],
        false,
        provider,
        module(
            Vec::new(),
            vec![bootstrap::WorkerSpec::observational_deferred(
                "crates.runtimeexec.src.tests.domain-after-leftover",
                move |_| {
                    domain_factory_calls.fetch_add(1, Ordering::SeqCst);
                    resource("domain-worker", &domain_worker_transcript)
                },
            )],
        ),
        |_| Ok(()),
    );

    let error = launch_until(launch, || Ok(async { Ok(()) }))
        .await
        .err()
        .expect("leftover probe must fail");

    assert!(error.to_string().contains("undrained probes"));
    assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
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

    let error = launch_until(launch, || Ok(async { Ok(()) }))
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

    let error = launch_until(launch, || Ok(std::future::pending::<anyhow::Result<()>>()))
        .await
        .err()
        .expect("ready hook must fail");

    assert_eq!(error.to_string(), "ready publication failed");
    assert_eq!(transcript.snapshot(), vec!["listener", "provider", "trace"]);
}

#[tokio::test]
async fn controlled_launch_completes_through_normal_shutdown_and_drains() {
    let transcript = Transcript::new();
    let (completion, controlled) = test_support::controlled::<usize>();
    let launch = plan(
        &transcript,
        vec!["listener"],
        false,
        DomainModuleResult::default(),
        DomainModuleResult::default(),
        move |inventory| completion.complete(Ok(inventory.listener_count)),
    );

    let listener_count = controlled
        .run(launch)
        .await
        .expect("controlled launch must stop successfully");

    assert_eq!(listener_count, 1);
    assert_eq!(transcript.snapshot(), vec!["listener", "trace"]);
}

#[derive(Debug, thiserror::Error)]
#[error("controlled request failed")]
struct ControlledRequestError;

#[tokio::test]
async fn controlled_launch_preserves_the_original_request_error() {
    let transcript = Transcript::new();
    let (completion, controlled) = test_support::controlled::<()>();
    let launch = plan(
        &transcript,
        vec!["listener"],
        false,
        DomainModuleResult::default(),
        DomainModuleResult::default(),
        move |_| completion.complete(Err(anyhow::Error::new(ControlledRequestError))),
    );

    let error = controlled
        .run(launch)
        .await
        .expect_err("request failure must be returned after a clean drain");

    assert!(error.is::<ControlledRequestError>());
    assert_eq!(transcript.snapshot(), vec!["listener", "trace"]);
}

#[tokio::test]
async fn listener_early_completion_failure_and_panic_fail_closed_and_drain() {
    for (exit, expected) in [
        (EarlyListenerExit::Completed, "completed"),
        (EarlyListenerExit::Failed, "task-failed"),
        (EarlyListenerExit::Panicked, "task-panicked"),
    ] {
        let transcript = Transcript::new();
        let launch = LaunchPlan::new(
            EarlyExitAdapter { exit },
            test_listener_receipt(ProbeReceipt),
            |()| std::future::pending::<anyhow::Result<()>>(),
            Some(resource("trace", &transcript)),
            lifecycle_batches(
                module(vec![resource("provider", &transcript)], Vec::new()),
                DomainModuleResult::default(),
            ),
            test_drain_budget(),
        );

        let error = launch_until(launch, || Ok(std::future::pending::<anyhow::Result<()>>()))
            .await
            .err()
            .expect("listener completion before shutdown must fail launch");
        let message = error.to_string();
        assert!(message.contains(expected), "{message}");
        assert!(message.contains("early-exit-listener"), "{message}");
        assert!(!message.contains("plaintext"), "{message}");
        assert_eq!(transcript.snapshot(), vec!["provider", "trace"]);
    }
}

#[tokio::test]
async fn shutdown_signal_wins_a_simultaneous_listener_completion_race() {
    let transcript = Transcript::new();
    let launch = LaunchPlan::new(
        EarlyExitAdapter {
            exit: EarlyListenerExit::Completed,
        },
        test_listener_receipt(ProbeReceipt),
        |()| ready(Ok(())),
        Some(resource("trace", &transcript)),
        lifecycle_batches(DomainModuleResult::default(), DomainModuleResult::default()),
        test_drain_budget(),
    );

    let _outputs = launch_until(launch, || Ok(ready(Ok(()))))
        .await
        .expect("signal must be the planned-stop authority when both futures are ready");
    assert_eq!(transcript.snapshot(), vec!["trace"]);
}

#[tokio::test]
async fn shutdown_signal_interrupts_pending_readiness_then_drains() {
    let transcript = Transcript::new();
    let readiness_started = Arc::new(Notify::new());
    let shutdown_after_readiness = Arc::clone(&readiness_started);
    let launch = LaunchPlan::new(
        FakeAdapter {
            listener_names: vec!["listener"],
            transcript: transcript.clone(),
            fail_prepare: false,
        },
        test_listener_receipt(ProbeReceipt),
        move |_| async move {
            readiness_started.notify_one();
            std::future::pending::<anyhow::Result<()>>().await
        },
        Some(resource("trace", &transcript)),
        lifecycle_batches(
            module(vec![resource("provider", &transcript)], Vec::new()),
            DomainModuleResult::default(),
        ),
        test_drain_budget(),
    );

    let _outputs = launch_until(launch, || {
        Ok(async move {
            shutdown_after_readiness.notified().await;
            Ok(())
        })
    })
    .await
    .expect("signal must interrupt readiness and complete a clean drain");

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

    let error = launch_until(launch, || {
        Ok(async { Err(anyhow::anyhow!("signal failed")) })
    })
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

    let error = launch_until(launch, || Ok(std::future::pending::<anyhow::Result<()>>()))
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

    let error = launch_until(launch, || Ok(async { Ok(()) }))
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
async fn total_drain_budget_bounds_multiple_hanging_resources() {
    let transcript = Transcript::new();
    let entered = Arc::new(AtomicUsize::new(0));
    let launch = LaunchPlan::new(
        FakeAdapter {
            listener_names: vec!["listener"],
            transcript,
            fail_prepare: false,
        },
        test_listener_receipt(ProbeReceipt),
        |_| ready(Ok(())),
        None,
        lifecycle_batches(
            module(
                vec![
                    hanging_resource("hang-a", &entered),
                    hanging_resource("hang-b", &entered),
                ],
                Vec::new(),
            ),
            DomainModuleResult::default(),
        ),
        TotalDrainBudget::new(Duration::from_millis(40)).expect("valid bounded drain budget"),
    );

    let error = tokio::time::timeout(
        Duration::from_millis(500),
        launch_until(launch, || Ok(async { Ok(()) })),
    )
    .await
    .expect("one total deadline must bound every hanging resource")
    .err()
    .expect("budget exhaustion must fail shutdown");

    assert!(error.to_string().contains("2 runtime resource failure"));
    assert_eq!(
        entered.load(Ordering::SeqCst),
        1,
        "the shared deadline aborts the in-flight resource and skips the remainder"
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
        test_listener_receipt(ProbeReceipt),
        |()| ready(Ok(())),
        None,
        lifecycle_batches(DomainModuleResult::default(), DomainModuleResult::default()),
        test_drain_budget(),
    );

    let task = tokio::spawn(launch_until(launch, || {
        Ok(std::future::pending::<anyhow::Result<()>>())
    }));
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
        test_listener_receipt(ProbeReceipt),
        |()| ready(Ok(())),
        None,
        lifecycle_batches(DomainModuleResult::default(), DomainModuleResult::default()),
        test_drain_budget(),
    );

    let task = tokio::spawn(launch_until(launch, || {
        Ok(std::future::pending::<anyhow::Result<()>>())
    }));
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
        test_listener_receipt(ProbeReceipt),
        |_| ready(Ok(())),
        None,
        lifecycle_batches(provider_module, DomainModuleResult::default()),
        test_drain_budget(),
    );

    let task = tokio::spawn(launch_until(launch, || Ok(ready(Ok(())))));
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

#[test]
fn shutdown_error_sinks_strip_url_credentials() {
    const LEAK_MARKER: &str = "launch-log-leak-marker";
    let failure = bootstrap::shutdown::ResourceShutdownError {
        name: format!("postgres://runtime:{LEAK_MARKER}@db.internal/app"),
        kind: bootstrap::shutdown::ShutdownFailureKind::Failed(ShutdownError::new(
            std::io::Error::other("redacted source"),
        )),
    };
    let cleanup = anyhow::anyhow!("cleanup postgres://runtime:{LEAK_MARKER}@db.internal/app");

    let fields = [
        rss_redact::redact_error(&failure).to_string(),
        rss_redact::redact_error(cleanup.as_ref()).to_string(),
    ];
    assert!(fields.iter().all(|field| !field.contains(LEAK_MARKER)));
    assert!(fields.iter().all(|field| field.contains("<redacted>")));

    let _ = report_shutdown_failures(vec![failure]);
    let result =
        preserve_launch_error(Err(anyhow::anyhow!("primary launch failure")), Err(cleanup));
    assert_eq!(
        result
            .err()
            .expect("primary failure must remain primary")
            .to_string(),
        "primary launch failure"
    );
}

assert_not_impl_any!(RuntimeOutputs: Clone, Copy);

struct BlockingStartup {
    transcript: Transcript,
    started: Arc<Notify>,
    ready_calls: Arc<AtomicUsize>,
}

impl StartupAdapter for BlockingStartup {
    type Adapter = FakeAdapter;
    type ProbeReceipt = ProbeReceipt;
    type ReadyHook = fn(ReadyInventory) -> std::future::Ready<anyhow::Result<()>>;
    type Ready = std::future::Ready<anyhow::Result<()>>;

    async fn prepare(
        self,
        transaction: &mut StartupTransaction<'_>,
    ) -> anyhow::Result<PreparedLaunch<Self::Adapter, Self::ProbeReceipt, Self::ReadyHook>> {
        let mut output = module(
            vec![resource("startup-provider", &self.transcript)],
            Vec::new(),
        );
        output.push_probe((
            ProbeName::parse("startup-blocked").expect("valid probe name"),
            Box::new(LeftoverProbe),
        ));
        transaction.stage_provider_output(output);
        self.started.notify_one();
        let _ready_calls = self.ready_calls;
        std::future::pending().await
    }
}

struct FailingStartup {
    transcript: Transcript,
}

impl StartupAdapter for FailingStartup {
    type Adapter = FakeAdapter;
    type ProbeReceipt = ProbeReceipt;
    type ReadyHook = fn(ReadyInventory) -> std::future::Ready<anyhow::Result<()>>;
    type Ready = std::future::Ready<anyhow::Result<()>>;

    async fn prepare(
        self,
        transaction: &mut StartupTransaction<'_>,
    ) -> anyhow::Result<PreparedLaunch<Self::Adapter, Self::ProbeReceipt, Self::ReadyHook>> {
        let mut output = module(
            vec![resource("startup-provider", &self.transcript)],
            Vec::new(),
        );
        output.push_probe((
            ProbeName::parse("startup-failed").expect("valid probe name"),
            Box::new(LeftoverProbe),
        ));
        transaction.stage_provider_output(output);
        Err(anyhow::anyhow!("original startup failure"))
    }
}

#[tokio::test]
async fn startup_signal_discards_unregistered_probes_and_drains_staged_resources_once() {
    let transcript = Transcript::new();
    let started = Arc::new(Notify::new());
    let signal_after_stage = Arc::clone(&started);
    let ready_calls = Arc::new(AtomicUsize::new(0));
    let plan = StartupPlan::new(
        BlockingStartup {
            transcript: transcript.clone(),
            started,
            ready_calls: Arc::clone(&ready_calls),
        },
        test_drain_budget(),
    );

    let _outputs = launch_startup_until(plan, || {
        Ok(async move {
            signal_after_stage.notified().await;
            Ok(())
        })
    })
    .await
    .expect("startup signal must produce a clean bounded drain");

    assert_eq!(ready_calls.load(Ordering::SeqCst), 0);
    assert_eq!(transcript.snapshot(), ["startup-provider"]);
}

#[tokio::test]
async fn abort_during_startup_transfers_transaction_and_drains_staged_resources_once() {
    let transcript = Transcript::new();
    let started = Arc::new(Notify::new());
    let ready_calls = Arc::new(AtomicUsize::new(0));
    let plan = StartupPlan::new(
        BlockingStartup {
            transcript: transcript.clone(),
            started: Arc::clone(&started),
            ready_calls,
        },
        test_drain_budget(),
    );

    let task = tokio::spawn(launch_startup_until(plan, || {
        Ok(std::future::pending::<anyhow::Result<()>>())
    }));
    started.notified().await;
    task.abort();
    let _cancelled = task.await;

    tokio::time::timeout(Duration::from_secs(1), async {
        while transcript.snapshot() != ["startup-provider"] {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled startup must finish its detached bounded drain");
    assert_eq!(transcript.snapshot(), ["startup-provider"]);
}

#[tokio::test]
async fn startup_error_with_unregistered_probe_preserves_primary_and_drains() {
    let transcript = Transcript::new();
    let plan = StartupPlan::new(
        FailingStartup {
            transcript: transcript.clone(),
        },
        test_drain_budget(),
    );

    let error = launch_startup_until(plan, || Ok(std::future::pending::<anyhow::Result<()>>()))
        .await
        .err()
        .expect("startup failure must propagate after drain");

    assert_eq!(error.to_string(), "original startup failure");
    assert_eq!(transcript.snapshot(), ["startup-provider"]);
}

#[test]
fn total_drain_budget_requires_positive_assembly_budget() {
    assert!(TotalDrainBudget::new(Duration::from_secs(20)).is_ok());
    assert!(TotalDrainBudget::new(Duration::ZERO).is_err());
}
