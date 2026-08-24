//! Canonical lifecycle owner for long-lived event workers on dedicated OS threads.
//!
//! Tokio documents that an already-started `spawn_blocking` task cannot be aborted and can make
//! runtime shutdown wait indefinitely. Long-lived event loops therefore stay on dedicated OS
//! threads and report completion over a cancel-safe oneshot instead of joining through Tokio's
//! blocking pool.
//!
//! ref: tokio-rs/tokio tokio/src/task/blocking.rs

use std::cell::Cell;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eventing::lifecycle::ShutdownBudget;
use tokio_util::sync::CancellationToken;

use crate::WorkerHealth;

/// Supervised dedicated-thread worker.
#[must_use = "dropping the worker loses its managed shutdown owner"]
pub struct ManagedBlockingWorker {
    name: String,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
    shutdown_budget: ShutdownBudget,
    completion: Mutex<Option<tokio::sync::oneshot::Receiver<Result<(), diport::ShutdownError>>>>,
}

#[derive(Debug, thiserror::Error)]
#[error("managed blocking worker thread panicked")]
struct BlockingWorkerPanicked;

thread_local! {
    static MANAGED_PANIC_SCOPE: Cell<bool> = const { Cell::new(false) };
}

/// Closed panic scope consumed by runtimeexec's single process hook dispatcher.
#[doc(hidden)]
pub fn managed_panic_scope_active() -> bool {
    MANAGED_PANIC_SCOPE.try_with(Cell::get).unwrap_or(false)
}

impl ManagedBlockingWorker {
    /// Spawn one long-lived runner on a dedicated OS thread.
    ///
    /// The same cancellation token is retained by the managed resource and passed to the runner,
    /// making shutdown admission and worker-loop cancellation one typed funnel.
    pub fn spawn<N, F>(
        name: N,
        token: CancellationToken,
        health: Arc<WorkerHealth>,
        shutdown_budget: ShutdownBudget,
        run: F,
    ) -> Self
    where
        N: Into<String>,
        F: FnOnce(CancellationToken) -> Result<(), diport::ShutdownError> + Send + 'static,
    {
        let name = name.into();
        let thread_name = name.clone();
        let thread_token = token.clone();
        let thread_health = Arc::clone(&health);
        let (completed, completion) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            MANAGED_PANIC_SCOPE.with(|scope| scope.set(true));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _stopped = thread_health.stopped_on_exit();
                run(thread_token)
            }));
            MANAGED_PANIC_SCOPE.with(|scope| scope.set(false));
            let result = match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => {
                    tracing::error!(
                        worker = thread_name,
                        "managed blocking worker runner failed; error redacted"
                    );
                    Err(error)
                }
                Err(_) => Err(diport::ShutdownError::task_panicked(BlockingWorkerPanicked)),
            };
            let _ = completed.send(result);
        });
        Self {
            name,
            token,
            health,
            shutdown_budget,
            completion: Mutex::new(Some(completion)),
        }
    }

    /// Read worker health for readiness aggregation.
    pub fn health(&self) -> Arc<WorkerHealth> {
        Arc::clone(&self.health)
    }
}

/// Spawn a `!Send` event future on a dedicated current-thread runtime.
///
/// The runtime is constructed inside the worker thread, so neither the future nor runtime-local
/// resources cross a thread boundary. Runtime construction failures flow through the canonical
/// completion channel instead of being logged as successful shutdown.
pub fn spawn_on_dedicated_runtime<N, M, Fut>(
    name: N,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
    shutdown_budget: ShutdownBudget,
    make_body: M,
) -> ManagedBlockingWorker
where
    N: Into<String>,
    M: FnOnce(CancellationToken) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), diport::ShutdownError>>,
{
    spawn_on_dedicated_runtime_with_build_failure(
        name,
        token,
        health,
        shutdown_budget,
        |_| {},
        make_body,
    )
}

/// Spawn through the canonical runtime policy and observe only runtime construction failure.
///
/// The observer preserves assembly-specific health evidence without exposing Tokio's open-ended
/// runtime builder as assembly policy. It runs before the typed shutdown error is completed.
pub fn spawn_on_dedicated_runtime_with_build_failure<N, O, M, Fut>(
    name: N,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
    shutdown_budget: ShutdownBudget,
    on_build_failure: O,
    make_body: M,
) -> ManagedBlockingWorker
where
    N: Into<String>,
    O: FnOnce(&std::io::Error) + Send + 'static,
    M: FnOnce(CancellationToken) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), diport::ShutdownError>>,
{
    spawn_on_dedicated_runtime_with_failure_observers(
        name,
        token,
        health,
        shutdown_budget,
        on_build_failure,
        || {},
        make_body,
    )
}

/// Spawn through the canonical runtime policy and observe runtime construction or worker panic.
///
/// Both observers run inside the supervised worker thread before its closed shutdown result is
/// completed. The panic payload is deliberately not exposed to either observer.
pub fn spawn_on_dedicated_runtime_with_failure_observers<N, O, P, M, Fut>(
    name: N,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
    shutdown_budget: ShutdownBudget,
    on_build_failure: O,
    on_panic: P,
    make_body: M,
) -> ManagedBlockingWorker
where
    N: Into<String>,
    O: FnOnce(&std::io::Error) + Send + 'static,
    P: FnOnce() + Send + 'static,
    M: FnOnce(CancellationToken) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), diport::ShutdownError>>,
{
    let name = name.into();
    let runtime_worker_name = name.clone();
    ManagedBlockingWorker::spawn(name, token, health, shutdown_budget, move |run_token| {
        let runtime = observe_runtime_build_result(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build(),
            on_build_failure,
            &runtime_worker_name,
        )?;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.block_on(make_body(run_token))
        })) {
            Ok(result) => result,
            Err(_) => {
                on_panic();
                Err(diport::ShutdownError::task_panicked(BlockingWorkerPanicked))
            }
        }
    })
}

fn observe_runtime_build_result<T, O>(
    result: std::io::Result<T>,
    on_build_failure: O,
    worker_name: &str,
) -> Result<T, diport::ShutdownError>
where
    O: FnOnce(&std::io::Error),
{
    result.map_err(|error| {
        on_build_failure(&error);
        tracing::error!(
            worker = worker_name,
            error = %error,
            "managed blocking worker runtime build failed"
        );
        diport::ShutdownError::new(error)
    })
}

impl diport::ManagedResource for ManagedBlockingWorker {
    fn name(&self) -> &str {
        &self.name
    }

    fn shutdown_timeout(&self) -> Duration {
        self.shutdown_budget.timeout()
    }

    async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        self.token.cancel();
        let completion = self
            .completion
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        let Some(completion) = completion else {
            return Ok(());
        };
        completion.await.map_err(diport::ShutdownError::new)?
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use diport::ManagedResource as _;
    use eventing::lifecycle::ShutdownBudget;
    use primitives::HealthStatus;
    use tokio_util::sync::CancellationToken;

    use super::{
        ManagedBlockingWorker, observe_runtime_build_result, spawn_on_dedicated_runtime,
        spawn_on_dedicated_runtime_with_failure_observers,
    };
    use crate::WorkerHealth;

    #[tokio::test]
    async fn shutdown_cancels_before_waiting_and_is_idempotent() {
        let observed_cancel = Arc::new(AtomicBool::new(false));
        let observed_cancel_run = Arc::clone(&observed_cancel);
        let worker = ManagedBlockingWorker::spawn(
            "managed-blocking-cancel",
            CancellationToken::new(),
            Arc::new(WorkerHealth::starting()),
            ShutdownBudget::new(Duration::from_secs(1)).expect("positive shutdown budget"),
            move |token| {
                while !token.is_cancelled() {
                    std::thread::yield_now();
                }
                observed_cancel_run.store(true, Ordering::Release);
                Ok(())
            },
        );

        assert!(worker.shutdown().await.is_ok());
        assert!(worker.shutdown().await.is_ok());
        assert!(observed_cancel.load(Ordering::Acquire));
    }

    #[tokio::test]
    #[allow(clippy::expect_used, clippy::panic)]
    // reason: panic is the supervised behavior under test; expect_err asserts its typed outcome.
    async fn runner_error_and_panic_are_shutdown_errors_and_mark_stopped() {
        let failed_health = Arc::new(WorkerHealth::starting());
        let failed = ManagedBlockingWorker::spawn(
            "managed-blocking-error",
            CancellationToken::new(),
            Arc::clone(&failed_health),
            ShutdownBudget::new(Duration::from_secs(1)).expect("positive shutdown budget"),
            |_token| {
                Err(diport::ShutdownError::new(std::io::Error::other(
                    "runner failed",
                )))
            },
        );
        assert!(failed.shutdown().await.is_err());
        assert_eq!(failed_health.status(), HealthStatus::Unhealthy);

        let panic_health = Arc::new(WorkerHealth::starting());
        let panicked = ManagedBlockingWorker::spawn(
            "managed-blocking-panic",
            CancellationToken::new(),
            Arc::clone(&panic_health),
            ShutdownBudget::new(Duration::from_secs(1)).expect("positive shutdown budget"),
            |_token| -> Result<(), diport::ShutdownError> { panic!("secret panic payload") },
        );
        let error = panicked
            .shutdown()
            .await
            .expect_err("panic must fail shutdown");
        assert_eq!(error.kind(), diport::ShutdownErrorKind::TaskPanicked);
        assert_eq!(error.to_string(), "resource shutdown failed");
        assert!(!format!("{error:?}").contains("secret panic payload"));
        assert_eq!(panic_health.status(), HealthStatus::Unhealthy);
    }

    #[tokio::test]
    async fn dedicated_runtime_propagates_async_runner_error() {
        let worker = spawn_on_dedicated_runtime(
            "managed-async-error",
            CancellationToken::new(),
            Arc::new(WorkerHealth::starting()),
            ShutdownBudget::new(Duration::from_secs(1)).expect("positive shutdown budget"),
            |_token| async {
                Err(diport::ShutdownError::new(std::io::Error::other(
                    "async runner failed",
                )))
            },
        );

        assert!(worker.shutdown().await.is_err());
    }

    #[test]
    fn dedicated_runtime_build_failure_notifies_observer() {
        let observed = AtomicBool::new(false);
        let result = observe_runtime_build_result::<(), _>(
            Err(std::io::Error::other("runtime unavailable")),
            |_| observed.store(true, Ordering::Release),
            "test-worker",
        );
        assert!(result.is_err());
        assert!(observed.load(Ordering::Acquire));
    }

    #[tokio::test]
    #[allow(clippy::panic)]
    // reason: panic supervision is the behavior under test.
    async fn dedicated_runtime_distinguishes_panic_from_normal_cancellation() {
        let panic_observed = Arc::new(AtomicBool::new(false));
        let panic_observed_run = Arc::clone(&panic_observed);
        let panicked = spawn_on_dedicated_runtime_with_failure_observers(
            "managed-async-panic",
            CancellationToken::new(),
            Arc::new(WorkerHealth::starting()),
            ShutdownBudget::new(Duration::from_secs(1)).expect("positive shutdown budget"),
            |_| {},
            move || panic_observed_run.store(true, Ordering::Release),
            |_token| async { panic!("redacted async panic") },
        );
        assert!(panicked.shutdown().await.is_err());
        assert!(panic_observed.load(Ordering::Acquire));

        let cancellation_observed = Arc::new(AtomicBool::new(false));
        let cancellation_observed_run = Arc::clone(&cancellation_observed);
        let cancelled = spawn_on_dedicated_runtime_with_failure_observers(
            "managed-async-cancel",
            CancellationToken::new(),
            Arc::new(WorkerHealth::starting()),
            ShutdownBudget::new(Duration::from_secs(1)).expect("positive shutdown budget"),
            |_| {},
            move || cancellation_observed_run.store(true, Ordering::Release),
            |token| async move {
                token.cancelled().await;
                Ok(())
            },
        );
        assert!(cancelled.shutdown().await.is_ok());
        assert!(!cancellation_observed.load(Ordering::Acquire));
    }

    #[test]
    #[allow(clippy::expect_used, clippy::panic)]
    // reason: the subprocess harness must fail-loud while proving panic payload redaction.
    fn managed_worker_keeps_process_hook_owner_and_redacts_runner_errors() {
        const CHILD_ENV: &str = "RSS_MANAGED_WORKER_DIAGNOSTICS_CHILD";
        const TEST_NAME: &str = concat!(
            "managed_blocking_worker::tests::",
            "managed_worker_keeps_process_hook_owner_and_redacts_runner_errors"
        );
        const ERROR_SECRET: &str = "secret runner error payload";
        const PANIC_SECRET: &str = "secret managed panic payload";
        const PRIOR_HOOK_MARKER: &str = "prior panic hook observed ordinary thread";

        if std::env::var_os(CHILD_ENV).is_some() {
            std::panic::set_hook(Box::new(|_panic_info| {
                eprintln!("{PRIOR_HOOK_MARKER}");
            }));
            let _ = tracing_subscriber::fmt()
                .without_time()
                .with_writer(std::io::stderr)
                .try_init();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("child runtime");
            runtime.block_on(async {
                let failed = ManagedBlockingWorker::spawn(
                    "managed-diagnostics-error",
                    CancellationToken::new(),
                    Arc::new(WorkerHealth::starting()),
                    ShutdownBudget::new(Duration::from_secs(1)).expect("positive shutdown budget"),
                    |_token| {
                        Err(diport::ShutdownError::new(std::io::Error::other(
                            ERROR_SECRET,
                        )))
                    },
                );
                assert!(failed.shutdown().await.is_err());

                let panicked = ManagedBlockingWorker::spawn(
                    "managed-diagnostics-panic",
                    CancellationToken::new(),
                    Arc::new(WorkerHealth::starting()),
                    ShutdownBudget::new(Duration::from_secs(1)).expect("positive shutdown budget"),
                    |_token| -> Result<(), diport::ShutdownError> { panic!("{PANIC_SECRET}") },
                );
                assert!(panicked.shutdown().await.is_err());
            });
            assert!(
                std::thread::spawn(|| panic!("ordinary thread panic"))
                    .join()
                    .is_err()
            );
            return;
        }

        let output = Command::new(std::env::current_exe().expect("current test executable"))
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(CHILD_ENV, "1")
            .output()
            .expect("run managed-worker diagnostics subprocess");
        assert!(
            output.status.success(),
            "diagnostics subprocess failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("managed-diagnostics-error"));
        assert!(stderr.contains("managed blocking worker runner failed"));
        assert_eq!(
            stderr.matches(PRIOR_HOOK_MARKER).count(),
            2,
            "managed and ordinary panics must both retain the process-owned hook: {stderr}"
        );
        assert!(!stderr.contains(ERROR_SECRET));
        assert!(!stderr.contains(PANIC_SECRET));
    }

    /// A cancelled shutdown future must not leave an unabortable Tokio blocking task behind.
    #[test]
    #[allow(clippy::panic)]
    fn cancelled_shutdown_does_not_block_runtime_drop() {
        let started = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let thread_started = Arc::clone(&started);
        let thread_release = Arc::clone(&release);
        let (dropped_tx, dropped_rx) = std::sync::mpsc::channel();

        let harness = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap_or_else(|error| panic!("test runtime: {error}"));
            runtime.block_on(async move {
                let worker = ManagedBlockingWorker::spawn(
                    "managed-blocking-stalled",
                    CancellationToken::new(),
                    Arc::new(WorkerHealth::starting()),
                    ShutdownBudget::new(Duration::from_secs(1)).expect("positive shutdown budget"),
                    move |_token| {
                        thread_started.store(true, Ordering::Release);
                        while !thread_release.load(Ordering::Acquire) {
                            std::thread::yield_now();
                        }
                        Ok(())
                    },
                );
                tokio::time::timeout(Duration::from_secs(1), async {
                    while !started.load(Ordering::Acquire) {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap_or_else(|error| panic!("worker did not start: {error}"));
                assert!(
                    tokio::time::timeout(Duration::from_millis(20), worker.shutdown())
                        .await
                        .is_err(),
                    "stalled worker must exercise cancellation of shutdown"
                );
            });
            drop(runtime);
            let _ = dropped_tx.send(());
        });

        let dropped_without_release = dropped_rx.recv_timeout(Duration::from_millis(200)).is_ok();
        release.store(true, Ordering::Release);
        harness
            .join()
            .unwrap_or_else(|_| panic!("runtime harness panicked"));
        assert!(
            dropped_without_release,
            "runtime drop waited for an unabortable blocking join"
        );
    }
}
