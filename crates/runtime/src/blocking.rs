//! Managed ownership for long-lived work on dedicated OS threads.
//!
//! Tokio documents that an already-started `spawn_blocking` task cannot be aborted and may keep a
//! runtime from shutting down. Long-lived runners therefore use a dedicated OS thread and report
//! completion through a cancellation-safe channel.
//!
//! ref: tokio-rs/tokio d8756916 tokio/src/task/blocking.rs

use std::time::Duration;
use tokio::sync::{Mutex, oneshot, watch};

use tokio_util::sync::CancellationToken;

use crate::resource::{JoinState, TaskTerminalGuard, task_status_channel};
use crate::{
    DynManagedResource, ManagedResource, ShutdownError, ShutdownErrorKind, TaskExit, TaskState,
    TaskStatus,
};

/// Supervised dedicated-thread worker.
#[must_use = "dropping the worker cancels its managed runner"]
pub struct ManagedBlockingWorker {
    name: String,
    token: CancellationToken,
    shutdown_timeout: Duration,
    join: Mutex<JoinState<ThreadJoin>>,
    status: TaskStatus,
}

type WorkerThread = std::thread::JoinHandle<Result<(), ShutdownError>>;

struct ThreadJoin {
    handoff: Option<(oneshot::Sender<WorkerThread>, WorkerThread)>,
    result: oneshot::Receiver<Result<(), ShutdownError>>,
}

// Reserve the blocking join before starting user code. A dropped request releases the helper
// immediately, including when worker startup fails. No host executor participates in the join.
// ref: rust-lang/rust library/std/src/thread/join_handle.rs@1.96.0
fn prepare_join(
    status: watch::Sender<TaskState>,
) -> std::io::Result<(
    oneshot::Sender<WorkerThread>,
    oneshot::Receiver<Result<(), ShutdownError>>,
)> {
    let (submit, request) = oneshot::channel::<WorkerThread>();
    let (publish, result) = oneshot::channel();
    std::thread::Builder::new()
        .name("rss-worker-join".into())
        .spawn(move || {
            if let Ok(worker) = request.blocking_recv() {
                let outcome = worker.join().unwrap_or_else(|_| {
                    status.send_replace(TaskState::Stopped(TaskExit::Failed(
                        ShutdownErrorKind::TaskPanicked,
                    )));
                    Err(ShutdownError::task_panicked(BlockingWorkerJoinPanicked))
                });
                let _ = publish.send(outcome);
            }
        })?;
    Ok((submit, result))
}

/// Opaque, unstarted dedicated-thread registration.
///
/// Only a lifecycle transaction can bind the worker to a stack-owned token and transfer the
/// resulting thread owner into the shutdown stack.
#[must_use = "blocking worker registrations must be staged in a lifecycle transaction"]
pub struct ManagedBlockingWorkerRegistration {
    pub(crate) critical: bool,
    name: String,
    shutdown_timeout: Duration,
    run: Option<Box<BlockingRunner>>,
}

type BlockingRunner = dyn FnOnce(CancellationToken) -> Result<(), ShutdownError> + Send + 'static;

/// Dedicated worker thread could not be created.
#[derive(Debug, thiserror::Error)]
#[error("managed blocking worker thread could not be started")]
pub struct ManagedBlockingWorkerStartError(#[source] std::io::Error);

#[derive(Debug, thiserror::Error)]
#[error("managed blocking worker thread panicked")]
struct BlockingWorkerPanicked;

#[derive(Debug, thiserror::Error)]
#[error("managed blocking worker thread join panicked")]
struct BlockingWorkerJoinPanicked;

impl ManagedBlockingWorker {
    /// Spawn a dedicated runner and reserve a second OS thread for its eventual blocking join.
    pub fn try_spawn<N, F>(
        name: N,
        token: CancellationToken,
        shutdown_timeout: Duration,
        run: F,
    ) -> Result<Self, ManagedBlockingWorkerStartError>
    where
        N: Into<String>,
        F: FnOnce(CancellationToken) -> Result<(), ShutdownError> + Send + 'static,
    {
        let name = name.into();
        let thread_name = name.clone();
        let thread_token = token.clone();
        let status_token = token.clone();
        let (sender, status) = task_status_channel(name.clone());
        let (submit, result) =
            prepare_join(sender.clone()).map_err(ManagedBlockingWorkerStartError)?;
        sender.send_replace(TaskState::Running);
        let terminal = TaskTerminalGuard::new(sender);
        let thread = std::thread::Builder::new()
            .name(name.clone())
            .spawn(move || {
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(thread_token)));
                match result {
                    Ok(Ok(())) => {
                        terminal.finish(if status_token.is_cancelled() {
                            TaskExit::Cancelled
                        } else {
                            TaskExit::Completed
                        });
                        Ok(())
                    }
                    Ok(Err(error)) => {
                        terminal.finish(TaskExit::Failed(error.kind()));
                        tracing::error!(
                            worker = thread_name,
                            error_kind = error.kind().as_str(),
                            "managed blocking worker runner failed; error redacted"
                        );
                        Err(error)
                    }
                    Err(_) => {
                        terminal.finish(TaskExit::Failed(ShutdownErrorKind::TaskPanicked));
                        Err(ShutdownError::task_panicked(BlockingWorkerPanicked))
                    }
                }
            })
            .map_err(ManagedBlockingWorkerStartError)?;
        Ok(Self {
            name,
            token,
            shutdown_timeout,
            join: Mutex::new(JoinState::Running(ThreadJoin {
                handoff: Some((submit, thread)),
                result,
            })),
            status,
        })
    }

    /// Read the same-source managed task status.
    pub fn status(&self) -> TaskStatus {
        self.status.clone()
    }

    /// Stable operator-controlled worker identity.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Upper bound used when a consumer wraps this worker as a managed resource.
    pub const fn shutdown_timeout(&self) -> Duration {
        self.shutdown_timeout
    }

    /// Cancel and join the dedicated worker thread, including thread-local destruction.
    ///
    /// A cancelled waiter leaves the join in this owner. Repeated or concurrent calls observe
    /// the same real result. Dropping the owner requests cancellation but cannot stop a thread.
    pub async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.token.cancel();
        let mut state = self.join.lock().await;
        if let JoinState::Running(join) = &mut *state {
            if let Some((submit, worker)) = join.handoff.take() {
                // A lost helper also closes the result channel and is reported to all waiters.
                let _ = submit.send(worker);
            }
            let result = (&mut join.result)
                .await
                .unwrap_or_else(|error| Err(ShutdownError::task_unknown(error)));
            *state = JoinState::Joined(result);
        }
        match &*state {
            JoinState::Joined(result) => result.as_ref().copied().map_err(ShutdownError::retained),
            JoinState::Running(_) => unreachable!("thread joined before recording its result"),
        }
    }
}

impl ManagedBlockingWorkerRegistration {
    /// Include this runner in the same-stack critical monitor and the scope early-exit policy.
    /// The status does not certify thread-local destruction; shutdown still joins the thread.
    pub const fn critical(mut self) -> Self {
        self.critical = true;
        self
    }

    pub(crate) fn bind(
        mut self,
        token: CancellationToken,
    ) -> Result<ManagedBlockingWorker, ManagedBlockingWorkerStartError> {
        let run = self
            .run
            .take()
            .unwrap_or_else(|| unreachable!("blocking registration is consumed exactly once"));
        ManagedBlockingWorker::try_spawn(self.name, token, self.shutdown_timeout, run)
    }
}

/// Prepare a synchronous dedicated-thread runner for lifecycle-owned startup.
pub fn blocking_worker_registration<N, F>(
    name: N,
    shutdown_timeout: Duration,
    run: F,
) -> ManagedBlockingWorkerRegistration
where
    N: Into<String>,
    F: FnOnce(CancellationToken) -> Result<(), ShutdownError> + Send + 'static,
{
    ManagedBlockingWorkerRegistration {
        critical: false,
        name: name.into(),
        shutdown_timeout,
        run: Some(Box::new(run)),
    }
}

struct RegisteredBlockingWorker(ManagedBlockingWorker);

impl ManagedResource for RegisteredBlockingWorker {
    fn name(&self) -> &str {
        self.0.name()
    }

    fn shutdown_timeout(&self) -> Duration {
        self.0.shutdown_timeout()
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.0.shutdown().await
    }
}

pub(crate) fn registered_blocking_worker(
    worker: ManagedBlockingWorker,
) -> Box<DynManagedResource<'static>> {
    DynManagedResource::new_box(RegisteredBlockingWorker(worker))
}

/// Prepare a `!Send` future for a lifecycle-owned dedicated current-thread Tokio runtime.
pub fn dedicated_runtime_registration<N, M, Fut>(
    name: N,
    shutdown_timeout: Duration,
    make_body: M,
) -> ManagedBlockingWorkerRegistration
where
    N: Into<String>,
    M: FnOnce(CancellationToken) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), ShutdownError>>,
{
    let name = name.into();
    let runtime_worker_name = name.clone();
    blocking_worker_registration(name, shutdown_timeout, move |run_token| {
        let runtime = observe_runtime_build_result(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build(),
            |_| {},
            &runtime_worker_name,
        )?;
        runtime.block_on(make_body(run_token))
    })
}

/// Spawn a `!Send` future on a dedicated current-thread Tokio runtime.
pub fn spawn_on_dedicated_runtime<N, M, Fut>(
    name: N,
    token: CancellationToken,
    shutdown_timeout: Duration,
    make_body: M,
) -> Result<ManagedBlockingWorker, ManagedBlockingWorkerStartError>
where
    N: Into<String>,
    M: FnOnce(CancellationToken) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), ShutdownError>>,
{
    spawn_on_dedicated_runtime_with_build_failure(name, token, shutdown_timeout, |_| {}, make_body)
}

/// Spawn through the canonical runtime policy and observe runtime construction failure.
pub(crate) fn spawn_on_dedicated_runtime_with_build_failure<N, O, M, Fut>(
    name: N,
    token: CancellationToken,
    shutdown_timeout: Duration,
    on_build_failure: O,
    make_body: M,
) -> Result<ManagedBlockingWorker, ManagedBlockingWorkerStartError>
where
    N: Into<String>,
    O: FnOnce(&std::io::Error) + Send + 'static,
    M: FnOnce(CancellationToken) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), ShutdownError>>,
{
    spawn_on_dedicated_runtime_with_failure_observers(
        name,
        token,
        shutdown_timeout,
        on_build_failure,
        || {},
        make_body,
    )
}

/// Spawn through the canonical runtime policy and observe build failure or worker panic.
pub(crate) fn spawn_on_dedicated_runtime_with_failure_observers<N, O, P, M, Fut>(
    name: N,
    token: CancellationToken,
    shutdown_timeout: Duration,
    on_build_failure: O,
    on_panic: P,
    make_body: M,
) -> Result<ManagedBlockingWorker, ManagedBlockingWorkerStartError>
where
    N: Into<String>,
    O: FnOnce(&std::io::Error) + Send + 'static,
    P: FnOnce() + Send + 'static,
    M: FnOnce(CancellationToken) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), ShutdownError>>,
{
    let name = name.into();
    let runtime_worker_name = name.clone();
    ManagedBlockingWorker::try_spawn(name, token, shutdown_timeout, move |run_token| {
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
                Err(ShutdownError::task_panicked(BlockingWorkerPanicked))
            }
        }
    })
}

fn observe_runtime_build_result<T, O>(
    result: std::io::Result<T>,
    on_build_failure: O,
    worker_name: &str,
) -> Result<T, ShutdownError>
where
    O: FnOnce(&std::io::Error),
{
    result.map_err(|error| {
        on_build_failure(&error);
        tracing::error!(
            worker = worker_name,
            "managed blocking worker runtime build failed"
        );
        ShutdownError::new(error)
    })
}

impl Drop for ManagedBlockingWorker {
    fn drop(&mut self) {
        self.token.cancel();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    struct ThreadExitGuard {
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    }

    impl Drop for ThreadExitGuard {
        fn drop(&mut self) {
            let _ = self.entered.send(());
            let _ = self.release.recv_timeout(Duration::from_secs(5));
        }
    }

    std::thread_local! {
        static THREAD_EXIT_GUARD: std::cell::RefCell<Option<ThreadExitGuard>> = const {
            std::cell::RefCell::new(None)
        };
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: thread creation is test setup and must fail the test.
    async fn shutdown_cancels_before_waiting_and_publishes_terminal_status() {
        let observed = Arc::new(AtomicBool::new(false));
        let run_observed = Arc::clone(&observed);
        let worker = ManagedBlockingWorker::try_spawn(
            "blocking-cancel",
            CancellationToken::new(),
            Duration::from_secs(1),
            move |token| {
                while !token.is_cancelled() {
                    std::thread::yield_now();
                }
                run_observed.store(true, Ordering::Release);
                Ok(())
            },
        )
        .expect("worker thread starts");
        let status = worker.status();
        assert_eq!(status.current(), TaskState::Running);
        assert!(worker.shutdown().await.is_ok());
        assert!(observed.load(Ordering::Acquire));
        assert_eq!(status.current(), TaskState::Stopped(TaskExit::Cancelled));
    }

    #[tokio::test]
    #[allow(clippy::expect_used, clippy::panic)]
    // reason: panic isolation is the behavior under test.
    async fn runner_panic_is_closed_and_redacted() {
        let worker = ManagedBlockingWorker::try_spawn(
            "blocking-panic",
            CancellationToken::new(),
            Duration::from_secs(1),
            |_token| -> Result<(), ShutdownError> { panic!("secret panic payload") },
        )
        .expect("worker thread starts");
        let error = worker
            .shutdown()
            .await
            .expect_err("panic must fail shutdown");
        assert_eq!(error.kind(), ShutdownErrorKind::TaskPanicked);
        assert!(!format!("{error:?}").contains("secret panic payload"));
        assert_eq!(
            worker.shutdown().await.expect_err("panic remains").kind(),
            ShutdownErrorKind::TaskPanicked
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: expected error paths are the test assertions.
    async fn runner_error_is_retained_by_every_shutdown() {
        let worker = ManagedBlockingWorker::try_spawn(
            "blocking-error",
            CancellationToken::new(),
            Duration::from_secs(1),
            |_token| Err(ShutdownError::new(std::io::Error::other("private"))),
        )
        .expect("worker thread starts");
        let status = worker.status();
        let error = worker
            .shutdown()
            .await
            .expect_err("runner error reaches owner");
        assert_eq!(error.kind(), ShutdownErrorKind::Operation);
        assert_eq!(
            status.current(),
            TaskState::Stopped(TaskExit::Failed(ShutdownErrorKind::Operation))
        );
        assert_eq!(
            worker.shutdown().await.expect_err("failure remains").kind(),
            ShutdownErrorKind::Operation
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: expected error paths are the test assertions.
    async fn dedicated_runtime_propagates_async_error() {
        let worker = spawn_on_dedicated_runtime(
            "async-error",
            CancellationToken::new(),
            Duration::from_secs(1),
            |_token| async { Err(ShutdownError::new(std::io::Error::other("private"))) },
        )
        .expect("worker thread starts");
        let error = worker
            .shutdown()
            .await
            .expect_err("async error reaches owner");
        assert_eq!(error.kind(), ShutdownErrorKind::Operation);
    }

    #[tokio::test]
    #[allow(clippy::expect_used, clippy::panic)]
    // reason: panic isolation and its closed error are the behavior under test.
    async fn dedicated_runtime_panic_observer_runs_once() {
        let observed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observer = Arc::clone(&observed);
        let worker = spawn_on_dedicated_runtime_with_failure_observers(
            "panic-observer",
            CancellationToken::new(),
            Duration::from_secs(1),
            |_| {},
            move || {
                observer.fetch_add(1, Ordering::AcqRel);
            },
            |_token| async { panic!("private panic payload") },
        )
        .expect("worker thread starts");
        let error = worker
            .shutdown()
            .await
            .expect_err("panic reaches owner as closed error");
        assert_eq!(error.kind(), ShutdownErrorKind::TaskPanicked);
        assert_eq!(observed.load(Ordering::Acquire), 1);
    }

    #[test]
    fn runtime_build_failure_notifies_observer_once() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let result = observe_runtime_build_result::<(), _>(
            Err(std::io::Error::other("build failed")),
            move |_| {
                observed.fetch_add(1, Ordering::AcqRel);
            },
            "build-observer",
        );
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::Acquire), 1);
    }

    #[test]
    #[allow(clippy::expect_used)] // reason: thread creation is test setup and must fail the test.
    fn dropping_worker_synchronously_cancels_runner_token() {
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = ManagedBlockingWorker::try_spawn(
            "drop-cancel",
            CancellationToken::new(),
            Duration::from_secs(1),
            move |token| {
                while !token.is_cancelled() {
                    std::thread::yield_now();
                }
                let _ = sender.send(());
                Ok(())
            },
        )
        .expect("worker thread starts");
        drop(worker);
        assert!(receiver.recv_timeout(Duration::from_secs(1)).is_ok());
    }

    #[derive(Default)]
    struct WakeCount(std::sync::atomic::AtomicUsize);
    impl std::task::Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    #[allow(clippy::expect_used)] // reason: thread, runtime and bounded gate failures are test assertions.
    fn delayed_tls_allows_waiter_timeout_runtime_drop_and_rejoin() {
        let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let worker = ManagedBlockingWorker::try_spawn(
            "thread-local-join",
            CancellationToken::new(),
            Duration::from_secs(1),
            move |_token| {
                THREAD_EXIT_GUARD.with(|guard| {
                    *guard.borrow_mut() = Some(ThreadExitGuard {
                        entered: entered_sender,
                        release: release_receiver,
                    });
                });
                Ok(())
            },
        )
        .expect("worker thread starts");
        entered_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("TLS destructor is parked");

        let wakes = Arc::new(WakeCount::default());
        let waker = std::task::Waker::from(wakes.clone());
        let mut first = Box::pin(worker.shutdown());
        assert!(
            first
                .as_mut()
                .poll(&mut std::task::Context::from_waker(&waker))
                .is_pending()
        );
        assert_eq!(wakes.0.load(Ordering::Relaxed), 0, "parked join self-woke");
        drop(first);

        let runtime = || {
            tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .start_paused(true)
                .build()
                .expect("timer runtime")
        };
        let first_runtime = runtime();
        first_runtime.block_on(async {
            assert!(
                tokio::time::timeout(Duration::from_secs(1), worker.shutdown())
                    .await
                    .is_err()
            );
        });
        drop(first_runtime);

        runtime().block_on(async {
            let mut retry = Box::pin(worker.shutdown());
            let mut concurrent = Box::pin(worker.shutdown());
            assert!(futures::poll!(&mut retry).is_pending());
            assert!(futures::poll!(&mut concurrent).is_pending());
            release_sender
                .send(())
                .expect("release destructor after runtime drop");
            let (one, two) = tokio::join!(retry, concurrent);
            assert!(one.is_ok() && two.is_ok());
            assert!(worker.shutdown().await.is_ok());
        });
    }

    #[test]
    #[allow(clippy::expect_used, clippy::panic)] // reason: exercise an uncaught panic from an actual native join.
    fn native_join_panic_is_published_after_thread_exit() {
        let (sender, status) = task_status_channel("native-panic");
        let (submit, result) = prepare_join(sender).expect("join thread starts");
        let worker = std::thread::spawn(|| panic!("private payload"));
        assert!(submit.send(worker).is_ok());
        let error = result
            .blocking_recv()
            .expect("join result published")
            .expect_err("native worker panicked");
        assert_eq!(error.kind(), ShutdownErrorKind::TaskPanicked);
        assert_eq!(
            status.current(),
            TaskState::Stopped(TaskExit::Failed(ShutdownErrorKind::TaskPanicked))
        );
        assert!(!format!("{error:?}").contains("private payload"));
    }
}
