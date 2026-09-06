//! Managed resource and task ownership primitives.
//!
//! This module is the sole owner of the public lifecycle trait and managed-task state. The bounded
//! two-phase driver lives in [`crate::ShutdownStack`].

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use std::{future::Future, panic::AssertUnwindSafe};

use dynosaur::dynosaur;
use futures::FutureExt as _;
use tokio::sync::{Mutex, watch};
use tokio_util::sync::CancellationToken;

use rss_redact::RedactedSource;

/// per-resource 默认关闭超时预算。重 I/O 资源（如 outbox relay）可在
/// [`ManagedResource::shutdown_timeout`] 覆盖为更长。
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Cancellation-safe owner for one Tokio task.
///
/// Awaiting [`join`](Self::join) consumes the owner. If the join future is cancelled, or the
/// surrounding managed resource is dropped while shutdown is in flight, `Drop` aborts the task
/// instead of allowing Tokio's raw [`tokio::task::JoinHandle`] drop semantics to detach it.
#[derive(Debug)]
#[must_use = "dropping an OwnedTask aborts its task; retain it until managed shutdown"]
struct OwnedTask<T> {
    handle: Option<tokio::task::JoinHandle<T>>,
}

impl<T> OwnedTask<T> {
    /// Adopt a spawned task at its lifecycle ownership boundary.
    const fn new(handle: tokio::task::JoinHandle<T>) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    /// Await task completion. Cancellation of this future aborts the still-owned task via `Drop`.
    async fn join(mut self) -> Result<T, tokio::task::JoinError> {
        let result = match self.handle.as_mut() {
            Some(handle) => handle.await,
            None => unreachable!("OwnedTask handle is present until join completes"),
        };
        self.handle.take();
        result
    }
}

/// Run and await one blocking, one-shot operation without accepting or exposing a raw join handle.
///
/// Long-lived background resources cannot enter this API because it accepts only a synchronous
/// closure; they must use [`ManagedTask`] instead. Tokio cannot abort an already-started blocking
/// closure: cancellation bounds the awaiter's ownership but does not by itself bound runtime or
/// process teardown. Callers must therefore supply an operation with its own finite upper bound.
pub async fn join_owned_task<F, T>(blocking: F) -> Result<T, tokio::task::JoinError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    OwnedTask::new(tokio::task::spawn_blocking(blocking))
        .join()
        .await
}

/// Closed runtime state of one canonical managed Tokio task.
///
/// INVARIANT: MANAGED-TASK-STATE-01 { level = "Hard", exec = "native-compile", source = "code", native = "private watch publisher plus move-only TaskStart, same-token future factory, and exhaustive TaskState/TaskExit" }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskState {
    /// The lifecycle slot exists but its task has not been spawned.
    Pending,
    /// The task has been spawned and has not reached a terminal outcome.
    Running,
    /// The task reached a sticky terminal outcome.
    Stopped(TaskExit),
}

/// Payload-free terminal outcome of a managed task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskExit {
    /// The task returned successfully after its lifecycle token was cancelled.
    Cancelled,
    /// The task returned successfully before lifecycle cancellation.
    Completed,
    /// The task failed, panicked, or was aborted.
    Failed(ShutdownErrorKind),
}

/// Cloneable, read-only task status receipt.
#[derive(Clone, Debug)]
pub struct TaskStatus {
    name: Arc<str>,
    receiver: watch::Receiver<TaskState>,
}

impl TaskStatus {
    /// Stable operator-controlled task identity.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Observe the current state without waiting.
    pub fn current(&self) -> TaskState {
        *self.receiver.borrow()
    }

    /// Whether the task is currently running.
    pub fn is_running(&self) -> bool {
        self.current() == TaskState::Running
    }

    /// Wait for the first terminal outcome.
    pub async fn wait_stopped(&self) -> TaskExit {
        let mut receiver = self.receiver.clone();
        loop {
            if let TaskState::Stopped(exit) = *receiver.borrow_and_update() {
                return exit;
            }
            if receiver.changed().await.is_err() {
                return TaskExit::Failed(ShutdownErrorKind::TaskUnknown);
            }
        }
    }
}

/// Move-only capability that can start exactly one managed task.
#[must_use = "TaskStart must be spawned or dropped as a failed startup path"]
pub struct TaskStart {
    name: Arc<str>,
    shutdown_timeout: Duration,
    sender: Option<watch::Sender<TaskState>>,
    status: TaskStatus,
}

impl TaskStart {
    /// Spawn work owned outside [`crate::ShutdownStack`].
    ///
    /// A task intended for the stack must use [`Self::into_registration`] instead, so the stack
    /// binds its own child token when the registration is staged.
    pub fn spawn_detached<F, Make>(self, token: CancellationToken, make: Make) -> ManagedTask
    where
        F: Future<Output = Result<(), ShutdownError>> + Send + 'static,
        Make: FnOnce(CancellationToken) -> F,
    {
        self.spawn(token, make)
    }

    /// Convert this unstarted capability into the only registration accepted by task funnels.
    pub fn into_registration<F, Make>(self, make: Make) -> ManagedTaskRegistration
    where
        F: Future<Output = Result<(), ShutdownError>> + Send + 'static,
        Make: FnOnce(CancellationToken) -> F + Send + 'static,
    {
        let status = self.status.clone();
        ManagedTaskRegistration {
            start: Some(self),
            make: Some(Box::new(move |token| Box::pin(make(token)))),
            status,
        }
    }

    fn spawn<F, Make>(mut self, token: CancellationToken, make: Make) -> ManagedTask
    where
        F: Future<Output = Result<(), ShutdownError>> + Send + 'static,
        Make: FnOnce(CancellationToken) -> F,
    {
        let sender = self
            .sender
            .take()
            .unwrap_or_else(|| unreachable!("TaskStart is consumed exactly once"));
        sender.send_replace(TaskState::Running);
        let terminal = TaskTerminalGuard::new(sender);
        let task_token = token.clone();
        let future = std::panic::catch_unwind(AssertUnwindSafe(|| make(token.clone())))
            .map_err(|_| OpaqueTaskPanic);
        let handle = tokio::spawn(async move {
            let result = match future {
                Ok(future) => AssertUnwindSafe(future).catch_unwind().await,
                Err(_) => Err(Box::new(OpaqueTaskPanic) as Box<dyn std::any::Any + Send>),
            };
            match result {
                Ok(Ok(())) => {
                    terminal.finish(if task_token.is_cancelled() {
                        TaskExit::Cancelled
                    } else {
                        TaskExit::Completed
                    });
                    Ok(())
                }
                Ok(Err(error)) => {
                    terminal.finish(TaskExit::Failed(error.kind()));
                    Err(error)
                }
                Err(_) => {
                    let error = ShutdownError::task_panicked(OpaqueTaskPanic);
                    terminal.finish(TaskExit::Failed(ShutdownErrorKind::TaskPanicked));
                    Err(error)
                }
            }
        });
        ManagedTask {
            name: Arc::clone(&self.name),
            shutdown_timeout: self.shutdown_timeout,
            token,
            task: Mutex::new(Some(OwnedTask::new(handle))),
            status: self.status.clone(),
        }
    }
}

impl Drop for TaskStart {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            sender.send_replace(TaskState::Stopped(TaskExit::Failed(
                ShutdownErrorKind::TaskCancelled,
            )));
        }
    }
}

pub(crate) struct TaskTerminalGuard {
    sender: Option<watch::Sender<TaskState>>,
}

impl TaskTerminalGuard {
    pub(crate) const fn new(sender: watch::Sender<TaskState>) -> Self {
        Self {
            sender: Some(sender),
        }
    }

    pub(crate) fn finish(mut self, exit: TaskExit) {
        if let Some(sender) = self.sender.take() {
            sender.send_replace(TaskState::Stopped(exit));
        }
    }
}

impl Drop for TaskTerminalGuard {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            sender.send_replace(TaskState::Stopped(TaskExit::Failed(
                ShutdownErrorKind::TaskCancelled,
            )));
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("managed task panicked")]
struct OpaqueTaskPanic;

impl<T> Drop for OwnedTask<T> {
    fn drop(&mut self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
}

/// 进程关闭时需要按依赖逆序 await 关干净的托管资源
/// （DB pool / outbox relay / event consumer / 后台 worker / HTTP listener 等）。
///
/// Rust 无 async `Drop`——关闭顺序与等待由 [`crate::ShutdownStack`] 显式驱动，而非 RAII `Drop`。
/// 公开 [`ManagedResource`] 是 **Send 变体**（adapter resource / service worker / runtime wrapper 均可实现）；
/// [`DynManagedResource`] 是其 dyn-compatible wrapper——`ShutdownStack` 以
/// `Box<DynManagedResource<'static>>` 持有并 `tokio::spawn` 隔离 panic（boxed future 须 Send，
/// 故走 Send 变体）。非 Send 基 trait `ManagedResourceLocal` 不在 crate 根 re-export。
///
/// # 实现者须知（消费侧契约）
///
/// - **取消信号经构造器注入**：资源的后台 task 用的 `CancellationToken` 经
///   [`crate::StartupTransaction::stage_with_token`] 或 launch transaction 的同名入口注入，
///   不在 `shutdown` 参数里传；无后台 task 的资源经 `stage_resource` 注册。
/// - **不要在 `shutdown` 内部自设超时**：per-resource 超时由驱动器外层 `tokio::time::timeout`
///   包裹（[`shutdown_timeout`](ManagedResource::shutdown_timeout)）；内部再设超时是双重计时。
/// - **幂等性免费**：驱动器消费 stack 单次驱动，`shutdown` 不会被重复调用，无需自保幂等。
/// - **注册到 RSS 的后台任务由 [`ManagedTask`] 持有**：调用方只保留只读 [`TaskStatus`]。
///   adapter 自有的私有 recovery/cleanup 任务可直接使用 Tokio 所有权工具；adapter 必须保证
///   admission 封闭、取消安全的 join/abort 和资源清理，不能向调用方泄漏任务控制权。
/// - **其它需要 `&mut` 的内部状态**：因 `shutdown(&self)`，用 `Mutex<Option<Inner>>` 或
///   `tokio::sync::Mutex` 包装，在 `shutdown` 中 `take()`。
#[trait_variant::make(ManagedResource: Send)]
#[dynosaur(pub DynManagedResource = dyn(box) ManagedResource, bridge(dyn))]
#[allow(async_fn_in_trait)]
#[allow(dead_code)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `ManagedResource` 变体 +
// dynosaur `DynManagedResource` 承载——ShutdownStack 经 tokio::spawn 隔离 panic，需 Send future。
pub trait ManagedResourceLocal {
    /// 资源可读名称（kebab/snake 稳定标识），用于日志与超时报错。
    fn name(&self) -> &str;

    /// 关闭此资源：await 内部 task 收敛、flush 未完成工作、释放连接 / 句柄。
    ///
    /// 驱动器在调用前已 `cancel` root `CancellationToken`，实现可据此提前退出。
    /// 超时由驱动器在外层 wrap，实现内部无需自设超时。
    ///
    /// 失败用 typed [`ShutdownError`] 表达（**非 `anyhow`**）：adapter 内部错误经
    /// [`ShutdownError::new`] 包成内部 source，`Display` 仅暴露资源无关的安全摘要常量——
    /// 杜绝 adapter runtime 信息经公共 port / 默认日志泄漏（PII 边界）。
    async fn shutdown(&self) -> Result<(), ShutdownError>;

    /// 本资源期望的关闭超时上界。驱动器据此做 per-resource timeout。
    fn shutdown_timeout(&self) -> Duration {
        DEFAULT_SHUTDOWN_TIMEOUT
    }
}

/// 资源关闭失败：lifecycle owner 实现 [`ManagedResource::shutdown`] 时返回的 typed 错误。
///
/// **PII 边界**（替代 `anyhow` 暴露在公共 port）：`Display` 仅输出资源无关的安全摘要常量
/// （不含 runtime 数据）；source 经 [`RedactedSource`] 脱敏（`Debug`/`Display` 固定 `<redacted>`、
/// `Error::source()` 恒 `None`——原始错误不经任何 `Error` 接口暴露，fail-closed）。`rss_redact::redact_error`
/// funnel 取顶层 Display、不遍历 source 链；[`crate::ShutdownStack`] 业务错误分支已采纳 `redact_error`
/// 记录 redacted 顶层摘要。
/// 见 INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
#[derive(Debug, thiserror::Error)]
#[error("resource shutdown failed")]
pub struct ShutdownError {
    kind: ShutdownErrorKind,
    #[source]
    source: RedactedSource,
}

/// Payload-free reason carried by [`ShutdownError`] into the canonical shutdown observer.
///
/// The raw source remains write-only behind [`RedactedSource`]; this closed value is the only
/// diagnostic surface available to orchestration code.
///
/// INVARIANT: SHUTDOWN-ERROR-KIND-CLOSED-01 { level = "Hard", exec = "native-compile", source = "code", native = "private ShutdownError fields plus exhaustive closed enum" }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownErrorKind {
    /// The resource reported an ordinary provider/transport shutdown failure.
    Operation,
    /// A resource-owned background task panicked.
    TaskPanicked,
    /// A resource-owned background task was cancelled before joining cleanly.
    TaskCancelled,
    /// Tokio reported an unrecognized abnormal task termination.
    TaskUnknown,
    /// A nested lifecycle exhausted its own explicit shutdown deadline.
    DeadlineExceeded,
}

impl ShutdownErrorKind {
    /// Stable, low-cardinality observation label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Operation => "operation",
            Self::TaskPanicked => "task_panicked",
            Self::TaskCancelled => "task_cancelled",
            Self::TaskUnknown => "task_unknown",
            Self::DeadlineExceeded => "deadline_exceeded",
        }
    }
}

impl ShutdownError {
    /// 把一个 adapter 内部错误包成关闭失败。原始错误仅作 internal source 保留，
    /// 不经 `Display` 暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::with_kind(ShutdownErrorKind::Operation, source)
    }

    /// Convert a Tokio task join failure at the resource ownership boundary.
    ///
    /// The returned error contains no panic payload; callers observe only the closed
    /// [`ShutdownErrorKind`]. This does not suppress the process-wide panic hook.
    pub fn from_join_error(source: tokio::task::JoinError) -> Self {
        let kind = if source.is_panic() {
            ShutdownErrorKind::TaskPanicked
        } else if source.is_cancelled() {
            ShutdownErrorKind::TaskCancelled
        } else {
            ShutdownErrorKind::TaskUnknown
        };
        Self::with_kind(kind, source)
    }

    /// Preserve a known background-task panic without accepting its payload as diagnostics.
    pub fn task_panicked<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::with_kind(ShutdownErrorKind::TaskPanicked, source)
    }

    /// Preserve a known background-task cancellation without exposing task diagnostics.
    pub fn task_cancelled<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::with_kind(ShutdownErrorKind::TaskCancelled, source)
    }

    /// Preserve an unknown abnormal background-task termination.
    pub fn task_unknown<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::with_kind(ShutdownErrorKind::TaskUnknown, source)
    }

    /// Preserve an explicit nested lifecycle deadline failure.
    pub fn deadline_exceeded<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::with_kind(ShutdownErrorKind::DeadlineExceeded, source)
    }

    /// Return the payload-free shutdown failure category.
    pub const fn kind(&self) -> ShutdownErrorKind {
        self.kind
    }

    fn with_kind<E>(kind: ShutdownErrorKind, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            kind,
            source: RedactedSource::new(source),
        }
    }
}

/// Canonical owner for one long-lived Tokio background task.
pub struct ManagedTask {
    name: Arc<str>,
    shutdown_timeout: Duration,
    token: CancellationToken,
    task: Mutex<Option<OwnedTask<Result<(), ShutdownError>>>>,
    status: TaskStatus,
}

impl ManagedTask {
    /// Prepare a lifecycle slot before the task is spawned.
    ///
    /// The status receipt can be retained for lifecycle observation before the move-only start
    /// capability is transferred to a shutdown-token factory.
    pub fn prepare(name: impl Into<String>, shutdown_timeout: Duration) -> (TaskStart, TaskStatus) {
        let (sender, receiver) = watch::channel(TaskState::Pending);
        let name: Arc<str> = Arc::from(name.into());
        let status = TaskStatus {
            name: Arc::clone(&name),
            receiver,
        };
        (
            TaskStart {
                name,
                shutdown_timeout,
                sender: Some(sender),
                status: status.clone(),
            },
            status,
        )
    }

    /// Read the task's unforgeable status receipt.
    pub fn status(&self) -> TaskStatus {
        self.status.clone()
    }

    /// Stable operator-controlled resource identity.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Per-task shutdown upper bound.
    pub const fn shutdown_timeout(&self) -> Duration {
        self.shutdown_timeout
    }

    /// Cancel and join this externally owned task.
    pub async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.token.cancel();
        let task = self.task.lock().await.take();
        match task {
            Some(task) => task.join().await.map_err(ShutdownError::from_join_error)?,
            None => Ok(()),
        }
    }
}

pub(crate) fn task_status_channel(
    name: impl Into<String>,
) -> (watch::Sender<TaskState>, TaskStatus) {
    let (sender, receiver) = watch::channel(TaskState::Pending);
    let name: Arc<str> = Arc::from(name.into());
    (sender, TaskStatus { name, receiver })
}

impl Drop for ManagedTask {
    fn drop(&mut self) {
        self.token.cancel();
        if let Ok(mut task) = self.task.try_lock() {
            task.take();
        }
    }
}

type TaskFactory = Box<
    dyn FnOnce(CancellationToken) -> Pin<Box<dyn Future<Output = Result<(), ShutdownError>> + Send>>
        + Send,
>;

/// Opaque unstarted task factory and same-source status receipt.
///
/// Fields are private and the only constructor consumes [`ManagedTask`].
#[must_use = "managed task registration must enter a shutdown-token funnel"]
pub struct ManagedTaskRegistration {
    start: Option<TaskStart>,
    make: Option<TaskFactory>,
    status: TaskStatus,
}

impl ManagedTaskRegistration {
    /// Borrow the same-source read-only status without exposing task ownership.
    pub fn status(&self) -> TaskStatus {
        self.status.clone()
    }

    pub(crate) fn bind(mut self, token: CancellationToken) -> RegisteredManagedTask {
        let start = self
            .start
            .take()
            .unwrap_or_else(|| unreachable!("registration binds exactly once"));
        let make = self
            .make
            .take()
            .unwrap_or_else(|| unreachable!("registration factory binds exactly once"));
        RegisteredManagedTask(start.spawn(token, make))
    }
}

pub(crate) struct RegisteredManagedTask(ManagedTask);

impl ManagedResource for RegisteredManagedTask {
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

#[cfg(test)]
mod smoke {
    //! build smoke：证明 ManagedResource 可 native AFIT impl + 经 `Box<DynManagedResource>`
    //! 动态注入 + move 进 `tokio::spawn`（ShutdownStack panic 隔离的真实形态：Box 仅需 Send，无需 Sync）。
    use super::{
        DEFAULT_SHUTDOWN_TIMEOUT, DynManagedResource, ManagedResource, ManagedTask, OwnedTask,
        ShutdownError, ShutdownErrorKind, TaskExit, TaskState,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    struct DropMarker(Arc<AtomicBool>);
    impl Drop for DropMarker {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn shutdown_error_wraps_source() {
        let err = ShutdownError::new(std::io::Error::other("leak-marker-shut"));
        assert_eq!(err.to_string(), "resource shutdown failed");
        assert!(std::error::Error::source(&err).is_some());
        // 端到端：derive(Debug) 经 RedactedSource 脱敏、不展开内层 source（anti-vacuity 前置）。
        assert!(
            format!("{:?}", std::io::Error::other("leak-marker-shut")).contains("leak-marker-shut"),
            "前提失效：内层 Debug 未携 marker"
        );
        assert!(
            !format!("{err:?}").contains("leak-marker-shut"),
            "wrapper Debug 泄漏 source: {err:?}"
        );
    }

    #[tokio::test]
    async fn owned_task_drop_aborts_instead_of_detaching() {
        let dropped = Arc::new(AtomicBool::new(false));
        let started = Arc::new(tokio::sync::Notify::new());
        let task = OwnedTask::new(tokio::spawn({
            let dropped = Arc::clone(&dropped);
            let started = Arc::clone(&started);
            async move {
                let _marker = DropMarker(dropped);
                started.notify_one();
                std::future::pending::<()>().await;
            }
        }));
        started.notified().await;

        drop(task);
        tokio::task::yield_now().await;

        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: successful join is the test assertion.
    async fn managed_task_publishes_pending_running_and_expected_cancellation() {
        let (start, status) = ManagedTask::prepare("managed-task-cancel", Duration::from_secs(2));
        assert_eq!(status.current(), TaskState::Pending);
        let token = tokio_util::sync::CancellationToken::new();
        let task = start.spawn(token, |worker_token| async move {
            worker_token.cancelled().await;
            Ok(())
        });
        assert_eq!(status.current(), TaskState::Running);

        task.shutdown()
            .await
            .expect("managed cancellation must join");
        assert_eq!(status.current(), TaskState::Stopped(TaskExit::Cancelled));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: successful join is the test assertion.
    async fn managed_task_unexpected_completion_is_terminal_and_sticky() {
        let (start, status) = ManagedTask::prepare("managed-task-complete", Duration::from_secs(2));
        let task = start.spawn(tokio_util::sync::CancellationToken::new(), |_| async {
            Ok(())
        });
        assert_eq!(status.wait_stopped().await, TaskExit::Completed);
        assert_eq!(status.current(), TaskState::Stopped(TaskExit::Completed));

        task.shutdown().await.expect("completed task must join");
        assert_eq!(status.current(), TaskState::Stopped(TaskExit::Completed));
    }

    #[test]
    fn dropping_unspawned_task_start_closes_pending_status() {
        let (start, status) =
            ManagedTask::prepare("managed-task-unspawned", Duration::from_secs(2));
        assert_eq!(status.current(), TaskState::Pending);
        drop(start);
        assert_eq!(
            status.current(),
            TaskState::Stopped(TaskExit::Failed(ShutdownErrorKind::TaskCancelled))
        );
    }

    #[tokio::test]
    async fn dropping_managed_task_aborts_and_closes_status() {
        let started = Arc::new(tokio::sync::Notify::new());
        let (start, status) =
            ManagedTask::prepare("managed-task-owner-drop", Duration::from_secs(2));
        let task = start.spawn(tokio_util::sync::CancellationToken::new(), |_| {
            let started = Arc::clone(&started);
            async move {
                started.notify_one();
                std::future::pending::<()>().await;
                #[allow(unreachable_code)]
                Ok(())
            }
        });
        started.notified().await;
        drop(task);
        assert_eq!(
            status.wait_stopped().await,
            TaskExit::Failed(ShutdownErrorKind::TaskCancelled)
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: the expected typed error is the test assertion.
    async fn managed_task_typed_error_is_closed_sticky_and_redacted() {
        let (start, status) = ManagedTask::prepare("managed-task-error", Duration::from_secs(2));
        let task = start.spawn(tokio_util::sync::CancellationToken::new(), |_| async {
            Err(ShutdownError::new(std::io::Error::other(
                "managed-task-provider-secret",
            )))
        });
        assert_eq!(
            status.wait_stopped().await,
            TaskExit::Failed(ShutdownErrorKind::Operation)
        );
        let error = task
            .shutdown()
            .await
            .expect_err("typed task error must propagate");
        assert_eq!(error.kind(), ShutdownErrorKind::Operation);
        assert!(!format!("{error:?}").contains("managed-task-provider-secret"));
        assert_eq!(
            status.current(),
            TaskState::Stopped(TaskExit::Failed(ShutdownErrorKind::Operation))
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: successful planned-stop join is the test assertion.
    async fn cancellation_observed_before_completion_classifies_planned_stop() {
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let token = tokio_util::sync::CancellationToken::new();
        let (start, status) =
            ManagedTask::prepare("managed-task-cancel-race", Duration::from_secs(2));
        let task = start.spawn(token.clone(), |_| {
            let barrier = Arc::clone(&barrier);
            async move {
                barrier.wait().await;
                Ok(())
            }
        });
        token.cancel();
        barrier.wait().await;
        assert_eq!(status.wait_stopped().await, TaskExit::Cancelled);
        task.shutdown().await.expect("planned stop must join");
        assert_eq!(status.current(), TaskState::Stopped(TaskExit::Cancelled));
    }

    #[tokio::test]
    #[allow(clippy::expect_used, clippy::panic)]
    // reason: panic isolation and its closed error are the behavior under test.
    async fn managed_task_panic_is_closed_and_redacted() {
        let (start, status) = ManagedTask::prepare("managed-task-panic", Duration::from_secs(2));
        let task = start.spawn(tokio_util::sync::CancellationToken::new(), |_| async {
            panic!("managed-task-panic-secret")
        });
        assert_eq!(
            status.wait_stopped().await,
            TaskExit::Failed(ShutdownErrorKind::TaskPanicked)
        );
        let error = task.shutdown().await.expect_err("panic must fail shutdown");
        assert_eq!(error.kind(), ShutdownErrorKind::TaskPanicked);
        assert!(!format!("{error:?}").contains("managed-task-panic-secret"));
    }

    #[tokio::test]
    #[allow(clippy::expect_used, clippy::panic)]
    // reason: synchronous factory panic isolation is the behavior under test.
    async fn managed_task_factory_panic_is_closed_and_sticky() {
        let (start, status) =
            ManagedTask::prepare("managed-task-factory-panic", Duration::from_secs(2));
        let task = start.spawn(tokio_util::sync::CancellationToken::new(), |_| {
            panic!("managed-task-factory-panic-secret");
            #[allow(unreachable_code)]
            async {
                Ok(())
            }
        });

        assert_eq!(
            status.wait_stopped().await,
            TaskExit::Failed(ShutdownErrorKind::TaskPanicked)
        );
        let error = task
            .shutdown()
            .await
            .expect_err("factory panic must fail shutdown");
        assert_eq!(error.kind(), ShutdownErrorKind::TaskPanicked);
        assert!(!format!("{error:?}").contains("managed-task-factory-panic-secret"));
    }

    #[tokio::test]
    async fn cancelled_shutdown_future_aborts_task_and_closes_status() {
        let dropped = Arc::new(AtomicBool::new(false));
        let started = Arc::new(tokio::sync::Notify::new());
        let (start, status) = ManagedTask::prepare("managed-task-abort", Duration::from_secs(2));
        let task = start.spawn(tokio_util::sync::CancellationToken::new(), |_| {
            let dropped = Arc::clone(&dropped);
            let started = Arc::clone(&started);
            async move {
                let _marker = DropMarker(dropped);
                started.notify_one();
                std::future::pending::<()>().await;
                #[allow(unreachable_code)]
                Ok(())
            }
        });
        started.notified().await;

        let mut shutdown = Box::pin(task.shutdown());
        assert!(futures::poll!(&mut shutdown).is_pending());
        drop(shutdown);
        tokio::task::yield_now().await;

        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(
            status.wait_stopped().await,
            TaskExit::Failed(ShutdownErrorKind::TaskCancelled)
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used, clippy::panic)]
    // reason: join error variants and panic isolation are the test assertions.
    async fn shutdown_error_classifies_join_failures_without_exposing_payloads() {
        const MARKER: &str = "worker-join-plain-panic-secret";
        let panic_join = tokio::spawn(async { panic!("{MARKER}") })
            .await
            .expect_err("task must panic");
        assert!(panic_join.is_panic(), "anti-vacuity");
        assert!(panic_join.to_string().contains(MARKER), "anti-vacuity");
        let panic_error = ShutdownError::from_join_error(panic_join);
        assert_eq!(panic_error.kind(), ShutdownErrorKind::TaskPanicked);
        assert!(!panic_error.to_string().contains(MARKER));
        assert!(!format!("{panic_error:?}").contains(MARKER));

        let cancelled_handle = tokio::spawn(std::future::pending::<()>());
        cancelled_handle.abort();
        let cancelled_join = cancelled_handle.await.expect_err("task must be cancelled");
        assert!(cancelled_join.is_cancelled(), "anti-vacuity");
        let cancelled_error = ShutdownError::from_join_error(cancelled_join);
        assert_eq!(cancelled_error.kind(), ShutdownErrorKind::TaskCancelled);

        let deadline_error =
            ShutdownError::deadline_exceeded(std::io::Error::other("deadline-provider-secret"));
        assert_eq!(deadline_error.kind(), ShutdownErrorKind::DeadlineExceeded);
        assert!(!format!("{deadline_error:?}").contains("deadline-provider-secret"));
    }

    struct NoopResource;
    impl ManagedResource for NoopResource {
        fn name(&self) -> &str {
            "noop"
        }
        async fn shutdown(&self) -> Result<(), ShutdownError> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn managed_resource_box_move_into_spawn() {
        let resource: Box<DynManagedResource<'static>> = DynManagedResource::new_box(NoopResource);
        // name / shutdown_timeout 在 spawn 前读（&self），与 shutdown driver 一致。
        assert_eq!(resource.name(), "noop");
        assert_eq!(resource.shutdown_timeout(), DEFAULT_SHUTDOWN_TIMEOUT);
        let handle = tokio::spawn(async move { resource.shutdown().await });
        assert!(handle.await.is_ok());
    }
}
