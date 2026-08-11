//! `ManagedResource` —— 进程关闭时按依赖逆序 await 关干净的生命周期 seam。
//!
//! 关闭编排（[`ShutdownStack`] + 两阶段 LIFO 驱动器）归属 `bootstrap`（ADR-001）；本 crate 仅持
//! **lifecycle trait 单源**——adapter resource、服务 worker 与 runtime wrapper 均可 `impl ManagedResource`，
//! 经组合根注入 `bootstrap` 的 `ShutdownStack`。它与 provider port 同置于 diport 以复用 dynosaur 派发，
//! 但不受 provider impl-site allowlist 限制。迁入 diport 因 ADR-003 把跨 crate async trait 统一 dynosaur 派发
//! （原 ADR-001 用 `#[async_trait]` + `Arc<dyn>`，inter-ADR 冲突在 PR-diport 收敛，见 ADR-001/ADR-003 回链）。
//!
//! [`ShutdownStack`]: 见 `bootstrap` crate。

use std::time::Duration;

use dynosaur::dynosaur;

use crate::redacted::RedactedSource;

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
pub struct OwnedTask<T> {
    handle: Option<tokio::task::JoinHandle<T>>,
}

impl<T> OwnedTask<T> {
    /// Adopt a spawned task at its lifecycle ownership boundary.
    pub const fn new(handle: tokio::task::JoinHandle<T>) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    /// Abort the owned task without exposing its raw handle.
    pub fn abort(&self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }

    /// Await task completion. Cancellation of this future aborts the still-owned task via `Drop`.
    pub async fn join(mut self) -> Result<T, tokio::task::JoinError> {
        let result = match self.handle.as_mut() {
            Some(handle) => handle.await,
            None => unreachable!("OwnedTask handle is present until join completes"),
        };
        self.handle.take();
        result
    }
}

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
/// Rust 无 async `Drop`——关闭顺序与等待由 `bootstrap::ShutdownStack` 显式驱动，而非 RAII `Drop`。
/// 公开 [`ManagedResource`] 是 **Send 变体**（adapter resource / service worker / runtime wrapper 均可实现）；
/// [`DynManagedResource`] 是其 dyn-compatible wrapper——`ShutdownStack` 以
/// `Box<DynManagedResource<'static>>` 持有并 `tokio::spawn` 隔离 panic（boxed future 须 Send，
/// 故走 Send 变体）。非 Send 基 trait `ManagedResourceLocal` 不在 crate 根 re-export。
///
/// # 实现者须知（消费侧契约）
///
/// - **取消信号经构造器注入**：资源的后台 task 用的 `CancellationToken` 经
///   `ShutdownStack::register_with_token` 的闭包参数注入（RSS 必填依赖走构造器位置参），
///   不在 `shutdown` 参数里传；无后台 task 的资源经 `ShutdownStack::register_detached` 注册。
/// - **不要在 `shutdown` 内部自设超时**：per-resource 超时由驱动器外层 `tokio::time::timeout`
///   包裹（[`shutdown_timeout`](ManagedResource::shutdown_timeout)）；内部再设超时是双重计时。
/// - **幂等性免费**：驱动器消费 stack 单次驱动，`shutdown` 不会被重复调用，无需自保幂等。
/// - **后台 Tokio task 必须由 [`OwnedTask`] 持有**：裸 `JoinHandle` 在 shutdown future 被外层
///   deadline 取消时会 detach。实现可用 `Mutex<Option<OwnedTask<T>>>` 包装并在 shutdown 中
///   `take()` + [`OwnedTask::join`]；future 被取消时 guard 的 `Drop` 会 abort task。
/// - **其它需要 `&mut` 的内部状态**：因 `shutdown(&self)`，用 `Mutex<Option<Inner>>` 或
///   `tokio::sync::Mutex` 包装，在 `shutdown` 中 `take()`。
#[trait_variant::make(ManagedResource: Send)]
#[dynosaur(pub DynManagedResource = dyn(box) ManagedResource, bridge(dyn))]
#[allow(async_fn_in_trait)]
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
/// `Error::source()` 恒 `None`——原始错误不经任何 `Error` 接口暴露，fail-closed）。`secure::redact_error`
/// funnel 取顶层 Display、不遍历 source 链；`bootstrap::ShutdownStack` 业务错误分支已采纳 `redact_error`
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
    /// Panic payloads and task diagnostics remain confined to [`RedactedSource`]; callers can only
    /// observe the closed [`ShutdownErrorKind`].
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

#[cfg(test)]
mod smoke {
    //! build smoke：证明 ManagedResource 可 native AFIT impl + 经 `Box<DynManagedResource>`
    //! 动态注入 + move 进 `tokio::spawn`（ShutdownStack panic 隔离的真实形态：Box 仅需 Send，无需 Sync）。
    use super::{
        DEFAULT_SHUTDOWN_TIMEOUT, DynManagedResource, ManagedResource, OwnedTask, ShutdownError,
        ShutdownErrorKind,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

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
        struct DropMarker(Arc<AtomicBool>);
        impl Drop for DropMarker {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

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
    #[allow(clippy::expect_used, clippy::panic)]
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
        // name / shutdown_timeout 在 spawn 前读（&self），与 bootstrap::shutdown_one 一致。
        assert_eq!(resource.name(), "noop");
        assert_eq!(resource.shutdown_timeout(), DEFAULT_SHUTDOWN_TIMEOUT);
        let handle = tokio::spawn(async move { resource.shutdown().await });
        assert!(handle.await.is_ok());
    }
}
