//! Bounded reverse-order shutdown orchestration.
//!
//! Rust 的 [`Drop`] 是同步的，不能 `.await`——所以进程关闭时「按依赖逆序 await 每个资源
//! 关干净」不能只靠 RAII `Drop`。本模块由 [`ShutdownStack`] 独占取消 root、注册栈和有界
//! drain；显式 shutdown、owner drop 与 waiter cancellation 都汇合到同一个后台 drain。
//!
//! 两阶段关闭模型（对标 tokio + uber-go/fx）：
//!
//! 1. **广播（并发、无序）**：[`ShutdownStack::shutdown`] 先 `cancel` 内部 root
//!    [`CancellationToken`]，所有普通注册的后台 task 同时感知「该停了」，开始自行退出。
//! 2. **逆序确认（串行、有序）**：按注册逆序（LIFO）逐个 await 每个资源的
//!    [`ManagedResource::shutdown`]，确认其真正释放干净，再关下一个（被依赖的）资源。必须等前序
//!    LIFO 资源完成才停止 admission 的后台 task 经
//!    deferred 注册，其 token 在到达自身相位时才取消。
//!
//! 单 cancel 广播不保证资源释放顺序（outbox relay 可能晚于它依赖的 DB pool 关闭）；
//! 单 LIFO await 又无法让后台 task 提前退出。两者配合才安全。
//!
//! 不变式：
//!
//! - `INVARIANT: SHUTDOWN-LIFO-ORDER-01` { level = "Medium", exec = "manual/opt-in", source = "code" }—— 关闭顺序 = 注册顺序的逆序（后注册的先关）。
//! - `INVARIANT: SHUTDOWN-CONTINUE-ON-ERROR-01` { level = "Medium", exec = "manual/opt-in", source = "code" }—— 任一资源失败/超时/panic 必须**继续**关后续，
//!   禁止 fail-fast（否则被依赖资源泄漏）。
//! - `INVARIANT: SHUTDOWN-ERROR-AGGREGATE-01` { level = "Medium", exec = "manual/opt-in", source = "code" }—— 所有 per-resource 失败聚合返回，不丢弃。
//! - `INVARIANT: SHUTDOWN-TIMEOUT-BOUNDED-01` { level = "Medium", exec = "manual/opt-in", source = "code" }—— 每个资源关闭有 per-resource 超时上界。
//! - `INVARIANT: SHUTDOWN-PANIC-ISOLATE-01` { level = "Medium", exec = "manual/opt-in", source = "code" }—— 下游资源 panic 被隔离，不击穿驱动循环。
//! - `INVARIANT: SHUTDOWN-SINGLE-SHOT-01` { level = "Medium", exec = "manual/opt-in", source = "code" }—— `shutdown(self)` 消费 self，double-shutdown /
//!   关闭后注册在类型层不可表达（编译期，Hard）。
//! - `INVARIANT: SHUTDOWN-TOKEN-FUNNEL-01` { level = "Medium", exec = "manual/opt-in", source = "code" }—— canonical managed task 先形成不含 token 的
//!   [`crate::ManagedTaskRegistration`]，再由 transaction 绑定 stack 铸造的 token；普通 adapter
//!   resource 的 closure 仍是实现者契约。无公开 root/child accessor。
//! - `INVARIANT: SHUTDOWN-BUDGET-CANCEL-SAFE-01` { level = "Medium", exec = "test", source = "code" }—— 整体 shutdown 预算由驱动器内部承担；等待者取消不取消已提交的 drain。异步 drain 要求创建 stack 的 Tokio runtime 在总预算期间继续被驱动；owner drop 始终同步广播取消，但 runtime 已停止时不能承诺异步 flush。

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::{
    DEFAULT_SHUTDOWN_TIMEOUT, DynManagedResource, ManagedResource, ManagedTaskRegistration,
    ShutdownError, ShutdownErrorKind, TaskStatus,
};
use tokio::runtime::Handle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

/// 单个资源关闭失败的原因。
#[derive(Debug, thiserror::Error)]
pub enum ShutdownFailureKind {
    /// [`ManagedResource::shutdown`] 返回了 `Err`（typed [`ShutdownError`]，安全摘要 Display）。
    #[error("returned error: {0}")]
    Failed(#[source] ShutdownError),
    /// 关闭超过 per-resource 超时上界，被驱动器跳过（hung task 已 abort）。
    #[error("timed out after {0:?}")]
    TimedOut(Duration),
    /// 关闭过程 panic（下游 adapter），被驱动器隔离。
    #[error("panicked during shutdown")]
    Panicked,
    /// 资源持有的后台 task 在关闭期间被取消。
    #[error("background task cancelled during shutdown")]
    Cancelled,
    /// 资源持有的后台 task 以未知方式异常终止。
    #[error("background task terminated unexpectedly during shutdown")]
    TaskUnknown,
    /// 嵌套 lifecycle 的显式关闭 deadline 耗尽。
    #[error("nested shutdown deadline exceeded")]
    DeadlineExceeded,
    /// 整体 shutdown 预算耗尽，本资源未及关闭被跳过
    /// （cancel-safe：驱动器不再 await；在飞资源的 task 已 `abort`，剩余资源从未启动）。
    #[error("skipped: overall shutdown budget exhausted")]
    BudgetExhausted,
}

/// 关闭某个具名资源时发生的失败。驱动器把每个失败的资源包成一条，聚合返回。
#[derive(Debug, thiserror::Error)]
#[error("resource `{name}` shutdown {kind}")]
pub struct ResourceShutdownError {
    /// 失败资源的 [`ManagedResource::name`]。
    pub name: String,
    /// 失败原因。
    #[source]
    pub kind: ShutdownFailureKind,
}

/// Failure while validating the mandatory total drain budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TotalDrainBudgetError {
    /// Every shutdown sequence must have a positive total bound.
    #[error("total drain budget must be non-zero")]
    Zero,
}

/// Positive total bound shared by the complete LIFO drain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TotalDrainBudget(Duration);

impl TotalDrainBudget {
    /// Validate a total shutdown deadline.
    pub const fn new(value: Duration) -> Result<Self, TotalDrainBudgetError> {
        if value.is_zero() {
            Err(TotalDrainBudgetError::Zero)
        } else {
            Ok(Self(value))
        }
    }

    /// Return the exact total shutdown deadline.
    pub const fn duration(self) -> Duration {
        self.0
    }
}

/// Whether the driver visited the whole stack before its total deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainCompletion {
    /// Every registered resource reached a terminal shutdown observation.
    Complete,
    /// The shared total deadline expired; remaining resource state is unknown.
    BudgetExhausted,
}

/// Typed in-process observation of one bounded shutdown sequence.
#[derive(Debug)]
pub struct ShutdownReceipt {
    registered_resources: usize,
    completion: DrainCompletion,
    failures: Vec<ResourceShutdownError>,
}

impl ShutdownReceipt {
    /// Number of resources owned when the drain began.
    pub const fn registered_resources(&self) -> usize {
        self.registered_resources
    }

    /// Whether the driver visited the whole stack before the total deadline.
    pub const fn completion(&self) -> DrainCompletion {
        self.completion
    }

    /// Failures in exact LIFO observation order.
    pub fn failures(&self) -> &[ResourceShutdownError] {
        &self.failures
    }

    /// Consume the receipt and return its ordered failures.
    pub fn into_failures(self) -> Vec<ResourceShutdownError> {
        self.failures
    }

    /// True only when the full stack drained without any observed failure.
    pub fn is_clean(&self) -> bool {
        self.completion == DrainCompletion::Complete && self.failures.is_empty()
    }
}

/// A stack can only be created while a Tokio runtime is active.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ShutdownStackError {
    /// No current Tokio runtime can own the cancellation-safe background drain.
    #[error("shutdown stack requires an active Tokio runtime")]
    RuntimeUnavailable,
    /// The originating runtime stopped before the asynchronous drain produced a receipt.
    #[error("shutdown driver stopped before producing a receipt")]
    DriverUnavailable,
}

/// Invalid attempt to reopen the one-way registration lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("runtime registration phase is no longer open")]
pub struct RegistrationPhaseError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegistrationPhase {
    Open,
    Startup,
    Launch,
    Sealed,
}

/// 关闭注册栈 + 两阶段逆序驱动器。
///
/// 注册顺序即依赖顺序：**后注册的资源依赖先注册的资源**。关闭时按注册逆序（LIFO）
/// await 每个资源关干净，保证被依赖项（先注册）在依赖它的资源（后注册）之后关闭。
///
/// `shutdown` 消费 `self`——double-shutdown 与「关闭后再注册」在类型层不可表达
/// （`INVARIANT: SHUTDOWN-SINGLE-SHOT-01`， { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }编译期 Hard，强于运行期状态机 guard）。
pub struct ShutdownStack {
    runtime: Handle,
    total_budget: TotalDrainBudget,
    root_token: Option<CancellationToken>,
    resources: Option<Vec<Box<DynManagedResource<'static>>>>,
    registration_phase: RegistrationPhase,
}

/// 到达自身 LIFO 相位才取消后台 task 的资源包装。
///
/// 类型由 [`ShutdownStack::register_deferred_with_token`] 私有铸造，调用方不能提供外部 token 或
/// 自行构造另一种 deferred wrapper。wrapper 在委托 inner shutdown 前同步取消 token，因而后台
/// task 可开始退出并由 inner 在同一 per-resource budget 内 join。
struct DeferredCancellationResource {
    name: String,
    shutdown_timeout: Duration,
    token: CancelOnDrop,
    inner: tokio::sync::Mutex<Option<Box<DynManagedResource<'static>>>>,
}

/// deferred token 的 fail-safe owner：无论正常进入 wrapper shutdown、整体预算在此前耗尽，还是
/// stack owner 被取消并 drop，最后一个 wrapper owner 被释放时都主动 cancel，而非依赖 token drop。
struct CancelOnDrop(CancellationToken);

impl CancelOnDrop {
    fn cancel(&self) {
        self.0.cancel();
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

impl ManagedResource for DeferredCancellationResource {
    fn name(&self) -> &str {
        &self.name
    }

    fn shutdown_timeout(&self) -> Duration {
        self.shutdown_timeout
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.token.cancel();
        match self.inner.lock().await.take() {
            Some(inner) => inner.shutdown().await,
            None => Ok(()),
        }
    }
}

impl ShutdownStack {
    /// Construct the sole lifecycle owner inside the active Tokio runtime.
    pub fn try_new(total_budget: TotalDrainBudget) -> Result<Self, ShutdownStackError> {
        let runtime = Handle::try_current().map_err(|_| ShutdownStackError::RuntimeUnavailable)?;
        Ok(Self::with_parts(
            runtime,
            total_budget,
            CancellationToken::new(),
        ))
    }

    fn with_parts(
        runtime: Handle,
        total_budget: TotalDrainBudget,
        root_token: CancellationToken,
    ) -> Self {
        Self {
            runtime,
            total_budget,
            root_token: Some(root_token),
            resources: Some(Vec::new()),
            registration_phase: RegistrationPhase::Open,
        }
    }

    #[cfg(test)]
    fn new(root_token: CancellationToken) -> Self {
        Self::with_parts(
            Handle::current(),
            TotalDrainBudget(Duration::from_secs(60)),
            root_token,
        )
    }

    fn root_token(&self) -> &CancellationToken {
        self.root_token
            .as_ref()
            .unwrap_or_else(|| unreachable!("root token is present until drain starts"))
    }

    fn resources(&self) -> &Vec<Box<DynManagedResource<'static>>> {
        self.resources
            .as_ref()
            .unwrap_or_else(|| unreachable!("resources are present until drain starts"))
    }

    fn resources_mut(&mut self) -> &mut Vec<Box<DynManagedResource<'static>>> {
        self.resources
            .as_mut()
            .unwrap_or_else(|| unreachable!("resources are present until drain starts"))
    }

    /// 注册一个**有后台 task**的托管资源，并为其后台 task 发放本 stack 派生的 child
    /// [`CancellationToken`]——token 在闭包内经资源构造器注入（RSS 必填依赖走构造器位置参）。
    ///
    /// 这是取消 token 的**唯一**发放入口（无 `pub child_token`）：「该资源后台 task 监听本
    /// stack 关闭广播」由注册 funnel 强制——无法注册一个绑定外部 / 无来源 token 的有 task
    /// 资源（`INVARIANT: SHUTDOWN-TOKEN-FUNNEL-01` { level = "Medium", exec = "manual/opt-in", source = "code" }）。注册顺序 = 依赖顺序（先注册 = 先启动 =
    /// 最后关闭）。
    ///
    /// token 在 `shutdown` 之前派生：`shutdown` 会 `cancel` root token；注册后关闭时资源 task
    /// 即感知广播。
    pub(crate) fn register_with_token<F>(&mut self, make: F)
    where
        F: FnOnce(CancellationToken) -> Box<DynManagedResource<'static>>,
    {
        let token = self.root_token().child_token();
        self.resources_mut().push(make(token));
    }

    /// Register the canonical owner for one Tokio background task and return its same-source
    /// read-only status receipt.
    ///
    /// The closure cannot return an arbitrary managed resource: the opaque registration proves
    /// that the task owner, lifecycle token, shutdown join, and status publisher were minted by
    /// one [`crate::ManagedTask`].
    pub(crate) fn register_managed_task_with_token(
        &mut self,
        registration: ManagedTaskRegistration,
    ) -> TaskStatus {
        let token = self.root_token().child_token();
        let status = registration.status();
        let task = registration.bind(token);
        self.resources_mut().push(DynManagedResource::new_box(task));
        status
    }

    pub(crate) fn try_register_blocking_worker_with_token(
        &mut self,
        registration: crate::ManagedBlockingWorkerRegistration,
    ) -> Result<TaskStatus, crate::ManagedBlockingWorkerStartError> {
        let worker = registration.bind(self.root_token().child_token())?;
        let status = worker.status();
        self.resources_mut()
            .push(crate::blocking::registered_blocking_worker(worker));
        Ok(status)
    }

    /// Register a canonical managed task whose cancellation begins only at its own LIFO phase.
    pub(crate) fn register_deferred_managed_task_with_token(
        &mut self,
        registration: ManagedTaskRegistration,
    ) -> TaskStatus {
        let token = CancellationToken::new();
        let status = registration.status();
        let task = registration.bind(token.clone());
        let name = task.name().to_owned();
        let shutdown_timeout = task.shutdown_timeout();
        let resource = DynManagedResource::new_box(task);
        self.resources_mut()
            .push(DynManagedResource::new_box(DeferredCancellationResource {
                name,
                shutdown_timeout,
                token: CancelOnDrop(token),
                inner: tokio::sync::Mutex::new(Some(resource)),
            }));
        status
    }

    pub(crate) fn try_register_deferred_blocking_worker_with_token(
        &mut self,
        registration: crate::ManagedBlockingWorkerRegistration,
    ) -> Result<TaskStatus, crate::ManagedBlockingWorkerStartError> {
        let token = CancellationToken::new();
        let worker = registration.bind(token.clone())?;
        let status = worker.status();
        let name = worker.name().to_owned();
        let shutdown_timeout = worker.shutdown_timeout();
        let resource = crate::blocking::registered_blocking_worker(worker);
        self.resources_mut()
            .push(DynManagedResource::new_box(DeferredCancellationResource {
                name,
                shutdown_timeout,
                token: CancelOnDrop(token),
                inner: tokio::sync::Mutex::new(Some(resource)),
            }));
        Ok(status)
    }

    /// 注册一个必须等到其**自身 LIFO 关闭相位**才取消的后台 task。
    ///
    /// 与 [`register_with_token`](Self::register_with_token) 的 root 广播语义不同，本入口铸造
    /// stack-owned 独立 token，并用私有 managed-resource wrapper 在该资源真正开始 shutdown 时
    /// 先 cancel、再 await inner shutdown。适用于 listener 已停止接入后才可停止 admission、并需要
    /// 在依赖仍存活时完成当前事务和 join 的 module worker。
    ///
    /// closure 仍是唯一 token 获取点；调用方无法自行提供 token，也无需构造 wrapper 或降级走
    /// [`register_detached`](Self::register_detached)。注册顺序与其它资源共用同一个 LIFO 栈。
    pub(crate) fn register_deferred_with_token<F>(&mut self, make: F)
    where
        F: FnOnce(CancellationToken) -> Box<DynManagedResource<'static>>,
    {
        let token = CancellationToken::new();
        let inner = make(token.clone());
        let name = inner.name().to_owned();
        let shutdown_timeout = inner.shutdown_timeout();
        self.resources_mut()
            .push(DynManagedResource::new_box(DeferredCancellationResource {
                name,
                shutdown_timeout,
                token: CancelOnDrop(token),
                inner: tokio::sync::Mutex::new(Some(inner)),
            }));
    }

    /// 注册一个**无后台 task、不监听关闭广播**的资源（如纯同步 flush 的 buffer，关闭即 drain）。
    ///
    /// 显式 no-token 入口：声明「该资源有意不接关闭广播」，而非忘记接线。与
    /// 两个 token 入口与本入口覆盖全部注册路径，杜绝有后台 task 的资源静默绕过取消 funnel
    /// （`INVARIANT: SHUTDOWN-TOKEN-FUNNEL-01` { level = "Medium", exec = "manual/opt-in", source = "code" }）。注册顺序语义同上。
    pub(crate) fn register_detached(&mut self, resource: Box<DynManagedResource<'static>>) {
        self.resources_mut().push(resource);
    }

    /// 已注册资源数。
    pub fn len(&self) -> usize {
        self.resources().len()
    }

    /// 是否无已注册资源。
    pub fn is_empty(&self) -> bool {
        self.resources().is_empty()
    }

    /// 按注册顺序遍历已注册资源名，供组合根在关闭前记录注册清单。
    pub fn registered_names(&self) -> impl Iterator<Item = &str> {
        self.resources().iter().map(|r| r.name())
    }

    /// Begin the only startup registration phase.
    pub fn startup(&mut self) -> Result<crate::StartupTransaction<'_>, RegistrationPhaseError> {
        if self.registration_phase != RegistrationPhase::Open {
            return Err(RegistrationPhaseError);
        }
        self.registration_phase = RegistrationPhase::Startup;
        Ok(crate::StartupTransaction::new(self))
    }

    pub(crate) fn enter_launch(&mut self) {
        debug_assert_eq!(self.registration_phase, RegistrationPhase::Startup);
        self.registration_phase = RegistrationPhase::Launch;
    }

    pub(crate) fn seal_registration(&mut self) {
        debug_assert_eq!(self.registration_phase, RegistrationPhase::Launch);
        self.registration_phase = RegistrationPhase::Sealed;
    }

    /// Consume this owner and await its mandatory bounded drain.
    ///
    /// The inner task accepts the resources before the first await. Cancelling this waiter only
    /// drops its join handle; the captured runtime continues the drain while that runtime remains
    /// driven. If the originating runtime stops first, this returns
    /// [`ShutdownStackError::DriverUnavailable`] instead of panicking.
    #[must_use = "the typed shutdown receipt must be observed"]
    pub async fn shutdown(mut self) -> Result<ShutdownReceipt, ShutdownStackError> {
        let drain = self.spawn_owned_drain();
        match drain.await {
            Ok(receipt) => Ok(receipt),
            Err(_) => Err(ShutdownStackError::DriverUnavailable),
        }
    }

    #[cfg(test)]
    async fn shutdown_within(
        mut self,
        total_budget: Duration,
    ) -> Result<ShutdownReceipt, ShutdownStackError> {
        self.total_budget = TotalDrainBudget(total_budget);
        self.shutdown().await
    }

    fn spawn_owned_drain(&mut self) -> tokio::task::JoinHandle<ShutdownReceipt> {
        let root = self
            .root_token
            .take()
            .unwrap_or_else(|| unreachable!("root token transfers exactly once"));
        // Cancellation is synchronous and does not depend on the originating runtime polling the
        // detached drain. Async resource flushing still requires that runtime to remain driven.
        root.cancel();
        let resources = self
            .resources
            .take()
            .unwrap_or_else(|| unreachable!("resources transfer exactly once"));
        let total_budget = self.total_budget.duration();
        self.runtime.spawn(drain_resources(resources, total_budget))
    }
}

impl Drop for ShutdownStack {
    fn drop(&mut self) {
        if self.resources.is_some() {
            let _drain = self.spawn_owned_drain();
        }
    }
}

// reason: broadcast + strict LIFO + two nested deadlines form one lifecycle decision unit.
#[allow(clippy::cognitive_complexity)]
async fn drain_resources(
    resources: Vec<Box<DynManagedResource<'static>>>,
    total_budget: Duration,
) -> ShutdownReceipt {
    let total = resources.len();
    tracing::info!(resource_count = total, "shutdown sequence starting");
    let deadline = tokio::time::sleep(total_budget);
    tokio::pin!(deadline);
    let mut failures = Vec::new();
    let mut completion = DrainCompletion::Complete;
    let mut resources = resources.into_iter().rev();
    while let Some(resource) = resources.next() {
        match shutdown_one(resource, deadline.as_mut()).await {
            ShutdownStep::Exhausted(name) => {
                completion = DrainCompletion::BudgetExhausted;
                drain_budget_exhausted(name, &mut resources, &mut failures);
                break;
            }
            ShutdownStep::Done(failure) => {
                if let Some(failure) = failure {
                    failures.push(failure);
                }
            }
        }
    }
    if failures.is_empty() {
        tracing::info!(total, "shutdown sequence complete");
    } else {
        tracing::error!(
            failed = failures.len(),
            total,
            "shutdown sequence complete with failures"
        );
    }
    ShutdownReceipt {
        registered_resources: total,
        completion,
        failures,
    }
}

/// 整体预算耗尽：把当前及剩余未关资源全部记为 [`ShutdownFailureKind::BudgetExhausted`]
/// （cancel-safe：不 await）。当前在飞资源的 shutdown task 已由 [`shutdown_one`] 在返回
/// [`ShutdownStep::Exhausted`] 前 `abort`；剩余资源从未启动 task，此处仅记录。
fn drain_budget_exhausted<I>(
    current_name: String,
    remaining: &mut I,
    failures: &mut Vec<ResourceShutdownError>,
) where
    I: Iterator<Item = Box<DynManagedResource<'static>>> + ExactSizeIterator,
{
    tracing::error!(
        skipped = remaining.len() + 1,
        "overall shutdown budget exhausted; remaining resources skipped (state unknown)"
    );
    failures.push(budget_exhausted(current_name));
    for r in remaining {
        failures.push(budget_exhausted(safe_resource_name(r.as_ref())));
    }
}

const PANICKED_RESOURCE_NAME: &str = "<resource-metadata-panicked>";

fn safe_resource_name(resource: &DynManagedResource<'static>) -> String {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| resource.name().to_owned()))
        .unwrap_or_else(|_| PANICKED_RESOURCE_NAME.to_owned())
}

fn safe_resource_metadata(
    resource: &DynManagedResource<'static>,
) -> (String, Duration, Option<ResourceShutdownError>) {
    let (name, name_panicked) =
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| resource.name().to_owned()))
        {
            Ok(name) => (name, false),
            Err(_) => (PANICKED_RESOURCE_NAME.to_owned(), true),
        };
    let budget =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| resource.shutdown_timeout()));
    match budget {
        Ok(budget) => {
            let failure = name_panicked.then(|| ResourceShutdownError {
                name: name.clone(),
                kind: ShutdownFailureKind::Panicked,
            });
            (name, budget, failure)
        }
        Err(_) => (
            name.clone(),
            DEFAULT_SHUTDOWN_TIMEOUT,
            Some(ResourceShutdownError {
                name,
                kind: ShutdownFailureKind::Panicked,
            }),
        ),
    }
}

/// 把一个未及关闭的资源名包成 [`ShutdownFailureKind::BudgetExhausted`] 失败。
fn budget_exhausted(name: String) -> ResourceShutdownError {
    ResourceShutdownError {
        name,
        kind: ShutdownFailureKind::BudgetExhausted,
    }
}

fn observe_returned_shutdown_error(source: ShutdownError) -> ShutdownFailureKind {
    match source.kind() {
        ShutdownErrorKind::Operation => observe_operation_error(source),
        ShutdownErrorKind::TaskPanicked => observe_task_panicked(),
        ShutdownErrorKind::TaskCancelled => observe_task_cancelled(),
        ShutdownErrorKind::TaskUnknown => observe_task_unknown(),
        ShutdownErrorKind::DeadlineExceeded => observe_deadline_exceeded(),
    }
}

fn observe_operation_error(source: ShutdownError) -> ShutdownFailureKind {
    tracing::warn!(
        error_kind = ShutdownErrorKind::Operation.as_str(),
        error = %rss_redact::redact_error(&source),
        "resource shutdown returned error"
    );
    ShutdownFailureKind::Failed(source)
}

fn observe_task_panicked() -> ShutdownFailureKind {
    tracing::error!(
        error_kind = ShutdownErrorKind::TaskPanicked.as_str(),
        "resource background task panicked (state unknown)"
    );
    ShutdownFailureKind::Panicked
}

fn observe_task_cancelled() -> ShutdownFailureKind {
    tracing::warn!(
        error_kind = ShutdownErrorKind::TaskCancelled.as_str(),
        "resource background task cancelled unexpectedly"
    );
    ShutdownFailureKind::Cancelled
}

fn observe_task_unknown() -> ShutdownFailureKind {
    tracing::error!(
        error_kind = ShutdownErrorKind::TaskUnknown.as_str(),
        "resource background task terminated unexpectedly (state unknown)"
    );
    ShutdownFailureKind::TaskUnknown
}

fn observe_deadline_exceeded() -> ShutdownFailureKind {
    tracing::error!(
        error_kind = ShutdownErrorKind::DeadlineExceeded.as_str(),
        "nested resource shutdown deadline exceeded"
    );
    ShutdownFailureKind::DeadlineExceeded
}

/// 单资源关闭推进结果（`run` 据此决定继续或熔断）。
enum ShutdownStep {
    /// 整体预算在本资源在飞时耗尽——其 shutdown task 已 `abort` 并 await 析构；当前 + 剩余资源记 BudgetExhausted。
    Exhausted(String),
    /// 资源关闭完成（`None` = 干净）或失败（`Some`，交 `run` 聚合，不中断循环
    /// `INVARIANT: SHUTDOWN-CONTINUE-ON-ERROR-01` { level = "Medium", exec = "manual/opt-in", source = "code" }）。
    Done(Option<ResourceShutdownError>),
}

/// 关闭单个资源：单 `select` 整体预算 vs per-resource（超时 + panic 隔离）+ tracing span。
///
/// `deadline` 是 `run` 持有的**共享**整体预算 future（跨资源复用同一 deadline，cancel-safe）。
/// 预算先判（`biased`）：耗尽则 **abort 并 await 在飞 shutdown owner**（cancel-safe；owner 内的
/// canonical task owner 的 drop guard 同步发出内层 abort，不 detach 等进程退出回收，
/// `INVARIANT: SHUTDOWN-BUDGET-CANCEL-SAFE-01` { level = "Medium", exec = "manual/opt-in", source = "code" }）→ 返回 [`ShutdownStep::Exhausted`]。
async fn shutdown_one<D>(
    resource: Box<DynManagedResource<'static>>,
    deadline: Pin<&mut D>,
) -> ShutdownStep
where
    D: Future<Output = ()>,
{
    let (name, budget, metadata_failure) = safe_resource_metadata(resource.as_ref());
    let span = tracing::info_span!(
        "shutdown.resource",
        resource = %name,
        budget_secs = budget.as_secs()
    );

    async move {
        // panic 隔离：在独立 task 中执行——下游 adapter panic 被 tokio harness 捕获为
        // JoinError，不击穿驱动循环。`Box<DynManagedResource>` 直接 move 进 task（Box: Send，
        // boxed future: Send via trait_variant）——无需 Arc 共享（name/budget 已在前读取）。
        let mut handle = tokio::spawn(async move { resource.shutdown().await });

        // 单 select：整体预算 vs per-resource（timeout 包 task）。biased：先判预算。`&mut handle`
        // 的借用随 select 返回 `resolved` 释放——故后续 match 可再借 handle 做 abort（顺序不重叠）。
        let resolved = tokio::select! {
            biased;
            () = deadline => None,
            out = timeout(budget, &mut handle) => Some(out),
        };

        match resolved {
            // 整体预算耗尽：abort 并 await 在飞 shutdown owner 的析构。
            None => {
                handle.abort();
                let _ = handle.await;
                tracing::error!(
                    "overall shutdown budget exhausted; in-flight resource shutdown aborted"
                );
                ShutdownStep::Exhausted(name)
            }
            // timeout → JoinError → shutdown 三层 Result：超时 / task 异常终止 / 业务错误。
            // 日志级别按 `crates/observ`、`rss_redact::redact_error` 与 typed metric enums：业务 Err 降级（warn）；超时 / panic 资源状态未知（error）。
            Some(out) => {
                let kind = match out {
                    Ok(Ok(Ok(()))) => {
                        tracing::debug!("resource shut down cleanly");
                        return ShutdownStep::Done(metadata_failure);
                    }
                    // 业务错误：资源优雅上报 Err（typed `ShutdownError`，内部 source 经 `RedactedSource` 脱敏）。
                    // 经 `rss_redact::redact_error` 记录——funnel 只取顶层 Display（安全摘要常量、不遍历 source 链，
                    // 杜绝 adapter 原始错误 PII 经日志泄漏）；原始 source 由 `RedactedSource` owned 但 write-only
                    // 保留，不经 `Error::source()` 链暴露（fail-closed，DIPORT-ERR-SOURCE-REDACT-01）。
                    Ok(Ok(Err(source))) => Some(observe_returned_shutdown_error(source)),
                    // INVARIANT: SHUTDOWN-PANIC-ISOLATE-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— 下游 panic 被 spawn 隔离，仅本资源失败。
                    Ok(Err(join_err)) => {
                        // 未超时分支的 JoinError 只可能来自 panic（驱动器从不 abort 未超时 task）；
                        // is_cancelled 理论不可达，仍保守上报、不静默吞。
                        if join_err.is_cancelled() {
                            tracing::warn!("resource shutdown task cancelled unexpectedly");
                        }
                        tracing::error!("resource shutdown panicked (state unknown)");
                        Some(ShutdownFailureKind::Panicked)
                    }
                    // INVARIANT: SHUTDOWN-TIMEOUT-BOUNDED-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— per-resource 超时有界，hung task abort 后继续。
                    Err(_elapsed) => {
                        handle.abort();
                        let _ = handle.await;
                        tracing::error!("resource shutdown timed out (state unknown)");
                        Some(ShutdownFailureKind::TimedOut(budget))
                    }
                };
                ShutdownStep::Done(kind.map(|kind| ResourceShutdownError { name, kind }))
            }
        }
    }
    .instrument(span)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::sync::Notify;

    /// 共享调用序列记录器：每个 mock 资源在 shutdown 时 push 自己的 name，
    /// 用于确定性断言关闭顺序（不靠时序）。
    type Log = Arc<Mutex<Vec<String>>>;

    fn new_log() -> Log {
        Arc::new(Mutex::new(Vec::new()))
    }

    // Mutex 中毒不应影响测试断言：recover guard 而非 unwrap（满足 clippy unwrap_used deny）。
    fn record(log: &Log, name: &str) {
        log.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(name.to_owned());
    }

    fn entries(log: &Log) -> Vec<String> {
        log.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    #[allow(clippy::panic)] // reason: helper turns unexpected driver failure into a test failure.
    fn receipt_of(result: Result<ShutdownReceipt, ShutdownStackError>) -> ShutdownReceipt {
        match result {
            Ok(receipt) => receipt,
            Err(error) => panic!("shutdown driver failed in test: {error}"),
        }
    }

    enum Behavior {
        Ok,
        Err,
        Hang,
        Panic,
        ReportedTaskPanic,
        ReportedTaskCancelled,
        ReportedDeadline,
        AwaitCancel(CancellationToken),
        Gate {
            started: Arc<Notify>,
            release: Arc<Notify>,
        },
    }

    struct MockResource {
        name: String,
        behavior: Behavior,
        log: Log,
    }

    struct DropObservedHangingResource {
        dropped: Arc<AtomicBool>,
    }

    struct MetadataPanicResource {
        name_panics: bool,
        timeout_panics: bool,
        log: Log,
    }

    impl ManagedResource for MetadataPanicResource {
        fn name(&self) -> &str {
            assert!(!self.name_panics, "private name panic payload");
            "metadata-panic"
        }

        fn shutdown_timeout(&self) -> Duration {
            assert!(!self.timeout_panics, "private timeout panic payload");
            Duration::from_secs(1)
        }

        async fn shutdown(&self) -> Result<(), ShutdownError> {
            record(&self.log, "metadata-panic");
            Ok(())
        }
    }

    impl Drop for DropObservedHangingResource {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl ManagedResource for DropObservedHangingResource {
        fn name(&self) -> &str {
            "drop-observed-hang"
        }

        fn shutdown_timeout(&self) -> Duration {
            Duration::from_secs(5)
        }

        async fn shutdown(&self) -> Result<(), ShutdownError> {
            std::future::pending().await
        }
    }

    impl MockResource {
        // 经 dynosaur `DynManagedResource::new_box` 包成 dyn wrapper（native AFIT impl，无 async_trait）。
        // 注：`Arc::clone(log)` 是测试 log 的共享（与 `shutdown_one` 不再 Arc::clone resource 无关——
        // resource 现以 Box move 进 spawn，见 shutdown_one 注释）。
        fn boxed(name: &str, behavior: Behavior, log: &Log) -> Box<DynManagedResource<'static>> {
            DynManagedResource::new_box(Self {
                name: name.to_owned(),
                behavior,
                log: Arc::clone(log),
            })
        }
    }

    impl ManagedResource for MockResource {
        fn name(&self) -> &str {
            &self.name
        }

        fn shutdown_timeout(&self) -> Duration {
            Duration::from_secs(5)
        }

        // reason: Behavior::Panic 刻意 panic，验证驱动器对下游 adapter panic 的隔离；
        // 此 carve-out 仅作用于本 mock item。
        #[allow(clippy::expect_used, clippy::panic)]
        async fn shutdown(&self) -> Result<(), ShutdownError> {
            record(&self.log, &self.name);
            match &self.behavior {
                Behavior::Ok => Ok(()),
                // typed 错误：包一个携带敏感样本的 io::Error 作内部 source，验证 Display 不泄漏。
                Behavior::Err => Err(ShutdownError::new(std::io::Error::other(format!(
                    "boom-{}",
                    self.name
                )))),
                Behavior::Hang => {
                    #[allow(unknown_lints, rss_test_no_bare_sleep)]
                    // reason: paused-clock hang probe
                    {
                        tokio::time::sleep(Duration::MAX).await;
                    }
                    Ok(())
                }
                Behavior::Panic => panic!("mock-panic-{}", self.name),
                Behavior::ReportedTaskPanic => {
                    let join_error = tokio::spawn(async { panic!("reported-task-panic") })
                        .await
                        .expect_err("task must panic");
                    Err(ShutdownError::from_join_error(join_error))
                }
                Behavior::ReportedTaskCancelled => {
                    let handle = tokio::spawn(std::future::pending::<()>());
                    handle.abort();
                    let join_error = handle.await.expect_err("task must be cancelled");
                    Err(ShutdownError::from_join_error(join_error))
                }
                Behavior::ReportedDeadline => Err(ShutdownError::deadline_exceeded(
                    std::io::Error::other("nested deadline marker"),
                )),
                Behavior::AwaitCancel(token) => {
                    token.cancelled().await;
                    Ok(())
                }
                Behavior::Gate { started, release } => {
                    started.notify_one();
                    release.notified().await;
                    Ok(())
                }
            }
        }
    }

    #[tokio::test]
    async fn shutdown_runs_in_reverse_registration_order() {
        let log = new_log();
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_detached(MockResource::boxed("a", Behavior::Ok, &log));
        stack.register_detached(MockResource::boxed("b", Behavior::Ok, &log));
        stack.register_detached(MockResource::boxed("c", Behavior::Ok, &log));

        let receipt = receipt_of(stack.shutdown().await);
        let failures = receipt.failures();

        assert!(failures.is_empty(), "all-ok shutdown reports no failures");
        // LIFO：最后注册的 c 先关，先注册的 a 最后关。
        assert_eq!(entries(&log), vec!["c", "b", "a"]);
    }

    #[tokio::test]
    async fn shutdown_continues_after_error_and_aggregates() {
        let log = new_log();
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_detached(MockResource::boxed("a", Behavior::Ok, &log));
        stack.register_detached(MockResource::boxed("b", Behavior::Err, &log));
        stack.register_detached(MockResource::boxed("c", Behavior::Ok, &log));

        let receipt = receipt_of(stack.shutdown().await);
        let failures = receipt.failures();

        // SHUTDOWN-CONTINUE-ON-ERROR-01：b 失败不中断链，被依赖的 a 仍被关闭。
        assert_eq!(entries(&log), vec!["c", "b", "a"]);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].name, "b");
        assert!(matches!(failures[0].kind, ShutdownFailureKind::Failed(_)));
    }

    #[tokio::test]
    async fn shutdown_preserves_reported_task_failure_kinds_and_continues() {
        let log = new_log();
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_detached(MockResource::boxed("a", Behavior::Ok, &log));
        stack.register_detached(MockResource::boxed(
            "panic",
            Behavior::ReportedTaskPanic,
            &log,
        ));
        stack.register_detached(MockResource::boxed(
            "cancelled",
            Behavior::ReportedTaskCancelled,
            &log,
        ));
        stack.register_detached(MockResource::boxed(
            "deadline",
            Behavior::ReportedDeadline,
            &log,
        ));
        stack.register_detached(MockResource::boxed("c", Behavior::Ok, &log));

        let receipt = receipt_of(stack.shutdown().await);
        let failures = receipt.failures();

        assert_eq!(
            entries(&log),
            vec!["c", "deadline", "cancelled", "panic", "a"]
        );
        assert_eq!(failures.len(), 3);
        assert!(matches!(
            failures[0].kind,
            ShutdownFailureKind::DeadlineExceeded
        ));
        assert!(matches!(failures[1].kind, ShutdownFailureKind::Cancelled));
        assert!(matches!(failures[2].kind, ShutdownFailureKind::Panicked));
    }

    #[tokio::test]
    async fn shutdown_aggregates_all_errors_in_lifo_order() {
        let log = new_log();
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_detached(MockResource::boxed("a", Behavior::Err, &log));
        stack.register_detached(MockResource::boxed("b", Behavior::Err, &log));

        let receipt = receipt_of(stack.shutdown().await);
        let failures = receipt.failures();

        assert_eq!(entries(&log), vec!["b", "a"]);
        assert_eq!(failures.len(), 2);
        assert_eq!(failures[0].name, "b");
        assert_eq!(failures[1].name, "a");
    }

    // PII 边界：typed ShutdownError Display 是安全摘要常量，不泄漏 adapter 原始错误内容。
    // source 链首层是脱敏 newtype（`RedactedSource`，Display 亦 `<redacted>`），且其 source() 恒
    // `None`——原始内容**不经标准 Error 链暴露**（fail-closed）。聚合后的 ResourceShutdownError Display 同样不泄漏。
    #[test]
    fn shutdown_error_display_is_safe_summary_only() {
        let err = ShutdownError::new(std::io::Error::other("secret-conn-string-42"));
        assert_eq!(err.to_string(), "resource shutdown failed");
        let leaked_in_display = err.to_string().contains("secret-conn-string-42");
        assert!(!leaked_in_display, "raw source must not appear in Display");
        // 首层 source 是 RedactedSource：其 Display 已脱敏，不泄漏原始内容（fail-closed）。
        let first_redacted = std::error::Error::source(&err)
            .is_some_and(|s| !s.to_string().contains("secret-conn-string-42"));
        assert!(
            first_redacted,
            "first-level source (RedactedSource) Display must be redacted"
        );
        // fail-closed：source 链在 RedactedSource 处终止（其 source() 恒 None）——通用递归遍历
        // （anyhow `{:?}` / std::error::Report / tracing）永不到达原始 adapter 错误，无 PII 泄漏。
        let chain_dead_ends = std::error::Error::source(&err)
            .and_then(|redacted| redacted.source())
            .is_none();
        assert!(
            chain_dead_ends,
            "raw source must be unreachable: chain must dead-end at RedactedSource (source() == None)"
        );

        let agg = ResourceShutdownError {
            name: "db".to_owned(),
            kind: ShutdownFailureKind::Failed(err),
        };
        assert_eq!(
            agg.to_string(),
            "resource `db` shutdown returned error: resource shutdown failed"
        );
    }

    // start_paused：tokio test-util 虚拟时钟。当所有 task 都在等 timer 时（hang 的
    // sleep(MAX) + shutdown_one 的 5s timeout），运行时自动推进到最近 deadline（5s timeout）
    // 触发超时——零真实耗时、确定性，不靠真实 sleep（防 flaky）。
    #[tokio::test(start_paused = true)]
    async fn shutdown_times_out_hung_resource_and_continues() {
        let log = new_log();
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_detached(MockResource::boxed("a", Behavior::Ok, &log));
        stack.register_detached(MockResource::boxed("hang", Behavior::Hang, &log));
        stack.register_detached(MockResource::boxed("c", Behavior::Ok, &log));

        let receipt = receipt_of(stack.shutdown().await);
        let failures = receipt.failures();

        // hang 超时被跳过，但被依赖的 a 仍被关闭（顺序 c → hang → a）。
        assert_eq!(entries(&log), vec!["c", "hang", "a"]);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].name, "hang");
        assert!(matches!(failures[0].kind, ShutdownFailureKind::TimedOut(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_waits_for_aborted_shutdown_owner_to_drop_before_returning() {
        let dropped = Arc::new(AtomicBool::new(false));
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_detached(DynManagedResource::new_box(DropObservedHangingResource {
            dropped: Arc::clone(&dropped),
        }));

        let receipt = receipt_of(stack.shutdown().await);
        let failures = receipt.failures();

        assert_eq!(failures.len(), 1);
        assert!(
            dropped.load(Ordering::SeqCst),
            "shutdown owner must be dropped before LIFO advances or returns"
        );
    }

    // 混合失败类型同时出现：验证 SHUTDOWN-ERROR-AGGREGATE-01 在异构失败下仍逆序、全聚合、类型不串。
    #[tokio::test(start_paused = true)]
    async fn shutdown_aggregates_mixed_failure_kinds() {
        let log = new_log();
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_detached(MockResource::boxed("err", Behavior::Err, &log)); // 最后关
        stack.register_detached(MockResource::boxed("hang", Behavior::Hang, &log));
        stack.register_detached(MockResource::boxed("boom", Behavior::Panic, &log));
        stack.register_detached(MockResource::boxed("ok", Behavior::Ok, &log)); // 最先关

        let receipt = receipt_of(stack.shutdown().await);
        let failures = receipt.failures();

        // LIFO：ok → boom → hang → err；ok 成功不计入 failures。
        assert_eq!(entries(&log), vec!["ok", "boom", "hang", "err"]);
        assert_eq!(failures.len(), 3);
        assert_eq!(failures[0].name, "boom");
        assert!(matches!(failures[0].kind, ShutdownFailureKind::Panicked));
        assert_eq!(failures[1].name, "hang");
        assert!(matches!(failures[1].kind, ShutdownFailureKind::TimedOut(_)));
        assert_eq!(failures[2].name, "err");
        assert!(matches!(failures[2].kind, ShutdownFailureKind::Failed(_)));
    }

    #[tokio::test]
    async fn shutdown_isolates_panicking_resource() {
        let log = new_log();
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_detached(MockResource::boxed("a", Behavior::Ok, &log));
        stack.register_detached(MockResource::boxed("boom", Behavior::Panic, &log));
        stack.register_detached(MockResource::boxed("c", Behavior::Ok, &log));

        let receipt = receipt_of(stack.shutdown().await);
        let failures = receipt.failures();

        // SHUTDOWN-PANIC-ISOLATE-01：boom panic 被隔离，a/c 不受影响。
        assert_eq!(entries(&log), vec!["c", "boom", "a"]);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].name, "boom");
        assert!(matches!(failures[0].kind, ShutdownFailureKind::Panicked));
    }

    #[tokio::test]
    async fn shutdown_isolates_panicking_resource_metadata_and_continues() {
        let log = new_log();
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_detached(MockResource::boxed("dependency", Behavior::Ok, &log));
        stack.register_detached(DynManagedResource::new_box(MetadataPanicResource {
            name_panics: false,
            timeout_panics: true,
            log: Arc::clone(&log),
        }));
        stack.register_detached(DynManagedResource::new_box(MetadataPanicResource {
            name_panics: true,
            timeout_panics: false,
            log: Arc::clone(&log),
        }));

        let receipt = receipt_of(stack.shutdown().await);
        assert_eq!(
            entries(&log),
            vec!["metadata-panic", "metadata-panic", "dependency"]
        );
        assert_eq!(receipt.failures().len(), 2);
        assert!(
            receipt
                .failures()
                .iter()
                .all(|failure| matches!(failure.kind, ShutdownFailureKind::Panicked))
        );
    }

    // start_paused：cancel 是事件非 timer，广播后 cancelled().await 立即 resolve（零虚拟耗时）。
    // 若 phase1 广播回归失效，waiter 不会挂死——shutdown_one 的 5s timeout 是 timer，虚拟时钟
    // 自动推进触发它，测试会以 TimedOut failure 快速失败（而非真实挂起）。
    // 同时验证 register_with_token funnel：token 经闭包注入资源后台 task（无 pub child_token）。
    #[tokio::test(start_paused = true)]
    async fn cancellation_broadcast_unblocks_resource_shutdown() {
        let log = new_log();
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_with_token(|token| {
            MockResource::boxed("waiter", Behavior::AwaitCancel(token), &log)
        });

        let receipt = receipt_of(stack.shutdown().await);
        let failures = receipt.failures();

        assert!(failures.is_empty());
        assert_eq!(entries(&log), vec!["waiter"]);
    }

    #[tokio::test]
    async fn managed_task_registration_returns_its_same_source_status() {
        let (start, status) =
            crate::ManagedTask::prepare("canonical-task", crate::DEFAULT_SHUTDOWN_TIMEOUT);
        assert_eq!(status.current(), crate::TaskState::Pending);

        let mut stack = ShutdownStack::new(CancellationToken::new());
        let registration = start.into_registration(|task_token| async move {
            task_token.cancelled().await;
            Ok(())
        });
        let registered = stack.register_managed_task_with_token(registration);

        assert_eq!(registered.current(), crate::TaskState::Running);
        assert_eq!(status.current(), crate::TaskState::Running);
        assert!(receipt_of(stack.shutdown().await).failures().is_empty());
        assert_eq!(
            registered.current(),
            crate::TaskState::Stopped(crate::TaskExit::Cancelled)
        );
        assert_eq!(registered.current(), status.current());
    }

    // SHUTDOWN-TOKEN-FUNNEL-01：deferred token 同样只能由 stack 在 closure 内铸造，但不属于
    // phase-one root broadcast。后注册的 listener LIFO drain 完成前 token 必须保持 live；到 worker
    // 自身相位时 wrapper 先 cancel，再让 inner shutdown 观察并 join。
    #[tokio::test]
    async fn deferred_cancellation_waits_for_its_lifo_phase() {
        let log = new_log();
        let deferred_token = Arc::new(Mutex::new(None::<CancellationToken>));
        let capture = Arc::clone(&deferred_token);
        let listener_started = Arc::new(Notify::new());
        let release_listener = Arc::new(Notify::new());
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_deferred_with_token(|token| {
            *capture
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(token.clone());
            MockResource::boxed("worker", Behavior::AwaitCancel(token), &log)
        });
        stack.register_with_token({
            let listener_started = Arc::clone(&listener_started);
            let release_listener = Arc::clone(&release_listener);
            |_: CancellationToken| {
                MockResource::boxed(
                    "listener",
                    Behavior::Gate {
                        started: listener_started,
                        release: release_listener,
                    },
                    &log,
                )
            }
        });

        let drain = tokio::spawn(async move { stack.shutdown().await });
        listener_started.notified().await;
        let captured = deferred_token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        assert!(captured.is_some(), "deferred funnel must inject its token");
        let token = captured.unwrap_or_default();
        assert!(
            !token.is_cancelled(),
            "deferred worker must remain live while the later LIFO resource drains"
        );

        release_listener.notify_one();
        let joined = drain.await;
        assert!(joined.is_ok(), "shutdown task must join: {joined:?}");
        let failures = joined
            .ok()
            .and_then(Result::ok)
            .map(ShutdownReceipt::into_failures)
            .unwrap_or_default();

        assert!(failures.is_empty());
        assert!(token.is_cancelled());
        assert_eq!(entries(&log), vec!["listener", "worker"]);
    }

    // F6：整体预算在 deferred worker 之前被后注册的 hung resource 耗尽时，worker wrapper 不会
    // 进入 shutdown body。remaining iterator drop wrapper 必须经 CancelOnDrop 取消 token，不能让
    // 后台 task 因「从未轮到」而越过进程 drain 边界继续运行。
    #[tokio::test(start_paused = true)]
    async fn budget_exhaustion_before_deferred_phase_still_cancels_token() {
        let log = new_log();
        let deferred_token = Arc::new(Mutex::new(None::<CancellationToken>));
        let capture = Arc::clone(&deferred_token);
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_deferred_with_token(|token| {
            *capture
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(token.clone());
            MockResource::boxed("deferred", Behavior::AwaitCancel(token), &log)
        });
        stack.register_detached(MockResource::boxed("hang", Behavior::Hang, &log));

        let receipt = receipt_of(stack.shutdown_within(Duration::from_secs(3)).await);
        let failures = receipt.failures();
        let captured = deferred_token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        assert!(captured.is_some(), "deferred funnel must inject its token");
        let token = captured.unwrap_or_default();

        assert_eq!(failures.len(), 2);
        assert_eq!(failures[0].name, "hang");
        assert_eq!(failures[1].name, "deferred");
        assert!(
            failures
                .iter()
                .all(|failure| matches!(failure.kind, ShutdownFailureKind::BudgetExhausted))
        );
        assert!(
            token.is_cancelled(),
            "dropping an unvisited deferred wrapper must cancel its task token"
        );
        assert_eq!(
            entries(&log),
            vec!["hang"],
            "deferred shutdown body must remain unvisited in this regression"
        );
    }

    // SHUTDOWN-BUDGET-CANCEL-SAFE-01：整体预算 3s < hang 的 per-resource 超时 5s，hang 占满
    // 预算 → 它与被依赖的 a 都记 BudgetExhausted（cancel-safe，不 await），中途不泄漏聚合。
    #[tokio::test(start_paused = true)]
    async fn shutdown_within_budget_exhausted_marks_remaining() {
        let log = new_log();
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_detached(MockResource::boxed("a", Behavior::Ok, &log)); // 最后关
        stack.register_detached(MockResource::boxed("hang", Behavior::Hang, &log)); // 最先关

        let receipt = receipt_of(stack.shutdown_within(Duration::from_secs(3)).await);
        let failures = receipt.failures();

        // hang 先关（LIFO）：其 shutdown body 已 record（启动），随后 3s 预算耗尽 → BudgetExhausted；
        // a 未启动（无 record）→ 同样 BudgetExhausted。
        assert_eq!(entries(&log), vec!["hang"]);
        assert_eq!(failures.len(), 2);
        assert_eq!(failures[0].name, "hang");
        assert!(matches!(
            failures[0].kind,
            ShutdownFailureKind::BudgetExhausted
        ));
        assert_eq!(failures[1].name, "a");
        assert!(matches!(
            failures[1].kind,
            ShutdownFailureKind::BudgetExhausted
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn budget_exhaustion_isolates_remaining_resource_name_panic() {
        let log = new_log();
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_detached(DynManagedResource::new_box(MetadataPanicResource {
            name_panics: true,
            timeout_panics: false,
            log: Arc::clone(&log),
        }));
        stack.register_detached(MockResource::boxed("hang", Behavior::Hang, &log));

        let receipt = receipt_of(stack.shutdown_within(Duration::from_secs(3)).await);
        assert_eq!(receipt.completion(), DrainCompletion::BudgetExhausted);
        assert_eq!(receipt.failures().len(), 2);
        assert_eq!(receipt.failures()[1].name, PANICKED_RESOURCE_NAME);
    }

    // 部分成功后预算耗尽：c/b 立即成功关闭，hang 占满预算 → hang + 被依赖 a 记 BudgetExhausted。
    #[tokio::test(start_paused = true)]
    async fn shutdown_within_partial_then_budget_exhausted() {
        let log = new_log();
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_detached(MockResource::boxed("a", Behavior::Ok, &log)); // 最后关
        stack.register_detached(MockResource::boxed("hang", Behavior::Hang, &log));
        stack.register_detached(MockResource::boxed("b", Behavior::Ok, &log));
        stack.register_detached(MockResource::boxed("c", Behavior::Ok, &log)); // 最先关

        let receipt = receipt_of(stack.shutdown_within(Duration::from_secs(3)).await);
        let failures = receipt.failures();

        // LIFO：c, b 立即成功；hang 启动 → 占满 3s 预算 → BudgetExhausted；a 未启动 → BudgetExhausted。
        assert_eq!(entries(&log), vec!["c", "b", "hang"]);
        assert_eq!(failures.len(), 2);
        assert_eq!(failures[0].name, "hang");
        assert!(matches!(
            failures[0].kind,
            ShutdownFailureKind::BudgetExhausted
        ));
        assert_eq!(failures[1].name, "a");
        assert!(matches!(
            failures[1].kind,
            ShutdownFailureKind::BudgetExhausted
        ));
    }

    // 充裕预算：行为同 shutdown()，全部 LIFO 关闭、无 BudgetExhausted。
    #[tokio::test(start_paused = true)]
    async fn shutdown_within_ample_budget_closes_all_in_lifo() {
        let log = new_log();
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_detached(MockResource::boxed("a", Behavior::Ok, &log));
        stack.register_detached(MockResource::boxed("b", Behavior::Ok, &log));
        stack.register_detached(MockResource::boxed("c", Behavior::Ok, &log));

        let receipt = receipt_of(stack.shutdown_within(Duration::from_secs(60)).await);
        let failures = receipt.failures();

        assert!(failures.is_empty());
        assert_eq!(entries(&log), vec!["c", "b", "a"]);
    }

    #[tokio::test]
    async fn empty_stack_shutdown_is_noop() {
        let stack = ShutdownStack::new(CancellationToken::new());
        assert!(stack.is_empty());

        let receipt = receipt_of(stack.shutdown().await);
        let failures = receipt.failures();

        assert!(failures.is_empty());
    }

    #[tokio::test]
    async fn single_resource_shutdown() {
        let log = new_log();
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_detached(MockResource::boxed("only", Behavior::Ok, &log));
        assert_eq!(stack.len(), 1);

        let receipt = receipt_of(stack.shutdown().await);
        let failures = receipt.failures();

        assert!(failures.is_empty());
        assert_eq!(entries(&log), vec!["only"]);
    }

    /// 持 Drop guard 的 hung 资源：shutdown future 被 abort（task drop）时 guard.Drop 置位；
    /// 若退化回 detach（drop JoinHandle、task 后台续跑），future 不 drop、guard 不置位。
    struct AbortProbe {
        name: String,
        // shutdown task 的 future 被 drop 时（abort 生效）置 true。
        aborted: Arc<AtomicBool>,
    }

    impl AbortProbe {
        fn boxed(name: &str, aborted: &Arc<AtomicBool>) -> Box<DynManagedResource<'static>> {
            DynManagedResource::new_box(Self {
                name: name.to_owned(),
                aborted: Arc::clone(aborted),
            })
        }
    }

    impl ManagedResource for AbortProbe {
        fn name(&self) -> &str {
            &self.name
        }
        // per-resource 超时远大于整体预算 → 整体预算先耗尽（触发 abort 路径，而非 per-resource timeout）。
        fn shutdown_timeout(&self) -> Duration {
            Duration::from_secs(3600)
        }
        async fn shutdown(&self) -> Result<(), ShutdownError> {
            struct Guard(Arc<AtomicBool>);
            impl Drop for Guard {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::SeqCst);
                }
            }
            let _guard = Guard(Arc::clone(&self.aborted));
            // sleep(MAX) 是 timer：start_paused 下「所有 task 阻塞于 timer」成立、虚拟时钟自动推进到
            // 最近 deadline（整体预算）；预算耗尽 → 驱动器 abort 本 task → future drop → guard 置位。
            #[allow(unknown_lints, rss_test_no_bare_sleep)] // reason: paused-clock hang probe
            {
                tokio::time::sleep(Duration::MAX).await;
            }
            Ok(())
        }
    }

    // SHUTDOWN-BUDGET-CANCEL-SAFE-01（F2）：整体预算耗尽时**abort 在飞 task**（非 detach）。
    #[tokio::test(start_paused = true)]
    async fn shutdown_within_budget_exhausted_aborts_in_flight_task() {
        let aborted = Arc::new(AtomicBool::new(false));
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_detached(AbortProbe::boxed("hang", &aborted));

        let receipt = receipt_of(stack.shutdown_within(Duration::from_secs(3)).await);
        let failures = receipt.failures();

        assert_eq!(failures.len(), 1);
        assert!(matches!(
            failures[0].kind,
            ShutdownFailureKind::BudgetExhausted
        ));
        // abort 是协作式：让运行时处理取消、drop 掉 task future（guard 随之 drop）。
        for _ in 0..1000 {
            if aborted.load(Ordering::SeqCst) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            aborted.load(Ordering::SeqCst),
            "整体预算耗尽时在飞 shutdown task 必须被 abort（future+guard 已 drop），而非 detach 续跑"
        );
    }
}
