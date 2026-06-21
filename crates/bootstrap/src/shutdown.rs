//! 关闭逆序编排（无 async Drop）。
//!
//! Rust 的 [`Drop`] 是同步的，不能 `.await`——所以进程关闭时「按依赖逆序 await 每个资源
//! 关干净」不能靠 RAII `Drop`，必须由 bootstrap 显式驱动一个注册栈做 LIFO await。本模块
//! 提供该范式：[`ManagedResource`]（资源契约）+ [`ShutdownStack`]（注册栈 + 两阶段驱动器）。
//!
//! 两阶段关闭模型（对标 tokio + uber-go/fx）：
//!
//! 1. **广播（并发、无序）**：[`ShutdownStack::shutdown`] 先 `cancel` root [`CancellationToken`]，
//!    所有经 [`ShutdownStack::register_with_token`] 注入的后台 task 同时感知「该停了」，开始自行退出。
//! 2. **逆序确认（串行、有序）**：按注册逆序（LIFO）逐个 await 每个资源的
//!    [`ManagedResource::shutdown`]，确认其真正释放干净，再关下一个（被依赖的）资源。
//!
//! 单 cancel 广播不保证资源释放顺序（outbox relay 可能晚于它依赖的 DB pool 关闭）；
//! 单 LIFO await 又无法让后台 task 提前退出。两者配合才安全。
//!
//! 不变式（详见 `docs/architecture/202606212024-001-shutdown-reverse-order-orchestration.md`）：
//!
//! - `INVARIANT: SHUTDOWN-LIFO-ORDER-01` —— 关闭顺序 = 注册顺序的逆序（后注册的先关）。
//! - `INVARIANT: SHUTDOWN-CONTINUE-ON-ERROR-01` —— 任一资源失败/超时/panic 必须**继续**关后续，
//!   禁止 fail-fast（否则被依赖资源泄漏）。
//! - `INVARIANT: SHUTDOWN-ERROR-AGGREGATE-01` —— 所有 per-resource 失败聚合返回，不丢弃。
//! - `INVARIANT: SHUTDOWN-TIMEOUT-BOUNDED-01` —— 每个资源关闭有 per-resource 超时上界。
//! - `INVARIANT: SHUTDOWN-PANIC-ISOLATE-01` —— 下游资源 panic 被隔离，不击穿驱动循环。
//! - `INVARIANT: SHUTDOWN-SINGLE-SHOT-01` —— `shutdown(self)` 消费 self，double-shutdown /
//!   关闭后注册在类型层不可表达（编译期，Hard）。
//! - `INVARIANT: SHUTDOWN-TOKEN-FUNNEL-01` —— 后台 task 的取消 token 只能经
//!   [`ShutdownStack::register_with_token`] 由本 stack 派生并在闭包内经构造器注入；无后台 task
//!   的资源经 [`ShutdownStack::register_detached`] 显式声明不接广播。**无 `pub child_token`**——
//!   裸 token 发放无公开入口，杜绝注册「使用外部 / 无来源 token」的有 task 资源。
//! - `INVARIANT: SHUTDOWN-BUDGET-CANCEL-SAFE-01` —— 整体 shutdown 预算由驱动器内部
//!   [`ShutdownStack::shutdown_within`] 承担（cancel-safe），**不**交外层 `timeout` 取消包裹
//!   （外层取消会在 LIFO 中途 drop future、中断后续关闭、泄漏被依赖资源）。

use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

/// per-resource 默认关闭超时预算。重 I/O 资源（如 outbox relay）可在
/// [`ManagedResource::shutdown_timeout`] 覆盖为更长。
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// 进程关闭时需要按依赖逆序 await 关干净的托管资源
/// （DB pool / outbox relay / event consumer / 后台 worker / HTTP listener 等）。
///
/// Rust 无 async `Drop`——关闭顺序与等待由 [`ShutdownStack`] 显式驱动，而非 RAII `Drop`。
/// 实现是 `Send + Sync + 'static`，以便驱动器经 [`tokio::spawn`] 做 panic 隔离。
///
/// 本 trait **不 sealed**：各 adapter（postgres / amqp / relay …）实现它，经组合根注入是
/// 预期用例（对照 `Domain` 生命周期 trait），不阻止外部实现。
///
/// # 实现者须知（消费侧契约）
///
/// - **取消信号经构造器注入**：资源的后台 task 用的 [`CancellationToken`] 经
///   [`ShutdownStack::register_with_token`] 的闭包参数注入（RSS 必填依赖走构造器位置参），
///   不在 `shutdown` 参数里传；无后台 task 的资源经 [`ShutdownStack::register_detached`] 注册。
/// - **不要在 `shutdown` 内部自设超时**：per-resource 超时由驱动器外层 [`tokio::time::timeout`]
///   包裹（[`shutdown_timeout`](Self::shutdown_timeout)）；内部再设超时是双重计时。
/// - **幂等性免费**：驱动器消费 self 单次驱动，`shutdown` 不会被重复调用，无需自保幂等。
/// - **需要 `&mut` 内部状态时**：因 `shutdown(&self)`（驱动器经 `Arc` 持有以 spawn 隔离 panic），
///   若实现需消费内部状态（drain sender / take oneshot），用 `Mutex<Option<Inner>>`
///   或 `tokio::sync::Mutex` 包装，在 `shutdown` 中 `take()`。
#[async_trait::async_trait]
pub trait ManagedResource: Send + Sync + 'static {
    /// 资源可读名称（kebab/snake 稳定标识），用于日志与超时报错。
    fn name(&self) -> &str;

    /// 关闭此资源：await 内部 task 收敛、flush 未完成工作、释放连接 / 句柄。
    ///
    /// 驱动器在调用前已 `cancel` root [`CancellationToken`]，实现可据此提前退出。
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

/// 资源关闭失败：adapter 实现 [`ManagedResource::shutdown`] 时返回的 typed 错误。
///
/// **PII 边界**（替代 `anyhow` 暴露在公共 port）：`Display` 仅输出资源无关的安全摘要常量
/// （不含 runtime 数据）；包装的原始错误仅作 [`std::error::Error::source`] 内部保留，
/// **不进入默认日志**。驱动器在 redaction funnel（`secure::redact_error`，ADR-001 §5 延后项，
/// `secure` 当前为空骨架）落地前不打印 source——见 [`ShutdownStack::shutdown`] 业务错误分支。
#[derive(Debug, thiserror::Error)]
#[error("resource shutdown failed")]
pub struct ShutdownError {
    #[source]
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl ShutdownError {
    /// 把一个 adapter 内部错误包成关闭失败。原始错误仅作 internal source 保留，
    /// 不经 `Display` 暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: Box::new(source),
        }
    }
}

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
    /// 整体 shutdown 预算（[`ShutdownStack::shutdown_within`]）耗尽，本资源未及关闭被跳过
    /// （cancel-safe：驱动器不再 await，残留后台 task 由进程退出回收）。
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

/// 关闭注册栈 + 两阶段逆序驱动器。
///
/// 注册顺序即依赖顺序：**后注册的资源依赖先注册的资源**。关闭时按注册逆序（LIFO）
/// await 每个资源关干净，保证被依赖项（先注册）在依赖它的资源（后注册）之后关闭。
///
/// `shutdown` 消费 `self`——double-shutdown 与「关闭后再注册」在类型层不可表达
/// （`INVARIANT: SHUTDOWN-SINGLE-SHOT-01`，编译期 Hard，强于运行期状态机 guard）。
pub struct ShutdownStack {
    root_token: CancellationToken,
    resources: Vec<Arc<dyn ManagedResource>>,
}

impl ShutdownStack {
    /// 以一个 root [`CancellationToken`] 构造空栈。root token 由组合根（bootstrap）持有，
    /// 也可经它在收到 SIGTERM 等信号时从外部触发关闭广播。
    pub fn new(root_token: CancellationToken) -> Self {
        Self {
            root_token,
            resources: Vec::new(),
        }
    }

    /// 注册一个**有后台 task**的托管资源，并为其后台 task 发放本 stack 派生的 child
    /// [`CancellationToken`]——token 在闭包内经资源构造器注入（RSS 必填依赖走构造器位置参）。
    ///
    /// 这是取消 token 的**唯一**发放入口（无 `pub child_token`）：「该资源后台 task 监听本
    /// stack 关闭广播」由注册 funnel 强制——无法注册一个绑定外部 / 无来源 token 的有 task
    /// 资源（`INVARIANT: SHUTDOWN-TOKEN-FUNNEL-01`）。注册顺序 = 依赖顺序（先注册 = 先启动 =
    /// 最后关闭）。
    ///
    /// token 在 `shutdown` 之前派生：`shutdown` 会 `cancel` root token；注册后关闭时资源 task
    /// 即感知广播。
    pub fn register_with_token<F>(&mut self, make: F)
    where
        F: FnOnce(CancellationToken) -> Arc<dyn ManagedResource>,
    {
        let token = self.root_token.child_token();
        self.resources.push(make(token));
    }

    /// 注册一个**无后台 task、不监听关闭广播**的资源（如纯同步 flush 的 buffer，关闭即 drain）。
    ///
    /// 显式 no-token 入口：声明「该资源有意不接关闭广播」，而非忘记接线。与
    /// [`register_with_token`](Self::register_with_token) 二者覆盖全部注册路径，杜绝静默绕过
    /// 阶段 1 广播（`INVARIANT: SHUTDOWN-TOKEN-FUNNEL-01`）。注册顺序语义同上。
    pub fn register_detached(&mut self, resource: Arc<dyn ManagedResource>) {
        self.resources.push(resource);
    }

    /// 已注册资源数。
    pub fn len(&self) -> usize {
        self.resources.len()
    }

    /// 是否无已注册资源。
    pub fn is_empty(&self) -> bool {
        self.resources.is_empty()
    }

    /// 按注册顺序遍历已注册资源名，供组合根在关闭前记录注册清单。
    pub fn registered_names(&self) -> impl Iterator<Item = &str> {
        self.resources.iter().map(|r| r.name())
    }

    /// 驱动关闭（消费 `self`，单次），仅 per-resource 超时、**无整体预算上界**：
    ///
    /// 1. `cancel` root token，广播取消给所有 child（并发，让后台 task 开始退出）。
    /// 2. 按注册逆序（LIFO）逐个 await 每个资源的 [`ManagedResource::shutdown`]，
    ///    每个资源经 per-resource 超时 + panic 隔离；**遇错继续**关后续。
    ///
    /// 返回所有失败资源（空 = 全部成功）。调用方（组合根）据此记日志并决定退出码。
    ///
    /// # 取消安全（cancel-safety）
    ///
    /// **禁止**用 `tokio::time::timeout(budget, stack.shutdown())` 等外层 future 取消包裹本调用：
    /// 外层取消会在 LIFO 中途 drop 本 future、**中断后续资源关闭**（被依赖资源泄漏），违反
    /// `SHUTDOWN-CONTINUE-ON-ERROR-01`。需要整体耗时上界时改用
    /// [`shutdown_within`](Self::shutdown_within)——预算由驱动器内部承担、cancel-safe
    /// （`INVARIANT: SHUTDOWN-BUDGET-CANCEL-SAFE-01`）。
    #[must_use = "关闭失败列表必须检查（决定进程退出码 / 告警）；忽略将静默丢弃关闭错误"]
    pub async fn shutdown(self) -> Vec<ResourceShutdownError> {
        self.run(None).await
    }

    /// 同 [`shutdown`](Self::shutdown)，但附加**整体预算上界**（cancel-safe）：在 per-resource
    /// 超时之上再封顶**总**耗时。预算耗尽时，当前及剩余未关资源记为
    /// [`ShutdownFailureKind::BudgetExhausted`]——驱动器**不再 await**（cancel-safe，残留后台
    /// task 由进程退出回收），由驱动器自身聚合，**不**把取消安全交给外层 `timeout`
    /// （`INVARIANT: SHUTDOWN-BUDGET-CANCEL-SAFE-01`）。
    ///
    /// 预算实现为单一共享 deadline（[`tokio::time::sleep`]），跨资源复用——不测 per-resource
    /// elapsed（clippy 禁 `Instant`，时延测量待 `primitives::Clock`）。组合根按
    /// `< k8s grace − buffer` 注入 `total_budget`（ADR-001 §5，P2 接线）。
    #[must_use = "关闭失败列表必须检查（决定进程退出码 / 告警）；忽略将静默丢弃关闭错误"]
    pub async fn shutdown_within(self, total_budget: Duration) -> Vec<ResourceShutdownError> {
        self.run(Some(total_budget)).await
    }

    /// 两阶段逆序驱动核心。`budget` = 整体预算上界（`None` = 仅 per-resource 超时）。
    async fn run(self, budget: Option<Duration>) -> Vec<ResourceShutdownError> {
        let total = self.resources.len();
        tracing::info!(resource_count = total, "shutdown sequence starting");

        // 阶段 1：广播取消（并发）——所有 child token 持有者同时感知关闭、开始自行退出。
        self.root_token.cancel();

        // 阶段 2：按注册逆序（LIFO）逐个 await 关闭；遇错继续，聚合所有失败。
        // 整体预算（可选）：单一共享 deadline，cancel-safe 跨资源复用（不测 elapsed）。无预算时
        // 用永不 resolve 的 pending——两条路径收敛为同一 select 循环（零分支，统一 cancel-safe）。
        let deadline = budget_deadline(budget);
        tokio::pin!(deadline);
        let mut failures = Vec::new();
        let mut resources = self.resources.into_iter().rev();
        while let Some(resource) = resources.next() {
            let name = resource.name().to_owned();
            tokio::select! {
                // biased：先判预算耗尽，再尝试关闭——预算已过则不再启动新关闭。
                biased;
                () = &mut deadline => {
                    // SHUTDOWN-BUDGET-CANCEL-SAFE-01：整体预算耗尽，当前 + 剩余资源全部记
                    // BudgetExhausted（不 await，cancel-safe），残留后台 task 由进程退出回收。
                    drain_budget_exhausted(name, &mut resources, &mut failures);
                    break;
                }
                outcome = shutdown_one(resource) => {
                    if let Err(failure) = outcome {
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
        failures
    }
}

/// 整体预算 deadline future：有预算 → [`tokio::time::sleep`]；无预算 → 永不 resolve 的
/// [`std::future::pending`]（让无预算路径走同一 select 循环、永不触发预算耗尽分支）。
async fn budget_deadline(budget: Option<Duration>) {
    match budget {
        Some(b) => tokio::time::sleep(b).await,
        None => std::future::pending::<()>().await,
    }
}

/// 整体预算耗尽：把当前及剩余未关资源全部记为 [`ShutdownFailureKind::BudgetExhausted`]
/// （cancel-safe：不 await，残留后台 task 由进程退出回收）。
fn drain_budget_exhausted<I>(
    current_name: String,
    remaining: &mut I,
    failures: &mut Vec<ResourceShutdownError>,
) where
    I: Iterator<Item = Arc<dyn ManagedResource>> + ExactSizeIterator,
{
    tracing::error!(
        skipped = remaining.len() + 1,
        "overall shutdown budget exhausted; remaining resources skipped (state unknown)"
    );
    failures.push(budget_exhausted(current_name));
    for r in remaining {
        failures.push(budget_exhausted(r.name().to_owned()));
    }
}

/// 把一个未及关闭的资源名包成 [`ShutdownFailureKind::BudgetExhausted`] 失败。
fn budget_exhausted(name: String) -> ResourceShutdownError {
    ResourceShutdownError {
        name,
        kind: ShutdownFailureKind::BudgetExhausted,
    }
}

/// 关闭单个资源：per-resource 超时 + panic 隔离 + tracing span。
///
/// 返回 `Err` 仅表示该资源关闭失败（交由 [`ShutdownStack::shutdown`] 聚合），
/// 不中断驱动循环（`INVARIANT: SHUTDOWN-CONTINUE-ON-ERROR-01`）。
async fn shutdown_one(resource: Arc<dyn ManagedResource>) -> Result<(), ResourceShutdownError> {
    let name = resource.name().to_owned();
    let budget = resource.shutdown_timeout();
    let span = tracing::info_span!(
        "shutdown.resource",
        resource = %name,
        budget_secs = budget.as_secs()
    );

    async move {
        // panic 隔离：在独立 task 中执行——下游 adapter panic 被 tokio harness 捕获为
        // JoinError，不击穿驱动循环。
        let mut handle = tokio::spawn({
            let resource = Arc::clone(&resource);
            async move { resource.shutdown().await }
        });

        // timeout → JoinError → shutdown 三层 Result：超时 / task 异常终止 / 业务错误。
        // 日志级别按 observability.md：业务 Err 是降级（warn）；超时 / panic 资源状态未知，
        // 属正确性失败（error），需专项告警。
        let kind = match timeout(budget, &mut handle).await {
            Ok(Ok(Ok(()))) => {
                tracing::debug!("resource shut down cleanly");
                return Ok(());
            }
            // 业务错误：资源优雅上报 Err（降级，warn）。错误内容 held 为 ShutdownError 内部
            // source，**不打印**——Display 是安全摘要常量、原始 source 待 redaction funnel
            // （secure::redact_error，ADR-001 §5 延后）落地后经清洗记录。span 已含 resource 名。
            Ok(Ok(Err(source))) => {
                tracing::warn!("resource shutdown returned error");
                ShutdownFailureKind::Failed(source)
            }
            // INVARIANT: SHUTDOWN-PANIC-ISOLATE-01 —— 下游 panic 被 spawn 隔离，仅本资源失败。
            Ok(Err(join_err)) => {
                // 未超时分支的 JoinError 只可能来自 panic（驱动器从不 abort 未超时 task）；
                // is_cancelled 理论不可达，仍保守上报、不静默吞。
                if join_err.is_cancelled() {
                    tracing::warn!("resource shutdown task cancelled unexpectedly");
                }
                tracing::error!("resource shutdown panicked (state unknown)");
                ShutdownFailureKind::Panicked
            }
            // INVARIANT: SHUTDOWN-TIMEOUT-BOUNDED-01 —— per-resource 超时有界，hung task abort 后继续。
            Err(_elapsed) => {
                handle.abort(); // 停止 hung task，避免后台泄漏（进程退出前回收）。
                tracing::error!("resource shutdown timed out (state unknown)");
                ShutdownFailureKind::TimedOut(budget)
            }
        };

        Err(ResourceShutdownError { name, kind })
    }
    .instrument(span)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

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

    enum Behavior {
        Ok,
        Err,
        Hang,
        Panic,
        AwaitCancel(CancellationToken),
    }

    struct MockResource {
        name: String,
        behavior: Behavior,
        log: Log,
    }

    impl MockResource {
        fn arc(name: &str, behavior: Behavior, log: &Log) -> Arc<dyn ManagedResource> {
            Arc::new(Self {
                name: name.to_owned(),
                behavior,
                log: Arc::clone(log),
            })
        }
    }

    #[async_trait::async_trait]
    impl ManagedResource for MockResource {
        fn name(&self) -> &str {
            &self.name
        }

        fn shutdown_timeout(&self) -> Duration {
            Duration::from_secs(5)
        }

        // reason: Behavior::Panic 刻意 panic，验证驱动器对下游 adapter panic 的隔离；
        // 此 carve-out 仅作用于本 mock（item-level，见 error-handling.md §Carve-out）。
        #[allow(clippy::panic)]
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
                    tokio::time::sleep(Duration::MAX).await;
                    Ok(())
                }
                Behavior::Panic => panic!("mock-panic-{}", self.name),
                Behavior::AwaitCancel(token) => {
                    token.cancelled().await;
                    Ok(())
                }
            }
        }
    }

    #[tokio::test]
    async fn shutdown_runs_in_reverse_registration_order() {
        let log = new_log();
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_detached(MockResource::arc("a", Behavior::Ok, &log));
        stack.register_detached(MockResource::arc("b", Behavior::Ok, &log));
        stack.register_detached(MockResource::arc("c", Behavior::Ok, &log));

        let failures = stack.shutdown().await;

        assert!(failures.is_empty(), "all-ok shutdown reports no failures");
        // LIFO：最后注册的 c 先关，先注册的 a 最后关。
        assert_eq!(entries(&log), vec!["c", "b", "a"]);
    }

    #[tokio::test]
    async fn shutdown_continues_after_error_and_aggregates() {
        let log = new_log();
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_detached(MockResource::arc("a", Behavior::Ok, &log));
        stack.register_detached(MockResource::arc("b", Behavior::Err, &log));
        stack.register_detached(MockResource::arc("c", Behavior::Ok, &log));

        let failures = stack.shutdown().await;

        // SHUTDOWN-CONTINUE-ON-ERROR-01：b 失败不中断链，被依赖的 a 仍被关闭。
        assert_eq!(entries(&log), vec!["c", "b", "a"]);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].name, "b");
        assert!(matches!(failures[0].kind, ShutdownFailureKind::Failed(_)));
    }

    #[tokio::test]
    async fn shutdown_aggregates_all_errors_in_lifo_order() {
        let log = new_log();
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_detached(MockResource::arc("a", Behavior::Err, &log));
        stack.register_detached(MockResource::arc("b", Behavior::Err, &log));

        let failures = stack.shutdown().await;

        assert_eq!(entries(&log), vec!["b", "a"]);
        assert_eq!(failures.len(), 2);
        assert_eq!(failures[0].name, "b");
        assert_eq!(failures[1].name, "a");
    }

    // PII 边界：typed ShutdownError Display 是安全摘要常量，不泄漏 adapter 原始错误内容；
    // 原始内容仅经 source() 链内部可达。聚合后的 ResourceShutdownError Display 同样不泄漏。
    #[test]
    fn shutdown_error_display_is_safe_summary_only() {
        let err = ShutdownError::new(std::io::Error::other("secret-conn-string-42"));
        assert_eq!(err.to_string(), "resource shutdown failed");
        let leaked_in_display = err.to_string().contains("secret-conn-string-42");
        assert!(!leaked_in_display, "raw source must not appear in Display");
        // 原始内容仅经 source() 可达（供 redaction funnel 落地后清洗记录）。
        let source_carries_raw = std::error::Error::source(&err)
            .is_some_and(|s| s.to_string().contains("secret-conn-string-42"));
        assert!(
            source_carries_raw,
            "raw source preserved behind Error::source"
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
        stack.register_detached(MockResource::arc("a", Behavior::Ok, &log));
        stack.register_detached(MockResource::arc("hang", Behavior::Hang, &log));
        stack.register_detached(MockResource::arc("c", Behavior::Ok, &log));

        let failures = stack.shutdown().await;

        // hang 超时被跳过，但被依赖的 a 仍被关闭（顺序 c → hang → a）。
        assert_eq!(entries(&log), vec!["c", "hang", "a"]);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].name, "hang");
        assert!(matches!(failures[0].kind, ShutdownFailureKind::TimedOut(_)));
    }

    // 混合失败类型同时出现：验证 SHUTDOWN-ERROR-AGGREGATE-01 在异构失败下仍逆序、全聚合、类型不串。
    #[tokio::test(start_paused = true)]
    async fn shutdown_aggregates_mixed_failure_kinds() {
        let log = new_log();
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_detached(MockResource::arc("err", Behavior::Err, &log)); // 最后关
        stack.register_detached(MockResource::arc("hang", Behavior::Hang, &log));
        stack.register_detached(MockResource::arc("boom", Behavior::Panic, &log));
        stack.register_detached(MockResource::arc("ok", Behavior::Ok, &log)); // 最先关

        let failures = stack.shutdown().await;

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
        stack.register_detached(MockResource::arc("a", Behavior::Ok, &log));
        stack.register_detached(MockResource::arc("boom", Behavior::Panic, &log));
        stack.register_detached(MockResource::arc("c", Behavior::Ok, &log));

        let failures = stack.shutdown().await;

        // SHUTDOWN-PANIC-ISOLATE-01：boom panic 被隔离，a/c 不受影响。
        assert_eq!(entries(&log), vec!["c", "boom", "a"]);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].name, "boom");
        assert!(matches!(failures[0].kind, ShutdownFailureKind::Panicked));
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
            MockResource::arc("waiter", Behavior::AwaitCancel(token), &log)
        });

        let failures = stack.shutdown().await;

        assert!(failures.is_empty());
        assert_eq!(entries(&log), vec!["waiter"]);
    }

    // SHUTDOWN-BUDGET-CANCEL-SAFE-01：整体预算 3s < hang 的 per-resource 超时 5s，hang 占满
    // 预算 → 它与被依赖的 a 都记 BudgetExhausted（cancel-safe，不 await），中途不泄漏聚合。
    #[tokio::test(start_paused = true)]
    async fn shutdown_within_budget_exhausted_marks_remaining() {
        let log = new_log();
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_detached(MockResource::arc("a", Behavior::Ok, &log)); // 最后关
        stack.register_detached(MockResource::arc("hang", Behavior::Hang, &log)); // 最先关

        let failures = stack.shutdown_within(Duration::from_secs(3)).await;

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

    // 部分成功后预算耗尽：c/b 立即成功关闭，hang 占满预算 → hang + 被依赖 a 记 BudgetExhausted。
    #[tokio::test(start_paused = true)]
    async fn shutdown_within_partial_then_budget_exhausted() {
        let log = new_log();
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_detached(MockResource::arc("a", Behavior::Ok, &log)); // 最后关
        stack.register_detached(MockResource::arc("hang", Behavior::Hang, &log));
        stack.register_detached(MockResource::arc("b", Behavior::Ok, &log));
        stack.register_detached(MockResource::arc("c", Behavior::Ok, &log)); // 最先关

        let failures = stack.shutdown_within(Duration::from_secs(3)).await;

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
        stack.register_detached(MockResource::arc("a", Behavior::Ok, &log));
        stack.register_detached(MockResource::arc("b", Behavior::Ok, &log));
        stack.register_detached(MockResource::arc("c", Behavior::Ok, &log));

        let failures = stack.shutdown_within(Duration::from_secs(60)).await;

        assert!(failures.is_empty());
        assert_eq!(entries(&log), vec!["c", "b", "a"]);
    }

    #[tokio::test]
    async fn empty_stack_shutdown_is_noop() {
        let stack = ShutdownStack::new(CancellationToken::new());
        assert!(stack.is_empty());

        let failures = stack.shutdown().await;

        assert!(failures.is_empty());
    }

    #[tokio::test]
    async fn single_resource_shutdown() {
        let log = new_log();
        let mut stack = ShutdownStack::new(CancellationToken::new());
        stack.register_detached(MockResource::arc("only", Behavior::Ok, &log));
        assert_eq!(stack.len(), 1);

        let failures = stack.shutdown().await;

        assert!(failures.is_empty());
        assert_eq!(entries(&log), vec!["only"]);
    }
}
