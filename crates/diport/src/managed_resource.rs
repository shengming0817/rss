//! `ManagedResource` —— 进程关闭时按依赖逆序 await 关干净的托管资源 DI port。
//!
//! 关闭编排（[`ShutdownStack`] + 两阶段 LIFO 驱动器）归属 `bootstrap`（ADR-001）；本 crate 仅持
//! **port trait 单源**——adapters（postgres / amqp / relay …）`impl ManagedResource`，经组合根注入
//! `bootstrap` 的 `ShutdownStack`。迁入 diport 因 ADR-003 把可替换 provider DI port 统一 dynosaur 派发
//! （原 ADR-001 用 `#[async_trait]` + `Arc<dyn>`，inter-ADR 冲突在 PR-diport 收敛，见 ADR-001/ADR-003 回链）。
//!
//! [`ShutdownStack`]: 见 `bootstrap` crate。

use std::time::Duration;

use dynosaur::dynosaur;

/// per-resource 默认关闭超时预算。重 I/O 资源（如 outbox relay）可在
/// [`ManagedResource::shutdown_timeout`] 覆盖为更长。
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// 进程关闭时需要按依赖逆序 await 关干净的托管资源
/// （DB pool / outbox relay / event consumer / 后台 worker / HTTP listener 等）。
///
/// Rust 无 async `Drop`——关闭顺序与等待由 `bootstrap::ShutdownStack` 显式驱动，而非 RAII `Drop`。
/// 公开 [`ManagedResource`] 是 **Send 变体**（adapters `impl ManagedResource for ...`）；
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
/// - **需要 `&mut` 内部状态时**：因 `shutdown(&self)`，若实现需消费内部状态（drain sender /
///   take oneshot），用 `Mutex<Option<Inner>>` 或 `tokio::sync::Mutex` 包装，在 `shutdown` 中 `take()`。
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

/// 资源关闭失败：adapter 实现 [`ManagedResource::shutdown`] 时返回的 typed 错误。
///
/// **PII 边界**（替代 `anyhow` 暴露在公共 port）：`Display` 仅输出资源无关的安全摘要常量
/// （不含 runtime 数据）；包装的原始错误仅作 [`std::error::Error::source`] 内部保留，
/// **不进入默认日志**。驱动器在 redaction funnel（`secure::redact_error`，ADR-001 §5 延后项）
/// 落地前不打印 source——见 `bootstrap::ShutdownStack` 业务错误分支。
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

#[cfg(test)]
mod smoke {
    //! build smoke：证明 ManagedResource 可 native AFIT impl + 经 `Box<DynManagedResource>`
    //! 动态注入 + move 进 `tokio::spawn`（ShutdownStack panic 隔离的真实形态：Box 仅需 Send，无需 Sync）。
    use super::{DEFAULT_SHUTDOWN_TIMEOUT, DynManagedResource, ManagedResource, ShutdownError};

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
