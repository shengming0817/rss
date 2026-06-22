//! eventexec — 事件执行与 saga 编排接缝（签名冻结；全部函数体为 `todo!()`，ADR-004 C8 覆盖率豁免）。
//!
//! ref: watermill message/message.go+pubsub.go+router.go@master
//!      oxidecomputer/steno src/saga_action_generic.rs@main

use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;

// 消息原语（Message / MessageId / MessageMetadata / MessageStream）随 Subscriber DI port 迁 `diport`
// （issue #1075，ADR-003 DI port 收敛）；本 crate 经 `diport::Message` 消费（HandlerFn/ConsumerFn 入参）。
use diport::Message;

// ── 处理结论 ─────────────────────────────────────────────────────────────────

/// 处理结论（显式化 watermill 隐式 ack：Nack=不重入队，Requeue=重入队+可退避）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Disposition {
    Ack,
    Nack,
    Requeue { after: Option<Duration> },
}

// ── 处理器类型别名 ────────────────────────────────────────────────────────────

/// 单消息 handler（对齐 watermill HandlerFunc，去掉 `[]*Message` 输出——输出经 Publisher DI port）。
pub type HandlerFn = Arc<dyn Fn(Message) -> BoxFuture<'static, Disposition> + Send + Sync>;

/// 带错误通道的 consumer（区分业务 Nack 与基础设施故障）。
pub type ConsumerFn =
    Arc<dyn Fn(Message) -> BoxFuture<'static, Result<Disposition, ConsumerError>> + Send + Sync>;

// ── Consumer 错误 ─────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
#[error("consumer failed")]
pub struct ConsumerError {
    #[source]
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl ConsumerError {
    pub fn new<E: std::error::Error + Send + Sync + 'static>(_source: E) -> Self {
        todo!()
    }
}

// 主题初始化接缝（`SubscribeInitializer`）与 Subscriber 内部接缝（`EventSubscriber` → `Subscriber`）
// 及 `MessageStream` / `SubscribeInitError` 随 Subscriber DI port 迁 `diport`（issue #1075，
// ADR-003 DI port 收敛）；消费方经 `diport::{Subscriber, SubscribeInitializer, MessageStream}` 注入。

// ── saga 接缝（对齐 steno Action）─────────────────────────────────────────────

#[allow(dead_code)] // reason: 签名冻结骨架，todo!() 体暂不使用字段；ADR-004 C8 豁免
#[derive(Debug)]
pub struct SagaId(uuid::Uuid);

impl SagaId {
    pub fn new(_id: uuid::Uuid) -> Self {
        todo!()
    }

    pub fn as_uuid(&self) -> uuid::Uuid {
        todo!()
    }
}

pub struct SagaActionCtx {
    // 私有字段：外部不可字面构造（F6 funnel）；实现阶段替换为实际字段
    _saga_id: uuid::Uuid,
    _node_name: String,
}

impl SagaActionCtx {
    pub fn new(_saga_id: uuid::Uuid, _node_name: impl Into<String>) -> Self {
        todo!()
    }
}

pub trait SagaAction: std::fmt::Debug + Send + Sync {
    fn name(&self) -> &str;

    fn do_it(&self, ctx: SagaActionCtx) -> BoxFuture<'static, Result<Vec<u8>, SagaActionError>>;

    fn undo_it(&self, ctx: SagaActionCtx) -> BoxFuture<'static, Result<(), SagaActionError>>;
}

#[derive(Debug)]
#[non_exhaustive]
pub enum SagaOutcome {
    Succeeded {
        output: Vec<u8>,
    },
    Failed {
        failed_node: String,
        error: SagaActionError,
    },
}

#[derive(Debug)]
#[non_exhaustive]
pub enum SagaCommand {
    Start { saga_id: SagaId },
    Cancel { saga_id: SagaId },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaExecStatus {
    Ready,
    Running,
    Done,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SagaActionError {
    #[error("action failed")]
    ActionFailed,
    #[error("serialize failed")]
    SerializeFailed,
    #[error("subsaga create failed")]
    SubsagaCreateFailed,
}

// ── Saga 执行器 / 进度跟踪接缝（对标 steno SEC）────────────────────────────────

/// Saga 执行器接缝：驱动 SagaAction 栈（前向执行 + 失败逆序补偿）。
///
/// 对标 steno SEC（saga_create / saga_start）。
pub trait SagaExecutor: Send + Sync {
    /// 执行 saga：按顺序运行 actions，失败后逆序 undo_it。
    fn run(
        &self,
        saga_id: SagaId,
        actions: Vec<Box<dyn SagaAction>>,
    ) -> futures::future::BoxFuture<'static, SagaOutcome>;

    /// 从执行日志恢复（crash recovery；对标 steno saga_resume）。
    fn resume(&self, saga_id: SagaId) -> futures::future::BoxFuture<'static, SagaOutcome>;
}

/// Saga 进度跟踪接缝：查询执行状态。
///
/// 对标 steno saga status。
pub trait SagaTailer: Send + Sync {
    fn status(
        &self,
        saga_id: SagaId,
    ) -> futures::future::BoxFuture<'static, Option<SagaExecStatus>>;
}

// ── smoke tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn _assert_send_sync<T: Send + Sync + ?Sized>() {}

    #[test]
    fn message_and_handler_fn_are_send_sync() {
        _assert_send_sync::<Message>();
        _assert_send_sync::<HandlerFn>();
    }

    #[test]
    fn disposition_variants_exhaustive_match() {
        let variants: &[Disposition] = &[
            Disposition::Ack,
            Disposition::Nack,
            Disposition::Requeue { after: None },
            Disposition::Requeue {
                after: Some(Duration::from_secs(1)),
            },
        ];
        for d in variants {
            // 同 crate 内 #[non_exhaustive] 不强制 _ 臂；穷尽匹配验证变体可达
            let _ = match d {
                Disposition::Ack => "ack",
                Disposition::Nack => "nack",
                Disposition::Requeue { .. } => "requeue",
            };
        }
    }

    #[test]
    fn saga_exec_status_running_bindable() {
        let status = SagaExecStatus::Running;
        assert!(matches!(status, SagaExecStatus::Running));
    }

    #[test]
    fn saga_command_start_constructible_without_calling_todo() {
        // SagaId::new body 是 todo!()——只绑定 fn 指针，不真调用
        let _fn_ptr: fn(uuid::Uuid) -> SagaId = SagaId::new;
        // SagaExecStatus 的全变体 match 证明类型可达（同 crate 内无需 _ 臂）
        let _ = match SagaExecStatus::Done {
            SagaExecStatus::Ready => 0,
            SagaExecStatus::Running => 1,
            SagaExecStatus::Done => 2,
        };
    }

    #[test]
    fn disposition_clone_eq() {
        assert_eq!(Disposition::Ack, Disposition::Ack.clone());
        assert_eq!(
            Disposition::Requeue { after: None },
            Disposition::Requeue { after: None },
        );
    }

    // ── Finding#6：补全未覆盖冻结符号 ────────────────────────────────────────

    #[test]
    fn saga_command_cancel_fn_ptr_bindable() {
        // SagaId::new body 是 todo!()——只绑定 fn 指针，验证 Cancel 变体签名可达
        let _new_fn: fn(uuid::Uuid) -> SagaId = SagaId::new;
        // 穷尽 match SagaCommand 变体（同 crate 内 #[non_exhaustive] 无需 _ 臂）
        // 不构造 SagaId 实例，避免触发 todo!()
        fn _match_command(cmd: SagaCommand) -> &'static str {
            match cmd {
                SagaCommand::Start { .. } => "start",
                SagaCommand::Cancel { .. } => "cancel",
            }
        }
        // 验证函数本身可编译（不调用——不需要构造 SagaId 实例）
        let _: fn(SagaCommand) -> &'static str = _match_command;
    }

    #[test]
    fn saga_outcome_failed_constructible() {
        // SagaOutcome::Failed 不依赖 todo!() 路径，直接构造
        let outcome = SagaOutcome::Failed {
            failed_node: "n".into(),
            error: SagaActionError::ActionFailed,
        };
        // 穷尽 match 验证两个变体可达
        let _ = match outcome {
            SagaOutcome::Succeeded { .. } => "ok",
            SagaOutcome::Failed { .. } => "fail",
        };
    }

    #[test]
    fn consumer_fn_is_send_sync() {
        // ConsumerFn 是 Arc<dyn Fn..> 别名，?Sized 断言 object-safe + Send+Sync
        _assert_send_sync::<ConsumerFn>();
    }

    // SubscribeInitializer / EventSubscriber 的 Send+Sync/object-safe smoke 随其迁 `diport`
    // （diport::subscriber::smoke）；此处不再断言（类型已不在本 crate）。

    #[test]
    fn saga_executor_is_send_sync_object_safe() {
        _assert_send_sync::<dyn SagaExecutor>();
    }

    #[test]
    fn saga_tailer_is_send_sync_object_safe() {
        _assert_send_sync::<dyn SagaTailer>();
    }

    // ── F6：私有字段 funnel 验证——只绑定构造器 fn 指针，不触发 todo!() ─────────

    #[test]
    fn saga_action_ctx_new_fn_ptr_bindable() {
        // SagaActionCtx 含私有字段，外部不可字面构造；只能经 new() 受控构造
        // new() 为泛型，用 closure 强制单态化验证签名可达，不调用（body 为 todo!()）
        let _fn_ptr: fn(uuid::Uuid, &str) -> SagaActionCtx =
            |id, name| SagaActionCtx::new(id, name);
    }
}
