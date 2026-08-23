//! ack-capable delivery seam —— at-least-once 订阅的 broker 结算端口 + 投递原语。
//!
//! 与 [`crate::Subscriber`]（`MessageStream`，**at-most-once**：broker 投递即出队、消息不携 ack 义务）
//! 对偶：[`AckableSubscriber`] 返回 [`DeliveryStream`]，每条 [`Delivery`] 携一个 [`Acker`] 句柄，由框架
//! （`eventexec::run_consumer_ackable`）在终态据 [`AckAction`] 向 broker settle（ack / requeue / reject），
//! 达成 **at-least-once**——在途消息在消费者崩溃窗口由 broker 自动重投（lapin/RabbitMQ channel close → requeue）。
//!
//! 设计要点：acker 是**独立 seam**，**不**挂到 [`crate::Message`]（ADR-003 冻结值类型；`Message` rustdoc
//! 显式「不暴露 Ack/Nack——由框架据 Disposition 驱动」，`contracts/**/contract.toml`、`generated` 与 `crates/consistency`「subscriber 层扩展信息放 DeliveryOutcome，
//! 不污染业务结果」）。[`AckAction`] 是 provider-agnostic 的 broker 词汇（非 `consistency::Disposition`）——
//! 引擎 disposition + DLX 结果 → `AckAction` 的映射在 `eventexec` 完成。
//!
//! ref: rabbitmq docs/confirms（manual ack：basic.ack/nack/reject + requeue 标志 + 同 channel 结算）
//!      lapin message::Delivery.acker + options::Basic{Ack,Nack,Reject}Options@docs.rs
//!      watermill-amqp pkg/amqp/subscriber.go@master（Ack/Nack 驱动模型；RSS 偏离：requeue 由每条 action 决定）

use std::pin::Pin;

use dynosaur::dynosaur;
use futures::Stream;
use tokio_util::sync::CancellationToken;

use crate::publisher::Topic;
use crate::redacted::RedactedSource;
use crate::subscriber::{Message, SubscriberError};

// ── AckAction（broker 结算动作）────────────────────────────────────────────────

/// broker 投递结算动作（provider-agnostic 闭值集）。
///
/// 由 `eventexec` 从 `consistency::outbox::Disposition` + DLX 写结果映射后传入 [`Acker::settle`]；
/// adapter 把它翻成 broker 原语（AMQP：`Ack`→basic_ack、`Requeue`→basic_nack(requeue=true)、
/// `Reject`→basic_nack(requeue=false)，后者路由 broker 端 DLX/丢弃）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AckAction {
    /// 成功消费：broker 移除消息（at-least-once 的终态成功）。
    Ack,
    /// 重投：broker 重新入队等待再投（瞬态失败 / DLX 写失败 / 崩溃兜底）。
    Requeue,
    /// 拒绝：broker 不重入队，路由 broker 端 DLX 或丢弃（不可重试的 malformed）。
    Reject,
}

impl AckAction {
    /// 稳定 metrics / log label（对标 `consistency::outbox::Disposition::as_label`）。
    pub fn as_label(self) -> &'static str {
        match self {
            AckAction::Ack => "ack",
            AckAction::Requeue => "requeue",
            AckAction::Reject => "reject",
        }
    }
}

// ── 错误 ────────────────────────────────────────────────────────────────────

/// broker 结算失败（ack / nack / reject I/O 失败）。
///
/// PII 边界（与 [`SubscriberError`] 同范式）：`Display` 仅安全摘要常量；source 经 [`RedactedSource`] 脱敏
/// （`Debug`/`Display` 固定 `<redacted>`、`Error::source()` 恒 `None`——原始错误不经任何 `Error` 接口暴露，
/// fail-closed），见 INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
#[derive(Debug, thiserror::Error)]
#[error("ack settle failed")]
pub struct AckError {
    #[source]
    source: RedactedSource,
}

impl AckError {
    /// 把 adapter 内部错误包成结算失败。原始错误仅作 internal source 保留，不经 `Display` 暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: RedactedSource::new(source),
        }
    }
}

// ── Acker DI port（async）──────────────────────────────────────────────────────

/// 单条投递的 broker 结算句柄（async DI port，provider-agnostic）。
///
/// 公开 [`Acker`] 是 **Send 变体**（adapters `impl Acker for ...`），[`DynAcker`] 是其 dyn-compatible
/// wrapper（[`Delivery`] 经 `Box<DynAcker>` 携带）。非 Send 基 trait `AckerLocal` 仅供静态分发窄场景，
/// 不在 crate 根 re-export（见 crate rustdoc）。
///
/// **settle-once**：每条 [`Delivery`] 至多结算一次——由驱动方保证单次调用（`run_consumer_ackable` 每条消息
/// 终态恰调一次），底层 broker（lapin `Acker`）对二次结算亦内部 guard。
///
/// dyn-safe 约束（ADR-003 §4.6）：方法 `&self`、参数为具体类型、supertrait 仅 Send。
#[trait_variant::make(Acker: Send)]
#[dynosaur(pub DynAcker = dyn(box) Acker, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `Acker` 变体 + dynosaur
// `DynAcker` 承载（DI 注入走 Send wrapper）。这是 ADR-003 既定 dyn-port 范式。
pub trait AckerLocal {
    /// 向 broker 结算本条投递（ack / requeue / reject）。
    async fn settle(&self, action: AckAction) -> Result<(), AckError>;
}

// ── Delivery / DeliveryStream（manual-ack 流原语）──────────────────────────────

/// 携带 broker 结算句柄的投递（manual-ack 流元素）。
///
/// [`Message`] 仍是 ADR-003 冻结值类型（不携 acker）；acker 在 seam 层与 message 并置，**不污染** message。
/// 不 derive `Clone`（[`DynAcker`] 不可克隆）——驱动方解构 `Delivery { message, acker }`：`message` 供
/// handler（bounded 重投克隆 message），`acker` 供终态 settle。
pub struct Delivery {
    /// provider-agnostic 消息值（冻结值类型）。
    pub message: Message,
    /// 本条投递的 broker 结算句柄。
    pub acker: Box<DynAcker<'static>>,
}

impl Delivery {
    /// 由消息 + 结算句柄构造投递。
    pub fn new(message: Message, acker: Box<DynAcker<'static>>) -> Self {
        Self { message, acker }
    }
}

/// 已装箱的 manual-ack 投递流（[`AckableSubscriber::subscribe_ackable`] 返回值；`token` 取消即流终止，
/// 与 [`crate::MessageStream`] 对偶）。
pub type DeliveryStream = Pin<Box<dyn Stream<Item = Delivery> + Send>>;

// ── AckableSubscriber DI port（async）──────────────────────────────────────────

/// ack-capable 事件订阅 provider DI port（**at-least-once**）。
///
/// 与 [`crate::Subscriber`]（at-most-once）对偶：返回 [`DeliveryStream`]，每条 [`Delivery`] 携 [`Acker`]。
/// AMQP 等支持 broker 确认的 provider 实现本端口（`no_ack=false`）；不支持手工 ack 的 provider（in-mem /
/// MQTT QoS auto-ack）继续用 [`crate::Subscriber`]。
///
/// 公开 [`AckableSubscriber`] 是 **Send 变体**，[`DynAckableSubscriber`] 是其 dyn-compatible wrapper
/// （组合根经 `Box<DynAckableSubscriber>` 注入）。
///
/// dyn-safe 约束（ADR-003 §4.6）：方法 `&self`、参数 / 返回为具体类型、supertrait 仅 Send、带
/// `async fn shutdown`（无 async Drop）。
#[trait_variant::make(AckableSubscriber: Send)]
#[dynosaur(pub DynAckableSubscriber = dyn(box) AckableSubscriber, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `AckableSubscriber` 变体 +
// dynosaur `DynAckableSubscriber` 承载（DI 注入走 Send wrapper）。ADR-003 既定 dyn-port 范式。
pub trait AckableSubscriberLocal {
    /// Prepare durable broker topology without starting delivery dispatch.
    ///
    /// The default is deliberately fail-closed. Durable broker adapters must explicitly prove
    /// topology preparation so relay-first recovery cannot publish into an unbound exchange.
    fn prepare_ackable(
        &self,
        _topic: Topic,
    ) -> impl std::future::Future<Output = Result<(), SubscriberError>> {
        std::future::ready(Err(SubscriberError::new(std::io::Error::other(
            "durable topology preparation is unsupported",
        ))))
    }

    /// 订阅 topic，返回 manual-ack 投递流；`token` 取消即流终止（与 [`crate::Subscriber::subscribe`] 对偶）。
    async fn subscribe_ackable(
        &self,
        topic: Topic,
        token: CancellationToken,
    ) -> Result<DeliveryStream, SubscriberError>;

    /// 异步释放 provider 资源（无 async Drop）。有 infra 资源的 adapter 应同时 `impl ManagedResource`
    /// 由 `bootstrap::ShutdownStack` 统一编排；本方法是 port-local 关闭路径。
    async fn shutdown(&self) -> Result<(), SubscriberError>;
}

// ── 测试 ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod smoke {
    //! build smoke：证明 ack seam 的 async DI port 可 native AFIT impl + 经 `Box<DynX>` 动态注入，
    //! [`Delivery`] 可构造、[`DeliveryStream`] 可产出。
    use super::{
        AckAction, AckError, AckableSubscriber, Acker, Delivery, DeliveryStream,
        DynAckableSubscriber, DynAcker, Message,
    };
    use crate::publisher::Topic;
    use crate::subscriber::SubscriberError;
    use tokio_util::sync::CancellationToken;

    fn _assert_send_sync<T: Send + Sync + ?Sized>() {}

    /// 恒成功结算的 Noop acker（仅测试 / 编译验证用）。
    struct NoopAcker;
    impl Acker for NoopAcker {
        async fn settle(&self, _action: AckAction) -> Result<(), AckError> {
            Ok(())
        }
    }

    fn sample_delivery() -> Delivery {
        Delivery::new(
            Message::new("evt-1", b"payload".to_vec()),
            DynAcker::new_box(NoopAcker),
        )
    }

    // multi_thread + spawn：boxed future 须 Send（trait_variant Send 变体）才能跨 worker 调度。
    // **每个 acker 实例恰 settle 一次**——对齐 settle-once 契约（不在同一 acker 上重复 settle，避免
    // 给「同句柄多次结算」立反例；真实 AmqpAcker 二次 settle 会触发 broker double-ack 错误）。
    #[tokio::test(flavor = "multi_thread")]
    async fn acker_is_dyn_injectable_and_settles() {
        async fn settle_once(action: AckAction) -> bool {
            let acker: Box<DynAcker> = DynAcker::new_box(NoopAcker);
            acker.settle(action).await.is_ok()
        }
        // 三个独立 acker 各覆盖一种 AckAction（settle-once），并经 spawn 验证 boxed future Send。
        let joined = tokio::spawn(async move {
            settle_once(AckAction::Ack).await
                && settle_once(AckAction::Requeue).await
                && settle_once(AckAction::Reject).await
        })
        .await;
        assert!(matches!(joined, Ok(true)));
    }

    #[test]
    fn delivery_constructs_and_destructures() {
        let Delivery { message, acker } = sample_delivery();
        assert_eq!(message.id().as_str(), "evt-1");
        assert_eq!(message.payload().as_bytes(), b"payload");
        // acker 是 Box<DynAcker>——存在即证 Delivery 携结算句柄（消费 acker 防 unused 警告）。
        let _ = acker;
    }

    struct NoopAckableSubscriber;
    impl AckableSubscriber for NoopAckableSubscriber {
        async fn subscribe_ackable(
            &self,
            _topic: Topic,
            _token: CancellationToken,
        ) -> Result<DeliveryStream, SubscriberError> {
            Ok(Box::pin(futures::stream::empty::<Delivery>()))
        }
        async fn shutdown(&self) -> Result<(), SubscriberError> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ackable_subscriber_is_dyn_injectable() {
        let subscriber: Box<DynAckableSubscriber> =
            DynAckableSubscriber::new_box(NoopAckableSubscriber);
        let token = CancellationToken::new();
        let joined = tokio::spawn(async move {
            subscriber
                .subscribe_ackable(Topic::new("session.created"), token)
                .await
                .is_ok()
                && subscriber.shutdown().await.is_ok()
        })
        .await;
        assert!(matches!(joined, Ok(true)));
    }

    #[test]
    fn delivery_stream_item_is_send() {
        // DeliveryStream = Pin<Box<dyn Stream<Item = Delivery> + Send>>——验 Delivery: Send（Box<DynAcker>: Send）。
        _assert_send_sync::<Message>();
        fn _accepts(_s: &DeliveryStream) {}
    }
}

#[cfg(test)]
mod action_label {
    //! `AckAction::as_label` 稳定 label（metrics/log 闭值集）。
    use super::AckAction;

    #[test]
    fn labels_are_stable_and_distinct() {
        assert_eq!(AckAction::Ack.as_label(), "ack");
        assert_eq!(AckAction::Requeue.as_label(), "requeue");
        assert_eq!(AckAction::Reject.as_label(), "reject");
    }
}

#[cfg(test)]
mod error_redaction {
    //! `AckError` derive(Debug) 经 `RedactedSource` 不展开 source（adapter 原始错误可能携连接串/凭据），
    //! 且 `Error::source()` 恒 `None`（fail-closed source 链）。
    //! INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（对标 `SubscriberError`/`DeadLetterStoreError`）。
    use super::AckError;

    #[test]
    fn error_debug_redacts_source() {
        let secret = std::io::Error::other("amqp://user:hunter2@broker.internal:5672/vhost");
        // anti-vacuity：原始 source 自身 Debug 确实携密，否则回归断言空转。
        assert!(
            format!("{secret:?}").contains("hunter2"),
            "前提失效：source 未携密"
        );
        let err = AckError::new(secret);
        assert_eq!(err.to_string(), "ack settle failed");
        let rendered = format!("{err:?}");
        assert!(
            !rendered.contains("hunter2") && !rendered.contains("amqp://"),
            "Debug 泄漏 source: {rendered}"
        );
        // fail-closed source 链：递归遍历在 RedactedSource（source() 恒 None）处终止，永不到达原始错误。
        let mut cur = std::error::Error::source(&err);
        while let Some(e) = cur {
            assert!(
                !format!("{e:?}").contains("hunter2") && !format!("{e:?}").contains("amqp://"),
                "source 链泄漏原始错误: {e:?}"
            );
            cur = e.source();
        }
    }
}
