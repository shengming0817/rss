//! `Subscriber` —— 事件订阅 provider DI port（可替换：prod AMQP / test in-mem）+ 订阅消息原语。
//!
//! 自 `eventexec`（服务层）迁入（issue #1075，ADR-003 DI port 收敛）：订阅接缝是可替换-provider 的
//! DI 注入端口，归属 DI-infra 单源；端口数据类型（[`Message`] 及 [`MessageStream`]）随端口一并落本层——
//! 与 [`crate::Publisher`] 拥有 [`crate::PublishRequest`]/[`crate::Topic`] 对称（watermill `message` 包内聚）。
//! ref: watermill message/message.go+pubsub.go@master

use std::collections::HashMap;
use std::pin::Pin;

use dynosaur::dynosaur;
use futures::Stream;
use tokio_util::sync::CancellationToken;

use crate::publisher::Topic;

// ── 消息原语（对齐 watermill Message UUID/Metadata/Payload）─────────────────────

/// 消息唯一标识（对齐 watermill Message.UUID）。newtype funnel（私有字段，单一构造入口）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageId(String);

impl MessageId {
    /// 由字符串构造消息标识。
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
    /// 借出底层标识。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 消息元数据（key-value 字符串映射，对齐 watermill Metadata）——只读访问。
///
/// **冻结期不开放公开写入口**：reserved envelope key（trace / correlation / principal / occurred_at）
/// 由 `outbox::Entry::new` + sealed option 注入，业务不得经 metadata 伪造（`docs/rules/observability.md`
/// §Outbox Envelope）。free-form 非-reserved key 的受控写入路径（typed key funnel，排除 reserved key）
/// 随 outbox envelope 行为 PR 落地。冻结期无 `set` ⇒ 经 metadata bag 伪造任何 key（含 reserved）从 API
/// 面即不可表达（Hard：无 setter）。
#[derive(Debug, Clone, Default)]
pub struct MessageMetadata(HashMap<String, String>);

impl MessageMetadata {
    /// 取元数据值（只读；写入路径见类型 rustdoc，冻结期未开放）。
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }
}

/// 消息值类型（对齐 watermill Message UUID/Metadata/Payload）。
///
/// 不暴露 Ack/Nack——由框架据 `eventexec::Disposition` 驱动。
#[derive(Debug, Clone)]
pub struct Message {
    /// 消息唯一标识。
    pub id: MessageId,
    /// 消息元数据。
    pub metadata: MessageMetadata,
    /// provider-agnostic 消息字节。
    pub payload: Vec<u8>,
}

impl Message {
    /// 由标识 + payload 构造消息（元数据初始为空）。
    pub fn new(id: impl Into<String>, payload: Vec<u8>) -> Self {
        Self {
            id: MessageId::new(id),
            metadata: MessageMetadata::default(),
            payload,
        }
    }
}

/// 已装箱的消息流（[`Subscriber::subscribe`] 返回值；取消即流终止，对齐 watermill `<-chan *Message`）。
pub type MessageStream = Pin<Box<dyn Stream<Item = Message> + Send>>;

// ── 错误 ────────────────────────────────────────────────────────────────────

/// 订阅失败。
///
/// PII 边界（与 [`crate::PublisherError`] 同范式）：`Display` 仅安全摘要常量；adapter 原始错误经
/// [`SubscriberError::new`] 包成 [`std::error::Error::source`] 内部保留，**不进默认日志**。
#[derive(Debug, thiserror::Error)]
#[error("subscription failed")]
pub struct SubscriberError {
    #[source]
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl SubscriberError {
    /// 把 adapter 内部错误包成订阅失败。原始错误仅作 internal source 保留，不经 `Display` 暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: Box::new(source),
        }
    }
}

/// 主题初始化失败（[`SubscribeInitializer`]）。
#[derive(Debug, thiserror::Error)]
#[error("subscribe initialize failed")]
pub struct SubscribeInitError {
    #[source]
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl SubscribeInitError {
    /// 把 adapter 内部错误包成初始化失败。原始错误仅作 internal source 保留（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: Box::new(source),
        }
    }
}

// ── 主题初始化接缝（sync DI port，对齐 watermill SubscribeInitializer）──────────

/// 主题初始化接缝（**sync** DI port，对齐 watermill SubscribeInitializer）。
///
/// sync trait 天然 dyn-compatible，经 `Box<dyn SubscribeInitializer>` 注入即可，**不需** dynosaur
/// （同 [`crate::Clock`]）。通常在 [`Subscriber::subscribe`] 前调用，初始化 topic 的 broker 端资源。
pub trait SubscribeInitializer: Send + Sync {
    /// 初始化 topic 的 broker 端资源（幂等）。
    fn subscribe_initialize(&self, topic: &Topic) -> Result<(), SubscribeInitError>;
}

// ── 事件订阅 provider DI port（async）──────────────────────────────────────────

/// 事件订阅 provider DI port（async）。
///
/// 公开 [`Subscriber`] 是 **Send 变体**（adapters `impl Subscriber for ...`），[`DynSubscriber`] 是其
/// dyn-compatible wrapper（组合根经 `Box<DynSubscriber>` / `Arc<DynSubscriber>` 注入）。非 Send 基 trait
/// `SubscriberLocal` 仅供静态分发窄场景，不在 crate 根 re-export（见 crate rustdoc）。
///
/// dyn-safe 约束（ADR-003 §4.6）：方法 `&self`、参数 / 返回为具体类型、supertrait 仅 Send、
/// 带 `async fn shutdown`（无 async Drop）。
#[trait_variant::make(Subscriber: Send)]
#[dynosaur(pub DynSubscriber = dyn(box) Subscriber, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `Subscriber` 变体 +
// dynosaur `DynSubscriber` 承载（DI 注入走 Send wrapper）。这是 ADR-003 既定 dyn-port 范式。
pub trait SubscriberLocal {
    /// 订阅 topic，返回消息流；`token` 取消即流终止。
    async fn subscribe(
        &self,
        topic: Topic,
        token: CancellationToken,
    ) -> Result<MessageStream, SubscriberError>;

    /// 异步释放 provider 资源（无 async Drop）。有 infra 资源的 adapter 应同时 `impl ManagedResource`
    /// 由 `bootstrap::ShutdownStack` 统一编排；本方法是 port-local 关闭路径（参 [`crate::Publisher::shutdown`]）。
    async fn shutdown(&self) -> Result<(), SubscriberError>;
}

#[cfg(test)]
mod smoke {
    //! build smoke：证明 async DI port 可 native AFIT impl + 经 `Box<DynSubscriber>` 动态注入，
    //! sync 初始化接缝可经 `Box<dyn SubscribeInitializer>` 注入，消息原语可构造。
    use super::{
        DynSubscriber, Message, MessageStream, SubscribeInitError, SubscribeInitializer,
        Subscriber, SubscriberError,
    };
    use crate::publisher::Topic;
    use tokio_util::sync::CancellationToken;

    fn _assert_send_sync<T: Send + Sync + ?Sized>() {}

    struct NoopSubscriber;
    impl Subscriber for NoopSubscriber {
        async fn subscribe(
            &self,
            _topic: Topic,
            _token: CancellationToken,
        ) -> Result<MessageStream, SubscriberError> {
            Ok(Box::pin(futures::stream::empty::<Message>()))
        }
        async fn shutdown(&self) -> Result<(), SubscriberError> {
            Ok(())
        }
    }

    // multi_thread + spawn：验证 boxed future Send（trait_variant Send 变体），与真实 spawn 场景对齐。
    #[tokio::test(flavor = "multi_thread")]
    async fn subscriber_is_dyn_injectable() {
        let subscriber: Box<DynSubscriber> = DynSubscriber::new_box(NoopSubscriber);
        let token = CancellationToken::new();
        let joined = tokio::spawn(async move {
            subscriber
                .subscribe(Topic::new("session.created"), token)
                .await
                .is_ok()
                && subscriber.shutdown().await.is_ok()
        })
        .await;
        assert!(matches!(joined, Ok(true)));
    }

    struct NoopInitializer;
    impl SubscribeInitializer for NoopInitializer {
        fn subscribe_initialize(&self, _topic: &Topic) -> Result<(), SubscribeInitError> {
            Ok(())
        }
    }

    #[test]
    fn subscribe_initializer_is_dyn_object_safe() {
        _assert_send_sync::<dyn SubscribeInitializer>();
        let init: Box<dyn SubscribeInitializer> = Box::new(NoopInitializer);
        assert!(
            init.subscribe_initialize(&Topic::new("session.created"))
                .is_ok()
        );
    }

    #[test]
    fn message_is_send_sync_and_constructible() {
        _assert_send_sync::<Message>();
        let msg = Message::new("m-1", b"payload".to_vec());
        assert_eq!(msg.id.as_str(), "m-1");
        // 无公开 setter ⇒ metadata bag 冻结期恒空，reserved key 经此路径不可伪造（observability.md §Outbox Envelope）。
        assert_eq!(msg.metadata.get("trace"), None);
        assert_eq!(msg.payload, b"payload".to_vec());
    }

    #[test]
    fn subscriber_error_wraps_source() {
        let err = SubscriberError::new(std::fmt::Error);
        assert_eq!(err.to_string(), "subscription failed");
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn subscribe_init_error_wraps_source() {
        let err = SubscribeInitError::new(std::fmt::Error);
        assert_eq!(err.to_string(), "subscribe initialize failed");
        assert!(std::error::Error::source(&err).is_some());
    }
}
