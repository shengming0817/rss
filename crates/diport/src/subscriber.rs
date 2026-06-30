//! `Subscriber` —— 事件订阅 provider DI port（可替换：prod AMQP / test in-mem）+ 订阅消息原语。
//!
//! 自 `eventexec`（服务层）迁入（issue #1075，ADR-003 DI port 收敛）：订阅接缝是可替换-provider 的
//! DI 注入端口，归属 DI-infra 单源；端口数据类型（[`Message`] 及 [`MessageStream`]）随端口一并落本层——
//! 与 [`crate::Publisher`] 拥有 [`crate::PublishRequest`]/[`crate::Topic`] 对称（watermill `message` 包内聚）。
//! ref: watermill message/message.go+pubsub.go@master

use std::pin::Pin;

use dynosaur::dynosaur;
use futures::Stream;
use tokio_util::sync::CancellationToken;

use crate::envelope::EnvelopeMetadata;
use crate::publisher::Topic;
use crate::redacted::RedactedSource;
use crate::redacted_bytes::RedactedBytes;

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

/// 消息值类型（对齐 watermill Message UUID/Metadata/Payload）。
///
/// 不暴露 Ack/Nack——由框架据 `eventexec::Disposition` 驱动。`metadata` 是统一 delivery envelope
/// （[`EnvelopeMetadata`]）：transport-safe reserved key（trace / correlation / occurredAt / tenantId /
/// tenantAuthority）由 adapter subscriber 从 broker header 经 [`EnvelopeMetadata::insert_wire_pair`] 透传
/// （来源已 sealed），业务不得伪造（writer 两层强度见 [`EnvelopeMetadata`] rustdoc + dylint
/// DIPORT-ENVELOPE-WIRE-WRITER-01）。
/// PII 边界（类型层 Hard，对标 [`crate::Signature`]）：`payload`（消息体，可能含 PII）经 [`RedactedBytes`] 持有
/// （`Debug` 恒 `<redacted>`、经 `as_bytes` 受控读取），故 struct `derive(Debug)` 即安全；`id`（路由）可观测；
/// `metadata` 经 [`EnvelopeMetadata`] 自身 Debug（subjectId / principal 脱敏）。
///
/// INVARIANT: DIPORT-DTO-BYTES-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（payload 脱敏由 `RedactedBytes` 类型保证，回归见 `pii_debug` 单测）。
#[derive(Debug, Clone)]
pub struct Message {
    /// 消息唯一标识。
    pub id: MessageId,
    /// 统一 delivery envelope metadata（仅 transport-safe broker header 透传）。
    pub metadata: EnvelopeMetadata,
    /// provider-agnostic 消息字节（[`RedactedBytes`] 持有：`Debug` 恒 `<redacted>`，经 `payload.as_bytes()` 读取）。
    pub payload: RedactedBytes,
}

impl Message {
    /// 由标识 + payload 构造消息（元数据初始为空）。
    pub fn new(id: impl Into<String>, payload: Vec<u8>) -> Self {
        Self {
            id: MessageId::new(id),
            metadata: EnvelopeMetadata::empty(),
            payload: RedactedBytes::new(payload),
        }
    }

    /// 由标识 + payload + 统一 delivery envelope metadata 构造（adapter subscriber 从 broker delivery 调用）。
    pub fn new_with_metadata(
        id: impl Into<String>,
        payload: Vec<u8>,
        metadata: EnvelopeMetadata,
    ) -> Self {
        Self {
            id: MessageId::new(id),
            metadata,
            payload: RedactedBytes::new(payload),
        }
    }
}

/// 已装箱的消息流（[`Subscriber::subscribe`] 返回值；取消即流终止，对齐 watermill `<-chan *Message`）。
pub type MessageStream = Pin<Box<dyn Stream<Item = Message> + Send>>;

// ── 错误 ────────────────────────────────────────────────────────────────────

/// 订阅失败。
///
/// PII 边界（与 [`crate::PublisherError`] 同范式）：`Display` 仅安全摘要常量；source 经
/// [`RedactedSource`] 脱敏（`Debug`/`Display` 固定 `<redacted>`、`Error::source()` 恒 `None`——原始错误
/// 不经任何 `Error` 接口暴露，fail-closed），见 INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
#[derive(Debug, thiserror::Error)]
#[error("subscription failed")]
pub struct SubscriberError {
    #[source]
    source: RedactedSource,
}

impl SubscriberError {
    /// 把 adapter 内部错误包成订阅失败。原始错误仅作 internal source 保留，不经 `Display` 暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: RedactedSource::new(source),
        }
    }
}

/// 主题初始化失败（[`SubscribeInitializer`]）。
///
/// source 经 [`RedactedSource`] 脱敏（`Debug`/`Display` 固定 `<redacted>`、`Error::source()` 恒 `None`——
/// 原始错误不经任何 `Error` 接口暴露，fail-closed），见 INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
#[derive(Debug, thiserror::Error)]
#[error("subscribe initialize failed")]
pub struct SubscribeInitError {
    #[source]
    source: RedactedSource,
}

impl SubscribeInitError {
    /// 把 adapter 内部错误包成初始化失败。原始错误仅作 internal source 保留（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: RedactedSource::new(source),
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
        // Message::new 默认空 envelope（无 metadata 路径）。
        assert_eq!(msg.metadata.get("trace"), None);
        assert!(msg.metadata.is_empty());
        assert_eq!(msg.payload.as_bytes(), b"payload");
    }

    #[test]
    fn message_with_metadata_carries_envelope() {
        use crate::envelope::{EnvelopeMetadata, KEY_CORRELATION, KEY_OCCURRED_AT};
        // adapter subscriber 从 broker header 透传 reserved key（来源已 sealed，走 insert_wire_pair）。
        let mut md = EnvelopeMetadata::empty();
        md.insert_wire_pair(KEY_OCCURRED_AT, "1700000000");
        md.insert_wire_pair(KEY_CORRELATION, "corr-3");
        let msg = Message::new_with_metadata("m-2", b"p".to_vec(), md);
        assert_eq!(msg.metadata.occurred_at_secs(), Some(1_700_000_000));
        assert_eq!(msg.metadata.get(KEY_CORRELATION), Some("corr-3"));
    }

    #[test]
    fn subscriber_error_wraps_source() {
        let err = SubscriberError::new(std::io::Error::other("leak-marker-sub"));
        assert_eq!(err.to_string(), "subscription failed");
        assert!(std::error::Error::source(&err).is_some());
        // 端到端：derive(Debug) 经 RedactedSource 脱敏、不展开内层 source（anti-vacuity 前置）。
        assert!(
            format!("{:?}", std::io::Error::other("leak-marker-sub")).contains("leak-marker-sub"),
            "前提失效：内层 Debug 未携 marker"
        );
        assert!(
            !format!("{err:?}").contains("leak-marker-sub"),
            "wrapper Debug 泄漏 source: {err:?}"
        );
    }

    #[test]
    fn subscribe_init_error_wraps_source() {
        let err = SubscribeInitError::new(std::io::Error::other("leak-marker-init"));
        assert_eq!(err.to_string(), "subscribe initialize failed");
        assert!(std::error::Error::source(&err).is_some());
        // 端到端：derive(Debug) 经 RedactedSource 脱敏、不展开内层 source（anti-vacuity 前置）。
        assert!(
            format!("{:?}", std::io::Error::other("leak-marker-init")).contains("leak-marker-init"),
            "前提失效：内层 Debug 未携 marker"
        );
        assert!(
            !format!("{err:?}").contains("leak-marker-init"),
            "wrapper Debug 泄漏 source: {err:?}"
        );
    }
}

#[cfg(test)]
mod pii_debug {
    //! `Message.payload`（消息体，可能含 PII）字节 Debug 脱敏回归。
    //! INVARIANT: DIPORT-DTO-BYTES-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（payload 经 `RedactedBytes` 脱敏；`derive(Debug)` 即安全）。
    use super::Message;

    #[test]
    fn message_debug_redacts_payload() {
        // anti-vacuity：原始 Vec<u8> Debug 把 0xDE 渲染成 "222"，证明 "!contains(222)" 检测非空转。
        assert!(
            format!("{:?}", vec![0xDE_u8]).contains("222"),
            "前提失效：检测字节不在原始 Debug"
        );
        let msg = Message::new("msg-1", vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let dbg = format!("{msg:?}");
        assert!(!dbg.contains("222"), "payload 字节泄漏(0xDE=222): {dbg}");
        assert!(!dbg.contains("173"), "payload 字节泄漏(0xAD=173): {dbg}");
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
        assert!(dbg.contains("msg-1"), "id 应可见: {dbg}");
    }
}
