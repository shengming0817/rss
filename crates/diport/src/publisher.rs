//! `Publisher` —— 事件发布 provider DI port（可替换：prod AMQP / test in-mem）。

use dynosaur::dynosaur;

use crate::redacted::RedactedSource;
use crate::subscriber::MessageId;

/// 发布失败。
///
/// PII 边界（与 [`crate::ShutdownError`] 同范式）：`Display` 仅安全摘要常量；source 经
/// [`RedactedSource`] 脱敏（`Debug`/`Display` 固定 `<redacted>`、`Error::source()` 恒 `None`——原始错误
/// 不经任何 `Error` 接口暴露，fail-closed），见 INVARIANT: DIPORT-ERR-SOURCE-REDACT-01。
#[derive(Debug, thiserror::Error)]
#[error("publish failed")]
pub struct PublisherError {
    #[source]
    source: RedactedSource,
}

impl PublisherError {
    /// 把 adapter 内部错误包成发布失败。原始错误仅作 internal source 保留，不经 `Display` 暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: RedactedSource::new(source),
        }
    }
}

/// 事件 topic 标识——newtype funnel（私有字段，单一构造入口），不裸传 `&str`。
/// opaque：闭值集随 contract/event metadata 派生（消费域 eventexec），不在 DI-infra 层冻结。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Topic(String);

impl Topic {
    /// 由字符串构造 topic。
    pub fn new(topic: impl Into<String>) -> Self {
        Self(topic.into())
    }
    /// 借出底层 topic。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// typed 事件发布请求：`topic` 经 [`Topic`] newtype 收口（不裸 `&str`），`payload` 为 provider-agnostic
/// 字节。
///
/// **租户 / correlation** 经 ambient [`runctx::RequestCtx`] 解析（请求级 context 值，非发布请求字段）。
/// 跨域 wire 类型单源仍是 contract——`payload` 由 `eventexec`/outbox 层按 contract envelope 预编码后传入，
/// DI-infra port **不**引 `generated`（ADR-003 §6 偏离 2）。字段集随消费域细化（pre-GA 可原地加 content-type 等）。
#[derive(Clone)]
pub struct PublishRequest {
    /// 目标 topic。
    pub topic: Topic,
    /// 事件去重锚点（= outbox `event_id` / `Entry::idem_key`）。relay 据此盖章 broker `message_id`，
    /// 经订阅侧 `Message.id` 流回消费幂等键（`run_consumer` 的 `IdemKey`），实现「至少一次 + 幂等 =
    /// 有效一次」端到端去重（`docs/rules/eventbus.md` §DLX 与幂等）。路由元数据，非 PII。
    pub event_id: MessageId,
    /// provider-agnostic 事件字节（已按 contract envelope 编码）。
    pub payload: Vec<u8>,
}

/// PII 边界（类型层 Hard，对标 [`crate::Signature`]）：手写 `Debug` 对 `payload`（事件序列化体，可能含
/// PII——如审计事件本身被编码进 payload）输出 `<redacted>`；`topic` / `event_id` 是路由元数据，可观测。
///
/// INVARIANT: DIPORT-DTO-PII-DEBUG-REDACT-01（回归见 `pii_debug` 单测）。
impl std::fmt::Debug for PublishRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublishRequest")
            .field("topic", &self.topic)
            .field("event_id", &self.event_id)
            .field("payload", &"<redacted>")
            .finish()
    }
}

/// 事件发布 provider DI port（async）。
///
/// 公开 [`Publisher`] 是 **Send 变体**（adapters `impl Publisher for ...`），[`DynPublisher`] 是其
/// dyn-compatible wrapper。
#[trait_variant::make(Publisher: Send)]
#[dynosaur(pub DynPublisher = dyn(box) Publisher, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `Publisher` 变体 +
// dynosaur `DynPublisher` 承载（DI 注入走 Send wrapper）。这是 ADR-003 既定 dyn-port 范式。
pub trait PublisherLocal {
    /// 按 typed [`PublishRequest`] 发布事件。
    async fn publish(&self, request: PublishRequest) -> Result<(), PublisherError>;

    /// 异步释放 provider 资源（无 async Drop）。有 infra 资源的 adapter 应同时 `impl ManagedResource`
    /// 由 `bootstrap::ShutdownStack` 统一编排；本方法是 port-local 关闭路径（参 [`crate::Signer::shutdown`]）。
    async fn shutdown(&self) -> Result<(), PublisherError>;
}

#[cfg(test)]
mod smoke {
    //! build smoke：证明 async DI port 可 native AFIT impl + 经 `Box<DynPublisher>` 动态注入。
    use super::{DynPublisher, MessageId, PublishRequest, Publisher, PublisherError, Topic};

    #[test]
    fn publisher_error_wraps_source() {
        let err = PublisherError::new(std::io::Error::other("leak-marker-pub"));
        assert_eq!(err.to_string(), "publish failed");
        assert!(std::error::Error::source(&err).is_some());
        // 端到端：derive(Debug) 经 RedactedSource 脱敏、不展开内层 source（anti-vacuity 前置）。
        assert!(
            format!("{:?}", std::io::Error::other("leak-marker-pub")).contains("leak-marker-pub"),
            "前提失效：内层 Debug 未携 marker"
        );
        assert!(
            !format!("{err:?}").contains("leak-marker-pub"),
            "wrapper Debug 泄漏 source: {err:?}"
        );
    }

    fn sample_request() -> PublishRequest {
        PublishRequest {
            topic: Topic::new("session.created"),
            event_id: MessageId::new("evt-1"),
            payload: b"evt".to_vec(),
        }
    }

    struct NoopPublisher;
    impl Publisher for NoopPublisher {
        async fn publish(&self, _request: PublishRequest) -> Result<(), PublisherError> {
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), PublisherError> {
            Ok(())
        }
    }

    // multi_thread + spawn：验证 boxed future Send（trait_variant Send 变体），与真实 spawn 场景对齐。
    #[tokio::test(flavor = "multi_thread")]
    async fn publisher_is_dyn_injectable() {
        let publisher: Box<DynPublisher> = DynPublisher::new_box(NoopPublisher);
        let joined = tokio::spawn(async move {
            publisher.publish(sample_request()).await.is_ok() && publisher.shutdown().await.is_ok()
        })
        .await;
        assert!(matches!(joined, Ok(true)));
    }
}

#[cfg(test)]
mod pii_debug {
    //! `PublishRequest.payload`（事件序列化体，可能含 PII）字节 Debug 脱敏回归。
    //! INVARIANT: DIPORT-DTO-PII-DEBUG-REDACT-01.
    use super::{MessageId, PublishRequest, Topic};

    #[test]
    fn publish_request_debug_redacts_payload() {
        // anti-vacuity：原始 Vec<u8> Debug 把 0xDE 渲染成 "222"，证明 "!contains(222)" 检测非空转。
        assert!(
            format!("{:?}", vec![0xDE_u8]).contains("222"),
            "前提失效：检测字节不在原始 Debug"
        );
        let req = PublishRequest {
            topic: Topic::new("session.created"),
            event_id: MessageId::new("evt-routing-id"),
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let dbg = format!("{req:?}");
        assert!(!dbg.contains("222"), "payload 字节泄漏(0xDE=222): {dbg}");
        assert!(!dbg.contains("173"), "payload 字节泄漏(0xAD=173): {dbg}");
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
        assert!(dbg.contains("session.created"), "topic 应可见: {dbg}");
        // event_id 是路由元数据（去重锚点），应可见——非 PII。
        assert!(dbg.contains("evt-routing-id"), "event_id 应可见: {dbg}");
    }
}
