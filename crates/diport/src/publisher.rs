//! `Publisher` —— 事件发布 provider DI port（可替换：prod AMQP / test in-mem）。

use dynosaur::dynosaur;

/// 发布失败。
///
/// PII 边界（与 [`crate::ShutdownError`] 同范式）：`Display` 仅安全摘要常量；adapter 原始错误经
/// [`PublisherError::new`] 包成 [`std::error::Error::source`] 内部保留，**不进默认日志**。
#[derive(Debug, thiserror::Error)]
#[error("publish failed")]
pub struct PublisherError {
    #[source]
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl PublisherError {
    /// 把 adapter 内部错误包成发布失败。原始错误仅作 internal source 保留，不经 `Display` 暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: Box::new(source),
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
#[derive(Debug, Clone)]
pub struct PublishRequest {
    /// 目标 topic。
    pub topic: Topic,
    /// provider-agnostic 事件字节（已按 contract envelope 编码）。
    pub payload: Vec<u8>,
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
    use super::{DynPublisher, PublishRequest, Publisher, PublisherError, Topic};

    fn sample_request() -> PublishRequest {
        PublishRequest {
            topic: Topic::new("session.created"),
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
