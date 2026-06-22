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

/// 事件发布 provider DI port（async）。
///
/// 公开 [`Publisher`] 是 **Send 变体**（adapters `impl Publisher for ...`），[`DynPublisher`] 是其
/// dyn-compatible wrapper。payload 为 provider-agnostic 字节 + topic 字符串——DI infra port **不**引
/// `generated` wire 类型（diport 只依赖基础 + 引擎；跨域 wire 单源仍是 contract，ADR-003 §6 偏离 2）。
#[trait_variant::make(Publisher: Send)]
#[dynosaur(pub DynPublisher = dyn(box) Publisher, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `Publisher` 变体 +
// dynosaur `DynPublisher` 承载（DI 注入走 Send wrapper）。这是 ADR-003 既定 dyn-port 范式。
pub trait PublisherLocal {
    /// 向 `topic` 发布 `payload`（provider-agnostic 字节）。
    ///
    /// event metadata（correlation / tenant / content-type 等 outbox envelope 字段）由 `eventexec` /
    /// outbox 层在调用前编码进 `payload`——DI infra port 不在类型层结构化 envelope（ADR-003 §6 偏离 2，
    /// 跨域 wire 单源仍是 contract）。
    async fn publish(&self, topic: &str, payload: &[u8]) -> Result<(), PublisherError>;

    /// 异步释放 provider 资源（无 async Drop）。有 infra 资源的 adapter 应同时 `impl ManagedResource`
    /// 由 `bootstrap::ShutdownStack` 统一编排；本方法是 port-local 关闭路径（参 [`crate::Signer::shutdown`]）。
    async fn shutdown(&self) -> Result<(), PublisherError>;
}

#[cfg(test)]
mod smoke {
    //! build smoke：证明 async DI port 可 native AFIT impl + 经 `Box<DynPublisher>` 动态注入。
    use super::{DynPublisher, Publisher, PublisherError};

    struct NoopPublisher;
    impl Publisher for NoopPublisher {
        async fn publish(&self, _topic: &str, _payload: &[u8]) -> Result<(), PublisherError> {
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
            publisher.publish("topic", b"evt").await.is_ok() && publisher.shutdown().await.is_ok()
        })
        .await;
        assert!(matches!(joined, Ok(true)));
    }
}
