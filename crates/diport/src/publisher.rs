//! `Publisher` —— 事件发布 provider DI port（可替换：prod AMQP / test in-mem）。

use dynosaur::dynosaur;

use crate::envelope::{EnvelopeHeader, EnvelopeHeaderError, EnvelopeMetadata, MessageEnvelope};
use crate::redacted::RedactedSource;
use crate::redacted_bytes::RedactedBytes;
use crate::subscriber::MessageId;

/// 发布失败的处置类别——决定 relay 是按稳定事件 ID 有界重试，还是首投即 DLX。
///
/// 闭合 3 值（非 `#[non_exhaustive]`）：发布失败分为「明确未成功且值得重试」「重试无意义」和
/// 「broker 是否已接收不可判定」。查询经 [`PublisherError::is_permanent`] / [`PublisherError::is_ambiguous`] /
/// [`PublisherError::is_retryable`] 全覆盖。`Transient`/`Permanent` 语义对齐引擎层
/// [`consistency::EngineErrorKind`]，但不引入对 publish disposition 无意义的 `Invariant` 臂。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishErrorKind {
    /// 明确未发送或已明确拒绝的可重试失败（例如 pre-send transport unavailable）
    /// → relay 退避重试至预算耗尽。
    ///
    /// 发送后或等待 confirm 时丢失连接/通道不能归入本变体；该类结果必须使用 [`Self::Ambiguous`]。
    Transient,
    /// 永久失败（序列化 / 路由 / 编码非法，重试无意义）→ relay 首投即 DLX（跳过重试预算）。
    Permanent,
    /// 发布结果不确定（发送后连接丢失 / confirm 丢失 / deadline）→ relay 使用稳定事件 ID 重试。
    ///
    /// broker 可能已经接收并投递消息，因此该类别明确保留 at-least-once duplicate 语义。
    Ambiguous,
}

/// 发布失败（携 [`PublishErrorKind`] 决定 relay 按稳定事件 ID 重试 vs 首投 DLX）。
///
/// 构造**必经** [`PublisherError::transient`] / [`PublisherError::permanent`] /
/// [`PublisherError::ambiguous`] 三选一显式声明 disposition——类型层杜绝「构造发布失败却不分类」
/// （typed function choice，Hard）。
///
/// PII 边界（与 [`crate::ShutdownError`] 同范式）：`Display` 仅安全摘要常量；source 经 [`RedactedSource`]
/// 脱敏。注意主语——`PublisherError::source()` 因 `#[source]` 返回 `Some(&RedactedSource)`（非 `None`），而
/// **`RedactedSource` 自身**的 `Debug`/`Display` 固定 `<redacted>`、`RedactedSource::source()` 恒 `None`：
/// 通用 source 链遍历在 `RedactedSource` 处终止于 `<redacted>`，原始错误不经任何 `Error` 接口暴露
/// （fail-closed），见 INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
#[derive(Debug, thiserror::Error)]
#[error("publish failed")]
pub struct PublisherError {
    kind: PublishErrorKind,
    #[source]
    source: RedactedSource,
}

impl PublisherError {
    /// 明确未发送或已明确拒绝的可重试发布失败（例如 pre-send transport unavailable）
    /// → relay 退避重试至预算耗尽。发送后/confirm 阶段的连接或通道丢失必须构造为
    /// [`PublisherError::ambiguous`]。原始错误仅作 internal source 保留，不经 `Display` 暴露（PII 边界）。
    pub fn transient<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            kind: PublishErrorKind::Transient,
            source: RedactedSource::new(source),
        }
    }

    /// 永久发布失败（序列化 / 路由 / 编码非法，重试无意义）→ relay 首投即 DLX。原始错误仅作 internal source
    /// 保留，不经 `Display` 暴露（PII 边界）。
    pub fn permanent<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            kind: PublishErrorKind::Permanent,
            source: RedactedSource::new(source),
        }
    }

    /// 发布结果不确定（broker 可能已接收）→ relay 使用稳定事件 ID 退避重试至预算耗尽。原始错误仅作
    /// internal source 保留，不经 `Display` 暴露（PII 边界）。
    pub fn ambiguous<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            kind: PublishErrorKind::Ambiguous,
            source: RedactedSource::new(source),
        }
    }

    /// 失败处置类别（relay settle 据此分流重试 vs DLX）。
    pub fn kind(&self) -> PublishErrorKind {
        self.kind
    }

    /// 发布结果是否不确定（`Ambiguous`）——broker 可能已接收，retry 必须保持事件 ID 不变。
    pub fn is_ambiguous(&self) -> bool {
        self.kind == PublishErrorKind::Ambiguous
    }

    /// 是否值得重试（`Transient | Ambiguous`）——relay 据此退避重试至预算耗尽。
    pub fn is_retryable(&self) -> bool {
        matches!(
            self.kind,
            PublishErrorKind::Transient | PublishErrorKind::Ambiguous
        )
    }

    /// 是否永久（`Permanent`）——relay 据此首投即 DLX，跳过重试预算。
    pub fn is_permanent(&self) -> bool {
        self.kind == PublishErrorKind::Permanent
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
/// 字节，`metadata` 是统一 delivery envelope（[`EnvelopeMetadata`]，relay 从 `outbox.metadata` 列透传）。
///
/// 字段私有 + 构造器 funnel（[`PublishRequest::new`] + [`PublishRequest::with_metadata`]）：业务 / relay
/// 不能裸构造 metadata 字段，envelope 写面收口在 [`EnvelopeMetadata`] 两层入口（见其 rustdoc）。
///
/// **correlation** 经 ambient [`diagctx`] 诊断信道在 outbox emit 点注入 `outbox.metadata`（ADR-002 §D1-bis；
/// **非** `runctx::RequestCtx`——后者只承载授权用 tenant / principal）；**租户**经 `runctx::RequestCtx` 解析。
/// 跨域 wire 类型单源仍是 contract——`payload` 由 `eventexec`/outbox 层按 contract envelope 预编码后传入，
/// DI-infra port **不**引 `generated`（ADR-003 §6 偏离 2）。字段集随消费域细化（pre-GA 可原地加 content-type 等）。
#[derive(Debug, Clone)]
pub struct PublishRequest {
    topic: Topic,
    event_id: MessageId,
    payload: RedactedBytes,
    metadata: EnvelopeMetadata,
}

impl PublishRequest {
    /// 构造发布请求（metadata 默认空 bag）。topic / event_id / payload 必填位置参。
    pub fn new(topic: Topic, event_id: MessageId, payload: Vec<u8>) -> Self {
        Self {
            topic,
            event_id,
            payload: RedactedBytes::new(payload),
            metadata: EnvelopeMetadata::empty(),
        }
    }

    /// 携统一 delivery envelope metadata（relay 从 `outbox.metadata` 列 hydrate 后调用）。
    #[must_use]
    pub fn with_metadata(mut self, metadata: EnvelopeMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// 目标 topic。
    pub fn topic(&self) -> &Topic {
        &self.topic
    }

    /// 事件去重锚点（= outbox `event_id` / `Entry::idem_key`）。relay 据此盖章 broker `message_id`，
    /// 经订阅侧 `Message::id()` 流回消费幂等键（`run_consumer` 的 `IdemKey`），实现「至少一次 + 幂等 =
    /// 有效一次」端到端去重（`contracts/**/contract.toml`、`generated` 与 `crates/consistency`）。路由元数据，非 PII。
    pub fn event_id(&self) -> &MessageId {
        &self.event_id
    }

    /// provider-agnostic 事件字节（已按 contract envelope 编码）。
    pub fn payload(&self) -> &[u8] {
        self.payload.as_bytes()
    }

    /// 统一 delivery envelope metadata；publisher 只能外发 transport-safe view（trace / correlation /
    /// occurredAt / tenantId / tenantAuthority）。
    pub fn metadata(&self) -> &EnvelopeMetadata {
        &self.metadata
    }

    /// 将发布请求视为标准 delivery envelope；缺 tenant/schema header 时 fail-closed。
    pub fn try_envelope(&self) -> Result<MessageEnvelope, EnvelopeHeaderError> {
        MessageEnvelope::try_from_metadata(
            self.payload.as_bytes().to_vec(),
            self.metadata.clone(),
            None,
        )
    }

    /// 只解析标准 delivery envelope header；不 materialize payload。
    pub fn try_header(&self) -> Result<EnvelopeHeader, EnvelopeHeaderError> {
        EnvelopeHeader::try_from_metadata(&self.metadata, None)
    }

    /// move 出 payload（adapter publish 避 clone）。
    pub fn into_payload(self) -> Vec<u8> {
        self.payload.into_bytes()
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
    use super::{
        DynPublisher, MessageId, PublishErrorKind, PublishRequest, Publisher, PublisherError, Topic,
    };

    #[test]
    fn publisher_error_wraps_source() {
        let err = PublisherError::transient(std::io::Error::other("leak-marker-pub"));
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

    // transient / permanent / ambiguous 构造器 → kind 往返 +
    // is_ambiguous/is_retryable/is_permanent 真值表（镜像 consistency::EngineError 真值表测试）。
    // 三种 kind 的 source 均经 RedactedSource 脱敏，Display/Debug 边界相同。
    #[test]
    fn publisher_error_kind_classification() {
        let cases: &[(&str, PublisherError, PublishErrorKind, bool, bool, bool)] = &[
            (
                "leak-marker-transient",
                PublisherError::transient(std::io::Error::other("leak-marker-transient")),
                PublishErrorKind::Transient,
                false,
                true,
                false,
            ),
            (
                "leak-marker-permanent",
                PublisherError::permanent(std::io::Error::other("leak-marker-permanent")),
                PublishErrorKind::Permanent,
                false,
                false,
                true,
            ),
            (
                "leak-marker-ambiguous",
                PublisherError::ambiguous(std::io::Error::other("leak-marker-ambiguous")),
                PublishErrorKind::Ambiguous,
                true,
                true,
                false,
            ),
        ];
        for (marker, err, kind, ambiguous, retryable, permanent) in cases {
            assert_eq!(err.kind(), *kind, "kind mismatch");
            assert_eq!(err.is_ambiguous(), *ambiguous, "is_ambiguous kind={kind:?}");
            assert_eq!(err.is_retryable(), *retryable, "is_retryable kind={kind:?}");
            assert_eq!(err.is_permanent(), *permanent, "is_permanent kind={kind:?}");
            // Display/source/Debug 脱敏不随 kind 改变（PII 边界恒定）。
            assert_eq!(err.to_string(), "publish failed", "Display kind={kind:?}");
            assert!(
                std::error::Error::source(err).is_some(),
                "source present kind={kind:?}"
            );
            assert!(
                format!("{:?}", std::io::Error::other(*marker)).contains(*marker),
                "anti-vacuity: raw source Debug omitted marker kind={kind:?}"
            );
            assert!(
                !format!("{err:?}").contains(*marker),
                "wrapper Debug leaked source kind={kind:?}: {err:?}"
            );
        }
        assert_ne!(PublishErrorKind::Transient, PublishErrorKind::Permanent);
        assert_ne!(PublishErrorKind::Transient, PublishErrorKind::Ambiguous);
        assert_ne!(PublishErrorKind::Permanent, PublishErrorKind::Ambiguous);
    }

    // permanent 路径同样经 RedactedSource 脱敏，不泄漏内层 source（与 transient 路径对称回归）。
    #[test]
    fn publisher_error_permanent_redacts_source() {
        let err = PublisherError::permanent(std::io::Error::other("leak-marker-perm"));
        assert!(
            format!("{:?}", std::io::Error::other("leak-marker-perm")).contains("leak-marker-perm"),
            "前提失效：内层 Debug 未携 marker"
        );
        assert!(
            !format!("{err:?}").contains("leak-marker-perm"),
            "permanent wrapper Debug 泄漏 source: {err:?}"
        );
    }

    fn sample_request() -> PublishRequest {
        PublishRequest::new(
            Topic::new("session.created"),
            MessageId::new("evt-1"),
            b"evt".to_vec(),
        )
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
mod metadata_carry {
    //! `PublishRequest` 携 [`EnvelopeMetadata`] 往返 + accessor。
    use super::{MessageId, PublishRequest, Topic};
    use crate::envelope::{EnvelopeMetadata, KEY_OCCURRED_AT, KEY_SUBJECT_ID};

    #[test]
    fn new_defaults_to_empty_metadata() {
        let req = PublishRequest::new(Topic::new("t"), MessageId::new("e"), b"p".to_vec());
        assert!(req.metadata().is_empty());
        assert_eq!(req.topic().as_str(), "t");
        assert_eq!(req.event_id().as_str(), "e");
        assert_eq!(req.payload(), b"p");
    }

    #[test]
    fn with_metadata_carries_envelope() {
        let mut md = EnvelopeMetadata::empty();
        md.insert_wire_pair(KEY_OCCURRED_AT, "1700000000");
        md.insert_wire_pair(KEY_SUBJECT_ID, "user-7");
        let req = PublishRequest::new(Topic::new("t"), MessageId::new("e"), b"p".to_vec())
            .with_metadata(md);
        assert_eq!(req.metadata().get(KEY_OCCURRED_AT), Some("1700000000"));
        assert_eq!(req.metadata().get(KEY_SUBJECT_ID), Some("user-7"));
        // into_payload move 出字节。
        assert_eq!(req.into_payload(), b"p".to_vec());
    }
}

#[cfg(test)]
mod pii_debug {
    //! `PublishRequest.payload`（事件序列化体，可能含 PII）字节 Debug 脱敏回归。
    //! INVARIANT: DIPORT-DTO-BYTES-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（payload 经 `RedactedBytes` 脱敏；`derive(Debug)` 即安全）。
    use super::{MessageId, PublishRequest, Topic};
    use crate::envelope::{EnvelopeMetadata, KEY_SUBJECT_ID};

    #[test]
    fn publish_request_debug_redacts_payload_and_subject() {
        // anti-vacuity：原始 Vec<u8> Debug 把 0xDE 渲染成 "222"，证明 "!contains(222)" 检测非空转。
        assert!(
            format!("{:?}", vec![0xDE_u8]).contains("222"),
            "前提失效：检测字节不在原始 Debug"
        );
        let mut md = EnvelopeMetadata::empty();
        let _ = md.try_insert(KEY_SUBJECT_ID, "SECRET_SUBJECT");
        let req = PublishRequest::new(
            Topic::new("session.created"),
            MessageId::new("evt-routing-id"),
            vec![0xDE, 0xAD, 0xBE, 0xEF],
        )
        .with_metadata(md);
        let dbg = format!("{req:?}");
        assert!(!dbg.contains("222"), "payload 字节泄漏(0xDE=222): {dbg}");
        assert!(!dbg.contains("173"), "payload 字节泄漏(0xAD=173): {dbg}");
        assert!(!dbg.contains("SECRET_SUBJECT"), "subjectId 值泄漏: {dbg}");
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
        assert!(dbg.contains("session.created"), "topic 应可见: {dbg}");
        // event_id 是路由元数据（去重锚点），应可见——非 PII。
        assert!(dbg.contains("evt-routing-id"), "event_id 应可见: {dbg}");
    }
}
