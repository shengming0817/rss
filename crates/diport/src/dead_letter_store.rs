//! `DeadLetterStore` —— 死信持久化 DI port（可替换：prod postgres / test in-mem）。
//!
//! 消费方在重试预算耗尽后调用 `write_dead_letter` 持久化死信记录，供运维巡检 / 重放。
//! `DeadLetterRecord.tenant` 是 DLX RLS scope 的 typed 锚点；`original_payload` 是原始消息字节，
//! **完整存入** `dead_letter.original_entry` 供重放 / 巡检（无 DB 侧脱敏）；PII 保留策略属后续治理（backlog 跟踪）。
//! Debug 输出一律隐藏（INVARIANT: DIPORT-DTO-PII-DEBUG-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }）。

use dynosaur::dynosaur;

use crate::envelope::EnvelopeMetadata;
use crate::redacted::RedactedSource;
use crate::redacted_bytes::RedactedBytes;

// ── DeadLetterSummary ─────────────────────────────────────────────────────────

/// DLX 安全摘要（类型层 PII 边界，Hard）。
///
/// 内层固定为 `&'static str` const literal——从类型层**杜绝**任意 runtime `String` / handler 错误原文 /
/// payload 片段流入死信摘要字段（对标 `vocab` 错误 message 的 `&'static str` const-literal 约束，
/// error-handling.md §Message 与 PII）。[`DeadLetterRecord::new`] 只经本 newtype 接收摘要，故摘要只能是
/// 编译期作者控制的常量、不可由运行期数据伪造（input struct field exclusion + newtype funnel）——
/// 不再靠「调用方记得脱敏」的 rustdoc 纪律（review #216 F7）。
/// INVARIANT: DIPORT-DLX-SUMMARY-STATIC-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary", facet = "summary-type" }（回归见 `summary` 单测；「不可传 `String`」由类型层编译期保证）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeadLetterSummary(&'static str);

impl DeadLetterSummary {
    /// 由编译期 const literal 构造安全摘要。`const fn`——可在常量上下文构造（消费方 `SUMMARY_*` 常量）。
    pub const fn new(summary: &'static str) -> Self {
        Self(summary)
    }

    /// 借出摘要文本（`&'static str` const literal）。
    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

// ── DeadLetterRecord ─────────────────────────────────────────────────────────

/// 死信来源单源。
///
/// Historical rows are rejected by the forward-only v3 migration; every row has exact provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadLetterSource {
    /// 消费方重试预算耗尽后进入 DLQ。
    Consumer,
    /// outbox relay 发布失败进入 DLX，同时登记统一 DLQ 审计行。
    OutboxRelay,
    /// saga 补偿失败进入 DLQ。
    Saga,
    /// projection poison event 进入 DLQ。
    Projection,
}

impl DeadLetterSource {
    /// DB/API 稳定 wire 值。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Consumer => "consumer",
            Self::OutboxRelay => "outbox_relay",
            Self::Saga => "saga",
            Self::Projection => "projection",
        }
    }

    /// Parse DB/API stable wire value.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "consumer" => Some(Self::Consumer),
            "outbox_relay" => Some(Self::OutboxRelay),
            "saga" => Some(Self::Saga),
            "projection" => Some(Self::Projection),
            _ => None,
        }
    }
}

/// Closed provenance of a newly written dead letter.
///
/// Producer and consumer domains are separate typed fields. Replay routing always uses the
/// producer domain; consumer attribution is present only for consumer/projection failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeadLetterProvenance {
    Consumer {
        producer_domain: String,
        consumer_domain: String,
    },
    OutboxRelay {
        producer_domain: String,
    },
    Saga {
        producer_domain: String,
    },
    Projection {
        producer_domain: String,
        consumer_domain: String,
    },
}

impl DeadLetterProvenance {
    pub fn consumer(
        producer_domain: impl Into<String>,
        consumer_domain: impl Into<String>,
    ) -> Self {
        Self::Consumer {
            producer_domain: producer_domain.into(),
            consumer_domain: consumer_domain.into(),
        }
    }

    pub fn outbox_relay(producer_domain: impl Into<String>) -> Self {
        Self::OutboxRelay {
            producer_domain: producer_domain.into(),
        }
    }

    pub fn saga(producer_domain: impl Into<String>) -> Self {
        Self::Saga {
            producer_domain: producer_domain.into(),
        }
    }

    pub fn projection(
        producer_domain: impl Into<String>,
        consumer_domain: impl Into<String>,
    ) -> Self {
        Self::Projection {
            producer_domain: producer_domain.into(),
            consumer_domain: consumer_domain.into(),
        }
    }

    pub const fn source(&self) -> DeadLetterSource {
        match self {
            Self::Consumer { .. } => DeadLetterSource::Consumer,
            Self::OutboxRelay { .. } => DeadLetterSource::OutboxRelay,
            Self::Saga { .. } => DeadLetterSource::Saga,
            Self::Projection { .. } => DeadLetterSource::Projection,
        }
    }

    pub fn producer_domain(&self) -> &str {
        match self {
            Self::Consumer {
                producer_domain, ..
            }
            | Self::OutboxRelay { producer_domain }
            | Self::Saga { producer_domain }
            | Self::Projection {
                producer_domain, ..
            } => producer_domain,
        }
    }

    pub fn consumer_domain(&self) -> Option<&str> {
        match self {
            Self::Consumer {
                consumer_domain, ..
            }
            | Self::Projection {
                consumer_domain, ..
            } => Some(consumer_domain),
            Self::OutboxRelay { .. } | Self::Saga { .. } => None,
        }
    }
}

/// 死信写入记录（值类型，单一 funnel 构造）。
///
/// `original_payload` 是原始消息字节，可能含 PII；经 [`RedactedBytes`] 持有（`Debug` 恒 `<redacted>`、经
/// `original_payload()` 受控读取）。`metadata` 来自 broker/header，可能含业务自定义 PII，`Debug` 手写为
/// `<redacted>`（INVARIANT: DIPORT-DTO-BYTES-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }）。
/// 其余字段（`domain` / `contract_id` / `topic` / `error_summary` / `num_attempts`）均为
/// 运维归因元数据，可观测。
#[derive(Clone)]
pub struct DeadLetterRecord {
    provenance: DeadLetterProvenance,
    contract_id: String,
    topic: String,
    consumer_group: Option<String>,
    tenant: vocab::TenantId,
    message_id: String,
    original_payload: RedactedBytes,
    metadata: EnvelopeMetadata,
    /// 安全摘要——类型层强制 `&'static str` const literal（经 [`DeadLetterSummary`] funnel），
    /// 不含 runtime 数据 / 原始 payload / handler 错误原文（INVARIANT: DIPORT-DLX-SUMMARY-STATIC-01 { level = "Medium", exec = "manual/opt-in", source = "code", facet = "content-test" }）。
    error_summary: &'static str,
    num_attempts: u32,
}

impl std::fmt::Debug for DeadLetterRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeadLetterRecord")
            .field("provenance", &self.provenance)
            .field("contract_id", &self.contract_id)
            .field("topic", &self.topic)
            .field("consumer_group", &self.consumer_group)
            .field("tenant", &self.tenant)
            .field("message_id", &self.message_id)
            .field("original_payload", &self.original_payload)
            .field("metadata", &"<redacted>")
            .field("error_summary", &self.error_summary)
            .field("num_attempts", &self.num_attempts)
            .finish()
    }
}

impl DeadLetterRecord {
    /// 单一 funnel 构造（私有字段，外部只能经此入口）。
    ///
    /// # 摘要 PII 边界（类型层 Hard）
    ///
    /// `error_summary: DeadLetterSummary` 只能由编译期 const literal 构造（见 [`DeadLetterSummary`]）——
    /// 任意 runtime `String` / handler 错误原文 / payload 片段**无法**流入死信摘要字段（不再靠调用方
    /// 脱敏纪律，review #216 F7）。`consumer.rs` 经 `SUMMARY_*` 常量构造，天然满足。
    #[allow(clippy::too_many_arguments)]
    // reason: DLX 记录的 tenant/message/domain/contract/topic/payload/summary/attempts 均为必填审计字段；
    // 聚合 builder 会重新引入 tenantless 中间态，本构造器刻意保持一次性完整信封。
    pub fn new(
        tenant: vocab::TenantId,
        message_id: impl Into<String>,
        provenance: DeadLetterProvenance,
        contract_id: impl Into<String>,
        topic: impl Into<String>,
        consumer_group: Option<String>,
        original_payload: Vec<u8>,
        error_summary: DeadLetterSummary,
        num_attempts: u32,
        metadata: EnvelopeMetadata,
    ) -> Self {
        Self {
            provenance,
            contract_id: contract_id.into(),
            topic: topic.into(),
            consumer_group,
            tenant,
            message_id: message_id.into(),
            original_payload: RedactedBytes::new(original_payload),
            metadata,
            error_summary: error_summary.as_str(),
            num_attempts,
        }
    }

    /// Producer domain used for replay routing.
    pub fn producer_domain(&self) -> &str {
        self.provenance.producer_domain()
    }

    /// Consumer domain attribution, when this source has a downstream consumer.
    pub fn consumer_domain(&self) -> Option<&str> {
        self.provenance.consumer_domain()
    }

    /// Closed source/domain provenance.
    pub fn provenance(&self) -> &DeadLetterProvenance {
        &self.provenance
    }

    /// 借出 contract_id。
    pub fn contract_id(&self) -> &str {
        &self.contract_id
    }

    /// 借出 topic。
    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// 借出 consumer group（consumer 来源有值；非 consumer 来源为 `None`）。
    pub fn consumer_group(&self) -> Option<&str> {
        self.consumer_group.as_deref()
    }

    /// 借出租户标识（DLX RLS scope）。
    pub fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    /// 借出消息标识（broker / producer 关联键）。
    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    /// 借出原始 payload 字节。
    ///
    /// PII 边界由 [`RedactedBytes`] 类型保证（`Debug` 恒 `<redacted>`），本访问器仅供 provider 持久化收发字节。
    pub fn original_payload(&self) -> &[u8] {
        self.original_payload.as_bytes()
    }

    /// 原始 payload 长度（可观测，不含内容）。
    pub fn payload_len(&self) -> usize {
        self.original_payload.len()
    }

    /// 死信来源。
    pub fn source(&self) -> DeadLetterSource {
        self.provenance.source()
    }

    /// 原始 delivery metadata（用于重放时保留 trace/correlation/tenant 等 envelope 信息）。
    pub fn metadata(&self) -> &EnvelopeMetadata {
        &self.metadata
    }

    /// 借出已脱敏错误摘要（`&'static str` const literal，见 [`DeadLetterSummary`]）。
    pub fn error_summary(&self) -> &str {
        self.error_summary
    }

    /// 已重试次数。
    pub fn num_attempts(&self) -> u32 {
        self.num_attempts
    }
}

// ── DeadLetterStoreError ──────────────────────────────────────────────────────

/// 死信写入失败。
///
/// PII 边界（与 [`crate::SignerError`] 同范式）：`Display` 仅输出安全摘要常量；source 经 [`RedactedSource`]
/// 脱敏（`Debug`/`Display` 固定 `<redacted>`、`Error::source()` 恒 `None`——原始错误不经任何 `Error` 接口暴露，
/// fail-closed），见 INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。`secure::redact_error` funnel 取顶层 Display、不遍历 source 链。
#[derive(Debug, thiserror::Error)]
#[error("dead letter write failed")]
pub struct DeadLetterStoreError {
    #[source]
    source: RedactedSource,
}

impl DeadLetterStoreError {
    /// 把 adapter 内部错误包成死信写入失败。原始错误仅 owned 保留，不经任何 `Error` 接口暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: RedactedSource::new(source),
        }
    }
}

// ── DeadLetterStore DI port（async）──────────────────────────────────────────

/// 死信持久化 DI port（async）。
///
/// 公开 [`DeadLetterStore`] 是 **Send 变体**（adapters `impl DeadLetterStore for ...`），
/// [`DynDeadLetterStore`] 是其 dyn-compatible wrapper（组合根经 `Box<DynDeadLetterStore>` 注入）。
/// 非 Send 基 trait `DeadLetterStoreLocal` 仅供静态分发窄场景，不在 crate 根 re-export（见 crate rustdoc）。
///
/// dyn-safe 约束（ADR-003 §4.6）：方法 `&self`、参数 / 返回为具体类型、supertrait 仅 Send、
/// 带 `async fn shutdown`（无 async Drop）。
#[trait_variant::make(DeadLetterStore: Send)]
#[dynosaur(pub DynDeadLetterStore = dyn(box) DeadLetterStore, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `DeadLetterStore` 变体 +
// dynosaur `DynDeadLetterStore` 承载（DI 注入走 Send wrapper）。这是 ADR-003 既定 dyn-port 范式。
pub trait DeadLetterStoreLocal {
    /// 持久化一条死信记录（消费方重试预算耗尽后调用）。
    ///
    /// 实现必须幂等安全（上层可能在 transient 失败后重试）。
    async fn write_dead_letter(&self, record: DeadLetterRecord)
    -> Result<(), DeadLetterStoreError>;

    /// 异步释放 provider 资源（无 async Drop；infra teardown 显式异步）。
    ///
    /// 有 infra 资源（连接 / 句柄）的 adapter 应同时 `impl ManagedResource`，由
    /// `bootstrap::ShutdownStack` 统一编排；本方法是 port-local 关闭路径。
    async fn shutdown(&self) -> Result<(), DeadLetterStoreError>;
}

// ── 测试 ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod smoke {
    //! build smoke：证明 async DI port 可 native AFIT impl + 经 `Box<DynDeadLetterStore>` 动态注入。
    use super::{
        DeadLetterProvenance, DeadLetterRecord, DeadLetterStore, DeadLetterStoreError,
        DeadLetterSummary, DynDeadLetterStore,
    };
    use crate::EnvelopeMetadata;

    fn sample_record() -> DeadLetterRecord {
        DeadLetterRecord::new(
            tenant(),
            "message-1",
            DeadLetterProvenance::consumer("identity", "audit"),
            "contract-session",
            "session.created",
            Some("identity.session.consumer".to_string()),
            b"payload".to_vec(),
            DeadLetterSummary::new("max retries exhausted"),
            10,
            EnvelopeMetadata::empty(),
        )
    }

    struct NoopDeadLetterStore;
    impl DeadLetterStore for NoopDeadLetterStore {
        async fn write_dead_letter(
            &self,
            _record: DeadLetterRecord,
        ) -> Result<(), DeadLetterStoreError> {
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
            Ok(())
        }
    }

    #[allow(clippy::expect_used)]
    fn tenant() -> vocab::TenantId {
        vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("canonical tenant")
    }

    // multi_thread + spawn：boxed future 须 Send（trait_variant Send 变体）才能跨 worker 调度——
    // current-thread 不暴露 Send 违规，故用 multi_thread 真正验证 dyn 注入的 Send 语义。
    #[tokio::test(flavor = "multi_thread")]
    async fn dead_letter_store_is_dyn_injectable() {
        let store: Box<DynDeadLetterStore> = DynDeadLetterStore::new_box(NoopDeadLetterStore);
        let joined = tokio::spawn(async move {
            store.write_dead_letter(sample_record()).await.is_ok() && store.shutdown().await.is_ok()
        })
        .await;
        assert!(matches!(joined, Ok(true)));
    }

    mockall::mock! {
        TestDeadLetterStore {}
        impl DeadLetterStore for TestDeadLetterStore {
            async fn write_dead_letter(&self, record: DeadLetterRecord) -> Result<(), DeadLetterStoreError>;
            async fn shutdown(&self) -> Result<(), DeadLetterStoreError>;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mockall_mock_loads_into_dyn_dead_letter_store() {
        let mut mock = MockTestDeadLetterStore::new();
        mock.expect_write_dead_letter().returning(|_| Ok(()));
        let store: Box<DynDeadLetterStore> = DynDeadLetterStore::new_box(mock);
        let joined =
            tokio::spawn(async move { store.write_dead_letter(sample_record()).await }).await;
        assert!(matches!(joined, Ok(Ok(()))));
    }
}

#[cfg(test)]
mod pii_debug {
    //! `DeadLetterRecord.original_payload`（原始消息字节，可能含 PII）Debug 脱敏回归。
    //! INVARIANT: DIPORT-DTO-PII-DEBUG-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（对标 `SignRequest.message` / `Message.payload`）。
    use super::{DeadLetterProvenance, DeadLetterRecord, DeadLetterSummary};
    use crate::EnvelopeMetadata;

    #[allow(clippy::expect_used)]
    fn tenant() -> vocab::TenantId {
        vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("canonical tenant")
    }

    #[test]
    fn dead_letter_record_debug_redacts_payload() {
        // anti-vacuity：原始 Vec<u8> Debug 把 0xDE 渲染成 "222"，证明 "!contains(222)" 检测非空转。
        assert!(
            format!("{:?}", vec![0xDE_u8]).contains("222"),
            "前提失效：检测字节不在原始 Debug"
        );
        let record = DeadLetterRecord::new(
            tenant(),
            "message-1",
            DeadLetterProvenance::consumer("identity", "audit"),
            "contract-session",
            "session.created",
            Some("identity.session.consumer".to_string()),
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            DeadLetterSummary::new("max retries exhausted"),
            10,
            EnvelopeMetadata::empty(),
        );
        let dbg = format!("{record:?}");
        assert!(!dbg.contains("222"), "payload 字节泄漏(0xDE=222): {dbg}");
        assert!(!dbg.contains("173"), "payload 字节泄漏(0xAD=173): {dbg}");
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
        assert!(dbg.contains("identity"), "domain 应可见: {dbg}");
        assert!(
            dbg.contains("f47ac10b-58cc-4372-a567-0e02b2c3d479"),
            "tenant 应可见: {dbg}"
        );
        assert!(dbg.contains("message-1"), "message_id 应可见: {dbg}");
        assert!(dbg.contains("session.created"), "topic 应可见: {dbg}");
        assert!(
            dbg.contains("max retries exhausted"),
            "error_summary 应可见: {dbg}"
        );
    }

    #[test]
    fn dead_letter_record_debug_redacts_metadata_values() {
        let mut metadata = EnvelopeMetadata::empty();
        assert!(metadata.try_insert("email", "alice@example.test").is_ok());
        assert!(
            metadata
                .try_insert("customerHeader", "secret-header")
                .is_ok()
        );

        let record = DeadLetterRecord::new(
            tenant(),
            "message-1",
            DeadLetterProvenance::consumer("identity", "audit"),
            "contract-session",
            "session.created",
            Some("identity.session.consumer".to_string()),
            b"payload".to_vec(),
            DeadLetterSummary::new("max retries exhausted"),
            10,
            metadata,
        );
        let dbg = format!("{record:?}");
        assert!(
            !dbg.contains("alice@example.test"),
            "metadata PII leaked: {dbg}"
        );
        assert!(
            !dbg.contains("secret-header"),
            "metadata custom value leaked: {dbg}"
        );
        assert!(dbg.contains("metadata"));
        assert!(dbg.contains("<redacted>"));
    }
}

#[cfg(test)]
mod summary {
    //! `DeadLetterSummary` 安全摘要 newtype——类型层强制 `&'static str` const literal。
    //! INVARIANT: DIPORT-DLX-SUMMARY-STATIC-01 { level = "Medium", exec = "manual/opt-in", source = "code", facet = "content-test" }.
    //!
    //! 类型层「不可传 runtime `String`」由编译期保证（`DeadLetterRecord::new` 的 `error_summary`
    //! 形参类型为 `DeadLetterSummary`，无 `From<String>` / `Into` 通路）——故无运行期红用例可写；
    //! 本测试覆盖 const-fn 构造可用性 + 往返。
    use super::DeadLetterSummary;

    #[test]
    fn summary_round_trips_via_const_fn() {
        // const 上下文构造（消费方 SUMMARY_* 常量同款用法）。
        const S: DeadLetterSummary = DeadLetterSummary::new("requeue budget exhausted");
        assert_eq!(S.as_str(), "requeue budget exhausted");
    }
}

#[cfg(test)]
mod tenant_scope {
    //! `DeadLetterRecord` 必须携 typed tenant + message_id。
    use super::{DeadLetterProvenance, DeadLetterRecord, DeadLetterSource, DeadLetterSummary};
    use crate::EnvelopeMetadata;

    #[test]
    #[allow(clippy::expect_used)]
    fn tenant_and_message_id_round_trip() {
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical tenant");
        let record = DeadLetterRecord::new(
            tenant,
            "msg-tenant-1",
            DeadLetterProvenance::consumer("identity", "audit"),
            "contract-session",
            "session.created",
            Some("identity.session.consumer".to_string()),
            b"payload".to_vec(),
            DeadLetterSummary::new("max retries exhausted"),
            10,
            EnvelopeMetadata::empty(),
        );
        assert_eq!(record.tenant(), tenant);
        assert_eq!(record.message_id(), "msg-tenant-1");
        assert_eq!(record.consumer_group(), Some("identity.session.consumer"));
        assert_eq!(record.source(), DeadLetterSource::Consumer);
    }
}

#[cfg(test)]
mod error_redaction {
    //! `DeadLetterStoreError` derive(Debug) 经 `RedactedSource` 不展开 source（adapter 原始错误可能携连接串/凭据），
    //! 且 `Error::source()` 恒 `None`（fail-closed source 链）。
    //! INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（对标 `SignerError`，PR #215 RedactedSource 统一）。
    use super::DeadLetterStoreError;

    #[test]
    fn error_debug_redacts_source() {
        let secret = std::io::Error::other("postgres://user:hunter2@db.internal:5432/rss");
        // anti-vacuity：原始 source 自身 Debug 确实携密，否则回归断言空转。
        assert!(
            format!("{secret:?}").contains("hunter2"),
            "前提失效：source 未携密"
        );
        let err = DeadLetterStoreError::new(secret);
        let rendered = format!("{err:?}");
        assert!(
            !rendered.contains("hunter2") && !rendered.contains("postgres://"),
            "Debug 泄漏 source: {rendered}"
        );
        // fail-closed source 链：标准递归遍历在 RedactedSource（Debug=<redacted>、其 source() 恒 None）处
        // 终止，永不到达原始 adapter 错误——逐级走链断言无泄漏。
        let mut cur = std::error::Error::source(&err);
        while let Some(e) = cur {
            assert!(
                !format!("{e:?}").contains("hunter2") && !format!("{e:?}").contains("postgres://"),
                "source 链泄漏原始错误: {e:?}"
            );
            cur = e.source();
        }
    }
}
