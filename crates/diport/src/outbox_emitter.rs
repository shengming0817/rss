//! `OutboxEmitter` —— durable outbox 发射 provider DI port（可替换：prod postgres / demo in-mem）。
//!
//! 域 crate 经此 port 把一条 [`consistency::Entry`]（topic + idem_key(EventId) + 编码 payload）落 durable
//! outbox（与契约声明的 L2 OutboxFact 语义同源）。**域不能命名 `PgConnection` / `OutboxEnvelope`**
//! （域→adapter 被 `deny.toml` 禁），故 envelope 字段以 opaque [`OutboxEnvelopeParts`] 传入，由 adapter
//! 组装 provider 私有 envelope（reserved key `occurredAt` 在 adapter 受控构造点经注入 `Clock` 注入，#1129；
//! trace 待 #1076 OTel；correlation 已接线 #1160；principal 待 #1397；业务均不得伪造，FR-020 /
//! `docs/rules/observability.md` §Outbox Envelope）。
//!
//! 与 [`crate::Publisher`] 的分工：`Publisher` 是 relay 把**已持久化** entry 直发到 broker 的端口；
//! `OutboxEmitter` 是 producer 把业务事件**持久化进 durable outbox**（含幂等锚点 EventId）的端口——
//! 二者语义正交，故为不同 port（不复用 `Publisher` 的 fire-and-forget 语义）。
//!
//! **单事实 emit 语义**：本 port 保证一条 [`Entry`] 的 durable 落库原子性（单 outbox 写自成事务）——
//! 用于**无 co-located 业务写**的 OutboxFact 事件（纯通知）。与业务写同事务的 **co-tx 原子性**（FR-003
//! 完整 L2，如 session 持久化与 outbox append 同一 `PgTransaction`）**已交付**（#1083/#1192）：经各域**域形
//! Unit-of-Work 端口**（如 `identity::ports::SessionLifecycle`，combined 方法把业务写 + `append_outbox`
//! 收进同一事务）承载，与本 emit-only port 语义正交（二者并存：emit-only 路由纯事件、UoW 路由 co-tx）。
//! 本 port 的单事实 emit 语义不变。
//!
//! ref: debezium outbox SMT（业务写 + outbox 行同一本地事务，producer 侧 durable 落库）
//! ref: eventuate-tram-core io.eventuate.tram.consumer.common.DuplicateMessageDetector@master
//!      （message-id 作幂等键，对应 RSS `inbox_dedup(event_id, consumer_group)`）

use dynosaur::dynosaur;

use consistency::Entry;

use crate::redacted::RedactedSource;

/// outbox 发射失败。
///
/// PII 边界（与 [`crate::PublisherError`] 同范式）：`Display` 仅安全摘要常量；source 经
/// [`RedactedSource`] 脱敏（`Debug` / `Display` 固定 `<redacted>`、`Error::source()` 恒 `None`），见
/// INVARIANT: DIPORT-ERR-SOURCE-REDACT-01。
#[derive(Debug, thiserror::Error)]
#[error("outbox emit failed")]
pub struct OutboxEmitError {
    #[source]
    source: RedactedSource,
}

impl OutboxEmitError {
    /// 把 adapter 内部错误包成发射失败。原始错误仅作 internal source 保留，不经 `Display` 暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: RedactedSource::new(source),
        }
    }
}

/// outbox envelope 的 **opaque** 字段集（域传，adapter 组装成 provider 私有 envelope）。
///
/// 仅承载非-reserved、可由业务安全提供的字段：`contract`（[`vocab::ContractBinding`]，domain + contract_id
/// 同源契约归属，#1193——business 不再裸 string 分别 author，杜绝 domain/contract_id 漂移）、`subject_id` 是
/// **opaque** 主体标识（FR-020：不容完整 Principal / email / 姓名等 PII）、`partition_key` 是可选有序投递
/// 分区键（`None` = 无序并行；`Some` = 同 partition 串行有序，#1211）。reserved envelope key
/// （trace / correlation / principal / occurredAt）**不在此**——由 adapter 在受控构造点注入（`occurredAt`
/// 取注入 `Clock`，#1129；trace 待 #1076 OTel；correlation 已接线 #1160；principal 待 #1397）。
///
/// 字段私有 + 构造器 [`OutboxEnvelopeParts::new`]（input-struct-field-exclusion，**Hard**）：business 不能绕过
/// 构造器分别 set domain/contract_id 字段，只能给 `(contract, subject_id)`。`contract` 的**预期**来源是
/// `generated::event::{domain}_v1::CONTRACT`（契约派生常量 + golden 锁，CONTRACT-BINDING-FUNNEL-01，**Medium**）——
/// 但 `vocab::ContractBinding::from_static` 是普通 `pub` 构造器，业务**仍可裸构造**任意绑定（residual，非 Hard；
/// 同 `ContractOwner::of_domain`，统一守卫见 #1327 / #1091）。
///
/// INVARIANT: DIPORT-DTO-PII-DEBUG-REDACT-01 —— `Debug` 仅输出路由元数据（`contract` 的 domain / contract_id）；
/// `subject_id` 固定渲染为 `<redacted>`；`partition_key` 只渲染 presence（Some/None），其值经 `PartitionKey`
/// 脱敏 Debug 收口为 `<redacted>`（可能凭据级，如 tenant-scoped 含 sessionId，F3 #1211 review）。防主体标识 /
/// 分区键经 `{:?}` 泄漏至日志（回归见 `pii_debug` 单测）。
#[derive(Clone)]
pub struct OutboxEnvelopeParts {
    /// 契约绑定（domain + contract_id 同源；`generated::…::CONTRACT`）。
    contract: vocab::ContractBinding,
    /// opaque 主体标识（无 PII）。
    subject_id: String,
    /// 可选有序投递分区键（`None` = 无序并行；`Some` = 同 partition 串行有序，#1211）。
    partition_key: Option<consistency::PartitionKey>,
}

impl OutboxEnvelopeParts {
    /// 构造 envelope parts——`contract` 经契约派生常量绑定（非裸 string），`subject_id` 是 opaque 主体标识。
    /// `partition_key` 默认 `None`（无序并行）；需有序投递时经 [`OutboxEnvelopeParts::with_partition_key`] 设置。
    pub fn new(contract: vocab::ContractBinding, subject_id: impl Into<String>) -> Self {
        Self {
            contract,
            subject_id: subject_id.into(),
            partition_key: None,
        }
    }

    /// 设置有序投递分区键（builder，#1211）。
    ///
    /// 设置后同 `(domain, partition_key)` 的 outbox 行严格按 `seq` 顺序投递（head-of-partition gating）；
    /// 未设（`None`）时与现有行为完全兼容——无序并行投递。
    ///
    /// **⚠ 必须 tenant-scoped**：`partition_key` **必须自带 tenant scope**（含 tenantId 或全局唯一如
    /// sessionId）——outbox 表无 `tenant_id` 列、gating 仅按 `(domain, partition_key)`，无 tenant scope 的
    /// 裸 aggregate id 跨租户碰撞会让租户 A 的队头阻塞租户 B（liveness DoS）。推荐 `<tenantId>:<aggregateId>`
    /// 或显式全局唯一 key。类型层强制（`for_tenant`）/ outbox `tenant_id` 列见 issue #1405；语义见
    /// `docs/rules/tenancy.md` + `eventbus.md §投递顺序保证`。
    ///
    /// **⚠ DLX 警示**：队头行一旦进入 DLX（永久错误或重试预算耗尽），会**阻塞该
    /// `(domain, partition_key)` 的所有后继行**，直到运维 re-drive（`UPDATE outbox SET
    /// status='pending', retry_count=0, retry_after=NULL WHERE event_id=…`）解冻队头。
    #[must_use]
    pub fn with_partition_key(mut self, key: consistency::PartitionKey) -> Self {
        self.partition_key = Some(key);
        self
    }

    /// 借出契约绑定（adapter 取 `domain()` / `contract_id()` 路由列）。
    pub fn contract(&self) -> &vocab::ContractBinding {
        &self.contract
    }

    /// 借出 opaque 主体标识（无 PII；只读检视——生产组装走 [`OutboxEnvelopeParts::into_parts`]）。
    pub fn subject_id(&self) -> &str {
        &self.subject_id
    }

    /// 拆出 `(contract, subject_id, partition_key)` 供 adapter 组装 provider envelope（消费式，避免 borrow/move 冲突）。
    ///
    /// `partition_key` 为 `None` 时 adapter 写 `NULL`（无序并行）；`Some(key)` 时写非空字符串（串行有序）。
    pub fn into_parts(
        self,
    ) -> (
        vocab::ContractBinding,
        String,
        Option<consistency::PartitionKey>,
    ) {
        (self.contract, self.subject_id, self.partition_key)
    }
}

impl std::fmt::Debug for OutboxEnvelopeParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboxEnvelopeParts")
            .field("domain", &self.contract.domain())
            .field("contract_id", &self.contract.contract_id())
            .field("subject_id", &"<redacted>")
            // partition_key 可能凭据级（推荐 tenant-scoped 含 sessionId）：仅渲染 presence（Some/None），
            // 值经 `PartitionKey` 的脱敏 Debug 收口为 `<redacted>`，不泄漏明文（F3，#1211 review）。
            .field("partition_key", &self.partition_key)
            .finish()
    }
}

/// durable outbox 发射 provider DI port（async）。
///
/// 公开 [`OutboxEmitter`] 是 **Send 变体**（adapters `impl OutboxEmitter for ...`），[`DynOutboxEmitter`]
/// 是其 dyn-compatible wrapper（组合根经 `Box<DynOutboxEmitter>` 注入，必填构造器位置参，缺失即编译错误）。
#[trait_variant::make(OutboxEmitter: Send)]
#[dynosaur(pub DynOutboxEmitter = dyn(box) OutboxEmitter, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `OutboxEmitter` 变体 +
// dynosaur `DynOutboxEmitter` 承载（DI 注入走 Send wrapper）。ADR-003 既定 dyn-port 范式。
pub trait OutboxEmitterLocal {
    /// 把一条 [`Entry`] 落 durable outbox（envelope 由 [`OutboxEnvelopeParts`] 组装）。
    async fn emit(
        &self,
        entry: Entry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), OutboxEmitError>;
}

#[cfg(test)]
mod pii_debug {
    //! `OutboxEnvelopeParts.subject_id` Debug 脱敏回归。
    //! INVARIANT: DIPORT-DTO-PII-DEBUG-REDACT-01.
    use super::OutboxEnvelopeParts;

    #[test]
    fn outbox_envelope_parts_debug_redacts_subject_id() {
        // anti-vacuity：证明 "SECRET-SUBJECT" 会出现在普通 String Debug 中（前提不成立则检测无意义）。
        assert!(
            format!("{:?}", "SECRET-SUBJECT").contains("SECRET-SUBJECT"),
            "前提失效：普通字符串 Debug 未携 marker"
        );
        let parts = OutboxEnvelopeParts::new(
            vocab::ContractBinding::from_static("identity", "identity.session-created"),
            "SECRET-SUBJECT",
        );
        let dbg = format!("{parts:?}");
        assert!(
            !dbg.contains("SECRET-SUBJECT"),
            "subject_id 泄漏至 Debug: {dbg}"
        );
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
        assert!(dbg.contains("identity"), "domain 应可见: {dbg}");
    }

    // partition_key Debug 脱敏：presence 可见（Some/None），值不泄漏（可能凭据级，F3 #1211 review）。
    #[allow(clippy::unwrap_used)]
    // reason: 测试构造已知合法 PartitionKey，item-level carve-out。
    #[test]
    fn outbox_envelope_parts_debug_redacts_partition_key_value() {
        use consistency::PartitionKey;

        let parts = OutboxEnvelopeParts::new(
            vocab::ContractBinding::from_static("identity", "identity.session-created"),
            "subj",
        )
        .with_partition_key(PartitionKey::parse("tenant-7:session-secret").unwrap());
        let dbg = format!("{parts:?}");
        // presence 可见（Some），但明文值脱敏为 <redacted>。
        assert!(dbg.contains("Some"), "partition_key presence 应可见: {dbg}");
        assert!(dbg.contains("<redacted>"), "partition_key 值应脱敏: {dbg}");
        assert!(
            !dbg.contains("session-secret"),
            "凭据级 partition_key 值不得泄漏至 Debug: {dbg}"
        );

        // None 路径。
        let parts_none = OutboxEnvelopeParts::new(
            vocab::ContractBinding::from_static("identity", "identity.session-created"),
            "subj",
        );
        let dbg_none = format!("{parts_none:?}");
        assert!(
            dbg_none.contains("None"),
            "未设 partition_key 时应渲染 None: {dbg_none}"
        );
    }
}

#[cfg(test)]
mod partition_key_tests {
    //! `with_partition_key` builder + `into_parts` 透出 partition_key 回归。

    use consistency::PartitionKey;

    use super::OutboxEnvelopeParts;

    #[allow(clippy::unwrap_used)]
    // reason: 测试构造已知合法 PartitionKey，item-level carve-out。
    #[test]
    fn with_partition_key_roundtrips_through_into_parts() {
        let key = PartitionKey::parse("aggregate-123").unwrap();
        let parts = OutboxEnvelopeParts::new(
            vocab::ContractBinding::from_static("identity", "identity.session-created"),
            "subj",
        )
        .with_partition_key(key);
        let (_contract, _subject, pk) = parts.into_parts();
        assert!(pk.is_some(), "with_partition_key 后 into_parts 应透出 Some");
        assert_eq!(pk.unwrap().as_str(), "aggregate-123");
    }

    #[test]
    fn without_partition_key_into_parts_gives_none() {
        let parts = OutboxEnvelopeParts::new(
            vocab::ContractBinding::from_static("identity", "identity.session-created"),
            "subj",
        );
        let (_contract, _subject, pk) = parts.into_parts();
        assert!(pk.is_none(), "未设 partition_key 时 into_parts 应透出 None");
    }
}

#[cfg(test)]
mod smoke {
    //! build smoke：证明 async DI port 可 native AFIT impl + 经 `Box<DynOutboxEmitter>` 动态注入（Send）。
    use consistency::{Entry, IdemKey, Topic};

    use super::{DynOutboxEmitter, OutboxEmitError, OutboxEmitter, OutboxEnvelopeParts};

    #[test]
    fn outbox_emit_error_wraps_source() {
        let err = OutboxEmitError::new(std::io::Error::other("leak-marker-emit"));
        assert_eq!(err.to_string(), "outbox emit failed");
        assert!(std::error::Error::source(&err).is_some());
        // anti-vacuity：内层 Debug 确携 marker（前提），wrapper Debug 不得泄漏。
        assert!(
            format!("{:?}", std::io::Error::other("leak-marker-emit")).contains("leak-marker-emit"),
            "前提失效：内层 Debug 未携 marker"
        );
        assert!(
            !format!("{err:?}").contains("leak-marker-emit"),
            "wrapper Debug 泄漏 source: {err:?}"
        );
    }

    #[allow(clippy::expect_used)]
    // reason: 测试构造 Entry 需 parse Topic/IdemKey（合法输入恒 Ok）；item-level carve-out。
    fn sample() -> (Entry, OutboxEnvelopeParts) {
        let entry = Entry::new(
            Topic::parse("identity.session-created").expect("topic"),
            IdemKey::parse("evt-1").expect("idem"),
            b"payload".to_vec(),
        );
        let env = OutboxEnvelopeParts::new(
            vocab::ContractBinding::from_static("identity", "identity.session-created"),
            "subject-opaque",
        );
        (entry, env)
    }

    struct NoopEmitter;
    impl OutboxEmitter for NoopEmitter {
        async fn emit(
            &self,
            _entry: Entry,
            _env: OutboxEnvelopeParts,
        ) -> Result<(), OutboxEmitError> {
            Ok(())
        }
    }

    // multi_thread + spawn：验证 boxed future Send（trait_variant Send 变体），与真实 spawn 场景对齐。
    #[tokio::test(flavor = "multi_thread")]
    async fn outbox_emitter_is_dyn_injectable() {
        let emitter: Box<DynOutboxEmitter> = DynOutboxEmitter::new_box(NoopEmitter);
        let joined = tokio::spawn(async move {
            let (entry, env) = sample();
            emitter.emit(entry, env).await.is_ok()
        })
        .await;
        assert!(matches!(joined, Ok(true)));
    }
}
