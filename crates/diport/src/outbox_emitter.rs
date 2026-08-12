//! `OutboxEmitter` —— in-memory demo/test event emission port.
//!
//! This raw two-coordinate port remains only for memory demos and test doubles. Durable production
//! adapters consume `eventexec::event::ReviewedEvent` through the eventexec-owned writer seam; a
//! plain [`consistency::EventEntry`] cannot reach PostgreSQL production writers.
//!
//! 与 [`crate::Publisher`] 的分工：`Publisher` 是 relay 把**已持久化** entry 直发到 broker 的端口；
//! `OutboxEmitter` is not a production persistence capability and must not be wired to a durable
//! adapter.
//!
//! Co-transactional production writes continue through domain-shaped Unit-of-Work ports; standalone
//! durable facts use the reviewed writer seam.
//!
//! ref: debezium outbox SMT（业务写 + outbox 行同一本地事务，producer 侧 durable 落库）
//! ref: eventuate-tram-core io.eventuate.tram.consumer.common.DuplicateMessageDetector@master
//!      （message-id 作幂等键，对应 RSS `inbox_receipts(event_id, consumer_group)`）

use dynosaur::dynosaur;

use consistency::{EventEntry, OutboxFactConflict};

use crate::redacted::RedactedSource;

const OPAQUE_ID_MAX_LEN: usize = 256;

/// outbox 发射失败。
///
/// PII 边界（与 [`crate::PublisherError`] 同范式）：`Display` 仅安全摘要常量；source 经
/// [`RedactedSource`] 脱敏（`Debug` / `Display` 固定 `<redacted>`、`Error::source()` 恒 `None`），见
/// INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
#[derive(Debug, thiserror::Error)]
#[error("outbox emit failed")]
pub struct OutboxEmitError {
    kind: OutboxEmitErrorKind,
    #[source]
    source: RedactedSource,
}

/// Closed, payload-free classification for outbox emit failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxEmitErrorKind {
    /// Provider, transaction, or canonicalization infrastructure failed.
    Infrastructure,
    /// The event id already names a different durable fact.
    FactConflict,
}

impl OutboxEmitError {
    /// 把 adapter 内部错误包成发射失败。原始错误仅作 internal source 保留，不经 `Display` 暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            kind: OutboxEmitErrorKind::Infrastructure,
            source: RedactedSource::new(source),
        }
    }

    /// Preserve a typed fact conflict without exposing fact material.
    pub fn fact_conflict(source: OutboxFactConflict) -> Self {
        Self {
            kind: OutboxEmitErrorKind::FactConflict,
            source: RedactedSource::new(source),
        }
    }

    /// Return the closed failure classification.
    pub const fn kind(&self) -> OutboxEmitErrorKind {
        self.kind
    }
}

/// envelope subject / actor opaque id 解析失败。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeIdentityError {
    /// 空 id 非法。
    #[error("envelope identity is empty")]
    Empty,
    /// id 超出上限，避免 metadata/header 膨胀。
    #[error("envelope identity exceeds 256 bytes")]
    TooLong,
}

/// outbox envelope 的事件主体/聚合根 opaque id。
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct EnvelopeSubjectId(String);

impl EnvelopeSubjectId {
    /// 从已审查的 opaque 事件主体 id 构造。
    pub fn from_opaque(raw: impl Into<String>) -> Result<Self, EnvelopeIdentityError> {
        parse_opaque_id(raw.into()).map(Self)
    }

    /// 从 UUID 构造（infallible：hyphenated 形式恒非空且 ≪ 256 bytes）。
    ///
    /// 供 privacy-pseudonym / 其它已是 UUID 的聚合根；canonical 用户主体优先
    /// [`Self::from_user_id`]（#1235 typed funnel）。
    pub fn from_uuid(id: uuid::Uuid) -> Self {
        Self(id.hyphenated().to_string())
    }

    /// 从 canonical [`ids::UserId`] 构造（#1235 Hard：login/PII 字符串在类型层不可进入此入口）。
    pub fn from_user_id(user_id: ids::UserId) -> Self {
        Self::from_uuid(user_id.as_uuid())
    }

    /// 借出底层字符串。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for EnvelopeSubjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EnvelopeSubjectId(<redacted>)")
    }
}

/// outbox actor 的 opaque id。
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct OpaqueActorId(String);

impl OpaqueActorId {
    /// 从已认证/已审查的 opaque actor id 构造。
    pub fn from_opaque(raw: impl Into<String>) -> Result<Self, EnvelopeIdentityError> {
        parse_opaque_id(raw.into()).map(Self)
    }

    /// 从 UUID 构造（infallible：hyphenated 形式恒非空且 ≪ 256 bytes）。
    pub fn from_uuid(id: uuid::Uuid) -> Self {
        Self(id.hyphenated().to_string())
    }

    /// 从 canonical [`ids::UserId`] 构造（#1235 Hard：login/PII 字符串在类型层不可进入此入口）。
    pub fn from_user_id(user_id: ids::UserId) -> Self {
        Self::from_uuid(user_id.as_uuid())
    }

    /// 借出底层字符串。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for OpaqueActorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OpaqueActorId(<redacted>)")
    }
}

/// outbox envelope 的 causation id（opaque persisted-only）。
///
/// 该字段仅用于 durable outbox 追因链落库，不进入 broker header / 日志 / metrics。约束与其它 envelope
/// opaque id 一致：非空、最大 256 bytes，`Debug` 固定脱敏。
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct EnvelopeCausationId(String);

impl EnvelopeCausationId {
    /// 从已审查的 opaque causation id 构造。
    pub fn from_opaque(raw: impl Into<String>) -> Result<Self, EnvelopeIdentityError> {
        parse_opaque_id(raw.into()).map(Self)
    }

    /// 借出底层字符串。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for EnvelopeCausationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EnvelopeCausationId(<redacted>)")
    }
}

fn parse_opaque_id(raw: String) -> Result<String, EnvelopeIdentityError> {
    if raw.is_empty() {
        return Err(EnvelopeIdentityError::Empty);
    }
    if raw.len() > OPAQUE_ID_MAX_LEN {
        return Err(EnvelopeIdentityError::TooLong);
    }
    Ok(raw)
}

/// 最小化 outbox actor view。
#[derive(Clone, PartialEq, Eq)]
pub struct OutboxActor {
    kind: rss_request_context::PrincipalKind,
    actor_id: OpaqueActorId,
    tenant: Option<rss_request_context::TenantId>,
    scope: vocab::VisibilityScope,
}

impl OutboxActor {
    /// 租户内 actor。`RowScope` 位置参从类型层排除跨租户 `All` 误用。
    pub fn scoped(
        kind: rss_request_context::PrincipalKind,
        actor_id: OpaqueActorId,
        tenant: rss_request_context::TenantId,
        scope: rss_request_context::RowScope,
    ) -> Self {
        Self {
            kind,
            actor_id,
            tenant: Some(tenant),
            scope: scope.into(),
        }
    }

    /// 系统/service actor。用于没有 human principal 的内部 producer。
    pub fn service(actor_id: OpaqueActorId) -> Self {
        Self {
            kind: rss_request_context::PrincipalKind::Service,
            actor_id,
            tenant: None,
            scope: vocab::VisibilityScope::All,
        }
    }

    /// actor kind。
    pub fn kind(&self) -> rss_request_context::PrincipalKind {
        self.kind
    }

    /// actor opaque id。
    pub fn actor_id(&self) -> &OpaqueActorId {
        &self.actor_id
    }

    /// actor tenant constraint。
    pub fn tenant(&self) -> Option<rss_request_context::TenantId> {
        self.tenant
    }

    /// actor row scope。
    pub fn scope(&self) -> vocab::VisibilityScope {
        self.scope
    }
}

impl std::fmt::Debug for OutboxActor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboxActor")
            .field("kind", &self.kind.as_actor_metadata_label())
            .field("actor_id", &"<redacted>")
            .field("tenant", &self.tenant)
            .field("scope", &self.scope.as_label())
            .finish()
    }
}

/// outbox envelope 的 **opaque** 字段集（域传，adapter 组装成 provider 私有 envelope）。
///
/// 仅承载非-reserved、可由业务安全提供的字段：`contract`（[`vocab::ContractBinding`]，domain / contract_id /
/// version / schema_hash 同源契约归属，#1193/#1618——business 不再裸 string 分别 author，杜绝 envelope header 漂移）、`tenant` 是
/// typed 租户 scope（adapter 盖章进 reserved `tenantId`）、`subject_id` 是
/// **opaque** 主体标识（FR-020：不容完整 Principal / email / 姓名等 PII）、`causation_id` 是可选 opaque
/// 追因链锚点（persisted-only，不进 broker header / 日志 / metrics）、`partition_key` 是可选有序投递
/// 分区键（`None` = 无序并行；`Some` = 同 partition 串行有序，#1211）。reserved envelope key
/// （trace / correlation / principal / occurredAt）**不在此**——由 adapter 在受控构造点注入（`occurredAt`
/// 取注入 `Clock`，#1129；trace 已接线 #1224（`tracewire::capture_current`）；correlation 已接线 #1160；principal 待 #1397）。
///
/// 字段私有 + 构造器 [`OutboxEnvelopeParts::new`]（input-struct-field-exclusion，**Hard**）：business 不能绕过
/// 构造器分别 set domain/contract_id 字段，只能给 `(contract, tenant, subject_id)`。`contract` 的**预期**来源是
/// `generated::event::{domain}_v1::CONTRACT`（契约派生常量 + golden 锁，CONTRACT-BINDING-FUNNEL-01，**Medium**）——
/// 但 `vocab::ContractBinding::from_static` 是普通 `pub` 构造器，业务**仍可裸构造**任意绑定（residual，非 Hard；
/// 由 `cargo xtask verify` 的 `contract-binding-guard` 收口生产调用站点）。
///
/// INVARIANT: DIPORT-DTO-PII-DEBUG-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—— `Debug` 仅输出公开契约元数据（`contract` 的 domain / contract_id / version / schema_hash）；
/// `subject_id` 固定渲染为 `<redacted>`；`partition_key` 只渲染 presence（Some/None），其值经 `PartitionKey`
/// 脱敏 Debug 收口为 `<redacted>`（可能凭据级，如 tenant-scoped 含 sessionId，F3 #1211 review）。防主体标识 /
/// causation id / 分区键经 `{:?}` 泄漏至日志（回归见 `pii_debug` 单测）。
#[derive(Clone)]
pub struct OutboxEnvelopeParts {
    /// 契约绑定（domain + contract_id + version + schema_hash 同源；`generated::…::CONTRACT`）。
    contract: vocab::ContractBinding,
    /// 租户标识（canonical UUID；adapter 将其盖章进 reserved `tenantId` envelope）。
    tenant: rss_request_context::TenantId,
    /// opaque 主体标识（无 PII）。
    subject_id: EnvelopeSubjectId,
    /// 最小化 actor view（persisted-only；不进 broker header）。
    actor: OutboxActor,
    /// 可选 opaque causation id（persisted-only；不进 broker header / 日志 / metrics）。
    causation_id: Option<EnvelopeCausationId>,
    /// 可选有序投递分区键（`None` = 无序并行；`Some` = 同 partition 串行有序，#1211）。
    partition_key: Option<consistency::PartitionKey>,
}

impl OutboxEnvelopeParts {
    /// 构造 envelope parts——`contract` 经契约派生常量绑定（非裸 string），`tenant` 是 typed RLS scope，
    /// `subject_id` 是 opaque 主体标识。
    /// `partition_key` 默认 `None`（无序并行）；需有序投递时经 [`OutboxEnvelopeParts::with_partition_key`] 设置。
    pub fn new(
        contract: vocab::ContractBinding,
        tenant: rss_request_context::TenantId,
        subject_id: EnvelopeSubjectId,
        actor: OutboxActor,
    ) -> Self {
        Self {
            contract,
            tenant,
            subject_id,
            actor,
            causation_id: None,
            partition_key: None,
        }
    }

    /// 设置可选 causation id（builder，persisted-only）。
    ///
    /// `EnvelopeCausationId` 构造器已拒空并限制 256 bytes；adapter 仅把值落入 outbox `causation_id`
    /// 物理列，不传播到 broker header、日志或 metrics。
    #[must_use]
    pub fn with_causation_id(mut self, causation_id: EnvelopeCausationId) -> Self {
        self.causation_id = Some(causation_id);
        self
    }

    /// 设置有序投递分区键（builder，#1211）。
    ///
    /// 设置后同 `(tenant_id, domain, partition_key)` 的 outbox 行严格按 `seq` 顺序投递（head-of-partition gating）；
    /// 未设（`None`）时与现有行为完全兼容——无序并行投递。
    ///
    /// `partition_key` 是不透明聚合根路由键；tenant scope 由必填的 [`rss_request_context::TenantId`] 落入 outbox
    /// `tenant_id` 列承载，跨租同 business key 不共享 gate。推荐直接使用稳定 aggregate id；
    /// 语义见 `docs/rules/tenancy.md` + `eventbus.md §投递顺序保证`。
    ///
    /// **⚠ DLX 警示**：队头行一旦进入 DLX（永久错误或重试预算耗尽），会**阻塞该
    /// `(tenant_id, domain, partition_key)` 的所有后继行**，直到运维经 DLQ redrive 解冻队头。
    #[must_use]
    pub fn with_partition_key(mut self, key: consistency::PartitionKey) -> Self {
        self.partition_key = Some(key);
        self
    }

    /// 借出契约绑定（adapter 取 `domain()` / `contract_id()` 路由列）。
    pub fn contract(&self) -> &vocab::ContractBinding {
        &self.contract
    }

    /// 借出租户标识。
    pub fn tenant(&self) -> rss_request_context::TenantId {
        self.tenant
    }

    /// 借出 opaque 主体标识（无 PII；只读检视——生产组装走 [`OutboxEnvelopeParts::into_parts`]）。
    pub fn subject_id(&self) -> &EnvelopeSubjectId {
        &self.subject_id
    }

    /// 借出 actor。
    pub fn actor(&self) -> &OutboxActor {
        &self.actor
    }

    /// 借出可选 causation id（persisted-only；只读检视——生产组装走 [`OutboxEnvelopeParts::into_parts`]）。
    pub fn causation_id(&self) -> Option<&EnvelopeCausationId> {
        self.causation_id.as_ref()
    }

    /// 拆出 `(contract, tenant, subject_id, actor, partition_key, causation_id)` 供 adapter 组装 provider envelope（消费式，避免 borrow/move 冲突）。
    ///
    /// `partition_key` 为 `None` 时 adapter 写 `NULL`（无序并行）；`Some(key)` 时写非空字符串（串行有序）。
    pub fn into_parts(
        self,
    ) -> (
        vocab::ContractBinding,
        rss_request_context::TenantId,
        EnvelopeSubjectId,
        OutboxActor,
        Option<consistency::PartitionKey>,
        Option<EnvelopeCausationId>,
    ) {
        (
            self.contract,
            self.tenant,
            self.subject_id,
            self.actor,
            self.partition_key,
            self.causation_id,
        )
    }
}

impl std::fmt::Debug for OutboxEnvelopeParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboxEnvelopeParts")
            .field("domain", &self.contract.domain())
            .field("contract_id", &self.contract.contract_id())
            .field("tenant", &self.tenant)
            .field("subject_id", &"<redacted>")
            .field("actor", &self.actor)
            .field("causation_id", &self.causation_id)
            // partition_key 可能凭据级（推荐 tenant-scoped 含 sessionId）：仅渲染 presence（Some/None），
            // 值经 `PartitionKey` 的脱敏 Debug 收口为 `<redacted>`，不泄漏明文（F3，#1211 review）。
            .field("partition_key", &self.partition_key)
            .finish()
    }
}

/// In-memory demo/test event emission port（async）。
///
/// 公开 [`OutboxEmitter`] 是 **Send 变体**（adapters `impl OutboxEmitter for ...`），[`DynOutboxEmitter`]
/// 是其 dyn-compatible wrapper（仅供 demo/test 组合根与替身注入）。
#[trait_variant::make(OutboxEmitter: Send)]
#[dynosaur(pub DynOutboxEmitter = dyn(box) OutboxEmitter, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `OutboxEmitter` 变体 +
// dynosaur `DynOutboxEmitter` 承载（DI 注入走 Send wrapper）。ADR-003 既定 dyn-port 范式。
pub trait OutboxEmitterLocal {
    /// Emit one raw entry in a non-production memory/test environment.
    async fn emit(
        &self,
        entry: EventEntry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), OutboxEmitError>;
}

#[cfg(test)]
mod pii_debug {
    //! `OutboxEnvelopeParts.subject_id` Debug 脱敏回归。
    //! INVARIANT: DIPORT-DTO-PII-DEBUG-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }.
    use super::{
        EnvelopeCausationId, EnvelopeSubjectId, OpaqueActorId, OutboxActor, OutboxEnvelopeParts,
    };

    const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const HASH: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[allow(clippy::expect_used)]
    fn tenant() -> rss_request_context::TenantId {
        rss_request_context::TenantId::parse(TENANT).expect("canonical tenant")
    }

    #[allow(clippy::expect_used)]
    fn subject(raw: &str) -> EnvelopeSubjectId {
        EnvelopeSubjectId::from_opaque(raw).expect("opaque subject")
    }

    #[allow(clippy::expect_used)]
    fn actor() -> OutboxActor {
        OutboxActor::scoped(
            rss_request_context::PrincipalKind::User,
            OpaqueActorId::from_opaque("actor-opaque").expect("opaque actor"),
            tenant(),
            rss_request_context::RowScope::SelfOnly,
        )
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn from_user_id_matches_hyphenated_uuid_and_redacts_debug() {
        let raw =
            uuid::Uuid::parse_str("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("canonical uuid");
        let user_id = ids::UserId::new(raw);
        let subject = EnvelopeSubjectId::from_user_id(user_id);
        let actor = OpaqueActorId::from_user_id(user_id);
        assert_eq!(subject.as_str(), raw.hyphenated().to_string());
        assert_eq!(actor.as_str(), raw.hyphenated().to_string());
        assert_eq!(EnvelopeSubjectId::from_uuid(raw).as_str(), subject.as_str());
        let dbg = format!("{subject:?}{actor:?}");
        assert!(
            !dbg.contains(raw.hyphenated().to_string().as_str()),
            "UserId-derived envelope ids must redact Debug: {dbg}"
        );
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
    }

    #[test]
    fn outbox_envelope_parts_debug_redacts_subject_id() {
        // anti-vacuity：证明 "SECRET-SUBJECT" 会出现在普通 String Debug 中（前提不成立则检测无意义）。
        assert!(
            format!("{:?}", "SECRET-SUBJECT").contains("SECRET-SUBJECT"),
            "前提失效：普通字符串 Debug 未携 marker"
        );
        let parts = OutboxEnvelopeParts::new(
            vocab::ContractBinding::from_static("identity", "identity.session-created", "v1", HASH),
            tenant(),
            subject("SECRET-SUBJECT"),
            actor(),
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
            vocab::ContractBinding::from_static("identity", "identity.session-created", "v1", HASH),
            tenant(),
            subject("subj"),
            actor(),
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
            vocab::ContractBinding::from_static("identity", "identity.session-created", "v1", HASH),
            tenant(),
            subject("subj"),
            actor(),
        );
        let dbg_none = format!("{parts_none:?}");
        assert!(
            dbg_none.contains("None"),
            "未设 partition_key 时应渲染 None: {dbg_none}"
        );
    }

    #[allow(clippy::expect_used)]
    #[test]
    fn outbox_envelope_parts_debug_redacts_causation_id_value() {
        let parts = OutboxEnvelopeParts::new(
            vocab::ContractBinding::from_static("identity", "identity.session-created", "v1", HASH),
            tenant(),
            subject("subj"),
            actor(),
        )
        .with_causation_id(
            EnvelopeCausationId::from_opaque("SECRET-CAUSATION").expect("opaque causation"),
        );
        let dbg = format!("{parts:?}");
        assert!(
            dbg.contains("causation_id"),
            "causation_id presence 应可见: {dbg}"
        );
        assert!(dbg.contains("<redacted>"), "causation_id 值应脱敏: {dbg}");
        assert!(
            !dbg.contains("SECRET-CAUSATION"),
            "causation_id 不得泄漏至 Debug: {dbg}"
        );
    }
}

#[cfg(test)]
mod partition_key_tests {
    //! `with_partition_key` builder + `into_parts` 透出 partition_key 回归。

    use consistency::PartitionKey;

    use super::{
        EnvelopeCausationId, EnvelopeIdentityError, EnvelopeSubjectId, OpaqueActorId, OutboxActor,
        OutboxEnvelopeParts,
    };

    const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const HASH: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[allow(clippy::expect_used)]
    fn tenant() -> rss_request_context::TenantId {
        rss_request_context::TenantId::parse(TENANT).expect("canonical tenant")
    }

    #[allow(clippy::expect_used)]
    fn subject(raw: &str) -> EnvelopeSubjectId {
        EnvelopeSubjectId::from_opaque(raw).expect("opaque subject")
    }

    #[allow(clippy::expect_used)]
    fn actor() -> OutboxActor {
        OutboxActor::scoped(
            rss_request_context::PrincipalKind::Admin,
            OpaqueActorId::from_opaque("actor-admin").expect("opaque actor"),
            tenant(),
            rss_request_context::RowScope::Tenant,
        )
    }

    #[allow(clippy::unwrap_used)]
    // reason: 测试构造已知合法 PartitionKey，item-level carve-out。
    #[test]
    fn with_partition_key_roundtrips_through_into_parts() {
        let key = PartitionKey::parse("aggregate-123").unwrap();
        let parts = OutboxEnvelopeParts::new(
            vocab::ContractBinding::from_static("identity", "identity.session-created", "v1", HASH),
            tenant(),
            subject("subj"),
            actor(),
        )
        .with_partition_key(key);
        let (_contract, got_tenant, got_subject, got_actor, pk, causation_id) = parts.into_parts();
        assert_eq!(got_tenant.to_string(), TENANT);
        assert_eq!(got_subject.as_str(), "subj");
        assert_eq!(got_actor.kind(), rss_request_context::PrincipalKind::Admin);
        assert_eq!(got_actor.actor_id().as_str(), "actor-admin");
        assert_eq!(got_actor.scope(), rss_request_context::RowScope::Tenant);
        assert!(pk.is_some(), "with_partition_key 后 into_parts 应透出 Some");
        assert_eq!(pk.unwrap().as_str(), "aggregate-123");
        assert!(causation_id.is_none(), "未设 causation_id 时应透出 None");
    }

    #[test]
    fn without_partition_key_into_parts_gives_none() {
        let parts = OutboxEnvelopeParts::new(
            vocab::ContractBinding::from_static("identity", "identity.session-created", "v1", HASH),
            tenant(),
            subject("subj"),
            actor(),
        );
        let (_contract, got_tenant, _subject, _actor, pk, causation_id) = parts.into_parts();
        assert_eq!(got_tenant.to_string(), TENANT);
        assert!(pk.is_none(), "未设 partition_key 时 into_parts 应透出 None");
        assert!(
            causation_id.is_none(),
            "未设 causation_id 时 into_parts 应透出 None"
        );
    }

    #[test]
    fn causation_id_parse_rejects_empty_and_too_long() {
        assert_eq!(
            EnvelopeCausationId::from_opaque(""),
            Err(EnvelopeIdentityError::Empty)
        );
        assert_eq!(
            EnvelopeCausationId::from_opaque("x".repeat(257)),
            Err(EnvelopeIdentityError::TooLong)
        );
    }

    #[allow(clippy::expect_used)]
    #[test]
    fn causation_id_roundtrips_through_into_parts() {
        let cause = EnvelopeCausationId::from_opaque("evt-root-1").expect("opaque causation");
        let parts = OutboxEnvelopeParts::new(
            vocab::ContractBinding::from_static("identity", "identity.session-created", "v1", HASH),
            tenant(),
            subject("subj"),
            actor(),
        )
        .with_causation_id(cause);
        assert_eq!(
            parts.causation_id().map(EnvelopeCausationId::as_str),
            Some("evt-root-1")
        );
        let (_contract, _tenant, _subject, _actor, pk, causation_id) = parts.into_parts();
        assert!(pk.is_none(), "未设 partition_key 时应透出 None");
        assert_eq!(
            causation_id.as_ref().map(EnvelopeCausationId::as_str),
            Some("evt-root-1")
        );
    }
}

#[cfg(test)]
mod smoke {
    //! build smoke：证明 async DI port 可 native AFIT impl + 经 `Box<DynOutboxEmitter>` 动态注入（Send）。
    use consistency::{EventEntry, EventTopic, IdemKey, OutboxPayload};

    use super::{
        DynOutboxEmitter, EnvelopeSubjectId, OpaqueActorId, OutboxActor, OutboxEmitError,
        OutboxEmitter, OutboxEnvelopeParts,
    };

    const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const HASH: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[allow(clippy::expect_used)]
    fn tenant() -> rss_request_context::TenantId {
        rss_request_context::TenantId::parse(TENANT).expect("canonical tenant")
    }

    #[allow(clippy::expect_used)]
    fn subject(raw: &str) -> EnvelopeSubjectId {
        EnvelopeSubjectId::from_opaque(raw).expect("opaque subject")
    }

    #[allow(clippy::expect_used)]
    fn actor() -> OutboxActor {
        OutboxActor::service(OpaqueActorId::from_opaque("rss.service").expect("service actor"))
    }

    #[test]
    fn outbox_emit_error_wraps_source() {
        let err = OutboxEmitError::new(std::io::Error::other("leak-marker-emit"));
        assert_eq!(err.kind(), super::OutboxEmitErrorKind::Infrastructure);
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

        let conflict = OutboxEmitError::fact_conflict(consistency::OutboxFactConflict);
        assert_eq!(conflict.kind(), super::OutboxEmitErrorKind::FactConflict);
        assert_eq!(conflict.to_string(), "outbox emit failed");
        assert!(!format!("{conflict:?}").contains("fingerprint"));
    }

    #[allow(clippy::expect_used)]
    // reason: 测试构造 Entry 需 parse Topic/IdemKey（合法输入恒 Ok）；item-level carve-out。
    fn sample() -> (EventEntry, OutboxEnvelopeParts) {
        let entry = EventEntry::new(
            EventTopic::parse("identity.session-created").expect("topic"),
            IdemKey::parse("evt-1").expect("idem"),
            OutboxPayload::from_reviewed_event_bytes(b"payload".to_vec()),
        );
        let env = OutboxEnvelopeParts::new(
            vocab::ContractBinding::from_static("identity", "identity.session-created", "v1", HASH),
            tenant(),
            subject("subject-opaque"),
            actor(),
        );
        (entry, env)
    }

    struct NoopEmitter;
    impl OutboxEmitter for NoopEmitter {
        async fn emit(
            &self,
            _entry: EventEntry,
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
