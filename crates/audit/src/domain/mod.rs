//! audit 域类型（dylint rss_domain_no_serialize 守护区：本模块所有类型禁止 derive Serialize/Deserialize）。
//!
//! 对标：sigstore/sigstore-rs src/rekor/models/log_entry.rs@main
//! 采纳：log_index 单调序（→ seq）、verify_inclusion 纯验证（→ verify_chain）。
//! 偏离：Merkle 树 → 线性哈希链；hex String → EntryHash([u8;32]) newtype；rekor 字段全 pub → RSS 私有字段 + funnel。

// ---------------------------------------------------------------------------
// AuditEntryId — 审计条目标识（uuid 底层，构造经 funnel）
// ---------------------------------------------------------------------------

/// 审计条目标识（uuid 底层；私有字段；构造只经 `new`/`parse` funnel）。
///
/// 不 derive `Serialize`——域类型不走 wire（domain-patterns.md）。
// reason: 签名冻结期字段已声明但 body 全为 todo!()，dead_code 来自冻结期，非 API 漂移（ADR-004 C8）。
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct AuditEntryId(uuid::Uuid);

// reason: 签名冻结期方法已声明但暂无调用 site（ADR-004 C8）。
#[allow(dead_code)]
impl AuditEntryId {
    /// 由已校验 uuid 构造（funnel）。
    pub(crate) fn new(_raw: uuid::Uuid) -> Self {
        todo!()
    }

    /// 解析字符串为 AuditEntryId。
    pub(crate) fn parse(_s: &str) -> Result<Self, AuditError> {
        todo!()
    }

    /// 取底层 uuid。
    pub(crate) fn as_uuid(&self) -> uuid::Uuid {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// EntryHash — 强类型哈希（[u8; 32]，不走 hex String）
// ---------------------------------------------------------------------------

/// 审计哈希链节点哈希（`[u8; 32]`；强类型，不走 hex String）。
///
/// 不 derive `Serialize`——域类型不走 wire。
// reason: 签名冻结期字段私有、body 全为 todo!()（ADR-004 C8）。
#[allow(dead_code)]
#[derive(PartialEq, Eq)]
pub(crate) struct EntryHash([u8; 32]);

// reason: 签名冻结期方法已声明但暂无调用 site（ADR-004 C8）。
#[allow(dead_code)]
impl EntryHash {
    /// 由原始字节数组构造。
    pub(crate) fn new(_bytes: [u8; 32]) -> Self {
        todo!()
    }

    /// 取底层字节切片引用。
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        todo!()
    }
}

impl std::fmt::Debug for EntryHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EntryHash(<redacted>)")
    }
}

// ---------------------------------------------------------------------------
// ResourceRef — 被操作资源引用（{kind, id} 值对象）
// ---------------------------------------------------------------------------

/// 被操作资源引用（值对象；私有字段；构造经 funnel）。
///
/// 不 derive `Serialize`——域类型不走 wire。
// reason: 签名冻结期字段私有、body 全为 todo!()（ADR-004 C8）。
#[allow(dead_code)]
pub(crate) struct ResourceRef {
    /// 资源类别（如 "user" / "device" / "setting"）。
    kind: String,
    /// 资源标识（不约束格式，由 kind 上下文决定）。
    id: String,
}

impl std::fmt::Debug for ResourceRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceRef")
            .field("kind", &self.kind)
            .field("id", &"<redacted>")
            .finish()
    }
}

// reason: 签名冻结期方法已声明但暂无调用 site（ADR-004 C8）。
#[allow(dead_code)]
impl ResourceRef {
    /// 构造资源引用（位置参 funnel；`kind` 和 `id` 不得为空）。
    pub(crate) fn new(_kind: impl Into<String>, _id: impl Into<String>) -> Self {
        todo!()
    }

    /// 取资源类别。
    pub(crate) fn kind(&self) -> &str {
        todo!()
    }

    /// 取资源标识。
    pub(crate) fn id(&self) -> &str {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// AuditOutcome — 审计操作结果
// ---------------------------------------------------------------------------

/// 审计操作结果（闭值集；`#[non_exhaustive]` 允许未来扩展）。
///
/// 不 derive `Serialize`——域类型不走 wire。
// reason: 签名冻结期枚举已声明但暂无构造 site，dead_code 来自冻结期（ADR-004 C8）。
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum AuditOutcome {
    /// 操作成功完成。
    Success,
    /// 操作被访问控制拒绝。
    Denied,
    /// 操作因系统错误失败。
    Error,
}

// ---------------------------------------------------------------------------
// AuditEntry — 审计条目实体（哈希链节点）
// ---------------------------------------------------------------------------

/// 审计条目实体（私有字段；构造经位置参 funnel；时间由调用方注入，不取系统时钟）。
///
/// 对标：sigstore-rs LogEntry.log_index（→ seq）+ body（→ entry 内容）。
/// 不 derive `Serialize`——域类型不走 wire（domain-patterns.md）。
// reason: 签名冻结期字段私有、body 全为 todo!()（ADR-004 C8）。
#[allow(dead_code)]
pub(crate) struct AuditEntry {
    /// 单调递增序列号（对标 rekor log_index）。
    seq: u64,
    /// 前一条目哈希（链首 seq=0 时为全零 hash）。
    prev_hash: EntryHash,
    /// 本条目哈希（由 `link_hash` 计算）。
    entry_hash: EntryHash,
    /// 操作者标识（用 `ids::UserId`；设备 / service 场景用 actor_kind 区分）。
    actor: ids::UserId,
    /// 操作者类别（驱动 audit 报告分层；与 authn principal 对齐）。
    actor_kind: authn::PrincipalKind,
    /// 租户标识（行级多租隔离；对标 settings::ConfigEntry.tenant）。
    tenant: vocab::TenantId,
    /// 授权动作。
    action: vocab::Action,
    /// 被操作资源引用。
    resource: ResourceRef,
    /// 操作结果。
    outcome: AuditOutcome,
    /// 记录时间（由调用方注入，不在此取系统时钟）。
    recorded_at: std::time::SystemTime,
}

// reason: 签名冻结期方法已声明但暂无调用 site（ADR-004 C8）。
#[allow(dead_code)]
impl AuditEntry {
    /// 构造审计条目（位置参 funnel；`recorded_at` 来自调用方注入的时钟，禁止在此取系统时间）。
    // reason: AuditEntry 是审计链节点实体，所有字段均为链完整性/取证必填参数，分组构造破坏原子性（ADR-004 C8 签名冻结期）
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        _seq: u64,
        _prev_hash: EntryHash,
        _entry_hash: EntryHash,
        _actor: ids::UserId,
        _actor_kind: authn::PrincipalKind,
        _tenant: vocab::TenantId,
        _action: vocab::Action,
        _resource: ResourceRef,
        _outcome: AuditOutcome,
        _recorded_at: std::time::SystemTime,
    ) -> Self {
        todo!()
    }

    /// 返回单调序列号。
    pub(crate) fn seq(&self) -> u64 {
        todo!()
    }

    /// 返回前一条目哈希。
    pub(crate) fn prev_hash(&self) -> &EntryHash {
        todo!()
    }

    /// 返回本条目哈希。
    pub(crate) fn entry_hash(&self) -> &EntryHash {
        todo!()
    }

    /// 返回操作者标识。
    pub(crate) fn actor(&self) -> ids::UserId {
        todo!()
    }

    /// 返回操作者类别。
    pub(crate) fn actor_kind(&self) -> authn::PrincipalKind {
        todo!()
    }

    /// 返回授权动作引用。
    pub(crate) fn action(&self) -> &vocab::Action {
        todo!()
    }

    /// 返回资源引用。
    pub(crate) fn resource(&self) -> &ResourceRef {
        todo!()
    }

    /// 返回审计结果。
    pub(crate) fn outcome(&self) -> AuditOutcome {
        todo!()
    }

    /// 返回记录时间。
    pub(crate) fn recorded_at(&self) -> std::time::SystemTime {
        todo!()
    }

    /// 返回租户标识（行级多租隔离）。
    pub(crate) fn tenant(&self) -> vocab::TenantId {
        todo!()
    }
}

impl std::fmt::Debug for AuditEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditEntry")
            .field("seq", &self.seq)
            .field("tenant", &self.tenant)
            .field("actor_kind", &self.actor_kind)
            .field("action", &self.action)
            .field("resource", &self.resource)
            .field("outcome", &self.outcome)
            .field("recorded_at", &self.recorded_at)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// AuditChainLink — 链节点投影（{seq, prev_hash, entry_hash}）
// ---------------------------------------------------------------------------

/// 哈希链节点投影（只含链结构字段；不含 actor / resource 等 PII）。
///
/// 对标：rekor verify_inclusion 只需 log_index + hash，不需完整 body。
/// 不 derive `Serialize`——域类型不走 wire。
// reason: 签名冻结期字段私有、body 全为 todo!()（ADR-004 C8）。
#[allow(dead_code)]
pub(crate) struct AuditChainLink {
    /// 对应条目的单调序列号。
    seq: u64,
    /// 前一条目哈希。
    prev_hash: EntryHash,
    /// 本条目哈希。
    entry_hash: EntryHash,
}

impl std::fmt::Debug for AuditChainLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditChainLink")
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

// reason: 签名冻结期方法已声明但暂无调用 site（ADR-004 C8）。
#[allow(dead_code)]
impl AuditChainLink {
    /// 构造链节点投影（位置参 funnel）。
    pub(crate) fn new(_seq: u64, _prev_hash: EntryHash, _entry_hash: EntryHash) -> Self {
        todo!()
    }

    /// 返回序列号。
    pub(crate) fn seq(&self) -> u64 {
        todo!()
    }

    /// 返回前一条目哈希。
    pub(crate) fn prev_hash(&self) -> &EntryHash {
        todo!()
    }

    /// 返回本条目哈希。
    pub(crate) fn entry_hash(&self) -> &EntryHash {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// 纯逻辑自由函数（L0 纯计算）
// ---------------------------------------------------------------------------

/// 计算链节点哈希（纯函数：prev_hash || entry_content → hash）。
///
/// 对标：sigstore-rs `verify_inclusion`（Merkle inclusion proof）→ 线性哈希链变体。
/// L0 LocalOnly——无 I/O、无副作用；body 在行为 PR 落地。
// reason: 签名冻结期函数已声明但暂无调用 site，dead_code 来自冻结期（ADR-004 C8）。
#[allow(dead_code)]
pub(crate) fn link_hash(_prev: &EntryHash, _entry: &AuditEntry) -> EntryHash {
    todo!()
}

/// 验证审计链完整性（纯函数；L0 LocalOnly）。
///
/// 逐条校验：序列号单调递增 + prev_hash 匹配 + entry_hash 一致。
/// 对标：sigstore-rs `verify_inclusion` 的整体 proof 路径（→ 线性变体）。
// reason: 签名冻结期函数已声明但暂无调用 site，dead_code 来自冻结期（ADR-004 C8）。
#[allow(dead_code)]
pub(crate) fn verify_chain(_entries: &[AuditEntry]) -> Result<(), AuditError> {
    todo!()
}

// ---------------------------------------------------------------------------
// 错误枚举
// ---------------------------------------------------------------------------

/// 审计域错误（库枚举；`thiserror`；message 为 const 静态字面量）。
// reason: 签名冻结期错误枚举已声明但暂无 raise site，dead_code 来自冻结期（ADR-004 C8）。
#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum AuditError {
    /// 哈希链在某条目处断裂（prev_hash 不匹配）。
    #[error("audit chain is broken")]
    ChainBroken,
    /// 条目哈希校验失败（entry_hash 与重算结果不符）。
    #[error("audit hash mismatch")]
    HashMismatch,
    /// 序列号不连续（gap 或重复）。
    #[error("audit sequence gap detected")]
    SequenceGap,
    /// AuditEntryId 解析失败（非法 uuid 格式）。
    #[error("audit entry id is invalid")]
    InvalidId,
}
