//! audit 域类型 + keyed HMAC 哈希链（dylint `rss_domain_no_serialize` 守护区：本模块所有类型禁止 derive
//! `Serialize`/`Deserialize`）。
//!
//! 对标：sigstore/sigstore-rs src/rekor/models/log_entry.rs@main
//! 采纳：`log_index` 单调序（→ `seq`）、`verify_inclusion` 纯验证（→ [`AuditChainHasher::verify`]）。
//! 偏离：Merkle 树 → 线性 keyed HMAC 哈希链；hex String → [`EntryHash`]`([u8;32])` newtype；rekor 字段全 pub
//!        → RSS 私有字段 + funnel。
//!
//! # keyed HMAC 链（#1014 P0-8）
//!
//! 链节点哈希 = `HMAC-SHA256(key, prev_hash ‖ canonical(entry_content))`，经注入的
//! [`primitives::MacVerifier`] + [`primitives::MacKey`] 计算（key 是凭据，构造器必填 ⇒ 无 key 不可造
//! hasher，防篡改属性类型层成立；缺 key 的旧 `link_hash` 自由函数已删）。`canonical_message` 字节布局
//! **冻结**（单源 `docs/rules/audit-ledger.md`，INVARIANT: AUDIT-LEDGER-BYTES-01 { level = "Medium", exec = "manual/opt-in", source = "code" }），golden 字节测试守。
//! postgres provider 承载每租户子链持久化；本模块泛型于 `MacVerifier`、域单测用确定性
//! `#[cfg(test)]` verifier（不依赖 adapter crate）。

use std::time::{Duration, SystemTime};

use primitives::{MacAlgorithm, MacKey, MacVerifier, constant_time_eq};

/// 链字节格式域分隔 + 版本 tag（锁布局版本；v2 布局产生不相交哈希）。
const DOMAIN_TAG: &[u8] = b"rss.audit.v1\x00";
/// 链首（seq=0）的前置哈希：全零。
const GENESIS_PREV: [u8; 32] = [0u8; 32];
/// buggy verifier（非 32B 输出）的 fail-closed 哨兵哈希：全 0xFF，非 genesis、非真实 HMAC 输出，
/// 保证 verify 遇 buggy verifier 时 fail-close（与任何合法链 entry_hash 不匹配）。
const FAIL_HASH: [u8; 32] = [0xFFu8; 32];

/// 审计链 HMAC key 最小长度（字节）。`docs/rules/audit-ledger.md` 声明链 key ≥32B；构造器 fail-closed
/// 校验，短 key 不可造 hasher（防弱 key 削弱链防篡改属性）。
const MIN_KEY_LEN: usize = 32;

// ---------------------------------------------------------------------------
// EntryHash — 强类型哈希（[u8; 32]，不走 hex String）
// ---------------------------------------------------------------------------

/// 审计哈希链节点哈希（`[u8; 32]`；强类型，不走 hex String）。不 derive `Serialize`（域类型不走 wire）。
///
/// `PartialEq`/`Eq` 是结构性相等；认证比较（链完整性/链接）一律经 [`primitives::constant_time_eq`]，勿用 `==`。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EntryHash([u8; 32]);

impl EntryHash {
    /// 由原始字节数组构造（adapter 从存储 `bytea` 列重建时经此 funnel）。
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// 取底层字节切片引用。
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 链首前置哈希（全零）。
    pub fn genesis() -> Self {
        Self(GENESIS_PREV)
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

/// 被操作资源引用（值对象；私有字段；构造经 funnel）。不 derive `Serialize`（域类型不走 wire）。
///
/// `kind`/`id` 不约束非空：canonical 字节布局对二者长度前缀编码，空串无歧义且 tamper-evident；`panic=deny`
/// 下不写 panic 校验，空值由上游（const `resource_kind` + 已解码 payload）保证。
#[derive(Clone)]
pub struct ResourceRef {
    /// 资源类别（如 "user" / "device" / "session"）。
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

impl ResourceRef {
    /// 构造资源引用（位置参 funnel；adapter 从存储 `resource_kind`/`resource_id` 列重建亦经此）。
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: id.into(),
        }
    }

    /// 取资源类别。
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// 取资源标识。
    pub fn id(&self) -> &str {
        &self.id
    }
}

// ---------------------------------------------------------------------------
// AuditOutcome — 审计操作结果
// ---------------------------------------------------------------------------

/// 审计操作结果（闭值集；`#[non_exhaustive]` 允许未来扩展）。不 derive `Serialize`（域类型不走 wire）。
// reason: Denied/Error 是审计结果完整词汇 + 冻结 tag 测试覆盖；当前仅 session-created（Success）有生产
// producer，denied/failed 操作审计随更多 event 订阅 follow-up 接入 producer（非死代码堆积，是闭值集完整性）。
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditOutcome {
    /// 操作成功完成。
    Success,
    /// 操作被访问控制拒绝。
    Denied,
    /// 操作因系统错误失败。
    Error,
}

impl AuditOutcome {
    /// 闭值集 → DB 持久化文本（snake_case；存储/rehydrate 单源 funnel）。同 crate 穷尽 match ⇒ 新变体编译期强制补。
    pub fn to_db(self) -> &'static str {
        match self {
            AuditOutcome::Success => "success",
            AuditOutcome::Denied => "denied",
            AuditOutcome::Error => "error",
        }
    }

    /// DB 文本 → 闭值集（rehydrate）；未知文本 fail-closed → `None`（adapter 据此回 `Storage`/`ChainBroken`）。
    pub fn from_db(raw: &str) -> Option<Self> {
        match raw {
            "success" => Some(AuditOutcome::Success),
            "denied" => Some(AuditOutcome::Denied),
            "error" => Some(AuditOutcome::Error),
            _ => None,
        }
    }
}

/// `vocab::PrincipalKind` → DB 持久化文本（snake_case；存储/rehydrate 单源 funnel）。
/// 跨 crate `#[non_exhaustive]` 无法穷尽，未知变体 fail-closed 落 "unknown"——DB CHECK 约束不含 "unknown"
/// ⇒ 未知 kind 的 append 被 DB 拒（fail-closed，不静默落库）。已知 6 变体的 round-trip 全集性由测试守。
pub fn actor_kind_to_db(kind: vocab::PrincipalKind) -> &'static str {
    match kind {
        vocab::PrincipalKind::User => "user",
        vocab::PrincipalKind::Device => "device",
        vocab::PrincipalKind::Admin => "admin",
        vocab::PrincipalKind::SuperAdmin => "super_admin",
        vocab::PrincipalKind::Service => "service",
        vocab::PrincipalKind::Anonymous => "anonymous",
        _ => "unknown",
    }
}

/// DB 文本 → `vocab::PrincipalKind`（rehydrate）；未知文本 fail-closed → `None`。
pub fn actor_kind_from_db(raw: &str) -> Option<vocab::PrincipalKind> {
    match raw {
        "user" => Some(vocab::PrincipalKind::User),
        "device" => Some(vocab::PrincipalKind::Device),
        "admin" => Some(vocab::PrincipalKind::Admin),
        "super_admin" => Some(vocab::PrincipalKind::SuperAdmin),
        "service" => Some(vocab::PrincipalKind::Service),
        "anonymous" => Some(vocab::PrincipalKind::Anonymous),
        _ => None,
    }
}

/// `AuditOutcome` → 冻结 tag 字节（同 crate `#[non_exhaustive]` 可穷尽 match ⇒ 新变体编译期强制补 tag）。
fn outcome_tag(outcome: AuditOutcome) -> u8 {
    match outcome {
        AuditOutcome::Success => 1,
        AuditOutcome::Denied => 2,
        AuditOutcome::Error => 3,
    }
}

/// `vocab::PrincipalKind` → 冻结 tag 字节。跨 crate `#[non_exhaustive]` 无法编译期穷尽，故补 `_ => 0`
/// fail-closed；已知变体非零唯一由 `enum_tag_mapping_is_total_and_nonzero` 测试守。
fn principal_kind_tag(kind: vocab::PrincipalKind) -> u8 {
    match kind {
        vocab::PrincipalKind::User => 1,
        vocab::PrincipalKind::Device => 2,
        vocab::PrincipalKind::Admin => 3,
        vocab::PrincipalKind::SuperAdmin => 4,
        vocab::PrincipalKind::Service => 5,
        vocab::PrincipalKind::Anonymous => 6,
        // reason: 跨 crate non_exhaustive，未知变体 fail-closed 落 0（与任何已知 tag 不撞 ⇒ 审计可发现）。
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// AuditEntry — 审计条目实体（哈希链节点）
// ---------------------------------------------------------------------------

/// 审计条目实体（私有字段；构造经位置参 funnel；时间由调用方注入，不取系统时钟）。
///
/// 对标：sigstore-rs LogEntry.log_index（→ seq）+ body（→ entry 内容）。不 derive `Serialize`（域类型不走 wire）。
/// `entry_hash` 是入参（由 appender 经 [`AuditChainHasher::link`] 预算后传入）——实体是 dumb data holder，
/// key 不进实体 ⇒ 域逻辑可无 key 测试。
#[derive(Clone)]
pub struct AuditEntry {
    /// 单调递增序列号（对标 rekor log_index）。
    seq: u64,
    /// 前一条目哈希（链首 seq=0 时为全零 hash）。
    prev_hash: EntryHash,
    /// 本条目哈希（由 [`AuditChainHasher::link`] 计算）。
    entry_hash: EntryHash,
    /// 操作者标识（用 `ids::UserId`；设备 / service 场景用 actor_kind 区分）。
    actor: ids::UserId,
    /// 操作者类别（驱动 audit 报告分层；与 authn principal 对齐）。
    actor_kind: vocab::PrincipalKind,
    /// 租户标识（行级多租隔离；对标 settings::ConfigEntry.tenant）。
    tenant: vocab::TenantId,
    /// 授权动作。
    action: vocab::Action,
    /// 被操作资源引用。
    resource: ResourceRef,
    /// 操作结果。
    outcome: AuditOutcome,
    /// 记录时间（由调用方注入，不在此取系统时钟）。
    recorded_at: SystemTime,
}

impl AuditEntry {
    /// 构造审计条目（位置参 funnel；`recorded_at` 来自调用方注入的时钟，禁止在此取系统时间）。
    // reason: AuditEntry 是审计链节点实体，所有字段均为链完整性/取证必填参数，分组构造破坏原子性。
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        seq: u64,
        prev_hash: EntryHash,
        entry_hash: EntryHash,
        actor: ids::UserId,
        actor_kind: vocab::PrincipalKind,
        tenant: vocab::TenantId,
        action: vocab::Action,
        resource: ResourceRef,
        outcome: AuditOutcome,
        recorded_at: SystemTime,
    ) -> Self {
        Self {
            seq,
            prev_hash,
            entry_hash,
            actor,
            actor_kind,
            tenant,
            action,
            resource,
            outcome,
            recorded_at,
        }
    }

    /// 从**可信存储**重建已封链条目（adapter `list`/`verify_tail` 读出行后 rehydrate；构造器 funnel `pub`，
    /// 供独立 adapter crate 跨 crate 重建）。
    ///
    /// rehydrate 是 dumb data holder 重建，**不内验**——完整性由 repo 显式调 [`AuditChainHasher::verify_window`]
    /// 检验（保持 entity=持有者 / hasher=验证者 分离，篡改在显式验证步 fail-closed）。
    // reason: 同 `new`——链节点所有字段是完整性/取证必填参数，分组构造破坏原子性。
    #[allow(clippy::too_many_arguments)]
    pub fn hydrate(
        seq: u64,
        prev_hash: EntryHash,
        entry_hash: EntryHash,
        actor: ids::UserId,
        actor_kind: vocab::PrincipalKind,
        tenant: vocab::TenantId,
        action: vocab::Action,
        resource: ResourceRef,
        outcome: AuditOutcome,
        recorded_at: SystemTime,
    ) -> Self {
        Self::new(
            seq,
            prev_hash,
            entry_hash,
            actor,
            actor_kind,
            tenant,
            action,
            resource,
            outcome,
            recorded_at,
        )
    }

    /// 返回单调序列号。
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// 返回前一条目哈希。
    pub fn prev_hash(&self) -> &EntryHash {
        &self.prev_hash
    }

    /// 返回本条目哈希。
    pub fn entry_hash(&self) -> &EntryHash {
        &self.entry_hash
    }

    /// 返回操作者标识。
    pub fn actor(&self) -> ids::UserId {
        self.actor
    }

    /// 返回操作者类别。
    pub fn actor_kind(&self) -> vocab::PrincipalKind {
        self.actor_kind
    }

    /// 返回授权动作引用。
    pub fn action(&self) -> &vocab::Action {
        &self.action
    }

    /// 返回资源引用。
    pub fn resource(&self) -> &ResourceRef {
        &self.resource
    }

    /// 返回审计结果。
    pub fn outcome(&self) -> AuditOutcome {
        self.outcome
    }

    /// 返回记录时间。
    pub fn recorded_at(&self) -> SystemTime {
        self.recorded_at
    }

    /// 返回租户标识（行级多租隔离）。
    pub fn tenant(&self) -> vocab::TenantId {
        self.tenant
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
// canonical_message — 冻结字节布局（安全关键，单源 docs/rules/audit-ledger.md）
// ---------------------------------------------------------------------------

/// 追加长度前缀（`u32` BE 长度 + 原始字节）——变长字段消歧（防 `kind="ab",id="c"` 与 `kind="a",id="bc"` 撞）。
fn push_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    // reason: 超 u32::MAX 的字段长度不可表达，fail-closed 截断为 MAX（实际审计字段远小于 4GiB）。
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// 计算链节点 HMAC 输入消息（纯函数；冻结布局）。
///
/// `message = prev_hash(32) ‖ DOMAIN_TAG ‖ tenant(16) ‖ seq(u64 BE) ‖ actor(16) ‖ actor_kind(tag) ‖
///            lp(action) ‖ lp(resource.kind) ‖ lp(resource.id) ‖ outcome(tag) ‖ secs(u64 BE) ‖ nanos(u32 BE)`
///
/// INVARIANT: AUDIT-LEDGER-BYTES-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（布局冻结，golden 字节测试守；改布局即破链 ⇒ 须同步 docs/rules/audit-ledger.md + golden）。
fn canonical_message(prev: &EntryHash, entry: &AuditEntry) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(prev.as_bytes());
    msg.extend_from_slice(DOMAIN_TAG);
    msg.extend_from_slice(entry.tenant.as_uuid().as_bytes());
    msg.extend_from_slice(&entry.seq.to_be_bytes());
    msg.extend_from_slice(entry.actor.as_uuid().as_bytes());
    msg.push(principal_kind_tag(entry.actor_kind));
    push_len_prefixed(&mut msg, entry.action.as_str().as_bytes());
    push_len_prefixed(&mut msg, entry.resource.kind.as_bytes());
    push_len_prefixed(&mut msg, entry.resource.id.as_bytes());
    msg.push(outcome_tag(entry.outcome));
    // reason: epoch 前的时间不可表达，fail-closed 落 (0,0)（审计 recorded_at 由注入时钟产生，必 ≥ epoch）。
    let since_epoch = entry
        .recorded_at
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    msg.extend_from_slice(&since_epoch.as_secs().to_be_bytes());
    msg.extend_from_slice(&since_epoch.subsec_nanos().to_be_bytes());
    msg
}

// ---------------------------------------------------------------------------
// AuditChainHasher — keyed HMAC 链服务（构造器注入 verifier + key）
// ---------------------------------------------------------------------------

/// keyed HMAC 哈希链服务（构造器注入 [`MacVerifier`] + [`MacKey`]）。
///
/// key 是凭据：构造器必填 ⇒ 无 key 不可造 hasher（防篡改属性类型层成立）；`Debug` 脱敏不泄 key。
/// `link`/`verify` 是 L0 纯计算（无 I/O、无时钟），确定性于 `(key, prev, entry_content)`。
pub struct AuditChainHasher<M: MacVerifier> {
    mac: M,
    key: MacKey,
}

impl<M: MacVerifier> std::fmt::Debug for AuditChainHasher<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditChainHasher")
            .field("key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl<M: MacVerifier> AuditChainHasher<M> {
    /// 注入 verifier + key 构造（key 托管入口）。
    ///
    /// fail-closed：key 短于 [`MIN_KEY_LEN`]（链 key ≥32B，`docs/rules/audit-ledger.md`）即返回 `None`
    /// ——弱 key 不可造 hasher。此处是 key 强度的**单一收口**（任何构造路径均经此校验，非仅 callsite）。
    pub fn new(mac: M, key: MacKey) -> Option<Self> {
        if key.as_bytes().len() < MIN_KEY_LEN {
            return None;
        }
        Some(Self { mac, key })
    }

    /// 计算链节点哈希 `HMAC-SHA256(key, prev ‖ canonical(entry))`。
    pub fn link(&self, prev: &EntryHash, entry: &AuditEntry) -> EntryHash {
        let message = canonical_message(prev, entry);
        let tag = self.mac.sign(&self.key, MacAlgorithm::HmacSha256, &message);
        // reason: HMAC-SHA256 输出恒 32B；非 32B 仅 buggy verifier，fail-closed 落 FAIL_HASH（全 0xFF，
        // 非 genesis、非真实 HMAC，verify 时与任何合法链不匹配 ⇒ fail-close，不会与 genesis 碰撞）。
        let bytes: [u8; 32] = tag.as_bytes().try_into().unwrap_or(FAIL_HASH);
        EntryHash::new(bytes)
    }

    /// 验证单租户、按 seq 升序、**genesis 起链**的审计链完整性（全链；委托 [`verify_window`](Self::verify_window)
    /// 以 `predecessor = None` 锚定 genesis）。
    ///
    /// 逐条 fail-closed：(A) 同租户 (B) 序列单调（首=0、后续 +1） (C) prev_hash 链接 (D) entry_hash 重算一致。
    /// 调用方须先按租户分区并升序；(A) 是防御纵深（混租户 slice 视为结构破坏）。
    pub fn verify(&self, entries: &[AuditEntry]) -> Result<(), AuditError> {
        self.verify_window(None, entries)
    }

    /// **增量窗口验证**（持久化 provider 读路径 + bootstrap tail-verify 用）：验证 `entries` 窗口自身链接 +
    /// 逐条 integrity，并校验窗口首条接续给定 `predecessor`——**不全扫整条租户链**（postgres provider 只读
    /// 窗口 + 1 前驱行，O(window) 而非 O(n)）。
    ///
    /// - `predecessor = None`：窗口首条按 **genesis** 锚定（seq=0、prev 全零）——等价全链 [`verify`](Self::verify)。
    /// - `predecessor = Some(p)`：窗口首条须 `seq == p.seq + 1` 且 `prev_hash == p.entry_hash`（接续 p）。
    ///
    /// 逐条 fail-closed：(A) 同租户（锚定 `predecessor.tenant`，无则窗口首条 tenant） (B) 序列单调 (C) prev_hash
    /// 链接 (D) entry_hash 重算一致。调用方须按 seq 升序传入窗口。
    pub fn verify_window(
        &self,
        predecessor: Option<&AuditEntry>,
        entries: &[AuditEntry],
    ) -> Result<(), AuditError> {
        let Some(first) = entries.first() else {
            return Ok(());
        };
        let tenant = predecessor.map_or(first.tenant, |p| p.tenant);
        for (i, entry) in entries.iter().enumerate() {
            if entry.tenant != tenant {
                return Err(AuditError::ChainBroken);
            }
            let prev = if i == 0 {
                predecessor
            } else {
                Some(&entries[i - 1])
            };
            verify_link(prev, entry)?;
            self.verify_integrity(entry)?;
        }
        Ok(())
    }

    /// (D) entry_hash 重算与存储一致（常数时间比较）。
    fn verify_integrity(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        let recomputed = self.link(entry.prev_hash(), entry);
        if constant_time_eq(recomputed.as_bytes(), entry.entry_hash().as_bytes()) {
            Ok(())
        } else {
            Err(AuditError::HashMismatch)
        }
    }
}

/// (B)+(C) 序列单调 + prev_hash 链接（与 key 无关，独立纯函数）。`prev = None` ⇒ 窗口首条按 genesis 锚定；
/// `prev = Some(p)` ⇒ 接续前驱 p（全链中 p 即 `entries[i-1]`，增量窗口中 p 是窗口外的存储前驱行）。
fn verify_link(prev: Option<&AuditEntry>, entry: &AuditEntry) -> Result<(), AuditError> {
    match prev {
        None => {
            // genesis：seq 必 0、prev 必全零。
            if entry.seq() != 0 {
                return Err(AuditError::SequenceGap);
            }
            if !constant_time_eq(entry.prev_hash().as_bytes(), &GENESIS_PREV) {
                return Err(AuditError::ChainBroken);
            }
        }
        Some(prev) => {
            // gap 与 dup 都使 `seq != prev.seq + 1`；溢出（None）亦判 gap。
            if prev.seq().checked_add(1) != Some(entry.seq()) {
                return Err(AuditError::SequenceGap);
            }
            if !constant_time_eq(entry.prev_hash().as_bytes(), prev.entry_hash().as_bytes()) {
                return Err(AuditError::ChainBroken);
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 错误枚举
// ---------------------------------------------------------------------------

/// 审计域错误（库枚举；`thiserror`；message 为 const 静态字面量，PII 边界——runtime 数据不进 `Display`）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuditError {
    /// 哈希链在某条目处断裂（prev_hash 不匹配 / 跨租户 / genesis prev 非零）。
    #[error("audit chain is broken")]
    ChainBroken,
    /// 条目哈希校验失败（entry_hash 与重算结果不符）。
    #[error("audit hash mismatch")]
    HashMismatch,
    /// 序列号不连续（gap 或重复）。
    #[error("audit sequence gap detected")]
    SequenceGap,
    /// 续页游标语义无效（base64url 合法但非有效页索引）——客户端错误，handler 映射 400。
    #[error("audit cursor is semantically invalid")]
    InvalidCursor,
    /// 持久化层失败（adapter 桥接，如 sqlx / 连接错误）。`Display` 仅静态摘要常量（PII 边界）；
    /// 原始错误经 `#[source]` 仅作 internal source 保留（服务端日志关联，不进 wire）。in-mem provider 永不产此。
    #[error("audit storage failure")]
    Storage(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl AuditError {
    /// 把 adapter 内部错误（sqlx 等）包成 [`AuditError::Storage`]（原始错误仅作 internal source，不经 `Display` 暴露）。
    pub fn storage<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        AuditError::Storage(Box::new(source))
    }
}

/// 跨模块共享的确定性测试 verifier（domain / internal / application 单测复用；非加密，仅确定性 + key/msg 敏感）。
/// 域单测不依赖 adapter crate（rust-standards.md §命名），真实 sha2/hmac 是 follow-up adapter。
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::AuditChainHasher;
    use primitives::{Mac, MacAlgorithm, MacKey, MacVerifier, constant_time_eq};

    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    /// keyed FNV-1a 折叠 verifier（4 lane → 32B，混 key+message ⇒ 对二者均敏感）。
    pub struct TestKeyedHasher;
    impl MacVerifier for TestKeyedHasher {
        fn sign(&self, key: &MacKey, _algorithm: MacAlgorithm, message: &[u8]) -> Mac {
            let mut lanes = [
                FNV_OFFSET,
                FNV_OFFSET ^ 0x1111_1111_1111_1111,
                FNV_OFFSET ^ 0x2222_2222_2222_2222,
                FNV_OFFSET ^ 0x3333_3333_3333_3333,
            ];
            for (i, &b) in key.as_bytes().iter().chain(message).enumerate() {
                let lane = i % 4;
                lanes[lane] ^= u64::from(b);
                lanes[lane] = lanes[lane].wrapping_mul(FNV_PRIME);
            }
            let mut out = [0u8; 32];
            for (lane, chunk) in lanes.iter().zip(out.chunks_mut(8)) {
                chunk.copy_from_slice(&lane.to_be_bytes());
            }
            Mac::from_bytes(out.to_vec())
        }

        fn verify(&self, key: &MacKey, algorithm: MacAlgorithm, message: &[u8], tag: &Mac) -> bool {
            constant_time_eq(
                self.sign(key, algorithm, message).as_bytes(),
                tag.as_bytes(),
            )
        }
    }

    /// 取定长 key（`key_byte` 重复 32 次）的 hasher（32B 满足 `MIN_KEY_LEN`，构造必 `Some`）。
    #[allow(clippy::expect_used)]
    pub fn keyed_hasher(key_byte: u8) -> AuditChainHasher<TestKeyedHasher> {
        AuditChainHasher::new(TestKeyedHasher, MacKey::from_bytes(vec![key_byte; 32]))
            .expect("32B test key satisfies MIN_KEY_LEN")
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{TestKeyedHasher, keyed_hasher};
    use super::*;
    use rstest::rstest;

    const TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const TENANT_B: &str = "00000000-0000-4000-8000-000000000abc";
    const ACTOR: &str = "11111111-2222-4333-8444-555555555555";

    fn hasher() -> AuditChainHasher<TestKeyedHasher> {
        keyed_hasher(0x5a)
    }

    #[allow(clippy::expect_used)]
    fn tenant(raw: &str) -> vocab::TenantId {
        vocab::TenantId::parse(raw).expect("canonical tenant")
    }

    #[allow(clippy::expect_used)]
    fn actor() -> ids::UserId {
        ids::UserId::parse(ACTOR).expect("canonical actor")
    }

    #[allow(clippy::expect_used)]
    fn action(raw: &str) -> vocab::Action {
        vocab::Action::parse(raw).expect("valid action")
    }

    /// 造一条未封哈希的内容（entry_hash 占位全零，由 caller 用 `seal` 替换）。
    fn raw_entry(seq: u64, prev: EntryHash, tenant_raw: &str) -> AuditEntry {
        AuditEntry::new(
            seq,
            prev,
            EntryHash::genesis(),
            actor(),
            vocab::PrincipalKind::User,
            tenant(tenant_raw),
            action("audit:read"),
            ResourceRef::new("session", "sess-1"),
            AuditOutcome::Success,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        )
    }

    /// 用 hasher 封一条 entry（计算 entry_hash 替换占位）。
    fn seal(h: &AuditChainHasher<TestKeyedHasher>, raw: AuditEntry) -> AuditEntry {
        let entry_hash = h.link(&raw.prev_hash, &raw);
        AuditEntry::new(
            raw.seq,
            raw.prev_hash,
            entry_hash,
            raw.actor,
            raw.actor_kind,
            raw.tenant,
            raw.action.clone(),
            raw.resource.clone(),
            raw.outcome,
            raw.recorded_at,
        )
    }

    /// 造一条已封 genesis 条目。
    fn genesis_sealed(h: &AuditChainHasher<TestKeyedHasher>) -> AuditEntry {
        seal(h, raw_entry(0, EntryHash::genesis(), TENANT_A))
    }

    /// 造长度 n 的合法链（genesis + 续接）。
    fn chain(h: &AuditChainHasher<TestKeyedHasher>, n: u64) -> Vec<AuditEntry> {
        let mut out = Vec::new();
        let mut prev = EntryHash::genesis();
        for seq in 0..n {
            let sealed = seal(h, raw_entry(seq, prev, TENANT_A));
            prev = *sealed.entry_hash();
            out.push(sealed);
        }
        out
    }

    // 0 — key 强度 fail-closed：<32B key 不可造 hasher，≥32B 可造（边界 31/32）。
    #[test]
    fn hasher_construction_rejects_keys_shorter_than_32_bytes() {
        for len in [0usize, 1, 16, 31] {
            assert!(
                AuditChainHasher::new(
                    TestKeyedHasher,
                    primitives::MacKey::from_bytes(vec![0x5a; len])
                )
                .is_none(),
                "len={len} <32B 须拒绝构造（fail-closed）"
            );
        }
        for len in [32usize, 33, 64] {
            assert!(
                AuditChainHasher::new(
                    TestKeyedHasher,
                    primitives::MacKey::from_bytes(vec![0x5a; len])
                )
                .is_some(),
                "len={len} ≥32B 须可构造"
            );
        }
    }

    // 1 — genesis link 用零 prev + 确定性。
    #[test]
    fn genesis_link_is_deterministic() {
        let h = hasher();
        let e = raw_entry(0, EntryHash::genesis(), TENANT_A);
        let a = h.link(&EntryHash::genesis(), &e);
        let b = h.link(&EntryHash::genesis(), &e);
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), &GENESIS_PREV, "link 输出不应恰为全零");
    }

    // 2 — 单 genesis 条目 verify Ok。
    #[test]
    fn single_genesis_entry_verifies() {
        let h = hasher();
        assert!(h.verify(&[genesis_sealed(&h)]).is_ok());
    }

    // 3 — 三条 append+verify happy。
    #[test]
    fn multi_entry_chain_verifies() {
        let h = hasher();
        assert!(h.verify(&chain(&h, 3)).is_ok());
    }

    /// 篡改目标字段（typed enum ⇒ 穷尽 match，无 `_` catch-all / panic）。
    #[derive(Clone, Copy)]
    enum TamperField {
        Tenant,
        Actor,
        ActorKind,
        Action,
        ResourceKind,
        ResourceId,
        Outcome,
        RecordedAt,
    }

    #[allow(clippy::expect_used)]
    fn other_actor() -> ids::UserId {
        ids::UserId::parse("99999999-2222-4333-8444-555555555555").expect("other actor")
    }

    // 4 — 逐字段篡改 → HashMismatch（证每字段入摘要）。
    #[rstest]
    #[case(TamperField::Tenant)]
    #[case(TamperField::Actor)]
    #[case(TamperField::ActorKind)]
    #[case(TamperField::Action)]
    #[case(TamperField::ResourceKind)]
    #[case(TamperField::ResourceId)]
    #[case(TamperField::Outcome)]
    #[case(TamperField::RecordedAt)]
    fn field_tamper_detected_as_hash_mismatch(#[case] field: TamperField) {
        let h = hasher();
        let original = genesis_sealed(&h);
        // 保留原 entry_hash（stale），只改一个内容字段 ⇒ 重算 ≠ 存储。
        let stale = *original.entry_hash();
        let prev = *original.prev_hash();
        let mut a = actor();
        let mut kind = vocab::PrincipalKind::User;
        let mut ten = TENANT_A;
        let mut act = action("audit:read");
        let mut res = ResourceRef::new("session", "sess-1");
        let mut outcome = AuditOutcome::Success;
        let mut at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        match field {
            TamperField::Tenant => ten = TENANT_B,
            TamperField::Actor => a = other_actor(),
            TamperField::ActorKind => kind = vocab::PrincipalKind::Admin,
            TamperField::Action => act = action("audit:write"),
            TamperField::ResourceKind => res = ResourceRef::new("device", "sess-1"),
            TamperField::ResourceId => res = ResourceRef::new("session", "sess-2"),
            TamperField::Outcome => outcome = AuditOutcome::Denied,
            TamperField::RecordedAt => {
                at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_001);
            }
        }
        let tampered = AuditEntry::new(0, prev, stale, a, kind, tenant(ten), act, res, outcome, at);
        assert!(matches!(
            h.verify(&[tampered]),
            Err(AuditError::HashMismatch)
        ));
    }

    // 5 — prev 链接断 → ChainBroken。
    #[test]
    fn broken_prev_linkage_is_chain_broken() {
        let h = hasher();
        let g = genesis_sealed(&h);
        // 第二条 prev_hash 指向错误哈希（非 g.entry_hash），但自洽封链。
        let wrong_prev = EntryHash::new([0xab; 32]);
        let second = seal(&h, raw_entry(1, wrong_prev, TENANT_A));
        assert!(matches!(
            h.verify(&[g, second]),
            Err(AuditError::ChainBroken)
        ));
    }

    // 6 — genesis prev 非零 → ChainBroken。
    #[test]
    fn genesis_nonzero_prev_is_chain_broken() {
        let h = hasher();
        let bad = seal(&h, raw_entry(0, EntryHash::new([1u8; 32]), TENANT_A));
        assert!(matches!(h.verify(&[bad]), Err(AuditError::ChainBroken)));
    }

    // 7 — 序列 gap → SequenceGap。
    #[test]
    fn sequence_gap_is_detected() {
        let h = hasher();
        let g = genesis_sealed(&h);
        let skipped = seal(&h, raw_entry(2, *g.entry_hash(), TENANT_A));
        assert!(matches!(
            h.verify(&[g, skipped]),
            Err(AuditError::SequenceGap)
        ));
    }

    // 8 — 序列 dup → SequenceGap。
    #[test]
    fn sequence_duplicate_is_detected() {
        let h = hasher();
        let g = genesis_sealed(&h);
        let dup = seal(&h, raw_entry(0, *g.entry_hash(), TENANT_A));
        assert!(matches!(h.verify(&[g, dup]), Err(AuditError::SequenceGap)));
    }

    // 9 — 首条 seq≠0 → SequenceGap。
    #[test]
    fn first_seq_nonzero_is_sequence_gap() {
        let h = hasher();
        let one = seal(&h, raw_entry(1, EntryHash::genesis(), TENANT_A));
        assert!(matches!(h.verify(&[one]), Err(AuditError::SequenceGap)));
    }

    // 10 — slice 混租户 → ChainBroken。
    #[test]
    fn cross_tenant_slice_is_chain_broken() {
        let h = hasher();
        let g = genesis_sealed(&h);
        let other = seal(&h, raw_entry(1, *g.entry_hash(), TENANT_B));
        assert!(matches!(
            h.verify(&[g, other]),
            Err(AuditError::ChainBroken)
        ));
    }

    // 11 — 空链 → Ok。
    #[test]
    fn empty_chain_is_ok() {
        assert!(hasher().verify(&[]).is_ok());
    }

    // 12 — 错 key 验证失败 → HashMismatch（P0 回归：证链 keyed）。
    #[test]
    fn wrong_key_fails_verification() {
        let signer = keyed_hasher(0x01);
        let entries = chain(&signer, 2);
        let verifier = keyed_hasher(0x02);
        assert!(matches!(
            verifier.verify(&entries),
            Err(AuditError::HashMismatch)
        ));
    }

    // 13 — test verifier 的 verify 对 key 敏感（不同 key 返回 false）。
    #[allow(clippy::expect_used)]
    #[test]
    fn test_keyed_hasher_verify_is_key_sensitive() {
        use primitives::{MacAlgorithm, MacKey};

        let msg = b"test-message";
        let key1 = MacKey::from_bytes(vec![0x01u8; 32]);
        let key2 = MacKey::from_bytes(vec![0x02u8; 32]);

        let verifier = TestKeyedHasher;
        let tag = verifier.sign(&key1, MacAlgorithm::HmacSha256, msg);
        // 同 key 验证应 true。
        assert!(
            verifier.verify(&key1, MacAlgorithm::HmacSha256, msg, &tag),
            "同 key verify 须 true"
        );
        // 不同 key 验证应 false（证 verify 对 key 敏感）。
        assert!(
            !verifier.verify(&key2, MacAlgorithm::HmacSha256, msg, &tag),
            "不同 key verify 须 false（verify 须 key 敏感）"
        );
    }

    // 14 — EntryHash Debug redacted。
    #[test]
    fn entry_hash_debug_redacted() {
        assert_eq!(
            format!("{:?}", EntryHash::new([1u8; 32])),
            "EntryHash(<redacted>)"
        );
    }

    // 15 — ResourceRef Debug 脱敏 id、保留 kind。
    #[test]
    fn resource_ref_debug_redacts_id() {
        let dbg = format!("{:?}", ResourceRef::new("session", "secret-id"));
        assert!(dbg.contains("session"), "kind 应可见: {dbg}");
        assert!(!dbg.contains("secret-id"), "id 应脱敏: {dbg}");
        assert!(dbg.contains("<redacted>"), "缺占位: {dbg}");
    }

    // 16 — hasher Debug 不含 key。
    #[test]
    fn hasher_debug_redacts_key() {
        let dbg = format!("{:?}", hasher());
        assert!(dbg.contains("<redacted>"), "缺占位: {dbg}");
        assert!(!dbg.contains("5a5a"), "key 字节不应出现: {dbg}");
    }

    // 17 — canonical_message 全字节 golden（冻结布局，INVARIANT: AUDIT-LEDGER-BYTES-01 { level = "Medium", exec = "manual/opt-in", source = "code" }）。
    #[allow(clippy::expect_used)]
    #[test]
    fn canonical_message_golden_full_bytes() {
        let genesis = EntryHash::genesis();
        let e = raw_entry(0, genesis, TENANT_A);
        let m1 = canonical_message(&genesis, &e);
        let m2 = canonical_message(&genesis, &e);
        assert_eq!(m1, m2, "确定性");

        // 构造期望全字节序列（与 docs/rules/audit-ledger.md §冻结字节布局 单源对齐）。
        let mut expected: Vec<u8> = Vec::new();
        // prev_hash(32): genesis 全零
        expected.extend_from_slice(&GENESIS_PREV);
        // DOMAIN_TAG(13)
        expected.extend_from_slice(DOMAIN_TAG);
        // tenant uuid bytes(16)
        expected.extend_from_slice(tenant(TENANT_A).as_uuid().as_bytes());
        // seq=0 u64 BE(8)
        expected.extend_from_slice(&0u64.to_be_bytes());
        // actor uuid bytes(16)
        expected.extend_from_slice(actor().as_uuid().as_bytes());
        // actor_kind tag(1): User=1
        expected.push(1u8);
        // lp("audit:read"): u32 BE len=10 ++ bytes
        let action_bytes = b"audit:read";
        expected.extend_from_slice(&(action_bytes.len() as u32).to_be_bytes());
        expected.extend_from_slice(action_bytes);
        // lp("session"): u32 BE len=7 ++ bytes
        let kind_bytes = b"session";
        expected.extend_from_slice(&(kind_bytes.len() as u32).to_be_bytes());
        expected.extend_from_slice(kind_bytes);
        // lp("sess-1"): u32 BE len=6 ++ bytes
        let id_bytes = b"sess-1";
        expected.extend_from_slice(&(id_bytes.len() as u32).to_be_bytes());
        expected.extend_from_slice(id_bytes);
        // outcome tag(1): Success=1
        expected.push(1u8);
        // secs u64 BE(8): 1_700_000_000
        expected.extend_from_slice(&1_700_000_000u64.to_be_bytes());
        // nanos u32 BE(4): 0
        expected.extend_from_slice(&0u32.to_be_bytes());

        assert_eq!(
            m1, expected,
            "canonical_message 全字节布局须与 audit-ledger.md 冻结布局一致（INVARIANT: AUDIT-LEDGER-BYTES-01）"
        );
    }

    // 18 — 值对象 accessor round-trip。
    #[test]
    fn value_object_accessors_round_trip() {
        let h = hasher();
        let e = genesis_sealed(&h);
        assert_eq!(e.seq(), 0);
        assert_eq!(e.tenant().to_string(), TENANT_A);
        assert_eq!(e.actor().as_uuid(), actor().as_uuid());
        assert!(matches!(e.actor_kind(), vocab::PrincipalKind::User));
        assert_eq!(e.action().as_str(), "audit:read");
        assert_eq!(e.resource().kind(), "session");
        assert_eq!(e.resource().id(), "sess-1");
        assert!(matches!(e.outcome(), AuditOutcome::Success));
        assert_eq!(
            e.recorded_at(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
        );
        assert_eq!(e.prev_hash().as_bytes(), &GENESIS_PREV);
        assert_ne!(e.entry_hash().as_bytes(), &GENESIS_PREV);
    }

    // 19 — enum tag 全且非零唯一。
    #[test]
    fn enum_tag_mapping_is_total_and_nonzero() {
        let pk = [
            principal_kind_tag(vocab::PrincipalKind::User),
            principal_kind_tag(vocab::PrincipalKind::Device),
            principal_kind_tag(vocab::PrincipalKind::Admin),
            principal_kind_tag(vocab::PrincipalKind::SuperAdmin),
            principal_kind_tag(vocab::PrincipalKind::Service),
            principal_kind_tag(vocab::PrincipalKind::Anonymous),
        ];
        assert!(pk.iter().all(|&t| t != 0), "已知 PrincipalKind tag 须非零");
        let mut sorted = pk.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), pk.len(), "PrincipalKind tag 须唯一");

        let oc = [
            outcome_tag(AuditOutcome::Success),
            outcome_tag(AuditOutcome::Denied),
            outcome_tag(AuditOutcome::Error),
        ];
        assert!(oc.iter().all(|&t| t != 0), "AuditOutcome tag 须非零");
        let mut ocs = oc.to_vec();
        ocs.sort_unstable();
        ocs.dedup();
        assert_eq!(ocs.len(), oc.len(), "AuditOutcome tag 须唯一");
    }

    // 20 — verify_window(None, ..) 等价全链 verify（genesis 锚定）。
    #[test]
    fn verify_window_genesis_anchored_equals_full_verify() {
        let h = hasher();
        let c = chain(&h, 3);
        assert!(h.verify_window(None, &c).is_ok());
        // 与 verify 一致：篡改 genesis prev 非零 → ChainBroken。
        let bad = seal(&h, raw_entry(0, EntryHash::new([1u8; 32]), TENANT_A));
        assert!(matches!(
            h.verify_window(None, &[bad]),
            Err(AuditError::ChainBroken)
        ));
    }

    // 21 — verify_window(Some(pred), window) happy：窗口接续存储前驱（增量验证，不全扫）。
    #[test]
    fn verify_window_with_predecessor_happy() {
        let h = hasher();
        let c = chain(&h, 5);
        // 前驱 = c[1]，窗口 = c[2..5]（seq 2,3,4）。
        let pred = &c[1];
        let window = &c[2..5];
        assert!(h.verify_window(Some(pred), window).is_ok());
    }

    // 22 — 窗口首条 seq 接续前驱、但 prev_hash 不接续（前驱 entry_hash 被改）→ ChainBroken。
    #[test]
    fn verify_window_broken_link_to_predecessor_is_chain_broken() {
        let h = hasher();
        let c = chain(&h, 4);
        // 伪前驱：保留真前驱 c[1] 的 seq(1)，但 entry_hash 改掉 ⇒ 与 c[2].prev_hash（== 真 c[1].entry）不接续。
        // seq 接续（1+1==2）通过，hash 链接失败 → ChainBroken（区别于 SequenceGap）。
        let bad_pred = AuditEntry::hydrate(
            c[1].seq(),
            *c[1].prev_hash(),
            EntryHash::new([0xCD; 32]),
            c[1].actor(),
            c[1].actor_kind(),
            c[1].tenant(),
            c[1].action().clone(),
            ResourceRef::new(c[1].resource().kind(), c[1].resource().id()),
            c[1].outcome(),
            c[1].recorded_at(),
        );
        let window = &c[2..4];
        assert!(matches!(
            h.verify_window(Some(&bad_pred), window),
            Err(AuditError::ChainBroken)
        ));
    }

    // 23 — 窗口首条 seq 不接续前驱（off-by-one）→ SequenceGap。
    #[test]
    fn verify_window_sequence_break_to_predecessor_is_gap() {
        let h = hasher();
        let c = chain(&h, 4);
        // 前驱 c[0]（seq 0），窗口首条 c[2]（seq 2 ≠ 0+1）→ gap。
        let pred = &c[0];
        let window = &c[2..4];
        // 注：先命中 seq gap（在 link 检查里 seq 先于 hash）。
        assert!(matches!(
            h.verify_window(Some(pred), &window[..1]),
            Err(AuditError::SequenceGap)
        ));
    }

    // 24 — 窗口内某条内容篡改 → HashMismatch（增量验证仍逐条 integrity）。
    #[test]
    fn verify_window_content_tamper_is_hash_mismatch() {
        let h = hasher();
        let c = chain(&h, 4);
        let pred = c[0].clone();
        // 窗口 = c[1..3]；篡改窗口第二条（c[2]）内容但保留其 entry_hash。
        let stale = *c[2].entry_hash();
        let tampered = AuditEntry::new(
            c[2].seq(),
            *c[2].prev_hash(),
            stale,
            c[2].actor(),
            vocab::PrincipalKind::Admin, // 改 actor_kind
            c[2].tenant(),
            c[2].action().clone(),
            ResourceRef::new(c[2].resource().kind(), c[2].resource().id()),
            c[2].outcome(),
            c[2].recorded_at(),
        );
        let window = [c[1].clone(), tampered];
        assert!(matches!(
            h.verify_window(Some(&pred), &window),
            Err(AuditError::HashMismatch)
        ));
    }

    // 25 — hydrate round-trip：从字段重建条目，访问器全等（dumb 重建，不内验）。
    #[test]
    fn hydrate_round_trips_fields() {
        let h = hasher();
        let sealed = genesis_sealed(&h);
        let rebuilt = AuditEntry::hydrate(
            sealed.seq(),
            *sealed.prev_hash(),
            *sealed.entry_hash(),
            sealed.actor(),
            sealed.actor_kind(),
            sealed.tenant(),
            sealed.action().clone(),
            ResourceRef::new(sealed.resource().kind(), sealed.resource().id()),
            sealed.outcome(),
            sealed.recorded_at(),
        );
        // 重建后链验证通过（与原条目同字节 ⇒ entry_hash 重算一致）。
        assert!(h.verify(std::slice::from_ref(&rebuilt)).is_ok());
        assert_eq!(rebuilt.seq(), sealed.seq());
        assert_eq!(
            rebuilt.entry_hash().as_bytes(),
            sealed.entry_hash().as_bytes()
        );
    }

    // 26 — verify_window(Some(predecessor), &[]) 空窗口 + 有前驱 → Ok（early None-arm 直接返回 Ok）。
    #[test]
    fn verify_window_empty_window_with_predecessor_is_ok() {
        let h = hasher();
        let c = chain(&h, 2);
        // 传入 predecessor = c[1]，窗口为空 &[] → entries.first() 返回 None → 立即 Ok。
        // 证明：空窗口时不验前驱接续（无条目无需检查接续关系），任意 predecessor 均可。
        let result = h.verify_window(Some(&c[1]), &[]);
        assert!(
            result.is_ok(),
            "verify_window(Some(pred), &[]) 空窗口 + 有前驱须返回 Ok（early-return）"
        );
    }

    // 27 — AuditOutcome / actor_kind DB funnel round-trip 全集性。
    #[test]
    fn db_text_funnels_round_trip_for_all_known_variants() {
        for oc in [
            AuditOutcome::Success,
            AuditOutcome::Denied,
            AuditOutcome::Error,
        ] {
            assert_eq!(AuditOutcome::from_db(oc.to_db()), Some(oc));
        }
        assert_eq!(AuditOutcome::from_db("bogus"), None);
        for kind in [
            vocab::PrincipalKind::User,
            vocab::PrincipalKind::Device,
            vocab::PrincipalKind::Admin,
            vocab::PrincipalKind::SuperAdmin,
            vocab::PrincipalKind::Service,
            vocab::PrincipalKind::Anonymous,
        ] {
            assert_eq!(actor_kind_from_db(actor_kind_to_db(kind)), Some(kind));
        }
        assert_eq!(actor_kind_from_db("unknown"), None);
        assert_eq!(actor_kind_from_db("bogus"), None);
    }

    // 27 — AuditError::storage 包 source，Display PII-safe（仅静态摘要，不含原始错误）。
    #[test]
    fn audit_error_storage_redacts_display() {
        let err = AuditError::storage(std::io::Error::other("leak-marker-db"));
        assert_eq!(err.to_string(), "audit storage failure");
        assert!(std::error::Error::source(&err).is_some(), "source 须保留");
        assert!(
            !err.to_string().contains("leak-marker-db"),
            "Display 不得泄漏原始错误: {err}"
        );
    }
}
