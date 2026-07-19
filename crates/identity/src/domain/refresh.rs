//! identity::domain::refresh — refresh token 持久化快照域实体（dylint rss_domain_no_serialize 守护区，#1325）。
//!
//! refresh token 形态 = 高熵不透明 secret（`secure::refresh::OpaqueToken`，**非 JWT**）；服务端**只持
//! SHA-256 摘要**（[`RefreshTokenHash`]），不存明文。本模块建模持久化**快照** + 合法状态迁移；轮换 /
//! 重放检测 / CAS 解释等编排逻辑在 `application::RefreshService`（域只持数据 + 状态枚举，不做 I/O / crypto）。
//!
//! 谱系（lineage）= reuse-detection 载体：一次 rotation 链上的全部 token 共享一个 `lineage_id`（家族根 id）；
//! 重放已 Consumed/Revoked 的 token ⇒ 服务按 `lineage_id` **级联撤销整条家族**（OAuth refresh rotation 标准，
//! Auth0/ory；旧 refresh 一次性失效 + 失窃检测）。
//!
//! `pub`（ADR-005 Option 2，同 `session::Session`）：作 `ports::RefreshTokenStore` 签名实体被独立 adapter crate
//! （postgres）跨 crate 命名 / 收发；字段私有、构造经 `pub(crate)` funnel + `pub hydrate`——adapter 可接收 /
//! 读取 / 重建 [`RefreshTokenRecord`]，但**不可伪造**其不变式（fail-closed，ADR-001）。
//!
//! ref: ory/fosite handler/oauth2/flow_refresh.go@master（refresh rotation + reuse-detection graceful revoke，概念谱系）
//! ref: eclipse-biscuit/biscuit-rust biscuit-auth/src/token/mod.rs@main（私有字段 + funnel，同 super::session）

use std::time::SystemTime;

use vocab::{PrincipalKind, TenantId};

use super::AuthnEpoch;

// ---------------------------------------------------------------------------
// RefreshTokenId — 记录稳定标识（lineage 锚点 / 撤销键）
// ---------------------------------------------------------------------------

/// refresh token 记录稳定标识（UUID v4；服务端 mint）。
///
/// **非** bearer 凭据（bearer secret 是 [`RefreshTokenHash`] 的原像，不在本类型）——故 Debug 不脱敏（opaque
/// 服务端随机 id，无 PII / 无冒充价值）。`lineage_id` 复用本类型：签发时 `lineage_id == id`（家族根）。
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RefreshTokenId(String);

impl RefreshTokenId {
    /// 生成新记录 id（UUID v4 随机值；不取系统时钟，满足 clock 纪律——同 `authn::SessionId::generate`）。
    pub(crate) fn generate() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    /// 由已校验字符串构造（funnel 边界 = `pub(crate)`，crate 内信任；hydrate 重建用）。
    pub(crate) fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// 取 id 字符串引用（`pub`：adapter impl body 跨 crate 读取以绑 INSERT/UPDATE 参数）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// RefreshTokenHash — secret 的 SHA-256 摘要（持久化查找键）
// ---------------------------------------------------------------------------

/// refresh secret 的 SHA-256 摘要（32 字节）——**唯一持久化查找键**（不可逆 ⇒ 不存明文）。
///
/// 服务端签发存 `digest(secret)`、校验对呈递串重算后按本类型查找（完整 32 字节匹配）。Debug 脱敏（防御性：
/// 摘要不可逆、本身无泄露价值，但避免 `{:?}` 把摘要写入日志被用于 token 关联）。
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RefreshTokenHash([u8; 32]);

impl std::fmt::Debug for RefreshTokenHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RefreshTokenHash(<redacted>)")
    }
}

impl RefreshTokenHash {
    /// 由 32 字节摘要构造（funnel 边界 = `pub(crate)`；服务经 `secure::refresh::digest` 产出后包装，
    /// adapter hydrate 经本 funnel 从 bytea 列重建）。
    pub(crate) fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// 取摘要字节引用（`pub`：adapter 绑 `bytea` 列 INSERT/WHERE）。
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// RefreshStatus — 生命周期状态闭值集
// ---------------------------------------------------------------------------

/// refresh token 生命周期状态（闭值集）。
///
/// 合法迁移：`Active → Consumed`（rotation 一次性消费）/ `Active|Consumed → Revoked`（撤销 / 级联）。
/// 仅 `Active` 可 rotate；命中 `Consumed`/`Revoked` 即重放（reuse-detection 触发级联撤销）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefreshStatus {
    /// 有效、可轮换（未消费、未撤销、未过期）。
    Active,
    /// 已被 rotation 一次性消费（旧 refresh 失效；重放即触发级联撤销）。
    Consumed,
    /// 已撤销（logout 单条 / reuse-detection 级联）。
    Revoked,
}

impl RefreshStatus {
    /// 持久化文本（adapter `status` 列；单源映射，避免 adapter 散落字面量）。
    pub fn as_db_str(self) -> &'static str {
        match self {
            RefreshStatus::Active => "active",
            RefreshStatus::Consumed => "consumed",
            RefreshStatus::Revoked => "revoked",
        }
    }

    /// 从持久化文本重建（未知文本 → `None`，adapter 视作 corrupt row → Storage 错误，fail-closed）。
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "active" => Some(RefreshStatus::Active),
            "consumed" => Some(RefreshStatus::Consumed),
            "revoked" => Some(RefreshStatus::Revoked),
            _ => None,
        }
    }
}

/// [`PrincipalKind`] → 持久化文本（`kind` 列单源映射）。
///
/// 未知未来变体（`PrincipalKind` 是 `#[non_exhaustive]`）→ `"anonymous"`（**fail-closed**：anonymous 不可
/// 映射为 `JwtAccessPrincipal`，rotate 时拒签，绝不静默把未知 kind 当作已知特权 kind 冒充）。
pub fn kind_to_db(kind: PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::User => "user",
        PrincipalKind::Device => "device",
        PrincipalKind::Admin => "admin",
        PrincipalKind::SuperAdmin => "super_admin",
        PrincipalKind::Service => "service",
        PrincipalKind::Anonymous => "anonymous",
        // reason: 未来新增 kind 落 anonymous（fail-closed，不可签 ⇒ rotate 拒签，不冒充已知特权 kind）。
        _ => "anonymous",
    }
}

/// 持久化文本 → [`PrincipalKind`]（未知文本 → `None`，adapter 视作 corrupt row）。
pub fn kind_from_db(s: &str) -> Option<PrincipalKind> {
    match s {
        "user" => Some(PrincipalKind::User),
        "device" => Some(PrincipalKind::Device),
        "admin" => Some(PrincipalKind::Admin),
        "super_admin" => Some(PrincipalKind::SuperAdmin),
        "service" => Some(PrincipalKind::Service),
        "anonymous" => Some(PrincipalKind::Anonymous),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// RefreshTokenRecord — 持久化快照
// ---------------------------------------------------------------------------

/// refresh token 持久化快照域实体（私有字段；构造经 funnel；不 derive Serialize——域类型）。
///
/// 持久化形态是 flat record。`subject` / `tenant` / `kind` 是 rotation 重签 access JWT 的 claim 源
/// （经 `RefreshService` fail-closed 映射为 `JwtAccessPrincipal`）；`token_hash` 是查找键；`parent_id` / `lineage_id`
/// 建模轮换谱系（reuse-detection 级联撤销锚点）；`status` + `expires_at` 控一次性 / 过期。
///
/// Debug：`subject`（生产 = canonical user id）防御性脱敏（同 `session::Session`），`token_hash` 经其自身脱敏
/// Debug；其余字段正常打印（id/kind/tenant/status/时间 可观测无敏感）。
#[derive(Clone)]
pub struct RefreshTokenRecord {
    id: RefreshTokenId,
    tenant: TenantId,
    subject: String,
    kind: PrincipalKind,
    token_hash: RefreshTokenHash,
    parent_id: Option<RefreshTokenId>,
    lineage_id: RefreshTokenId,
    issuance_epoch: AuthnEpoch,
    status: RefreshStatus,
    issued_at: SystemTime,
    expires_at: SystemTime,
}

impl std::fmt::Debug for RefreshTokenRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshTokenRecord")
            .field("id", &self.id)
            .field("tenant", &self.tenant)
            .field("subject", &"<redacted>")
            .field("kind", &self.kind)
            .field("token_hash", &self.token_hash)
            .field("parent_id", &self.parent_id)
            .field("lineage_id", &self.lineage_id)
            .field("issuance_epoch", &"<redacted>")
            .field("status", &self.status)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl RefreshTokenRecord {
    /// 构造快照（funnel 边界 = `pub(crate)`，crate 内信任；`RefreshService` 签发 / 轮换时调用）。
    ///
    /// 签发：`parent_id = None`、`lineage_id = id`（家族根）、`status = Active`。
    /// 轮换：`parent_id = Some(old.id)`、`lineage_id = old.lineage_id`、`status = Active`。
    #[allow(clippy::too_many_arguments)] // reason: flat 持久化 record（10 列），funnel 收口构造，非业务接口。
    pub(crate) fn new(
        id: RefreshTokenId,
        tenant: TenantId,
        subject: impl Into<String>,
        kind: PrincipalKind,
        token_hash: RefreshTokenHash,
        parent_id: Option<RefreshTokenId>,
        lineage_id: RefreshTokenId,
        issuance_epoch: AuthnEpoch,
        status: RefreshStatus,
        issued_at: SystemTime,
        expires_at: SystemTime,
    ) -> Self {
        Self {
            id,
            tenant,
            subject: subject.into(),
            kind,
            token_hash,
            parent_id,
            lineage_id,
            issuance_epoch,
            status,
            issued_at,
            expires_at,
        }
    }

    /// 跨 crate 受控重建 funnel（adapter `find_by_hash` 从持久化行重建；同 `session::Session::hydrate`）。
    ///
    /// `id` / `subject` / `lineage_id` / `parent_id` 是 opaque 串（写入时已校验，重建信任）；`token_hash` 由
    /// adapter 从 `bytea` 列还原为 32 字节；`kind` / `status` 由 adapter 经 [`kind_from_db`] /
    /// [`RefreshStatus::from_db_str`] 解析后传入（未知 → adapter 报 Storage，不进本 funnel）。
    #[allow(clippy::too_many_arguments)] // reason: 与 `new` 同构的 flat record 重建 funnel。
    pub fn hydrate(
        id: impl Into<String>,
        tenant: TenantId,
        subject: impl Into<String>,
        kind: PrincipalKind,
        token_hash: [u8; 32],
        parent_id: Option<String>,
        lineage_id: impl Into<String>,
        issuance_epoch: AuthnEpoch,
        status: RefreshStatus,
        issued_at: SystemTime,
        expires_at: SystemTime,
    ) -> Self {
        Self::new(
            RefreshTokenId::new(id),
            tenant,
            subject,
            kind,
            RefreshTokenHash::new(token_hash),
            parent_id.map(RefreshTokenId::new),
            RefreshTokenId::new(lineage_id),
            issuance_epoch,
            status,
            issued_at,
            expires_at,
        )
    }

    /// 复制并替换 status（合法迁移）。
    // reason: 消费方是 `#[cfg(test)]` in-mem 替身（`internal::mem::InMemRefreshTokenStore` 的 consume/revoke
    // 状态迁移）；生产 postgres adapter 经 SQL `UPDATE ... SET status` 迁移，不经本内存 helper ⇒ 非 test lib
    // 构建无调用方（同 domain::account::AccountLockout 的 test-only 消费范式）。
    #[allow(dead_code)]
    pub(crate) fn with_status(&self, status: RefreshStatus) -> Self {
        Self {
            status,
            ..self.clone()
        }
    }

    /// 由**本 record（轮换源）派生**轮换命令 [`RefreshRotation`]（#1325 review #284 F2，sealed command）。
    ///
    /// 子 record 的 `tenant` / `subject` / `kind` / `parent_id`(=self.id) / `lineage_id`(=self.lineage_id) 一律
    /// **从 self 派生**——调用方只提供新 secret 摘要 + 新 id + 时刻。tenant / parent / lineage 错位组合**类型层
    /// 不可表达**（无独立 `new_record` 入参可传），杜绝「rotate(tenant, old_id, 任意 new)」的错位写入。
    ///
    /// # INVARIANT: REFRESH-ROTATE-LINEAGE-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
    /// 轮换子 record 的租户 / 父指针 / 谱系根恒等于源 record 的对应字段（由本 funnel 派生，非调用方组装）——
    /// store 只接收 [`RefreshRotation`]、无三参 `(tenant, old_id, new)` 重载，故跨租 / 断谱系 / 错父的轮换写入
    /// 在类型层不可表达（Hard，对标 input-struct-field-exclusion 范本）。
    pub fn begin_rotation(
        &self,
        new_id: RefreshTokenId,
        new_hash: RefreshTokenHash,
        issued_at: SystemTime,
        expires_at: SystemTime,
    ) -> RefreshRotation {
        let new = Self::new(
            new_id,
            self.tenant,
            self.subject.clone(),
            self.kind,
            new_hash,
            Some(self.id.clone()),
            self.lineage_id.clone(),
            self.issuance_epoch,
            RefreshStatus::Active,
            issued_at,
            expires_at,
        );
        RefreshRotation {
            old_id: self.id.clone(),
            new,
        }
    }

    /// 过期判定（`now` 由注入 `Clock` 读出；`expires_at` 不晚于 now ⇒ 过期）。
    pub fn is_expired(&self, now: SystemTime) -> bool {
        self.expires_at <= now
    }

    // accessor：`pub`（adapter impl body 跨 crate 读取以绑 INSERT；service / in-mem 读取）。
    /// 记录 id。
    pub fn id(&self) -> &RefreshTokenId {
        &self.id
    }
    /// 所属租户（adapter SET LOCAL scope + `tenant_id` 列）。
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// 主体标识（rotation 重签 JWT 的 `sub`）。
    pub fn subject(&self) -> &str {
        &self.subject
    }
    /// 主体类别（rotation 重签 JWT 的 `kind`）。
    pub fn kind(&self) -> PrincipalKind {
        self.kind
    }
    /// secret 摘要（查找键）。
    pub fn token_hash(&self) -> &RefreshTokenHash {
        &self.token_hash
    }
    /// 父 token id（轮换链；签发根为 None）。
    pub fn parent_id(&self) -> Option<&RefreshTokenId> {
        self.parent_id.as_ref()
    }
    /// 家族根 id（级联撤销锚点）。
    pub fn lineage_id(&self) -> &RefreshTokenId {
        &self.lineage_id
    }
    /// Authentication epoch at which this refresh family was issued.
    pub fn issuance_epoch(&self) -> AuthnEpoch {
        self.issuance_epoch
    }
    /// 生命周期状态。
    pub fn status(&self) -> RefreshStatus {
        self.status
    }
    /// 签发时刻。
    pub fn issued_at(&self) -> SystemTime {
        self.issued_at
    }
    /// 过期时刻。
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
}

// ---------------------------------------------------------------------------
// RefreshRotation — sealed 轮换命令（#1325 review #284 F2）
// ---------------------------------------------------------------------------

/// sealed 轮换命令：由源 record 经 [`RefreshTokenRecord::begin_rotation`] 派生（私有字段 + 无公开构造）。
///
/// 携 `old_id`（CAS 消费目标）+ `new`（轮换子 record，tenant/parent/lineage 已从源派生）。port `rotate` 只
/// 接收本类型——store 据 `new().tenant()` 注入 scope、`old_id()` 做 CAS、`new()` 写入；调用方无法传错位的
/// tenant / old_id / new 组合（REFRESH-ROTATE-LINEAGE-01）。不 derive Serialize（域类型）。
#[derive(Debug, Clone)]
pub struct RefreshRotation {
    old_id: RefreshTokenId,
    new: RefreshTokenRecord,
}

/// Result of the final account-security check and refresh CAS in one transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshRotationOutcome {
    Applied,
    Replay,
    AccountStale,
}

impl RefreshRotation {
    /// CAS 消费目标（源 record id）。
    pub fn old_id(&self) -> &RefreshTokenId {
        &self.old_id
    }
    /// 轮换子 record（待写入；tenant/parent/lineage 已从源派生）。
    pub fn new_record(&self) -> &RefreshTokenRecord {
        &self.new
    }
}

// ---------------------------------------------------------------------------
// 测试（实体构造 / 访问器 / 状态映射 / 谱系 / Debug 脱敏）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{
        AuthnEpoch, PrincipalKind, RefreshStatus, RefreshTokenHash, RefreshTokenId,
        RefreshTokenRecord, kind_from_db, kind_to_db,
    };
    use std::time::{Duration, SystemTime};
    use vocab::tenant::TenantId;

    const TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    #[allow(clippy::expect_used)]
    fn tid(raw: &str) -> TenantId {
        TenantId::parse(raw).expect("canonical tenant uuid")
    }

    fn sample(status: RefreshStatus) -> RefreshTokenRecord {
        let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let id = RefreshTokenId::new("id-1");
        RefreshTokenRecord::new(
            id.clone(),
            tid(TENANT_A),
            "alice-subject",
            PrincipalKind::User,
            RefreshTokenHash::new([7u8; 32]),
            None,
            id,
            AuthnEpoch::ZERO,
            status,
            issued,
            issued + Duration::from_secs(3_600),
        )
    }

    #[test]
    fn generate_yields_distinct_uuid_ids() {
        let a = RefreshTokenId::generate();
        let b = RefreshTokenId::generate();
        assert_ne!(a, b);
        assert_eq!(a.as_str().len(), 36, "uuid hyphenated = 36 chars");
    }

    #[test]
    fn record_accessors_echo() {
        let r = sample(RefreshStatus::Active);
        assert_eq!(r.id().as_str(), "id-1");
        assert_eq!(r.tenant(), tid(TENANT_A));
        assert_eq!(r.subject(), "alice-subject");
        assert_eq!(r.kind(), PrincipalKind::User);
        assert_eq!(r.token_hash().as_bytes(), &[7u8; 32]);
        assert!(r.parent_id().is_none());
        assert_eq!(r.lineage_id().as_str(), "id-1");
        assert_eq!(r.status(), RefreshStatus::Active);
    }

    #[test]
    fn is_expired_boundary() {
        let r = sample(RefreshStatus::Active); // expires at 1000+3600 = 4600
        let exp = SystemTime::UNIX_EPOCH + Duration::from_secs(4_600);
        assert!(r.is_expired(exp), "exact expiry instant is expired (<=)");
        assert!(r.is_expired(exp + Duration::from_secs(1)));
        assert!(!r.is_expired(exp - Duration::from_secs(1)));
    }

    #[test]
    fn with_status_transitions_keep_other_fields() {
        let active = sample(RefreshStatus::Active);
        let consumed = active.with_status(RefreshStatus::Consumed);
        assert_eq!(consumed.status(), RefreshStatus::Consumed);
        assert_eq!(consumed.id().as_str(), active.id().as_str());
        assert_eq!(
            consumed.token_hash().as_bytes(),
            active.token_hash().as_bytes()
        );
        let revoked = consumed.with_status(RefreshStatus::Revoked);
        assert_eq!(revoked.status(), RefreshStatus::Revoked);
    }

    #[test]
    fn hydrate_rebuilds_with_parent_lineage() {
        let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000);
        let r = RefreshTokenRecord::hydrate(
            "child-id",
            tid(TENANT_A),
            "bob",
            PrincipalKind::Admin,
            [3u8; 32],
            Some("parent-id".to_string()),
            "root-id",
            AuthnEpoch::ZERO,
            RefreshStatus::Active,
            issued,
            issued + Duration::from_secs(7_200),
        );
        assert_eq!(r.id().as_str(), "child-id");
        assert_eq!(r.kind(), PrincipalKind::Admin);
        assert_eq!(r.parent_id().map(|p| p.as_str()), Some("parent-id"));
        assert_eq!(r.lineage_id().as_str(), "root-id");
        assert_eq!(r.token_hash().as_bytes(), &[3u8; 32]);
    }

    #[test]
    fn status_db_roundtrip() {
        for s in [
            RefreshStatus::Active,
            RefreshStatus::Consumed,
            RefreshStatus::Revoked,
        ] {
            assert_eq!(RefreshStatus::from_db_str(s.as_db_str()), Some(s));
        }
        assert_eq!(RefreshStatus::from_db_str("bogus"), None);
    }

    #[test]
    fn kind_db_roundtrip_known_variants() {
        for k in [
            PrincipalKind::User,
            PrincipalKind::Device,
            PrincipalKind::Admin,
            PrincipalKind::SuperAdmin,
            PrincipalKind::Service,
            PrincipalKind::Anonymous,
        ] {
            assert_eq!(kind_from_db(kind_to_db(k)), Some(k));
        }
        assert_eq!(kind_from_db("bogus"), None);
    }

    #[test]
    fn begin_rotation_derives_child_from_source() {
        // sealed command（#284 F2）：子 record 的 tenant/subject/kind/parent/lineage 全部从源派生，
        // 调用方只提供 new_id/new_hash/时刻——错位组合类型层不可表达（REFRESH-ROTATE-LINEAGE-01）。
        let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(5_000);
        let src = RefreshTokenRecord::new(
            RefreshTokenId::new("src-id"),
            tid(TENANT_A),
            "carol-subject",
            PrincipalKind::Admin,
            RefreshTokenHash::new([1u8; 32]),
            None,
            RefreshTokenId::new("lineage-root"),
            AuthnEpoch::ZERO,
            RefreshStatus::Active,
            issued,
            issued + Duration::from_secs(3_600),
        );
        let rotation = src.begin_rotation(
            RefreshTokenId::new("child-id"),
            RefreshTokenHash::new([2u8; 32]),
            issued + Duration::from_secs(10),
            issued + Duration::from_secs(3_610),
        );
        assert_eq!(rotation.old_id().as_str(), "src-id", "old_id = 源 id");
        let child = rotation.new_record();
        assert_eq!(child.id().as_str(), "child-id");
        assert_eq!(child.tenant(), tid(TENANT_A), "tenant 从源派生");
        assert_eq!(child.subject(), "carol-subject", "subject 从源派生");
        assert_eq!(child.kind(), PrincipalKind::Admin, "kind 从源派生");
        assert_eq!(
            child.parent_id().map(|p| p.as_str()),
            Some("src-id"),
            "parent = 源 id"
        );
        assert_eq!(
            child.lineage_id().as_str(),
            "lineage-root",
            "lineage = 源 lineage"
        );
        assert_eq!(child.status(), RefreshStatus::Active, "子 record Active");
        assert_eq!(child.token_hash().as_bytes(), &[2u8; 32], "新 hash");
    }

    #[test]
    fn record_debug_redacts_subject_and_hash() {
        let r = sample(RefreshStatus::Active);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("<redacted>"), "subject must redact: {dbg}");
        assert!(!dbg.contains("alice-subject"), "subject leaked: {dbg}");
        assert!(
            dbg.contains("RefreshTokenHash(<redacted>)"),
            "hash must redact: {dbg}"
        );
        // 非敏感字段正常可观测。
        assert!(dbg.contains("Active"), "status visible: {dbg}");
        assert!(dbg.contains("User"), "kind visible: {dbg}");
    }
}
