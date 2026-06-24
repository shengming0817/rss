//! identity::domain::session — 会话持久化快照域实体（dylint rss_domain_no_serialize 守护区）。
//!
//! `Session`（会话持久化快照）+ `SessionId` newtype。L2 OutboxFact **co-tx** 的业务写实体：登录 mint
//! 会话后，`ports::SessionUnitOfWork` 把 `Session` 行与 `identity.session-created` outbox 行**同一本地
//! 事务**原子写入（FR-003 完整 L2；见 `crate::ports` 与 postgres adapter 的 OUTBOX-COTX-SESSION-01）。
//!
//! 持久化形态是 **flat record**（session_id / subject / tenant / expires_at / created_at），刻意**不**复用
//! `authn::Session`：后者是会话**鉴权**视图（service 层，聚合 `Principal`），本类型是会话**持久化**快照
//! （域层）。域形 repo port 只引域内实体（ADR-005 Option 2，category line）——引 service 层 `authn::Session`
//! 会令 `ports` 端口耦合服务类型、层序倒置。
//!
//! `pub`（ADR-005 Option 2）：作 `ports::SessionUnitOfWork` 签名实体被独立 adapter crate（postgres）跨
//! crate 命名/收发；字段私有、构造经 `pub(crate)` funnel——adapter 可接收/读取 `Session` 但**不可伪造**
//! 其不变式（fail-closed，ADR-001）。
//!
//! ref: eclipse-biscuit/biscuit-rust biscuit-auth/src/token/mod.rs@main（私有字段 + funnel，同 super::RoleId）

use std::time::SystemTime;

use vocab::TenantId;

// ---------------------------------------------------------------------------
// SessionId newtype
// ---------------------------------------------------------------------------

/// 会话标识 newtype（私有字段；构造经 funnel；不 derive Serialize——域类型）。
///
/// 值来源是 `authn::SessionId::generate()`（UUID v4，已合法）经 app 层桥接；本 newtype 不重复校验
/// （funnel 边界 = `pub(crate)` `new`，crate 内信任，不变式同 [`super::RoleId::new`]）。当前无 wire 入口
/// （无 logout / session-lookup handler）故不设 `parse`——按需后补（不预设未来需求）。
///
/// **Debug 手写脱敏**：session id 是凭据级 bearer 标识（持有即可关联/冒充会话）——同 `application.rs` 的
/// 「session_id 敏感、不得进 broker metadata/日志」约束，`Debug` 不得回显明文（同 [`super::AttributeValue`]
/// / [`super::RoleBinding`] 的 redacted-Debug 范式，避免经 `{:?}` 泄漏至日志/断言）。
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SessionId(String);

impl std::fmt::Debug for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionId(<redacted>)")
    }
}

impl SessionId {
    /// 由已校验字符串构造（funnel 边界 = `pub(crate)`，crate 内信任）。
    pub(crate) fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// 取会话 id 字符串引用。
    ///
    /// `pub`（非 `pub(crate)`）：postgres adapter 的 `SessionUnitOfWork` impl body 跨 crate 读取以绑 INSERT
    /// 参数（ADR-005 Option 2 / W 阶段 step 3 最小读集——本 PR 已写实 adapter，故真升 `pub`）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Session — 会话持久化快照
// ---------------------------------------------------------------------------

/// 会话持久化快照域实体（私有字段；构造经 funnel；不 derive Serialize——域类型）。
///
/// `subject` 是凭据级标识（可能为 email / UPN），按 PII 处理 ⇒ Debug 手写脱敏（同 [`super::RoleBinding`]）。
/// 时间字段由注入 [`diport::Clock`] 派生（不取系统时钟，rust-standards §Clock）：`created_at` = 登录时刻，
/// `expires_at` = 登录时刻 + session_ttl。
#[derive(Clone)]
pub struct Session {
    id: SessionId,
    subject: String,
    tenant: TenantId,
    expires_at: SystemTime,
    created_at: SystemTime,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("subject", &"<redacted>") // subject 可能为 email/UPN，按 PII 脱敏（同 RoleBinding）
            .field("tenant", &self.tenant)
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl Session {
    /// 构造会话快照（位置参，必填；funnel 边界 = `pub(crate)`，crate 内信任）。
    pub(crate) fn new(
        id: SessionId,
        subject: impl Into<String>,
        tenant: TenantId,
        expires_at: SystemTime,
        created_at: SystemTime,
    ) -> Self {
        Self {
            id,
            subject: subject.into(),
            tenant,
            expires_at,
            created_at,
        }
    }

    // accessor：`pub`（adapter impl body 跨 crate 读取以绑 INSERT；ADR-005 W 阶段 step 3 最小读集）。
    /// 取会话 id 引用。
    pub fn id(&self) -> &SessionId {
        &self.id
    }
    /// 取 opaque subject 引用。
    pub fn subject(&self) -> &str {
        &self.subject
    }
    /// 取所属租户（adapter 用于 SET LOCAL tenant scope + `tenant_id` 列写入）。
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    /// 取过期时刻。
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
    /// 取创建时刻。
    pub fn created_at(&self) -> SystemTime {
        self.created_at
    }
}

// ---------------------------------------------------------------------------
// 测试（实体构造 / 访问器回显 / Debug 脱敏）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{Session, SessionId};
    use std::time::{Duration, SystemTime};
    use vocab::tenant::TenantId;

    const TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    #[allow(clippy::expect_used)]
    fn tid(raw: &str) -> TenantId {
        TenantId::parse(raw).expect("canonical tenant uuid")
    }

    #[test]
    fn session_id_new_and_as_str_echo() {
        let id = SessionId::new("11111111-2222-3333-4444-555555555555");
        assert_eq!(id.as_str(), "11111111-2222-3333-4444-555555555555");
    }

    #[test]
    fn session_accessors_echo() {
        let created = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let expires = created + Duration::from_secs(3_600);
        let s = Session::new(
            SessionId::new("sid-1"),
            "alice-subject",
            tid(TENANT_A),
            expires,
            created,
        );
        assert_eq!(s.id().as_str(), "sid-1");
        assert_eq!(s.subject(), "alice-subject");
        assert_eq!(s.tenant(), tid(TENANT_A));
        assert_eq!(s.expires_at(), expires);
        assert_eq!(s.created_at(), created);
    }

    // SessionId Debug 脱敏：凭据级 bearer 标识，{:?} 不得回显明文（review #244 F1）。
    #[test]
    fn session_id_debug_redacts_value() {
        let id = SessionId::new("super-secret-sid");
        let dbg = format!("{id:?}");
        assert_eq!(dbg, "SessionId(<redacted>)");
        assert!(
            !dbg.contains("super-secret-sid"),
            "session id 必须脱敏: {dbg}"
        );
    }

    // Session Debug 脱敏：subject（PII）**与 session id（凭据级）**均隐藏；tenant / 时间正常打印（review #244 F1）。
    #[test]
    fn session_debug_redacts_subject_and_id() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let s = Session::new(
            SessionId::new("sid-secret-1"),
            "alice@corp",
            tid(TENANT_A),
            now,
            now,
        );
        let dbg = format!("{s:?}");
        assert!(dbg.contains("<redacted>"), "subject/id 必须脱敏: {dbg}");
        assert!(!dbg.contains("alice@corp"), "Debug 不得泄露 subject 明文");
        assert!(
            !dbg.contains("sid-secret-1"),
            "Debug 不得泄露 session id 明文（凭据级敏感）: {dbg}"
        );
    }
}
