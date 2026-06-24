//! identity::domain — 身份域类型与纯逻辑（dylint rss_domain_no_serialize 守护区）。
//!
//! 本模块（及子模块 `rbac` / `abac` / `account`）是 dylint `rss_domain_no_serialize` lint 的扫描边界：
//! 定义在 `domain` 路径段下的类型**不可 derive Serialize/Deserialize**。
//!
//! 子域拆分（spec 003 T001，每子 PR 独占其文件，降并行写冲突）：
//! - `mod.rs`（本文件）：共享 newtype funnel（`RoleId` / `PermissionId` / `PolicyId` / `ResourcePattern`
//!   / `AttributeKey` / `AttributeValue`）+ `IdentityError` + 子模块 re-export 枢纽。【PR1】
//! - `rbac`：`Permission` / `Role` / `RoleBinding` + `authorize_rbac`。【PR1 实现】
//! - `abac`：`AbacAttribute` / `PolicyRule`（typed `Operator` + `PolicyEffect`）/ `Policy` +
//!   `evaluate_abac`（deny-overrides，fail-closed）。【PR2 实现】
//! - `account`：`AccountStatus` + `Credential` + `AccountLockout`（凭据 / 锁定 / CAS）。【PR3 实现】
//! - `session`：`Session` / `SessionId`（会话持久化 UoW）。【PR4 部分】
//!
//! # newtype funnel 校验（严格白名单，fail-closed）
//!
//! 字符串入口经单一 `parse`（fallible，对外校验入口）；空 → `*Error::Empty`，越界 / 含白名单外字符
//! → `*Error::Format`，**永不 panic**（零信任）。`new`（部分 newtype）是 crate 内「已校验值」信任构造器
//! （funnel 边界 = `pub(crate)`，不对外）。
//!
//! # 对标
//!
//! ref: casbin/casbin-rs src/core_api.rs@master（enforce 元组，闭值集 Decision，fail-closed）
//! ref: casbin/casbin-rs src/rbac/default_role_manager.rs@master（多租隔离，域 Role 绑定）
//! ref: eclipse-biscuit/biscuit-rust biscuit-auth/src/token/mod.rs@main（私有字段 funnel）
//!
//! 采纳：闭值集枚举、纯函数求值、强类型 newtype（不走裸 `Vec<Vec<String>>`）。
//! 复用 `vocab::Decision`（2 值；casbin 的 Indeterminate 映射为 Deny，fail-closed）。

mod abac;
mod account;
mod rbac;
mod session;

// 子模块类型经本枢纽 re-export，保持 `crate::domain::*` 路径（lib.rs `smoke` / `ports.rs` 消费方不破）。
pub use rbac::Role; // Role 是 pub（ports::RoleRepo 签名实体，跨 crate 命名）。
// Session / SessionId 是 pub（ports::SessionUnitOfWork 签名实体，跨 crate 命名）；与 RoleId 不同，二者有
// 生产消费方（application 构造 + postgres adapter 读取），非 ADR-004 C8 冻结期 dead，故不带 allow(dead_code)。
pub use session::{Session, SessionId};
// reason: pub(crate) re-export 经 facade 暴露域词汇；生产消费方（handler / authz 接线）待 W 阶段，
// 当前仅 #[cfg(test)] smoke / 子模块测试消费 ⇒ 非 test lib target 视作 unused（ADR-004 C8 遗留期）。
#[allow(unused_imports)]
pub(crate) use abac::{
    AbacAttribute, GlobPattern, Operator, Policy, PolicyEffect, PolicyRule, evaluate_abac,
};
// Credential（find/save/bump 签名实体）/ AccountStatus（record_failure 返回）是 pub——经 ports facade 跨 crate
// 收发；字段私有 + 构造器 pub(crate) funnel，外部不可伪造（ADR-005 Option 2）。AccountLockout 不在 port 签名
// （锁定推进由原子方法 record_failure/lockout_status/clear_lockout 内部管理，返回 AccountStatus/bool）⇒ pub(crate)。
pub use account::{AccountStatus, Credential};
// reason: in-mem 替身（mem.rs，test/seed-login 门控）内部消费；非 gated 构建链路无调用方（ADR-004 C8）。
#[allow(unused_imports)]
pub(crate) use account::AccountLockout;
// reason: 同上（facade re-export，生产消费方待 W；ADR-004 C8 遗留期）。
#[allow(unused_imports)]
pub(crate) use rbac::{Permission, RoleBinding, authorize_rbac};

// ---------------------------------------------------------------------------
// 共享校验 helper（ID 三连复用：同字符集 + 长度上界 + IdParseError）
// ---------------------------------------------------------------------------

/// ID newtype 字符集长度上界（`RoleId` / `PermissionId` / `PolicyId` 共用）。
// reason: 仅被 pub(crate) parse funnel 引用，funnel 生产调用方待 W ⇒ 非 test 构建链路 dead（ADR-004 C8）。
#[allow(dead_code)]
const ID_MAX_LEN: usize = 128;
/// 资源模式长度上界。
#[allow(dead_code)]
const PATTERN_MAX_LEN: usize = 256;
/// 属性键长度上界。
#[allow(dead_code)]
const ATTR_KEY_MAX_LEN: usize = 128;

/// 校验失败原因（私有；各 newtype 映射到自己的对外错误枚举 Empty / Format）。
// reason: 同上（仅被 parse funnel 引用，链路 dead 待 W；ADR-004 C8）。
#[allow(dead_code)]
enum Reason {
    Empty,
    Format,
}

/// 通用 fail-closed token 校验：非空 + 全字符过 `allowed` 白名单 + 长度 ≤ `max`。
///
/// 严格白名单（零信任）：空→`Reason::Empty`；越界 / 含白名单外字符→`Reason::Format`。**永不 panic**。
/// `raw.len()`（字节）作上界守卫：白名单仅 ASCII ⇒ 合法输入字节数 == 字符数；非 ASCII 先被白名单拒。
// reason: 同上（仅被 parse funnel 引用，链路 dead 待 W；ADR-004 C8）。
#[allow(dead_code)]
fn validate_token(raw: &str, max: usize, allowed: impl Fn(char) -> bool) -> Result<(), Reason> {
    if raw.is_empty() {
        return Err(Reason::Empty);
    }
    if raw.len() > max || !raw.chars().all(allowed) {
        return Err(Reason::Format);
    }
    Ok(())
}

/// ID 三连白名单字符：字母数字 + `_` `-` `.` `:`（`:` / `.` 供命名空间，如 `docs:read`）。
// reason: 同上（仅被 parse funnel 引用，链路 dead 待 W；ADR-004 C8）。
#[allow(dead_code)]
fn is_id_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':')
}

/// `RoleId` / `PermissionId` / `PolicyId` 共用解析（同字符集 + 同 `IdParseError`，避免三处重复）。
// reason: 同上（仅被 parse funnel 引用，链路 dead 待 W；ADR-004 C8）。
#[allow(dead_code)]
fn parse_id(raw: &str) -> Result<String, IdParseError> {
    validate_token(raw, ID_MAX_LEN, is_id_char).map_err(|r| match r {
        Reason::Empty => IdParseError::Empty,
        Reason::Format => IdParseError::Format,
    })?;
    Ok(raw.to_string())
}

// ---------------------------------------------------------------------------
// ID 解析错误（newtype funnel 共用）
// ---------------------------------------------------------------------------

/// ID 解析错误（RoleId / PermissionId / PolicyId 共用）。
// reason: 库错误枚举尚无生产返回方（funnel 调用方待 W），dead_code 来自冻结期（ADR-004 C8）。
#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum IdParseError {
    #[error("id is empty")]
    Empty,
    #[error("id has invalid format")]
    Format,
}

// ---------------------------------------------------------------------------
// RoleId newtype
// ---------------------------------------------------------------------------

/// 角色标识 newtype（私有字段；构造经 funnel；不 derive Serialize——域类型）。
///
/// `pub`（ADR-005 Option 2）：作 `ports::RoleRepo` 签名实体被独立 adapter crate 跨 crate 命名/收发；
/// 字段仍私有、构造器仍 `pub(crate)`（funnel）——外部可命名/接收 `RoleId` 但**不可伪造**（fail-closed）。
// reason: 类型作 ports 签名实体已被引用；其 pub(crate) 方法生产调用方待 W ⇒ 非 test 构建 dead（ADR-004 C8）。
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RoleId(String);

// reason: pub(crate) 方法生产调用方待 W，当前仅测试消费 ⇒ 非 test 构建 dead（ADR-004 C8）。
#[allow(dead_code)]
impl RoleId {
    /// 构造 RoleId（由**已校验**字符串；funnel 边界 = `pub(crate)`，crate 内信任；对外校验入口是 `parse`）。
    ///
    /// # 不变式（调用方责任）
    ///
    /// `raw` 必须已是合法 ID（经 `parse` 校验，或同等约束的内部来源如 repo 读出的已存值）。`new` **不**重复
    /// 校验、不返回 `Result`——传入未校验 / 空 / 非法值属调用方契约违反，非 `new` 的失败模式。所有外部字符串
    /// 入口（handler / wire）一律走 `parse`。
    pub(crate) fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// 解析字符串为 RoleId；拒绝空值 / 非法格式（严格白名单，fail-closed）。
    pub(crate) fn parse(raw: &str) -> Result<Self, IdParseError> {
        Ok(Self(parse_id(raw)?))
    }

    /// 取 ID 字符串引用。
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// PermissionId newtype
// ---------------------------------------------------------------------------

/// 权限标识 newtype（私有字段；构造经 funnel；不 derive Serialize——域类型）。
// reason: 同 RoleId（生产调用方待 W；当前仅测试消费）。
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct PermissionId(String);

// reason: 同 RoleId impl（生产调用方待 W；当前仅测试消费）。
#[allow(dead_code)]
impl PermissionId {
    /// 构造 PermissionId（由已校验字符串；不变式同 [`RoleId::new`]——调用方保证已校验，`new` 不重校验，
    /// 外部字符串入口走 `parse`）。
    pub(crate) fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// 解析字符串为 PermissionId；拒绝空值 / 非法格式（严格白名单，fail-closed）。
    pub(crate) fn parse(raw: &str) -> Result<Self, IdParseError> {
        Ok(Self(parse_id(raw)?))
    }

    /// 取 ID 字符串引用。
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// ResourcePattern newtype
// ---------------------------------------------------------------------------

/// 资源模式解析错误。
// reason: 库错误枚举尚无生产返回方（funnel 调用方待 W），dead_code 来自冻结期（ADR-004 C8）。
#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum PatternError {
    #[error("resource pattern is empty")]
    Empty,
    #[error("resource pattern has invalid format")]
    Format,
}

/// 资源模式 newtype（如 `"users:*"` / `"devices:{id}"`；私有字段；构造经 funnel）。
///
/// 不 derive Serialize——域类型（dylint 守护）。
// reason: 同 RoleId（生产调用方待 W；当前仅测试消费）。
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResourcePattern(String);

// reason: 同 RoleId impl（生产调用方待 W；当前仅测试消费）。
#[allow(dead_code)]
impl ResourcePattern {
    /// 解析资源模式；拒绝空值 / 非法格式（严格白名单 + glob `* ?` + 占位 `{ }` + 路径 `/`，fail-closed）。
    pub(crate) fn parse(raw: &str) -> Result<Self, PatternError> {
        // 白名单：ID 字符 + glob（`* ?`）+ 占位（`{ }`，对应 doc 例 `devices:{id}`）+ 路径分隔（`/`）。
        let allowed = |c: char| is_id_char(c) || matches!(c, '*' | '?' | '{' | '}' | '/');
        validate_token(raw, PATTERN_MAX_LEN, allowed).map_err(|r| match r {
            Reason::Empty => PatternError::Empty,
            Reason::Format => PatternError::Format,
        })?;
        Ok(Self(raw.to_string()))
    }

    /// 取模式字符串引用。
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// ABAC 属性键 / 值 newtype（共享；ABAC 求值在 `abac` 子模块）
// ---------------------------------------------------------------------------

/// 属性键解析错误。
// reason: 库错误枚举尚无生产返回方（funnel 调用方待 W），dead_code 来自冻结期（ADR-004 C8）。
#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum AttributeKeyError {
    #[error("attribute key is empty")]
    Empty,
    #[error("attribute key has invalid format")]
    Format,
}

/// ABAC 属性键 newtype（不 derive Serialize——域类型）。
// reason: 同 RoleId（生产调用方待 W；当前仅测试消费）。
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct AttributeKey(String);

// reason: 同 RoleId impl（生产调用方待 W；当前仅测试消费）。
#[allow(dead_code)]
impl AttributeKey {
    /// 解析属性键；拒绝空值 / 非法格式（严格白名单：字母数字 + `_` `-` `.`，fail-closed）。
    pub(crate) fn parse(raw: &str) -> Result<Self, AttributeKeyError> {
        let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.');
        validate_token(raw, ATTR_KEY_MAX_LEN, allowed).map_err(|r| match r {
            Reason::Empty => AttributeKeyError::Empty,
            Reason::Format => AttributeKeyError::Format,
        })?;
        Ok(Self(raw.to_string()))
    }

    /// 取键字符串引用。
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// ABAC 属性值 newtype（不 derive Serialize——域类型）。
///
/// Debug 手写 redacted：属性值可能含 PII / 敏感信息，不得原文打印到日志。
// reason: 同 RoleId（生产调用方待 W；当前仅测试消费）。
#[allow(dead_code)]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AttributeValue(String);

impl std::fmt::Debug for AttributeValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AttributeValue(<redacted>)")
    }
}

// reason: 同 RoleId impl（生产调用方待 W；当前仅测试消费）。
#[allow(dead_code)]
impl AttributeValue {
    /// 构造属性值（任意字符串；**不校验**）。
    ///
    /// reason: 与 `AttributeKey`（句法标识，严格白名单 + 上界）不对称是有意的——属性值是 ABAC 的不透明
    /// 载荷（claim / 设备属性 / 租户标签），无句法白名单可言；且冻结签名为不可失败构造（返回 `Self` 非
    /// `Result`），无法在此 fail-closed。值的语义校验与长度上界（若需 DoS 防护）由 ABAC 求值 / 持久化
    /// 边界承载（PR2，spec 003 US2）。本类型仅保证 Debug 脱敏，防 PII 泄漏。
    pub(crate) fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// 取值字符串引用。
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// PolicyId newtype
// ---------------------------------------------------------------------------

/// 策略标识 newtype（私有字段；构造经 funnel；不 derive Serialize——域类型）。
// reason: 同 RoleId（生产调用方待 W；当前仅测试消费）。
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct PolicyId(String);

// reason: 同 RoleId impl（生产调用方待 W；当前仅测试消费）。
#[allow(dead_code)]
impl PolicyId {
    /// 解析字符串为 PolicyId；拒绝空值 / 非法格式（严格白名单，fail-closed）。
    pub(crate) fn parse(raw: &str) -> Result<Self, IdParseError> {
        Ok(Self(parse_id(raw)?))
    }

    /// 取 ID 字符串引用。
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// IdentityError — 错误枚举
// ---------------------------------------------------------------------------

/// 身份域错误（库枚举；用 `thiserror`；message 为 const 静态字面量）。
///
/// `pub`（ADR-005 Option 2）：作 `ports::RoleRepo` 方法错误类型被 adapter 跨 crate 命名（adapter 把内部
/// 持久化错误映射成本枚举）。`#[non_exhaustive]` 保留扩展窗口。
///
/// **与 authz 决策分轨**：`authorize_rbac` / `evaluate_abac` 的允许/拒绝经 `vocab::Decision` 表达，**不**
/// 走本枚举。本枚举是 repo / 服务操作的失败通道，各 variant 触发路径：
/// - `RoleNotFound`：`RoleRepo` 查无角色。
/// - `InvalidPolicy`：策略构造 / 校验失败。
/// - `PermissionDenied`：handler / 服务层把 `Decision::Deny` 落为域错误时使用（生产接线待 W 阶段 PR5）。
/// - `CredentialNotFound`：`CredentialRepo` 查无凭据（PR3）。
/// - `VersionConflict`：`CredentialRepo::bump_version` CAS 期望版本不匹配（并发密码变更，PR3）。
// reason: 库错误枚举尚无生产返回方（repo / handler 接线待 W），dead_code 来自冻结期（ADR-004 C8）。
#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityError {
    #[error("role not found")]
    RoleNotFound,
    #[error("permission denied")]
    PermissionDenied,
    #[error("policy is invalid")]
    InvalidPolicy,
    #[error("credential not found")]
    CredentialNotFound,
    #[error("credential version conflict")]
    VersionConflict,
}

// ---------------------------------------------------------------------------
// 共享 newtype funnel 测试（表驱动；正常 / 空 / 非法字符 / 超长 fail-closed）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{
        AttributeKey, AttributeKeyError, AttributeValue, IdParseError, PatternError, PermissionId,
        PolicyId, ResourcePattern, RoleId,
    };
    use rstest::rstest;

    /// ID 三连（RoleId / PermissionId / PolicyId）共用 parse 的期望形态。
    #[derive(Debug, PartialEq, Eq)]
    enum Out {
        Ok,
        Empty,
        Format,
    }

    // ID 上界 128（见 ID_MAX_LEN）；200 字符必越界。
    fn over_max() -> String {
        "a".repeat(200)
    }

    // RoleId::parse 全面覆盖共享 parse_id（正常 / 空 / 非法字符 / 超长）。
    #[rstest]
    #[case("admin", Out::Ok)]
    #[case("docs:read", Out::Ok)] // 命名空间 ':' 合法
    #[case("role-1.v2_x", Out::Ok)] // '-' '.' '_' 合法
    #[case("", Out::Empty)]
    #[case("has space", Out::Format)]
    #[case("bad!char", Out::Format)]
    #[case("emoji😀", Out::Format)]
    fn role_id_parse(#[case] raw: &str, #[case] want: Out) {
        let got = match RoleId::parse(raw) {
            Ok(id) => {
                assert_eq!(id.as_str(), raw, "as_str 必须回显原值");
                Out::Ok
            }
            Err(IdParseError::Empty) => Out::Empty,
            Err(IdParseError::Format) => Out::Format,
        };
        assert_eq!(got, want, "input={raw:?}");
    }

    #[test]
    fn id_parse_rejects_over_max_len() {
        assert!(matches!(
            RoleId::parse(&over_max()),
            Err(IdParseError::Format)
        ));
        assert!(matches!(
            PermissionId::parse(&over_max()),
            Err(IdParseError::Format)
        ));
        assert!(matches!(
            PolicyId::parse(&over_max()),
            Err(IdParseError::Format)
        ));
    }

    // PermissionId / PolicyId 经同一 parse_id：各取一正一负确认接线。
    // （IdParseError 冻结无 PartialEq，用 matches! 而非 Result 直接比较。）
    #[test]
    fn permission_id_and_policy_id_share_funnel() {
        assert!(matches!(PermissionId::parse("docs:read"), Ok(p) if p.as_str() == "docs:read"));
        assert!(matches!(PermissionId::parse(""), Err(IdParseError::Empty)));
        assert!(matches!(PolicyId::parse("policy.1"), Ok(p) if p.as_str() == "policy.1"));
        // '/' 有意不在 ID 白名单（仅 ResourcePattern 含路径分隔符；ID 用 `:` `.` 命名空间）。
        assert!(matches!(PolicyId::parse("x/y"), Err(IdParseError::Format)));
    }

    // new()：已校验值信任构造（不校验，funnel 边界 = pub(crate)）。
    #[test]
    fn id_new_wraps_value() {
        assert_eq!(RoleId::new("admin").as_str(), "admin");
        assert_eq!(PermissionId::new("docs:read").as_str(), "docs:read");
    }

    #[rstest]
    #[case("users:*", true)] // glob '*'
    #[case("devices:{id}", true)] // 占位 '{ }'
    #[case("a/b/c", true)] // 路径 '/'
    #[case("read?", true)] // glob '?'
    #[case("", false)]
    #[case("has space", false)]
    #[case("bad%char", false)]
    fn resource_pattern_parse(#[case] raw: &str, #[case] ok: bool) {
        match ResourcePattern::parse(raw) {
            Ok(p) => {
                assert!(ok, "input={raw:?} 应被拒");
                assert_eq!(p.as_str(), raw);
            }
            Err(PatternError::Empty) => {
                assert!(!ok);
                assert!(raw.is_empty(), "Empty 仅对空串");
            }
            Err(PatternError::Format) => assert!(!ok),
        }
    }

    #[test]
    fn resource_pattern_rejects_over_max_len() {
        // 资源模式上界 256（见 PATTERN_MAX_LEN）；300 字符必越界。
        let long = "a".repeat(300);
        assert!(matches!(
            ResourcePattern::parse(&long),
            Err(PatternError::Format)
        ));
    }

    #[rstest]
    #[case("department", true)]
    #[case("env.region", true)]
    #[case("tier-1_x", true)]
    #[case("", false)]
    #[case("has:colon", false)] // ':' 不在属性键白名单
    #[case("has space", false)]
    fn attribute_key_parse(#[case] raw: &str, #[case] ok: bool) {
        match AttributeKey::parse(raw) {
            Ok(k) => {
                assert!(ok, "input={raw:?} 应被拒");
                assert_eq!(k.as_str(), raw);
            }
            Err(AttributeKeyError::Empty) => {
                assert!(!ok);
                assert!(raw.is_empty());
            }
            Err(AttributeKeyError::Format) => assert!(!ok),
        }
    }

    // AttributeValue：任意字符串构造 + as_str 回显 + Debug 脱敏（不泄原值）。
    #[test]
    fn attribute_value_new_and_redacted_debug() {
        let v = AttributeValue::new("s3cr3t-payload");
        assert_eq!(v.as_str(), "s3cr3t-payload");
        let dbg = format!("{v:?}");
        assert_eq!(dbg, "AttributeValue(<redacted>)");
        assert!(!dbg.contains("s3cr3t"), "Debug 不得泄露明文值");
    }
}
