//! identity::domain — 身份域类型与纯逻辑（dylint rss_domain_no_serialize 守护区）。
//!
//! 本模块（及子模块 `rbac` / `abac` / `account`）是 dylint `rss_domain_no_serialize` lint 的扫描边界：
//! 定义在 `domain` 路径段下的类型**不可 derive Serialize/Deserialize**。
//!
//! 子域拆分（spec 003 T001，每子 PR 独占其文件，降并行写冲突）：
//! - `mod.rs`（本文件）：共享 newtype funnel（`RoleId` / `PermissionId` / `PolicyId` / `ResourcePattern`
//!   / `AttributeKey` / `PolicyValue`）+ `IdentityError` + 子模块 re-export 枢纽。【PR1】
//! - `rbac`：`Permission` / `Role` / `RoleBinding` + `authorize_rbac`。【PR1 实现】
//! - `abac`：`AbacAttribute` / `PolicyRule`（typed `Operator` + `PolicyEffect`）/ `Policy` +
//!   `evaluate_abac`（deny-overrides，fail-closed）。【PR2 实现】
//! - `account`：`Credential` + `AccountLockout`（凭据 / 临时暴破锁 / CAS）。【PR3 实现】
//! - `account_security`：durable account lifecycle + authentication epoch。【#1833】
//! - `authn::grant`：认证授权根、状态机与关闭转换。【#1835】
//! - `refresh`：与 AuthGrant 强绑定的刷新族及轮换转换。
//!
//! # newtype funnel 校验（严格白名单，fail-closed）
//!
//! 字符串入口经单一 `parse`（fallible，对外校验入口）；空 → `*Error::Empty`，越界 / 含白名单外字符
//! → `*Error::Format`，**永不 panic**（零信任）。`new`（部分 newtype）是 crate 内「已校验值」信任构造器
//! （funnel 边界 = `pub(crate)`，不对外）。
//!
//! **`PolicyValue` 例外**：允许空串、无字符白名单；仅字节长度超 [`ATTR_VALUE_MAX_LEN`] →
//! `PolicyValueError::TooLong`。域权威为 UTF-8 **字节** ≤256；wire JSON Schema `maxLength` 按
//! Unicode **字符数**（typify）校验——多字节字符可过 wire 而被域拒。
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
mod account_security;
mod rbac;
mod refresh;
mod resource_attr;
mod security_event;

// 子模块类型经本枢纽 re-export，保持 `crate::domain::*` 路径（`ports` / `application` 等域内消费方不破）。
pub use abac::{
    AbacAttribute, EqualityPredicate, MembershipPredicate, Operator, OperatorInput,
    OperatorInputError, OperatorRef, OrderingPredicate, POLICY_ATTR_CONTRACT_ID,
    POLICY_ATTR_PERMISSION, POLICY_ATTR_PRINCIPAL_ID, POLICY_ATTR_PRINCIPAL_KIND,
    POLICY_ATTR_RESOURCE_ID, POLICY_ATTR_TENANT_ID, POLICY_VALUE_SET_MAX_ITEMS, PipAttributeKey,
    PipAttributeKeyError, Policy, PolicyCondition, PolicyEffect, PolicyObligations,
    PolicyRouteScope, PolicyRule, PolicyScalarInput, PolicyVersion, ScalarOperandInput,
    ScalarOperandRef, StringPredicate, TypedPolicyValueInput,
};
pub(crate) use abac::{PolicyEvaluation, evaluate_policies_for_tenant};
// Role / RoleBinding 是 pub（ports::{RoleReadRepo, RoleBindingLifecycle} 签名实体，跨 crate 命名）。
pub use rbac::{Role, RoleBinding};
pub use security_event::{
    AccountCredentialSecurityCommand, AccountStatusSetCommand, CredentialSecurityCommand,
    CredentialSecurityEvent, CredentialSecurityInitiator, CredentialSecurityReceipt,
    CredentialSecurityTargetKind, CredentialSecurityTargetRef, GrantCredentialSecurityCommand,
    LogoutAllCommand, LogoutCurrentCommand, PasswordChangeCommand, PasswordChangeCommandError,
    PendingCredentialSecurityCommit, ReactivateAccountCommand,
};
// RefreshTokenRecord / RefreshTokenId / RefreshTokenHash / RefreshStatus 是 pub（ports::RefreshTokenStore
// 签名实体，跨 crate 命名）；kind_to_db / kind_from_db 是 PrincipalKind↔text 单源映射（postgres adapter 消费）。
// 字段私有 + 构造经 pub(crate) funnel / pub hydrate，外部不可伪造（ADR-005 Option 2）。
pub use refresh::{
    RefreshRotation, RefreshStatus, RefreshTokenHash, RefreshTokenId, RefreshTokenRecord,
    RefreshTokenSnapshot,
};
pub use resource_attr::{
    ResourceAttribute, ResourceAttributeKey, ResourceAttributeKeyError,
    ResourceAttributeResolution, ResourceAttributeResourceId, ResourceAttributeVersion,
    ResourcePolicyAttributeKey,
};
// Credential（find/authenticate/save/bump 签名实体）/ LoginIdentifier（查找键签名实体）/ AuthOutcome
// （authenticate 返回）是 pub。AccountLockout/BruteForceDecision 供 postgres adapter 在 authenticate
// transaction 内重建与推进临时暴破锁。
pub use account::{AccountLockout, AuthOutcome, BruteForceDecision, Credential, LoginIdentifier};
pub(crate) use account_security::ActiveAccountSecurity;
pub use account_security::{
    AccountSecurityHydrationError, AccountSecurityMutation, AccountSecuritySnapshot,
    AccountSecurityState, AccountSecurityTransitionError, AccountSecurityVersion, AccountStatus,
};

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
/// 属性值字节长度上界（与 `GLOB_MAX_LEN` / `PATTERN_MAX_LEN` 对齐；防 Like/glob_match DoS）。
///
/// Soft 双单位：域权威 = UTF-8 **字节**；HTTP wire JSON Schema `maxLength` = Unicode **字符**
/// （Hard 对齐 defer #1947）。
pub const ATTR_VALUE_MAX_LEN: usize = 256;

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
pub enum IdParseError {
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
/// `pub`（ADR-005 Option 2）：作 `ports::RoleReadRepo` 签名实体被独立 adapter crate 跨 crate 命名/收发；
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
    ///
    /// `pub`（#1250）：postgres `PgRoleRepo` adapter 跨 crate 读取以绑 `roles.id` 列（find/save）。
    /// 字段仍私有、构造仍经 `pub(crate)` funnel（`new` / `parse`）——外部可读不可伪造。
    pub fn as_str(&self) -> &str {
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
pub enum AttributeKeyError {
    #[error("attribute key is empty")]
    Empty,
    #[error("attribute key has invalid format")]
    Format,
}

/// ABAC 属性键 newtype（不 derive Serialize——域类型）。
// reason: 同 RoleId（生产调用方待 W；当前仅测试消费）。
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AttributeKey(String);

// reason: 同 RoleId impl（生产调用方待 W；当前仅测试消费）。
#[allow(dead_code)]
impl AttributeKey {
    /// 构造 AttributeKey（由已校验字符串；crate 内常量路径使用，外部入口走 `parse`）。
    pub(crate) fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// 解析属性键；拒绝空值 / 非法格式（严格白名单：字母数字 + `_` `-` `.`，fail-closed）。
    pub fn parse(raw: &str) -> Result<Self, AttributeKeyError> {
        let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.');
        validate_token(raw, ATTR_KEY_MAX_LEN, allowed).map_err(|r| match r {
            Reason::Empty => AttributeKeyError::Empty,
            Reason::Format => AttributeKeyError::Format,
        })?;
        Ok(Self(raw.to_string()))
    }

    /// 取键字符串引用。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// RSS Common ABAC Profile 的闭合值类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PolicyValueType {
    String,
    Boolean,
    Integer,
    Decimal,
}

/// typed policy value 构造失败。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyValueError {
    #[error("attribute value exceeds max length")]
    TooLong,
    #[error("decimal value is not canonical or exceeds 64 bytes")]
    InvalidDecimal,
}

/// 精确十进制值；不经过 `f64`，wire 禁止指数形式。
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DecimalValue {
    canonical: String,
    negative: bool,
    integer: String,
    fractional: String,
}

impl std::fmt::Debug for DecimalValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DecimalValue(<redacted>)")
    }
}

impl DecimalValue {
    pub fn parse(raw: &str) -> Result<Self, PolicyValueError> {
        if raw.is_empty() || raw.len() > 64 || raw.starts_with('+') {
            return Err(PolicyValueError::InvalidDecimal);
        }
        let (negative, unsigned) = raw
            .strip_prefix('-')
            .map_or((false, raw), |value| (true, value));
        let mut parts = unsigned.split('.');
        let integer = parts.next().unwrap_or_default();
        let fractional = parts.next().unwrap_or_default();
        if parts.next().is_some()
            || integer.is_empty()
            || !integer.bytes().all(|byte| byte.is_ascii_digit())
            || (!fractional.is_empty() && !fractional.bytes().all(|byte| byte.is_ascii_digit()))
            || unsigned.ends_with('.')
            || (integer.len() > 1 && integer.starts_with('0'))
        {
            return Err(PolicyValueError::InvalidDecimal);
        }
        let fractional = fractional.trim_end_matches('0').to_string();
        let is_zero = integer == "0" && fractional.is_empty();
        let negative = negative && !is_zero;
        let canonical = if fractional.is_empty() {
            format!("{}{}", if negative { "-" } else { "" }, integer)
        } else {
            format!(
                "{}{}.{}",
                if negative { "-" } else { "" },
                integer,
                fractional
            )
        };
        if canonical != raw {
            return Err(PolicyValueError::InvalidDecimal);
        }
        Ok(Self {
            canonical,
            negative,
            integer: integer.to_string(),
            fractional,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    fn cmp_magnitude(&self, other: &Self) -> std::cmp::Ordering {
        self.integer
            .len()
            .cmp(&other.integer.len())
            .then_with(|| self.integer.cmp(&other.integer))
            .then_with(|| {
                let width = self.fractional.len().max(other.fractional.len());
                self.fractional
                    .bytes()
                    .chain(std::iter::repeat(b'0'))
                    .take(width)
                    .cmp(
                        other
                            .fractional
                            .bytes()
                            .chain(std::iter::repeat(b'0'))
                            .take(width),
                    )
            })
    }
}

impl Ord for DecimalValue {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self.negative, other.negative) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            (false, false) => self.cmp_magnitude(other),
            (true, true) => self.cmp_magnitude(other).reverse(),
        }
    }
}

impl PartialOrd for DecimalValue {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum PolicyValueKind {
    String(String),
    Boolean(bool),
    Integer(i64),
    Decimal(DecimalValue),
}

/// ABAC typed value. The private representation makes every bounded value pass through its
/// constructor; callers cannot forge an overlong string or non-canonical decimal.
///
/// ```compile_fail
/// use identity::ports::PolicyValue;
/// let _ = PolicyValue::String("x".repeat(257));
/// ```
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PolicyValue(PolicyValueKind);

/// Exhaustive borrowed view for serialization adapters. It exposes no construction path back into
/// [`PolicyValue`], so the bounded-value funnel remains sealed.
#[derive(Clone, Copy)]
pub enum PolicyValueRef<'a> {
    String(&'a str),
    Boolean(bool),
    Integer(i64),
    Decimal(&'a DecimalValue),
}

impl PolicyValueRef<'_> {
    pub const fn value_type(self) -> PolicyValueType {
        match self {
            Self::String(_) => PolicyValueType::String,
            Self::Boolean(_) => PolicyValueType::Boolean,
            Self::Integer(_) => PolicyValueType::Integer,
            Self::Decimal(_) => PolicyValueType::Decimal,
        }
    }
}

impl std::fmt::Debug for PolicyValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PolicyValue(<redacted>)")
    }
}

impl PolicyValue {
    #[cfg(test)]
    #[allow(clippy::expect_used)]
    pub(crate) fn new(raw: impl Into<String>) -> Self {
        let raw = raw.into();
        Self::string(&raw).expect("test policy string must satisfy the production bound")
    }

    /// 兼作 string value 的唯一外部解析 funnel。
    pub fn parse(raw: &str) -> Result<Self, PolicyValueError> {
        Self::string(raw)
    }

    pub fn string(raw: &str) -> Result<Self, PolicyValueError> {
        if raw.len() > ATTR_VALUE_MAX_LEN {
            return Err(PolicyValueError::TooLong);
        }
        Ok(Self(PolicyValueKind::String(raw.to_string())))
    }

    pub const fn boolean(value: bool) -> Self {
        Self(PolicyValueKind::Boolean(value))
    }

    pub const fn integer(value: i64) -> Self {
        Self(PolicyValueKind::Integer(value))
    }

    pub fn decimal(raw: &str) -> Result<Self, PolicyValueError> {
        DecimalValue::parse(raw).map(|value| Self(PolicyValueKind::Decimal(value)))
    }

    pub(crate) fn from_decimal(value: DecimalValue) -> Self {
        Self(PolicyValueKind::Decimal(value))
    }

    pub const fn value_type(&self) -> PolicyValueType {
        match &self.0 {
            PolicyValueKind::String(_) => PolicyValueType::String,
            PolicyValueKind::Boolean(_) => PolicyValueType::Boolean,
            PolicyValueKind::Integer(_) => PolicyValueType::Integer,
            PolicyValueKind::Decimal(_) => PolicyValueType::Decimal,
        }
    }

    pub fn as_ref(&self) -> PolicyValueRef<'_> {
        match &self.0 {
            PolicyValueKind::String(value) => PolicyValueRef::String(value),
            PolicyValueKind::Boolean(value) => PolicyValueRef::Boolean(*value),
            PolicyValueKind::Integer(value) => PolicyValueRef::Integer(*value),
            PolicyValueKind::Decimal(value) => PolicyValueRef::Decimal(value),
        }
    }

    pub fn string_value(&self) -> Option<&str> {
        match &self.0 {
            PolicyValueKind::String(value) => Some(value),
            _ => None,
        }
    }

    pub const fn boolean_value(&self) -> Option<bool> {
        match &self.0 {
            PolicyValueKind::Boolean(value) => Some(*value),
            _ => None,
        }
    }

    pub const fn integer_value(&self) -> Option<i64> {
        match &self.0 {
            PolicyValueKind::Integer(value) => Some(*value),
            _ => None,
        }
    }

    pub fn decimal_value(&self) -> Option<&DecimalValue> {
        match &self.0 {
            PolicyValueKind::Decimal(value) => Some(value),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// PolicyId newtype
// ---------------------------------------------------------------------------

/// 策略标识 newtype（私有字段；构造经 funnel；不 derive Serialize——域类型）。
// reason: 同 RoleId（生产调用方待 W；当前仅测试消费）。
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyId(String);

// reason: 同 RoleId impl（生产调用方待 W；当前仅测试消费）。
#[allow(dead_code)]
impl PolicyId {
    /// 构造 PolicyId（由已校验字符串；crate 内测试/seed 使用，外部入口走 `parse`）。
    pub(crate) fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// 解析字符串为 PolicyId；拒绝空值 / 非法格式（严格白名单，fail-closed）。
    pub fn parse(raw: &str) -> Result<Self, IdParseError> {
        Ok(Self(parse_id(raw)?))
    }

    /// 取 ID 字符串引用。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// IdentityError — 错误枚举
// ---------------------------------------------------------------------------

/// 身份域错误（库枚举；用 `thiserror`；message 为 const 静态字面量）。
///
/// `pub`（ADR-005 Option 2）：作 `ports::RoleReadRepo` 方法错误类型被 adapter 跨 crate 命名（adapter 把内部
/// 持久化错误映射成本枚举）。`#[non_exhaustive]` 保留扩展窗口。
///
/// **与 authz 决策分轨**：`authorize_rbac` / `evaluate_abac` 的允许/拒绝经 `vocab::Decision` 表达，**不**
/// 走本枚举。本枚举是 repo / 服务操作的失败通道，各 variant 触发路径：
/// - `RoleNotFound`：`RoleReadRepo` 查无角色。
/// - `InvalidPolicy`：策略构造 / 校验失败。
/// - `PermissionDenied`：handler / 服务层把 `Decision::Deny` 落为域错误时使用（生产接线待 W 阶段 PR5）。
/// - `CredentialNotFound`：`CredentialRepo` 查无凭据（PR3）。
/// - `VersionConflict`：统一 identity-security lifecycle 的完整 snapshot CAS 不匹配。
/// - `SecurityFactBuild`：事务开始前构造 generated fact identity/envelope 失败。
/// - `SecurityPayloadEncode`：事务开始前编码 generated security-event payload 失败。
/// - `Storage`：持久化层错误（`RoleReadRepo` postgres adapter 边界把 sqlx 等存储错误收口于此；#1250）。
///   原始错误进 `#[source]`，不进 Display / wire——message 是 `&'static str` const literal，
///   runtime 细节仅进服务端日志（error-handling.md §Message 与 PII）。
// reason: `RoleNotFound` / `PermissionDenied` / `InvalidPolicy` / `CredentialNotFound` / `VersionConflict`
// 生产返回方（repo / handler 接线）待 W ⇒ 冻结期 dead（ADR-004 C8）；`Storage` 已由 PgRoleRepo + Role::hydrate
// 真实构造（非 dead）。变体级 dead 由 enum 级 allow 覆盖该子集，待消费方落地后逐个收窄。
#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityError {
    #[error("role not found")]
    RoleNotFound,
    #[error("policy not found")]
    PolicyNotFound,
    #[error("policy already exists")]
    PolicyAlreadyExists,
    #[error("permission denied")]
    PermissionDenied,
    #[error("policy is invalid")]
    InvalidPolicy,
    #[error("credential not found")]
    CredentialNotFound,
    #[error("credential version conflict")]
    VersionConflict,
    /// 同一 event id 已持久化为不同稳定事实；与仓储 CAS 冲突分轨。
    #[error("identity outbox fact conflict")]
    OutboxFactConflict(#[source] consistency::OutboxFactConflict),
    /// Generated security-fact identity/envelope construction failed before persistence starts.
    #[error("identity security fact build failed")]
    SecurityFactBuild(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// Generated security-event payload encoding failed before persistence starts.
    #[error("identity security payload encode failed")]
    SecurityPayloadEncode(#[source] serde_json::Error),
    /// Explicitly classified temporary provider outage.
    #[error("identity provider unavailable")]
    ProviderUnavailable(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// 底层存储错误（持久化失败；原始错误进 `#[source]`，不进 Display / wire）。
    #[error("identity storage error")]
    Storage(#[source] Box<dyn std::error::Error + Send + Sync>),
}

// ---------------------------------------------------------------------------
// 共享 newtype funnel 测试（表驱动；正常 / 空 / 非法字符 / 超长 fail-closed）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{
        ATTR_VALUE_MAX_LEN, AttributeKey, AttributeKeyError, DecimalValue, IdParseError,
        PatternError, PermissionId, PolicyId, PolicyValue, PolicyValueError, ResourcePattern,
        RoleId,
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

    // PolicyValue：typed accessor + Debug 脱敏（不泄原值）。
    #[test]
    fn attribute_value_new_and_redacted_debug() {
        let v = PolicyValue::new("s3cr3t-payload");
        assert_eq!(v.string_value(), Some("s3cr3t-payload"));
        let dbg = format!("{v:?}");
        assert_eq!(dbg, "PolicyValue(<redacted>)");
        assert!(!dbg.contains("s3cr3t"), "Debug 不得泄露明文值");
    }

    #[rstest]
    #[case("", true)]
    #[case("admin", true)]
    #[case("claim/with spaces + unicode-😀", true)]
    fn attribute_value_parse_accepts_within_bound(#[case] raw: &str, #[case] ok: bool) {
        match PolicyValue::parse(raw) {
            Ok(v) => {
                assert!(ok, "input len={} 应被拒", raw.len());
                assert_eq!(v.string_value(), Some(raw));
            }
            Err(PolicyValueError::TooLong | PolicyValueError::InvalidDecimal) => assert!(!ok),
        }
    }

    #[test]
    fn attribute_value_parse_accepts_exact_max_len() {
        let raw = "a".repeat(ATTR_VALUE_MAX_LEN);
        assert!(
            matches!(
                PolicyValue::parse(&raw),
                Ok(ref v) if v.string_value().is_some_and(|value| value.len() == ATTR_VALUE_MAX_LEN)
            ),
            "exact max len must parse"
        );
    }

    #[test]
    fn attribute_value_parse_rejects_over_max_len() {
        let raw = "a".repeat(ATTR_VALUE_MAX_LEN + 1);
        assert!(matches!(
            PolicyValue::parse(&raw),
            Err(PolicyValueError::TooLong)
        ));
        // 257 字节拒绝与 exact-256 接受形成边界对；多字节字符按字节计（非 chars().count()）
        let multi = "あ".repeat(86); // 86 * 3 = 258 bytes
        assert!(multi.len() > ATTR_VALUE_MAX_LEN);
        assert!(matches!(
            PolicyValue::parse(&multi),
            Err(PolicyValueError::TooLong)
        ));
    }

    #[test]
    fn decimal_value_is_exact_canonical_and_ordered() {
        let one = DecimalValue::parse("1").expect("decimal");
        let one_point_five = DecimalValue::parse("1.5").expect("decimal");
        let negative = DecimalValue::parse("-0.25").expect("decimal");
        assert_eq!(one.as_str(), "1");
        assert_eq!(one_point_five.as_str(), "1.5");
        assert!(negative < one && one < one_point_five);
        for non_canonical in ["1.0", "1.00", "1.50", "-0"] {
            assert_eq!(
                DecimalValue::parse(non_canonical),
                Err(PolicyValueError::InvalidDecimal)
            );
        }
        for invalid in ["", "+1", "01", "1.", ".1", "1e3", "--1"] {
            assert_eq!(
                DecimalValue::parse(invalid),
                Err(PolicyValueError::InvalidDecimal)
            );
        }
    }
}
