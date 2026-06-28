//! 敏感值脱敏 + 字段级脱敏策略模型 + 统一脱敏 funnel。
//!
//! 两层能力：
//! - **sink/key funnel**：[`redact_error`]（顶层 `Display`-only）/ [`redact_field`]（按 key 判敏感）/
//!   [`redact_url_credentials`]（剥 URL userinfo）——span error / tracing sink / last_error 一律经此收口
//!   （`docs/rules/observability.md` §redaction），敏感 key 判定与 free-form scrub 不散落各 consumer。
//! - **字段级策略模型**（#1360）：[`Sensitivity`] / [`PiiKind`] / [`RedactionMode`] / `RedactionCtx` /
//!   [`Redact`] + 公开 funnel [`redact_struct`]。配 `#[derive(Redact)]`（securederive）让任意 struct
//!   字段**显式声明** public / internal / pii / secret 与脱敏模式，派生安全 `Debug`——替换各 crate 手写 `Debug`。
//!
//! `redact_field` 的 key 判敏感逻辑已**单源**进 [`Sensitivity::from_key`]，`Redacted::new` 仍 `pub(crate)`
//! 封闭（外部只经公开 funnel 取 `Redacted`，不可伪造安全值）。

use sha2::{Digest, Sha256};
use std::fmt::{Debug, Write as _};

/// 敏感 key 关键字白名单（小写包含匹配）。由 [`Sensitivity::from_key`] 单源消费。
const SENSITIVE_KEY_PATTERNS: &[&str] = &[
    "password",
    "secret",
    "token",
    "credential",
    "apikey",
    "api_key",
    "key",
    "authorization",
    "cookie",
    "jwt",
    "session",
    "bearer",
    "salt",
    "private",
];

/// 敏感字段脱敏占位符。由 [`RedactionMode::Fixed`] 单源消费。
const REDACTED_PLACEHOLDER: &str = "<redacted>";

/// [`RedactionMode::Hash`] 摘要截断字节数（6 字节 = 12 hex 字符）。PII 关联令牌 `sha256:<12hex>` 的
/// **格式稳定性单源**——改此值即改可观测关联令牌格式（operator 合约），须同步运维文档/告警。
const HASH_TRUNCATE_BYTES: usize = 6;

/// 脱敏器（sync 纯计算 trait）。
pub trait Redactor {
    /// 对输入做脱敏，返回不可逆的脱敏值。
    fn redact(&self, input: &str) -> Redacted;
}

/// 脱敏后的值（私有字段，禁直接还原）。`Display` 输出已脱敏内容（安全），可直接进日志。
#[derive(Clone, PartialEq, Eq)]
pub struct Redacted(String);

impl std::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Redacted(<redacted>)")
    }
}

impl std::fmt::Display for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // reason: Display 输出已脱敏内容（funnel 产物，安全可记录）；供 `warn!(error = %redact_error(..))`。
        f.write_str(&self.0)
    }
}

impl Redacted {
    /// 由已脱敏字符串构造（受控 funnel，**crate 内受信入口**）。
    ///
    /// `pub(crate)`：`Redacted::Display` 可直接进日志，故禁止 crate 外业务把**未脱敏**内容
    /// 包装成可打印「安全值」绕过 funnel（input-struct mint 收口，类型层 Hard）。crate 外只能经
    /// [`redact_error`] / [`redact_field`] / [`redact_url_credentials`] 这些**固定语义** `pub` sink
    /// funnel 取得 `Redacted`——它们均**先施加脱敏**再 wrap，外部不可伪造任意「安全值」。
    ///
    /// 注意 [`redact_struct`] / [`Redact::redact_scoped`] / `RedactionCtx::apply` 返回**裸 `String`** 而非
    /// `Redacted`（#1360 F1）：它们的 mode 由调用方 / 类型作者选择（含 `Show`），不享「已脱敏安全值」语义，
    /// 故不经本封闭构造口——避免 `Show + 任意明文` 成外部 mint `Redacted` 的旁路。
    ///
    /// INVARIANT: REDACT-SEALED-NEW-01 —— `Redacted` 唯一构造口；`pub(crate)` 封闭使 crate 外无法把未脱敏值
    /// mint 成可 `Display` 的「安全值」，只能经固定语义 sink funnel 取得（先脱敏再 wrap）。
    pub(crate) fn new(redacted: impl Into<String>) -> Self {
        Self(redacted.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ===== 字段级脱敏策略模型（#1360）=====

/// 字段敏感度（「是什么」）。闭值集——`Public` 可下发、`Internal` 仅服务端、`Pii` 个人信息、`Secret` 密钥物料。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Sensitivity {
    /// 可对外下发（非敏感）。
    Public,
    /// 仅服务端日志，不进 wire / `Debug`。
    Internal,
    /// 个人可识别信息（子类驱动默认脱敏 mode）。
    Pii(PiiKind),
    /// 密钥 / 密码 / token 等机密物料。
    Secret,
}

/// PII 子类——驱动默认脱敏 [`RedactionMode`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PiiKind {
    /// 邮箱（默认 [`RedactionMode::EmailMask`]）。
    Email,
    /// 电话（默认 [`RedactionMode::Last4`]）。
    Phone,
    /// 姓名（默认 [`RedactionMode::Fixed`]）。
    Name,
    /// 地址（默认 [`RedactionMode::Fixed`]）。
    Address,
    /// 通用 PII（默认 [`RedactionMode::Fixed`]）。
    Generic,
}

/// 脱敏模式（「怎么脱」）。闭值集。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RedactionMode {
    /// 原样输出（仅用于显式声明的非敏感字段）。
    Show,
    /// 固定占位 `<redacted>`。
    Fixed,
    /// 保留尾 4 字符（`****1234`），其余抹去；过短 / 非文本 → fixed。
    Last4,
    /// 邮箱掩码（`a***@example.com`）；非邮箱形 → fixed。
    ///
    /// **注意**：域名部分原样保留（视为非敏感，便于按域聚合诊断）。内网 / 机密域名本身属敏感时
    /// （如 `@m-and-a-target.com`）须改用 [`Fixed`](Self::Fixed)。
    EmailMask,
    /// 确定性不可逆摘要（`sha256:<12hex>`）——同值同令牌、可关联不可还原。
    ///
    /// **仅适用于高熵输入**（UUID / 随机 token / 高熵 secret）：48 bit 截断 SHA-256 **无盐**，对低熵 PII
    /// （手机号 / 邮编 / 短验证码）攻击者可预计算全空间反推，**禁用于低熵字段**——低熵 PII 用
    /// [`Fixed`](Self::Fixed) / [`Last4`](Self::Last4)。`sensitivity` 默认映射从不选 Hash（须显式 `mode = "hash"`）。
    Hash,
    /// 从输出剔除该字段。
    Drop,
}

impl Sensitivity {
    /// 按字段 key 判敏感（搬入旧 `redact_field` 的子串白名单判定，单源）。命中 → [`Secret`](Self::Secret)，
    /// 否则 [`Public`](Self::Public)。
    pub fn from_key(key: &str) -> Self {
        let lower = key.to_lowercase();
        if SENSITIVE_KEY_PATTERNS
            .iter()
            .any(|pattern| lower.contains(pattern))
        {
            Sensitivity::Secret
        } else {
            Sensitivity::Public
        }
    }

    /// 该敏感度的默认脱敏 mode（`sensitivity → mode` 单源映射；`#[derive(Redact)]` 对只给
    /// `sensitivity` 的字段经此解析最终 mode，不在宏内复制映射）。fail-closed：`Internal`/`Secret`/多数
    /// `Pii` → `Fixed`。
    pub const fn default_mode(self) -> RedactionMode {
        match self {
            Sensitivity::Public => RedactionMode::Show,
            Sensitivity::Internal => RedactionMode::Fixed,
            Sensitivity::Pii(kind) => kind.default_mode(),
            Sensitivity::Secret => RedactionMode::Fixed,
        }
    }
}

impl PiiKind {
    /// 该 PII 子类的默认脱敏 mode。
    pub const fn default_mode(self) -> RedactionMode {
        match self {
            PiiKind::Email => RedactionMode::EmailMask,
            PiiKind::Phone => RedactionMode::Last4,
            PiiKind::Name | PiiKind::Address | PiiKind::Generic => RedactionMode::Fixed,
        }
    }
}

/// 字段原值的脱敏输入视图（借出，不取所有权）。仅 `Show`/`Last4`/`EmailMask`/`Hash` 真正读取原值。
#[derive(Debug, Clone, Copy)]
pub enum RedactValue<'a> {
    /// 文本字段。
    Str(&'a str),
    /// 字节字段（如密钥物料 / 密文）。
    Bytes(&'a [u8]),
    /// 布尔标量。
    Bool(bool),
    /// 有符号整数标量。
    Signed(i128),
    /// 无符号整数标量。
    Unsigned(u128),
    /// UUID 标量。
    Uuid(uuid::Uuid),
    /// 时间间隔标量。
    Duration(std::time::Duration),
    /// 系统时间标量。
    SystemTime(std::time::SystemTime),
    /// `time` crate 时间戳标量。
    OffsetDateTime(time::OffsetDateTime),
    /// 仅供结构化 `Debug` 上下文的非敏感字段：按字段自身 `Debug` 渲染，避免给 public 字段新增
    /// `RedactField` impl。
    Debug(&'a dyn Debug),
    /// 缺省字段（`Option::None`）。
    Absent,
}

/// 把字段借出为 [`RedactValue`]。`#[derive(Redact)]` 经此统一取字段原值，再由 mode 脱敏；
/// 实现覆盖常见字段类型（`String` / `str` / `Vec<u8>` / `[u8]` / `Option<T>`）。
pub trait RedactField {
    /// 借出本字段的脱敏输入视图。
    fn as_redact_value(&self) -> RedactValue<'_>;
}

impl RedactField for str {
    fn as_redact_value(&self) -> RedactValue<'_> {
        RedactValue::Str(self)
    }
}

impl RedactField for String {
    fn as_redact_value(&self) -> RedactValue<'_> {
        RedactValue::Str(self)
    }
}

impl RedactField for [u8] {
    fn as_redact_value(&self) -> RedactValue<'_> {
        RedactValue::Bytes(self)
    }
}

impl RedactField for Vec<u8> {
    fn as_redact_value(&self) -> RedactValue<'_> {
        RedactValue::Bytes(self)
    }
}

impl RedactField for bool {
    fn as_redact_value(&self) -> RedactValue<'_> {
        RedactValue::Bool(*self)
    }
}

macro_rules! impl_redact_field_signed {
    ($($ty:ty),* $(,)?) => {
        $(
            impl RedactField for $ty {
                fn as_redact_value(&self) -> RedactValue<'_> {
                    RedactValue::Signed(i128::from(*self))
                }
            }
        )*
    };
}

macro_rules! impl_redact_field_unsigned {
    ($($ty:ty),* $(,)?) => {
        $(
            impl RedactField for $ty {
                fn as_redact_value(&self) -> RedactValue<'_> {
                    RedactValue::Unsigned(u128::from(*self))
                }
            }
        )*
    };
}

impl_redact_field_signed!(i8, i16, i32, i64, i128);
impl_redact_field_unsigned!(u8, u16, u32, u64, u128);

impl RedactField for isize {
    fn as_redact_value(&self) -> RedactValue<'_> {
        RedactValue::Signed(*self as i128)
    }
}

impl RedactField for usize {
    fn as_redact_value(&self) -> RedactValue<'_> {
        RedactValue::Unsigned(*self as u128)
    }
}

impl RedactField for uuid::Uuid {
    fn as_redact_value(&self) -> RedactValue<'_> {
        RedactValue::Uuid(*self)
    }
}

impl RedactField for std::time::Duration {
    fn as_redact_value(&self) -> RedactValue<'_> {
        RedactValue::Duration(*self)
    }
}

impl RedactField for std::time::SystemTime {
    fn as_redact_value(&self) -> RedactValue<'_> {
        RedactValue::SystemTime(*self)
    }
}

impl RedactField for time::OffsetDateTime {
    fn as_redact_value(&self) -> RedactValue<'_> {
        RedactValue::OffsetDateTime(*self)
    }
}

impl<T: RedactField> RedactField for Option<T> {
    fn as_redact_value(&self) -> RedactValue<'_> {
        match self {
            Some(inner) => inner.as_redact_value(),
            None => RedactValue::Absent,
        }
    }
}

impl RedactionMode {
    /// 把字段原值按本模式脱敏成可安全记录的片段。`Fixed`/`Drop` 不读 `value`；其余 fail-closed——
    /// 非适用输入（如 `Last4` 遇 `Bytes`/`Absent`）退回固定占位。
    ///
    /// `pub(crate)`（#1361 review A-F1）：直调 `mask()` 会绕过 `safe`/`redact_struct` 的 [`RedactScope`]
    /// Wire 塌缩（funnel 旁路）。字段级输出经 [`safe`]（单一命名入口）；本方法仅 crate 内渲染原语。
    pub(crate) fn mask(self, value: RedactValue<'_>) -> String {
        match self {
            RedactionMode::Show => mask_show(value),
            RedactionMode::Fixed => REDACTED_PLACEHOLDER.to_string(),
            RedactionMode::Drop => String::new(),
            RedactionMode::Last4 => mask_last4(value),
            RedactionMode::EmailMask => mask_email(value),
            RedactionMode::Hash => mask_hash(value),
        }
    }
}

fn mask_show(value: RedactValue<'_>) -> String {
    match value {
        // 单值上下文（redact_field 非敏感原样）返回原值；结构化 Debug 上下文的转义由 redact_struct
        //（#1360 F3）按 mode 施加，不在此统一转义以免破坏 redact_field 的 verbatim 语义。
        RedactValue::Str(s) => s.to_string(),
        // Bytes 即便声明 Show 也不回显原始字节（仅长度供诊断）；Debug 仅用于结构化上下文。
        RedactValue::Bytes(b) => format!("[{} bytes]", b.len()),
        RedactValue::Bool(_)
        | RedactValue::Signed(_)
        | RedactValue::Unsigned(_)
        | RedactValue::Uuid(_)
        | RedactValue::Duration(_)
        | RedactValue::SystemTime(_)
        | RedactValue::OffsetDateTime(_) => scalar_to_string(value),
        RedactValue::Debug(v) => format!("{v:?}"),
        RedactValue::Absent => "None".to_string(),
    }
}

fn mask_last4(value: RedactValue<'_>) -> String {
    let s = match value {
        RedactValue::Str(s) => s.to_string(),
        RedactValue::Bool(_)
        | RedactValue::Signed(_)
        | RedactValue::Unsigned(_)
        | RedactValue::Uuid(_)
        | RedactValue::Duration(_)
        | RedactValue::SystemTime(_)
        | RedactValue::OffsetDateTime(_) => scalar_to_string(value),
        RedactValue::Bytes(_) | RedactValue::Debug(_) | RedactValue::Absent => {
            return REDACTED_PLACEHOLDER.to_string();
        }
    };
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 4 {
        // 过短 ⇒ 保留尾 4 即泄全部，fail-closed 全脱。
        return REDACTED_PLACEHOLDER.to_string();
    }
    let last4: String = chars[chars.len() - 4..].iter().collect();
    // 固定 `****` 前缀（不按长度铺星 ⇒ 不泄原长度）。
    format!("****{last4}")
}

fn mask_email(value: RedactValue<'_>) -> String {
    let s = match value {
        RedactValue::Str(s) => s.to_string(),
        RedactValue::Bool(_)
        | RedactValue::Signed(_)
        | RedactValue::Unsigned(_)
        | RedactValue::Uuid(_)
        | RedactValue::Duration(_)
        | RedactValue::SystemTime(_)
        | RedactValue::OffsetDateTime(_) => scalar_to_string(value),
        RedactValue::Bytes(_) | RedactValue::Debug(_) | RedactValue::Absent => {
            return REDACTED_PLACEHOLDER.to_string();
        }
    };
    // 域名部分原样保留（视为非敏感，见 RedactionMode::EmailMask 文档）；local 仅留首字符。
    match s.as_str().split_once('@') {
        Some((local, domain)) if !domain.is_empty() => match local.chars().next() {
            Some(first) => format!("{first}***@{domain}"),
            // 空 local（如 `@d.com`）⇒ fail-closed 固定占位。
            None => REDACTED_PLACEHOLDER.to_string(),
        },
        // 非邮箱形 ⇒ fail-closed 固定占位。
        _ => REDACTED_PLACEHOLDER.to_string(),
    }
}

fn mask_hash(value: RedactValue<'_>) -> String {
    let mut hasher = Sha256::new();
    match value {
        RedactValue::Str(s) => hasher.update(s.as_bytes()),
        RedactValue::Bytes(b) => hasher.update(b),
        RedactValue::Bool(_)
        | RedactValue::Signed(_)
        | RedactValue::Unsigned(_)
        | RedactValue::Uuid(_)
        | RedactValue::Duration(_)
        | RedactValue::SystemTime(_)
        | RedactValue::OffsetDateTime(_) => hasher.update(scalar_to_string(value).as_bytes()),
        // 无值 / Debug-only 视图不可哈希 ⇒ fail-closed 固定占位。
        RedactValue::Absent | RedactValue::Debug(_) => return REDACTED_PLACEHOLDER.to_string(),
    }
    let digest = hasher.finalize();
    // 截断 HASH_TRUNCATE_BYTES 字节（= 12 hex 字符）：足够关联、不可逆、不回显全摘要。
    let mut hex = String::with_capacity(HASH_TRUNCATE_BYTES * 2);
    for byte in digest.iter().take(HASH_TRUNCATE_BYTES) {
        let _ = write!(hex, "{byte:02x}");
    }
    format!("sha256:{hex}")
}

fn scalar_to_string(value: RedactValue<'_>) -> String {
    match value {
        RedactValue::Bool(v) => v.to_string(),
        RedactValue::Signed(v) => v.to_string(),
        RedactValue::Unsigned(v) => v.to_string(),
        RedactValue::Uuid(v) => v.hyphenated().to_string(),
        RedactValue::Duration(v) => format!("{}ns", v.as_nanos()),
        RedactValue::SystemTime(v) => match v.duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => format!("{}ns_since_unix_epoch", duration.as_nanos()),
            Err(err) => format!("-{}ns_since_unix_epoch", err.duration().as_nanos()),
        },
        RedactValue::OffsetDateTime(v) => {
            format!("{}ns_since_unix_epoch", v.unix_timestamp_nanos())
        }
        RedactValue::Str(s) => s.to_string(),
        RedactValue::Bytes(b) => format!("[{} bytes]", b.len()),
        RedactValue::Debug(v) => format!("{v:?}"),
        RedactValue::Absent => "None".to_string(),
    }
}

/// 字段脱敏策略：绑定 [`Sensitivity`] 与最终 [`RedactionMode`]。
///
/// `pub(crate)`（#1361 review A-F1/C-F5）：`apply` 不应用 [`RedactScope`] Wire 塌缩，crate 外直用会绕过
/// 字段级 funnel；仅 [`redact_field`] 等 sink funnel 内部消费。字段级输出走 [`safe`]（单一命名入口）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RedactionCtx {
    sensitivity: Sensitivity,
    mode: RedactionMode,
}

impl RedactionCtx {
    /// 由 sensitivity（+可选显式 mode override）构造策略；`mode` 缺省取 [`Sensitivity::default_mode`]。
    pub(crate) fn new(sensitivity: Sensitivity, mode: Option<RedactionMode>) -> Self {
        Self {
            sensitivity,
            mode: mode.unwrap_or(sensitivity.default_mode()),
        }
    }

    /// 应用策略脱敏字段原值，产出**已脱敏的 `String` 片段**（非 [`Redacted`]）。
    ///
    /// 返回裸 `String` 而非 `Redacted`（#1360 F1）：`RedactionCtx` 的 mode 由调用方选择（含 `Show`），
    /// 若返回 `Redacted` 则外部可经 `apply(Show, Str(明文))` 伪造可 Display 的「安全值」绕开封闭面。
    /// `Redacted` 仅由固定语义的 sink funnel（[`redact_error`]/[`redact_field`]/[`redact_url_credentials`]）
    /// 经 `pub(crate)` [`Redacted::new`] 产出——类型层封闭，外部不可 mint。`String` 无「已脱敏」语义契约，
    /// 仅是 derive Debug 渲染与 key funnel 的内部片段。
    ///
    /// 注意：本方法**不应用** [`RedactScope`] Wire 塌缩（scope-unaware）；scope-aware 字段级渲染走 [`safe`]。
    pub(crate) fn apply(self, value: RedactValue<'_>) -> String {
        self.mode.mask(value)
    }
}

/// `#[derive(Redact)]` 为每字段产出的脱敏描述符（字段名 + mode + 字段原值视图）。
#[derive(Debug, Clone, Copy)]
pub struct FieldRedaction<'a> {
    /// `Some("name")`（named 字段）/ `None`（tuple 字段，位置式渲染）。
    pub name: Option<&'static str>,
    /// 该字段的脱敏模式。
    pub mode: RedactionMode,
    /// 字段原值视图（`Fixed`/`Drop` 不读）。
    pub value: RedactValue<'a>,
}

/// 字段级输出目标通道（issue #1361 的 `ctx`）——决定 pii / 部分泄露 mode 的渲染严格度。
///
/// 唯一通道差异：**部分泄露** mode（[`Last4`](RedactionMode::Last4) / [`EmailMask`](RedactionMode::EmailMask)
/// / [`Hash`](RedactionMode::Hash)）在 [`Wire`](Self::Wire) 塌缩为 [`Fixed`](RedactionMode::Fixed)，在
/// [`ServerLog`](Self::ServerLog) 保留声明 mode（诊断掩码 / 关联令牌）。`internal` / `secret` 两通道均 `Fixed`
/// （值在 derive 侧根本不捕获，见 [`Redact`]），`public` / `Show` 两通道均原样。
///
/// 对标 `iqlusioninc/crates` secrecy `ExposeSecret`（受控暴露语义）：[`ServerLog`](Self::ServerLog) 是受信
/// 进程内诊断通道（派生 `Debug` 默认即此），[`Wire`](Self::Wire) 是外部不可信 sink（导出 trace / API 响应 /
/// 外发日志聚合）的更严渲染——敏感值不部分泄露。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RedactScope {
    /// 受信服务端日志 / `last_error` 持久化 / 进程内诊断：保留声明 mode（含 `Last4`/`EmailMask`/`Hash` 掩码）。
    ServerLog,
    /// 外部不可信输出（导出 trace / API 响应 / 外发日志聚合）：部分泄露 mode 塌缩 `Fixed`，不部分泄露敏感值。
    Wire,
}

/// 字段级脱敏上游模型：类型声明自身字段策略，按输出 [`RedactScope`] 产出已脱敏的 `Debug` 渲染 `String`。
/// 由 `#[derive(Redact)]` 实现（生成的 `Debug` 委托 `self.redact_scoped(RedactScope::ServerLog)`）。
///
/// 返回 `String` 而非 [`Redacted`]（#1360 F1）：`redact_scoped` 是 `Debug` 渲染 helper，非「安全值」产出口——
/// 字段 mode 由类型作者声明（含 `Show`），若返回 `Redacted` 则任意类型经 `Show` 字段即可 mint 可 Display
/// 的 `Redacted`，绕开封闭面。`Redacted` 仅由固定语义 sink funnel 产出（见 `RedactionCtx::apply`）。
pub trait Redact {
    /// 按字段策略 + 输出 [`RedactScope`] 脱敏自身，返回 `Debug` 渲染片段。
    fn redact_scoped(&self, scope: RedactScope) -> String;
}

/// 字段级安全输出 funnel：按值**自身声明的字段策略**（`#[derive(Redact)]`）+ 输出 `scope`，产出可安全
/// 记录的 `String`——tracing field / 日志 / wire / `last_error` 字段级输出的**单一命名入口**（sink funnel
/// [`redact_error`] / [`redact_field`] / [`redact_url_credentials`] 的 typed-value 兄弟）。
///
/// 「字段声明优先于 key 猜测」的落点（#1361）：在值变成 `tracing` 字段字符串**之前**按声明策略渲染（与派生
/// `Debug` 同源——`safe(v, RedactScope::ServerLog) == format!("{v:?}")`）；OTel exporter 的 key-sweep 退化为
/// defense-in-depth 兜底（它只见擦除后的 `String`，无从读类型策略）。
///
/// 返回裸 `String` 而非 [`Redacted`]（#1360 F1，保 [`Redacted::new`] 封闭面）。
///
/// 用例：`tracing::warn!(subject = %secure::safe(&subj, secure::RedactScope::Wire), "rejected");`
pub fn safe<R: Redact + ?Sized>(value: &R, scope: RedactScope) -> String {
    value.redact_scoped(scope)
}

/// 按输出 [`RedactScope`] 解析字段有效 mode：[`Wire`](RedactScope::Wire) 把**部分泄露** mode
/// （`Last4`/`EmailMask`/`Hash`）塌缩为 `Fixed`（外部 sink 不部分泄露敏感值）；[`ServerLog`](RedactScope::ServerLog)
/// 原样保留声明 mode。`Show`/`Fixed`/`Drop` 两 scope 一致。
///
/// （不按 sensitivity 区分 public：`public` 字段几乎不会声明 `Last4`/`EmailMask`/`Hash`〔非敏感无需掩码〕，
/// 即便偶现、外部 sink 上塌缩为 `Fixed` 亦无害——故无需把 sensitivity 抬进 [`FieldRedaction`] 公开面。）
///
/// INVARIANT: REDACT-WIRE-COLLAPSE-01 —— `Wire` scope 下部分泄露 mode（Last4/EmailMask/Hash）必塌缩 `Fixed`；
/// 由 `safe_wire_collapses_partial_reveal_to_fixed` + `redact_struct_wire_collapses_partial_reveal`（anti-vacuity:
/// 同值两 scope 输出不同）守。`mask` 已 `pub(crate)`、`safe` 是唯一字段级输出入口 ⇒ 旁路收敛。
fn scope_effective_mode(mode: RedactionMode, scope: RedactScope) -> RedactionMode {
    match (scope, mode) {
        (
            RedactScope::Wire,
            RedactionMode::Last4 | RedactionMode::EmailMask | RedactionMode::Hash,
        ) => RedactionMode::Fixed,
        _ => mode,
    }
}

/// 字段级脱敏渲染 funnel（`#[derive(Redact)]` 调用）。对每字段 apply 声明的 mode、按 tuple / named
/// 形态渲染成已脱敏 `String`。`Drop` 字段从输出剔除。
///
/// **返回 `String` 而非 [`Redacted`]（#1360 F1，封闭面收窄）**：本函数须 `pub`（derive 在 diport 等
/// 外部 crate 生成的 `impl Redact` 调它），且字段 mode 由调用方传入（含 `Show`+任意 `value`）；若返回
/// `Redacted` 则成外部 mint「安全值」的旁路。`Redacted` 改由固定语义 sink funnel 经 `pub(crate)`
/// [`Redacted::new`] 独家产出——类型层封闭，外部不可伪造。
/// 结构化 Debug 上下文的单字段渲染：先按 mode 脱敏，再对 `Show` 字段 Debug-转义（#1360 F3）——
/// Show 字段含换行 / 控制字符时不污染 `Type { f: .. }` 渲染结构（与 derive(Debug) 对 `String` 字段一致）。
/// `Fixed`/`Last4`/`EmailMask`/`Hash`/`Drop` 产物是受控占位 / 掩码片段，不转义（避免给 `<redacted>` 加引号）。
fn render_field(mode: RedactionMode, value: RedactValue<'_>) -> String {
    let masked = mode.mask(value);
    if mode == RedactionMode::Show {
        if matches!(value, RedactValue::Debug(_)) {
            masked
        } else {
            format!("{masked:?}")
        }
    } else {
        masked
    }
}

pub fn redact_struct(
    type_name: &'static str,
    is_tuple: bool,
    scope: RedactScope,
    fields: &[FieldRedaction<'_>],
) -> String {
    let rendered: Vec<(Option<&'static str>, String)> = fields
        .iter()
        .filter_map(|f| {
            // 按输出 scope 解析有效 mode（Wire 塌缩部分泄露 mode），再剔除 Drop、渲染。
            let mode = scope_effective_mode(f.mode, scope);
            (mode != RedactionMode::Drop).then(|| (f.name, render_field(mode, f.value)))
        })
        .collect();

    if rendered.is_empty() {
        return type_name.to_string();
    }

    let mut out = String::from(type_name);
    if is_tuple {
        out.push('(');
        for (i, (_name, val)) in rendered.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(val);
        }
        out.push(')');
    } else {
        out.push_str(" { ");
        for (i, (name, val)) in rendered.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            if let Some(field_name) = name {
                out.push_str(field_name);
                out.push_str(": ");
            }
            out.push_str(val);
        }
        out.push_str(" }");
    }
    out
}

// ===== sink / key / url funnel =====

/// 统一脱敏 funnel：把 error 的**顶层** `Display` 作为可记录的安全摘要。
/// span error / tracing sink / last_error 一律经此（observability.md §redaction），不裸打印 error。
///
/// # 安全性（fail-closed）
///
/// **只输出顶层 `error.to_string()`，不遍历 `source()` 链**——source 链可能来自第三方 error
/// （驱动 / 网络层），其 `Display` 可能携连接串 / 凭据 / 用户输入等 PII；默认不展开，从根上杜绝
/// 经 error 链泄漏（也顺带消除 source 链循环遍历风险）。RSS 自有 `vocab::CoreError` 的 message 是
/// `&'static str` const（安全），顶层摘要已足够定位；需要链路诊断的调用方走显式 verbose 通道，
/// 不在本默认安全 funnel。
///
/// **belt-and-suspenders（#1361 review F2）**：顶层 `Display` 再经 [`redact_url_credentials`] 剥 URL
/// 内联凭据——第三方驱动错误常把 DSN（`postgres://u:p@host/db ...`）拼进顶层 message，本 funnel 统一
/// 兜住；无 `://` 时原样。调用方无需在每个 error-log callsite 记得手动清洗 DSN。
pub fn redact_error(error: &dyn std::error::Error) -> Redacted {
    redact_url_credentials(&error.to_string())
}

/// 统一脱敏 funnel：按敏感 key 判定清洗单个字段值（敏感 key → 脱敏，否则原样）。
///
/// 重构为字段级模型的一行入口（#1360）：key 判敏感经 [`Sensitivity::from_key`] 单源、脱敏经
/// `RedactionCtx`——非第二份实现，无双路径。敏感 key → `Secret`→`Fixed`→`<redacted>`；普通 key →
/// `Public`→`Show`→原样。
///
/// # ⚠️ key-sweep 盲区（#1361）
///
/// 本 funnel 只按 key 名猜敏感；敏感 key 白名单 **不含** `email` / `subject` / `dsn` 等——这些
/// key 返回 `Public`→`Show`→**原值**（`Redacted::Display` 仍是明文！类型名 `Redacted` 在此不代表已脱敏）。
/// 这类字段须经字段级声明覆盖：`#[derive(secure::Redact)]` + `#[redact(pii = "email")]` 等，再用
/// [`safe`]（声明优先于 key 猜测）；DSN 用 [`redact_url_credentials`]。**勿**把 `email` 加进 key 白名单
/// （违 declaration-over-key-guessing 设计）。
pub fn redact_field(key: &str, value: &str) -> Redacted {
    // apply 产出已脱敏 String 片段；本 sink funnel 经 pub(crate) Redacted::new 封装为安全值
    //（key 判敏感固定语义，非调用方选 mode，故可信地产出 Redacted）。
    Redacted::new(
        RedactionCtx::new(Sensitivity::from_key(key), None).apply(RedactValue::Str(value)),
    )
}

/// 统一脱敏 funnel：剥离 URL 的 userinfo（`user:pass@`）凭据，保留 scheme/host/port/path 供诊断。
///
/// 用于带内联凭据的连接串（AMQP `amqp://user:pass@host/vhost`、DB DSN 等）——authority 段的
/// userinfo 整段替换为 `<redacted>`，其余原样。无 `://`、或 authority 内无 `@` 时原样返回（仍包成
/// [`Redacted`]，禁 crate 外把未脱敏 URL 当安全值打印绕过 funnel）。只清洗 authority 段的 `@`，
/// path / query 里的 `@` 不动（[`redact_field`] 按 key 判定无法识别 URL 内联凭据，故需此姊妹 funnel）。
pub fn redact_url_credentials(url: &str) -> Redacted {
    let Some(scheme_end) = url.find("://") else {
        return Redacted::new(url);
    };
    let authority_start = scheme_end + 3;
    let rest = &url[authority_start..];
    // authority 终止于 path / query / fragment 首字符（其后的 '@' 属 path，非凭据）。
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let Some(at) = rest[..authority_end].rfind('@') else {
        return Redacted::new(url);
    };
    // 重建 scheme://<redacted>@<host:port/path...>；userinfo（at 之前）整段抹去。
    Redacted::new(format!(
        "{}{REDACTED_PLACEHOLDER}@{}",
        &url[..authority_start],
        &rest[at + 1..],
    ))
}

// ===== last_error 脱敏安全载体（#1361）=====

/// 持久化 `last_error` 的脱敏安全载体（sealed：内层 `String` 私有、仅经受控构造口产出已脱敏内容）。
///
/// **类型层 Hard 保证**：「未经脱敏的 last_error 不可构造 / 持久化」——业务无法 mint 携原始错误文本的
/// `LastError`，只能经 [`from_error`](Self::from_error)（顶层 `Display`，经 [`redact_error`] 收口、不遍历
/// source 链）或 [`from_redactable`](Self::from_redactable)（字段策略，经 [`safe`]）产出。`Display` / `Debug`
/// 输出已脱敏内容（安全可记录）。
///
/// 持久化列 / 域字段 / writer 待落地（本轮仅交付安全载体——落地时列写入取 `LastError`，redaction 由构造口
/// 强制；见 `docs/rules/observability.md` §Redaction）。
#[derive(Clone, PartialEq, Eq)]
pub struct LastError(String);

impl LastError {
    /// 由 error 构造：取**顶层** `Display`，经 [`redact_error`] 收口（不遍历 source 链，fail-closed）。
    /// [`redact_error`] 已内置 URL 凭据剥离（#1361 belt-and-suspenders）——顶层 `Display` 内联的 DSN 凭据
    /// 自动剥，调用方无需手动 [`redact_url_credentials`]；source 链（常是第三方驱动 PII）默认不展开。
    pub fn from_error(error: &dyn std::error::Error) -> Self {
        Self(redact_error(error).as_str().to_owned())
    }

    /// 由带字段策略的值构造：经 [`safe`] 按值声明策略 + `scope` 渲染（last_error 持久化通常用
    /// [`RedactScope::ServerLog`]——受信进程内诊断）。
    pub fn from_redactable<R: Redact + ?Sized>(value: &R, scope: RedactScope) -> Self {
        Self(safe(value, scope))
    }

    /// 借出已脱敏内容。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for LastError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // reason: 内容已脱敏（经 redact_error / safe funnel），可安全记录。
        f.write_str(&self.0)
    }
}

impl std::fmt::Debug for LastError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LastError({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FieldRedaction, LastError, PiiKind, RedactField, RedactScope, RedactValue, Redacted,
        RedactionCtx, RedactionMode, Sensitivity, redact_error, redact_field, redact_struct,
        redact_url_credentials, safe,
    };
    use rstest::rstest;

    #[test]
    fn redacted_new_and_as_str() {
        let r = Redacted::new("safe value");
        assert_eq!(r.as_str(), "safe value");
    }

    #[test]
    fn redacted_display_outputs_content() {
        let r = Redacted::new("visible");
        assert_eq!(r.to_string(), "visible");
    }

    #[test]
    fn redacted_debug_is_opaque() {
        let r = Redacted::new("secret");
        assert_eq!(format!("{r:?}"), "Redacted(<redacted>)");
    }

    #[test]
    fn redacted_clone_eq() {
        let r1 = Redacted::new("x");
        let r2 = r1.clone();
        assert_eq!(r1, r2);
    }

    // --- redact_error ---

    #[derive(Debug)]
    struct SimpleError(String);
    impl std::fmt::Display for SimpleError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }
    impl std::error::Error for SimpleError {}

    #[derive(Debug)]
    struct WrappedError {
        msg: String,
        cause: SimpleError,
    }
    impl std::fmt::Display for WrappedError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.msg)
        }
    }
    impl std::error::Error for WrappedError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.cause)
        }
    }

    #[test]
    fn redact_error_single_layer() {
        let e = SimpleError("io error".to_string());
        let r = redact_error(&e);
        assert_eq!(r.as_str(), "io error");
    }

    #[test]
    fn redact_error_emits_top_level_only_not_source_chain() {
        // fail-closed：source 链（可能含第三方 PII）不进摘要，只输出顶层 Display。
        let e = WrappedError {
            msg: "outer".to_string(),
            cause: SimpleError("inner-secret-dsn".to_string()),
        };
        let r = redact_error(&e);
        assert_eq!(r.as_str(), "outer");
        assert!(!r.as_str().contains("inner-secret-dsn"));
    }

    // --- redact_field（reframe 后 parity：行为与旧 key 白名单完全一致）---

    #[rstest]
    #[case("password", "hunter2", "<redacted>")]
    #[case("Authorization", "Bearer abc", "<redacted>")]
    #[case("access_token", "tok123", "<redacted>")]
    #[case("apiKey", "k-123", "<redacted>")]
    #[case("cookie", "session=abc", "<redacted>")]
    #[case("session_id", "x", "<redacted>")]
    #[case("jwt", "eyJhbGciOiJIUzI1NiJ9", "<redacted>")]
    #[case("bearer_value", "some-token", "<redacted>")]
    #[case("salt", "abc123", "<redacted>")]
    #[case("private_key", "BEGIN RSA PRIVATE KEY", "<redacted>")]
    // 普通 key 原样保留。
    #[case("username", "alice", "alice")]
    #[case("userId", "u-42", "u-42")]
    fn redact_field_key_parity(#[case] key: &str, #[case] value: &str, #[case] want: &str) {
        assert_eq!(redact_field(key, value).as_str(), want);
    }

    // --- Sensitivity / 模型 ---

    #[rstest]
    #[case("password", Sensitivity::Secret)]
    #[case("api_key", Sensitivity::Secret)]
    #[case("username", Sensitivity::Public)]
    #[case("userId", Sensitivity::Public)]
    fn sensitivity_from_key_classifies(#[case] key: &str, #[case] want: Sensitivity) {
        assert_eq!(Sensitivity::from_key(key), want);
    }

    #[rstest]
    #[case(Sensitivity::Public, RedactionMode::Show)]
    #[case(Sensitivity::Internal, RedactionMode::Fixed)]
    #[case(Sensitivity::Secret, RedactionMode::Fixed)]
    #[case(Sensitivity::Pii(PiiKind::Email), RedactionMode::EmailMask)]
    #[case(Sensitivity::Pii(PiiKind::Phone), RedactionMode::Last4)]
    #[case(Sensitivity::Pii(PiiKind::Name), RedactionMode::Fixed)]
    #[case(Sensitivity::Pii(PiiKind::Address), RedactionMode::Fixed)]
    #[case(Sensitivity::Pii(PiiKind::Generic), RedactionMode::Fixed)]
    fn sensitivity_default_mode(#[case] sens: Sensitivity, #[case] want: RedactionMode) {
        assert_eq!(sens.default_mode(), want);
    }

    // --- RedactionMode::mask（每模式掩码语义）---

    #[test]
    fn mask_show_passes_str_through() {
        assert_eq!(RedactionMode::Show.mask(RedactValue::Str("alice")), "alice");
    }

    #[test]
    fn mask_show_bytes_only_length() {
        assert_eq!(
            RedactionMode::Show.mask(RedactValue::Bytes(&[1, 2, 3])),
            "[3 bytes]"
        );
    }

    #[test]
    fn mask_show_absent_is_none() {
        assert_eq!(RedactionMode::Show.mask(RedactValue::Absent), "None");
    }

    #[test]
    fn mask_fixed_is_placeholder() {
        assert_eq!(
            RedactionMode::Fixed.mask(RedactValue::Str("secret")),
            "<redacted>"
        );
    }

    #[test]
    fn mask_drop_is_empty() {
        assert_eq!(RedactionMode::Drop.mask(RedactValue::Str("x")), "");
    }

    #[rstest]
    #[case("4242424242424242", "****4242")]
    #[case("abcd", "<redacted>")] // 过短（≤4）→ 全脱
    #[case("abcde", "****bcde")]
    fn mask_last4_keeps_tail(#[case] input: &str, #[case] want: &str) {
        assert_eq!(RedactionMode::Last4.mask(RedactValue::Str(input)), want);
    }

    #[test]
    fn mask_last4_non_str_is_fixed() {
        // Bytes / Absent 无 last4 文本语义 → fail-closed 固定占位。
        assert_eq!(
            RedactionMode::Last4.mask(RedactValue::Bytes(&[1, 2, 3, 4, 5])),
            "<redacted>"
        );
        assert_eq!(RedactionMode::Last4.mask(RedactValue::Absent), "<redacted>");
    }

    #[rstest]
    #[case("alice@example.com", "a***@example.com")]
    #[case("a@b.io", "a***@b.io")]
    #[case("not-an-email", "<redacted>")] // 非邮箱 → fixed
    #[case("@no-local.com", "<redacted>")] // 空 local → fixed
    fn mask_email_masks_local(#[case] input: &str, #[case] want: &str) {
        assert_eq!(RedactionMode::EmailMask.mask(RedactValue::Str(input)), want);
    }

    #[test]
    fn mask_hash_is_deterministic_and_irreversible() {
        let a = RedactionMode::Hash.mask(RedactValue::Str("user@corp.com"));
        let b = RedactionMode::Hash.mask(RedactValue::Str("user@corp.com"));
        assert_eq!(a, b, "同值同摘要（可关联）");
        assert!(a.starts_with("sha256:"));
        assert!(!a.contains("user@corp.com"), "不回显原值");
        assert_eq!(a.len(), "sha256:".len() + 12, "截断 12 hex");
        let c = RedactionMode::Hash.mask(RedactValue::Str("other@corp.com"));
        assert_ne!(a, c, "异值异摘要");
    }

    #[test]
    fn mask_hash_bytes_and_absent() {
        assert!(
            RedactionMode::Hash
                .mask(RedactValue::Bytes(&[0xDE, 0xAD]))
                .starts_with("sha256:")
        );
        assert_eq!(
            RedactionMode::Hash.mask(RedactValue::Absent),
            "<redacted>",
            "无值可哈希 → fail-closed"
        );
    }

    // --- RedactionCtx ---

    #[test]
    fn redaction_ctx_defaults_mode_from_sensitivity() {
        // 默认 mode 由 sensitivity 解析（Secret→Fixed）；经 apply() 输出验证（accessor 已收为 pub(crate) 内部）。
        let ctx = RedactionCtx::new(Sensitivity::Secret, None);
        assert_eq!(ctx.apply(RedactValue::Str("k")), "<redacted>");
    }

    #[test]
    fn redaction_ctx_explicit_mode_overrides_default() {
        let ctx = RedactionCtx::new(
            Sensitivity::Pii(PiiKind::Generic),
            Some(RedactionMode::Hash),
        );
        assert!(ctx.apply(RedactValue::Str("x")).starts_with("sha256:"));
    }

    // --- RedactField ---

    #[test]
    fn redact_field_trait_views() {
        assert!(matches!(
            RedactField::as_redact_value(&"s".to_string()),
            RedactValue::Str("s")
        ));
        assert!(matches!(
            RedactField::as_redact_value(&vec![1u8, 2]),
            RedactValue::Bytes(_)
        ));
        let some: Option<String> = Some("v".to_string());
        assert!(matches!(some.as_redact_value(), RedactValue::Str("v")));
        let none: Option<String> = None;
        assert!(matches!(none.as_redact_value(), RedactValue::Absent));
    }

    #[test]
    fn redact_field_trait_scalar_views() {
        assert!(matches!(
            RedactField::as_redact_value(&true),
            RedactValue::Bool(true)
        ));
        assert!(matches!(
            RedactField::as_redact_value(&42_u32),
            RedactValue::Unsigned(42)
        ));
        assert!(matches!(
            RedactField::as_redact_value(&-7_i64),
            RedactValue::Signed(-7)
        ));

        let uuid = uuid::Uuid::from_u128(0xf47ac10b58cc4372a5670e02b2c3d479);
        assert!(matches!(RedactField::as_redact_value(&uuid), RedactValue::Uuid(v) if v == uuid));
    }

    #[test]
    fn redact_field_trait_time_views_are_stable() {
        let duration = std::time::Duration::from_millis(1_234);
        assert!(matches!(
            RedactField::as_redact_value(&duration),
            RedactValue::Duration(v) if v == duration
        ));
        assert_eq!(
            RedactionMode::Show.mask(RedactField::as_redact_value(&duration)),
            "1234000000ns"
        );

        let system_time = std::time::UNIX_EPOCH + duration;
        assert!(matches!(
            RedactField::as_redact_value(&system_time),
            RedactValue::SystemTime(v) if v == system_time
        ));
        assert_eq!(
            RedactionMode::Show.mask(RedactField::as_redact_value(&system_time)),
            "1234000000ns_since_unix_epoch"
        );

        let offset = time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1_234);
        assert!(matches!(
            RedactField::as_redact_value(&offset),
            RedactValue::OffsetDateTime(v) if v == offset
        ));
        assert_eq!(
            RedactionMode::Show.mask(RedactField::as_redact_value(&offset)),
            "1234000000000ns_since_unix_epoch"
        );
    }

    #[test]
    fn scalar_redact_value_can_be_hashed() {
        let a = RedactionMode::Hash.mask(RedactField::as_redact_value(&42_u32));
        let b = RedactionMode::Hash.mask(RedactValue::Str("42"));
        assert_eq!(a, b);
        assert!(a.starts_with("sha256:"));
    }

    // --- redact_struct 渲染 ---

    #[test]
    fn redact_struct_tuple_newtype_render() {
        let r = redact_struct(
            "Ct",
            true,
            RedactScope::ServerLog,
            &[FieldRedaction {
                name: None,
                mode: RedactionMode::Fixed,
                value: RedactValue::Bytes(&[1, 2, 3]),
            }],
        );
        assert_eq!(r.as_str(), "Ct(<redacted>)");
    }

    #[test]
    fn redact_struct_named_multi_field_render() {
        let r = redact_struct(
            "Coord",
            false,
            RedactScope::ServerLog,
            &[
                FieldRedaction {
                    name: Some("store_id"),
                    mode: RedactionMode::Fixed,
                    value: RedactValue::Str("vault-prod"),
                },
                FieldRedaction {
                    name: Some("key"),
                    mode: RedactionMode::Fixed,
                    value: RedactValue::Str("db/password"),
                },
            ],
        );
        assert_eq!(
            r.as_str(),
            "Coord { store_id: <redacted>, key: <redacted> }"
        );
        assert!(!r.as_str().contains("vault-prod"));
    }

    #[test]
    fn redact_struct_drop_field_omitted() {
        let r = redact_struct(
            "T",
            false,
            RedactScope::ServerLog,
            &[
                FieldRedaction {
                    name: Some("shown"),
                    mode: RedactionMode::Show,
                    value: RedactValue::Str("yes"),
                },
                FieldRedaction {
                    name: Some("gone"),
                    mode: RedactionMode::Drop,
                    value: RedactValue::Str("secret"),
                },
            ],
        );
        // Show 字段经 Debug-转义（#1360 F3）：`yes` → `"yes"`。
        assert_eq!(r, "T { shown: \"yes\" }");
        assert!(!r.contains("gone"));
        assert!(!r.contains("secret"));
    }

    #[test]
    fn redact_struct_show_escapes_control_chars() {
        // F3 回归（#1360）：Show 字段含换行 / 控制字符 / 引号经 Debug-转义，不污染 `Type { .. }` 结构化渲染。
        let r = redact_struct(
            "T",
            false,
            RedactScope::ServerLog,
            &[FieldRedaction {
                name: Some("note"),
                mode: RedactionMode::Show,
                value: RedactValue::Str("a\nb\"q"),
            }],
        );
        assert_eq!(r, "T { note: \"a\\nb\\\"q\" }");
        assert!(!r.contains('\n'), "真实换行未转义会污染日志结构: {r}");
    }

    #[test]
    fn redact_struct_all_dropped_renders_bare_name() {
        let r = redact_struct(
            "T",
            true,
            RedactScope::ServerLog,
            &[FieldRedaction {
                name: None,
                mode: RedactionMode::Drop,
                value: RedactValue::Str("x"),
            }],
        );
        assert_eq!(r.as_str(), "T");
    }

    // --- #[derive(Redact)] 端到端（secure 内自用，验证派生 Debug + 多 mode 渲染）---

    #[allow(dead_code)]
    #[derive(secure::Redact)]
    struct DerivedNewtype(#[redact(secret)] Vec<u8>);

    #[derive(secure::Redact)]
    // `gone`（mode = "drop"）经 F2 后取 RedactValue::Absent、不被 redact 读取 ⇒ field never read。
    #[allow(dead_code)]
    struct DerivedMixed {
        #[redact(public, mode = "show")]
        visible: String,
        #[redact(secret)]
        secret: String,
        #[redact(pii = "phone", mode = "last4")]
        card: String,
        #[redact(pii = "email", mode = "email_mask")]
        email: String,
        #[redact(secret, mode = "drop")]
        gone: String,
    }

    // F2 回归（#1360）：自定义类型字段标显式 `mode = "fixed"`/`drop` **不要求** impl `RedactField`
    //（compile-pass 即证）——对标 serde `skip` 字段不走默认 Serialize bound。
    struct NotRedactField; // 故意不 impl RedactField

    #[derive(secure::Redact)]
    #[allow(dead_code)] // fixed/drop 字段取 Absent、不被读取
    struct CustomFixedDrop {
        #[redact(secret, mode = "fixed")]
        a: NotRedactField,
        #[redact(secret, mode = "drop")]
        b: NotRedactField,
    }

    #[test]
    fn derive_fixed_drop_needs_no_redact_field_bound() {
        let v = CustomFixedDrop {
            a: NotRedactField,
            b: NotRedactField,
        };
        // a: Fixed → <redacted>；b: Drop → 剔除；NotRedactField 无 RedactField impl。
        assert_eq!(format!("{v:?}"), "CustomFixedDrop { a: <redacted> }");
    }

    #[test]
    fn derive_newtype_debug_is_opaque() {
        let v = DerivedNewtype(vec![0xDE, 0xAD]);
        assert_eq!(format!("{v:?}"), "DerivedNewtype(<redacted>)");
    }

    #[test]
    fn derive_mixed_debug_applies_per_field_policy() {
        let v = DerivedMixed {
            visible: "ok".to_string(),
            secret: "topsecret".to_string(),
            card: "4242424242424242".to_string(),
            email: "alice@example.com".to_string(),
            gone: "vanish".to_string(),
        };
        let dbg = format!("{v:?}");
        // Show 字段 `visible` 经 Debug-转义（#1360 F3）：`ok` → `"ok"`；其余 mode 产物不转义。
        assert_eq!(
            dbg,
            "DerivedMixed { visible: \"ok\", secret: <redacted>, card: ****4242, email: a***@example.com }"
        );
        assert!(!dbg.contains("topsecret"));
        assert!(!dbg.contains("vanish"));
        assert!(!dbg.contains("gone"));
    }

    #[test]
    fn derive_impls_redact_trait() {
        // 派生实现 trait `Redact::redact_scoped`（Debug 委托它）；返回脱敏 String（非 Redacted，#1360 F1）。
        let v = DerivedNewtype(vec![1]);
        let r: String = secure::Redact::redact_scoped(&v, RedactScope::ServerLog);
        assert_eq!(r, "DerivedNewtype(<redacted>)");
    }

    // --- secure::safe + RedactScope（#1361 字段级输出 funnel + 输出通道）---

    #[test]
    fn safe_serverlog_eq_debug() {
        // ServerLog scope = 派生 Debug 默认（同源，零第二份脱敏逻辑）。
        let v = DerivedMixed {
            visible: "ok".to_string(),
            secret: "topsecret".to_string(),
            card: "4242424242424242".to_string(),
            email: "alice@example.com".to_string(),
            gone: "vanish".to_string(),
        };
        assert_eq!(safe(&v, RedactScope::ServerLog), format!("{v:?}"));
    }

    #[test]
    fn safe_wire_collapses_partial_reveal_to_fixed() {
        // Wire scope：pii 部分泄露 mode（email_mask / last4）塌缩 Fixed，不向外部 sink 部分泄露；
        // ServerLog 保留掩码诊断。secret 两 scope 均 Fixed；public(show) 两 scope 均原样。
        let v = DerivedMixed {
            visible: "ok".to_string(),
            secret: "topsecret".to_string(),
            card: "4242424242424242".to_string(),
            email: "alice@example.com".to_string(),
            gone: "vanish".to_string(),
        };
        let server = safe(&v, RedactScope::ServerLog);
        let wire = safe(&v, RedactScope::Wire);
        // ServerLog：掩码可见（诊断）。
        assert!(server.contains("card: ****4242"), "server={server}");
        assert!(
            server.contains("email: a***@example.com"),
            "server={server}"
        );
        // Wire：部分泄露塌缩 Fixed，原值 / 掩码片段一律不泄漏。
        assert!(wire.contains("card: <redacted>"), "wire={wire}");
        assert!(wire.contains("email: <redacted>"), "wire={wire}");
        assert!(!wire.contains("4242"), "wire 不得含卡号尾段: {wire}");
        assert!(!wire.contains("@example.com"), "wire 不得含邮箱域: {wire}");
        // 两 scope 均不泄漏全量 secret / 原始邮箱；public(show) 两 scope 均原样。
        for s in [&server, &wire] {
            assert!(s.contains("secret: <redacted>"), "{s}");
            assert!(!s.contains("topsecret"), "{s}");
            assert!(!s.contains("alice@example.com"), "{s}");
            assert!(s.contains("visible: \"ok\""), "{s}");
        }
        // anti-vacuity：含 pii 字段时两 scope 输出必须不同。
        assert_ne!(server, wire);
    }

    #[test]
    fn safe_works_on_unsized_dyn_redact() {
        let v = DerivedNewtype(vec![0xAB]);
        let r: &dyn super::Redact = &v;
        assert_eq!(safe(r, RedactScope::Wire), "DerivedNewtype(<redacted>)");
    }

    #[test]
    fn redact_struct_wire_collapses_partial_reveal() {
        // 直调 redact_struct 验证 Wire scope 塌缩部分泄露 mode（不经派生路径）；REDACT-WIRE-COLLAPSE-01。
        let fields = [
            FieldRedaction {
                name: Some("card"),
                mode: RedactionMode::Last4,
                value: RedactValue::Str("4242424242424242"),
            },
            FieldRedaction {
                name: Some("email"),
                mode: RedactionMode::EmailMask,
                value: RedactValue::Str("alice@example.com"),
            },
        ];
        let server = redact_struct("T", false, RedactScope::ServerLog, &fields);
        let wire = redact_struct("T", false, RedactScope::Wire, &fields);
        assert_eq!(server, "T { card: ****4242, email: a***@example.com }");
        assert_eq!(wire, "T { card: <redacted>, email: <redacted> }");
        assert_ne!(
            server, wire,
            "anti-vacuity：含部分泄露字段时两 scope 必不同"
        );
    }

    // --- LastError（#1361 持久化 last_error 脱敏安全载体）---

    #[test]
    fn last_error_from_error_top_level_only_not_source_chain() {
        // source 链（可能含第三方 DSN/PII）不进 last_error，只取顶层 Display。
        let e = WrappedError {
            msg: "reconcile failed".to_string(),
            cause: SimpleError("postgres://u:p@db/app connect refused".to_string()),
        };
        let le = LastError::from_error(&e);
        assert_eq!(le.as_str(), "reconcile failed");
        assert!(!le.as_str().contains("postgres://"));
        assert!(!le.as_str().contains("u:p"));
        // Display / Debug 输出已脱敏内容。
        assert_eq!(le.to_string(), "reconcile failed");
        assert_eq!(format!("{le:?}"), "LastError(reconcile failed)");
    }

    #[test]
    fn last_error_from_redactable_applies_field_policy() {
        // 带字段策略的值经 from_redactable + scope 渲染——Wire 塌缩 pii，原始邮箱不入 last_error。
        let v = DerivedMixed {
            visible: "ctx".to_string(),
            secret: "topsecret".to_string(),
            card: "4242424242424242".to_string(),
            email: "alice@example.com".to_string(),
            gone: "vanish".to_string(),
        };
        let le = LastError::from_redactable(&v, RedactScope::Wire);
        assert!(!le.as_str().contains("alice@example.com"));
        assert!(!le.as_str().contains("topsecret"));
        assert!(le.as_str().contains("email: <redacted>"));
    }

    #[test]
    fn redact_error_strips_inline_dsn_in_top_level_display() {
        // #1361 F2 belt-and-suspenders：顶层 Display 内联 DSN 凭据经 redact_error 自动剥（无需调用方手动清洗）。
        let e =
            SimpleError("connect postgres://svc:s3cr3t@db.internal:5432/app refused".to_string());
        let r = redact_error(&e);
        assert!(
            !r.as_str().contains("s3cr3t"),
            "DSN 凭据应被剥: {}",
            r.as_str()
        );
        assert!(
            r.as_str()
                .contains("postgres://<redacted>@db.internal:5432/app")
        );
    }

    #[test]
    fn last_error_from_error_strips_inline_dsn() {
        // LastError::from_error 经 redact_error（含 URL-cred 剥离）⇒ 顶层 Display 的 DSN 凭据不入 last_error。
        let e = SimpleError("pool create failed: postgres://svc:s3cr3t@db/app".to_string());
        let le = LastError::from_error(&e);
        assert!(!le.as_str().contains("s3cr3t"), "le={}", le.as_str());
        assert!(le.as_str().contains("<redacted>@db/app"));
    }

    // --- redact_url_credentials（AMQP / DSN 内联凭据脱敏）---

    #[rstest]
    #[case(
        "amqp://user:pass@host:5672/%2fvhost",
        "amqp://<redacted>@host:5672/%2fvhost"
    )]
    #[case("amqps://alice@broker/vh", "amqps://<redacted>@broker/vh")]
    #[case("amqp://host:5672/", "amqp://host:5672/")]
    #[case("amqp://u:p@host:5672", "amqp://<redacted>@host:5672")]
    #[case("amqp://host/p@th", "amqp://host/p@th")]
    #[case("not-a-url", "not-a-url")]
    #[case("amqp://host/vh?x=a@b", "amqp://host/vh?x=a@b")]
    #[case("amqp://host/vh#frag@ment", "amqp://host/vh#frag@ment")]
    #[case(
        "amqp://user:pass@[::1]:5672/vhost",
        "amqp://<redacted>@[::1]:5672/vhost"
    )]
    fn redact_url_credentials_strips_userinfo(#[case] input: &str, #[case] want: &str) {
        let r = redact_url_credentials(input);
        assert_eq!(r.as_str(), want);
        assert!(!r.as_str().contains("user:pass"));
    }
}
