//! 敏感值脱敏 + 字段级脱敏策略模型 + 统一脱敏 funnel。
//!
//! 两层能力：
//! - **sink/key funnel**：[`redact_error`]（顶层 `Display`-only）/ [`redact_field`]（按 key 判敏感）/
//!   [`redact_url_credentials`]（剥 URL userinfo）——span error / tracing sink / last_error 一律经此收口
//!   （`docs/rules/observability.md` §redaction），敏感 key 判定与 free-form scrub 不散落各 consumer。
//! - **字段级策略模型**（#1360）：[`Sensitivity`] / [`PiiKind`] / [`RedactionMode`] / [`RedactionCtx`] /
//!   [`Redactable`] + 公开 funnel [`redact_struct`]。配 `#[derive(Redactable)]`（securederive）让任意 struct
//!   字段**显式声明** public / internal / pii / secret 与脱敏模式，派生安全 `Debug`——替换各 crate 手写 `Debug`。
//!
//! `redact_field` 的 key 判敏感逻辑已**单源**进 [`Sensitivity::from_key`]，`Redacted::new` 仍 `pub(crate)`
//! 封闭（外部只经公开 funnel 取 `Redacted`，不可伪造安全值）。

use sha2::{Digest, Sha256};
use std::fmt::Write as _;

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
    /// 注意 [`redact_struct`] / [`Redactable::redact`] / [`RedactionCtx::apply`] 返回**裸 `String`** 而非
    /// `Redacted`（#1360 F1）：它们的 mode 由调用方 / 类型作者选择（含 `Show`），不享「已脱敏安全值」语义，
    /// 故不经本封闭构造口——避免 `Show + 任意明文` 成外部 mint `Redacted` 的旁路。
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
    /// [`Fixed`](Self::Fixed) / [`Last4`](Self::Last4)。`sensitivity` 默认映射从不选 Hash（须显式 `mode = hash`）。
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

    /// 该敏感度的默认脱敏 mode（`sensitivity → mode` 单源映射；`#[derive(Redactable)]` 对只给
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
    /// 缺省字段（`Option::None`）。
    Absent,
}

/// 把字段借出为 [`RedactValue`]。`#[derive(Redactable)]` 经此统一取字段原值，再由 mode 脱敏；
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
    pub fn mask(self, value: RedactValue<'_>) -> String {
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
        // Bytes 即便声明 Show 也不回显原始字节（仅长度供诊断）；Absent → None。
        RedactValue::Bytes(b) => format!("[{} bytes]", b.len()),
        RedactValue::Absent => "None".to_string(),
    }
}

fn mask_last4(value: RedactValue<'_>) -> String {
    let RedactValue::Str(s) = value else {
        return REDACTED_PLACEHOLDER.to_string();
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
    let RedactValue::Str(s) = value else {
        return REDACTED_PLACEHOLDER.to_string();
    };
    // 域名部分原样保留（视为非敏感，见 RedactionMode::EmailMask 文档）；local 仅留首字符。
    match s.split_once('@') {
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
        // 无值可哈希 ⇒ fail-closed 固定占位（不回显 None 暴露缺省）。
        RedactValue::Absent => return REDACTED_PLACEHOLDER.to_string(),
    }
    let digest = hasher.finalize();
    // 截断 HASH_TRUNCATE_BYTES 字节（= 12 hex 字符）：足够关联、不可逆、不回显全摘要。
    let mut hex = String::with_capacity(HASH_TRUNCATE_BYTES * 2);
    for byte in digest.iter().take(HASH_TRUNCATE_BYTES) {
        let _ = write!(hex, "{byte:02x}");
    }
    format!("sha256:{hex}")
}

/// 字段脱敏策略：绑定 [`Sensitivity`] 与最终 [`RedactionMode`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionCtx {
    sensitivity: Sensitivity,
    mode: RedactionMode,
}

impl RedactionCtx {
    /// 由 sensitivity（+可选显式 mode override）构造策略；`mode` 缺省取 [`Sensitivity::default_mode`]。
    pub fn new(sensitivity: Sensitivity, mode: Option<RedactionMode>) -> Self {
        Self {
            sensitivity,
            mode: mode.unwrap_or(sensitivity.default_mode()),
        }
    }

    /// 声明的敏感度。
    pub fn sensitivity(self) -> Sensitivity {
        self.sensitivity
    }

    /// 最终生效的脱敏 mode。
    pub fn mode(self) -> RedactionMode {
        self.mode
    }

    /// 应用策略脱敏字段原值，产出**已脱敏的 `String` 片段**（非 [`Redacted`]）。
    ///
    /// 返回裸 `String` 而非 `Redacted`（#1360 F1）：`RedactionCtx` 的 mode 由调用方选择（含 `Show`），
    /// 若返回 `Redacted` 则外部可经 `apply(Show, Str(明文))` 伪造可 Display 的「安全值」绕开封闭面。
    /// `Redacted` 仅由固定语义的 sink funnel（[`redact_error`]/[`redact_field`]/[`redact_url_credentials`]）
    /// 经 `pub(crate)` [`Redacted::new`] 产出——类型层封闭，外部不可 mint。`String` 无「已脱敏」语义契约，
    /// 仅是 derive Debug 渲染与 key funnel 的内部片段。
    pub fn apply(self, value: RedactValue<'_>) -> String {
        self.mode.mask(value)
    }
}

/// `#[derive(Redactable)]` 为每字段产出的脱敏描述符（字段名 + mode + 字段原值视图）。
#[derive(Debug, Clone, Copy)]
pub struct FieldRedaction<'a> {
    /// `Some("name")`（named 字段）/ `None`（tuple 字段，位置式渲染）。
    pub name: Option<&'static str>,
    /// 该字段的脱敏模式。
    pub mode: RedactionMode,
    /// 字段原值视图（`Fixed`/`Drop` 不读）。
    pub value: RedactValue<'a>,
}

/// 字段级脱敏上游模型：类型声明自身字段策略，产出已脱敏的 `Debug` 渲染 `String`。由 `#[derive(Redactable)]`
/// 实现（生成的 `Debug` 委托 `self.redact()`）。
///
/// 返回 `String` 而非 [`Redacted`]（#1360 F1）：`redact` 是 `Debug` 渲染 helper，非「安全值」产出口——
/// 字段 mode 由类型作者声明（含 `Show`），若返回 `Redacted` 则任意类型经 `Show` 字段即可 mint 可 Display
/// 的 `Redacted`，绕开封闭面。`Redacted` 仅由固定语义 sink funnel 产出（见 [`RedactionCtx::apply`]）。
pub trait Redactable {
    /// 按字段策略脱敏自身，返回 `Debug` 渲染片段。
    fn redact(&self) -> String;
}

/// 字段级脱敏渲染 funnel（`#[derive(Redactable)]` 调用）。对每字段 apply 声明的 mode、按 tuple / named
/// 形态渲染成已脱敏 `String`。`Drop` 字段从输出剔除。
///
/// **返回 `String` 而非 [`Redacted`]（#1360 F1，封闭面收窄）**：本函数须 `pub`（derive 在 diport 等
/// 外部 crate 生成的 `impl Redactable` 调它），且字段 mode 由调用方传入（含 `Show`+任意 `value`）；若返回
/// `Redacted` 则成外部 mint「安全值」的旁路。`Redacted` 改由固定语义 sink funnel 经 `pub(crate)`
/// [`Redacted::new`] 独家产出——类型层封闭，外部不可伪造。
/// 结构化 Debug 上下文的单字段渲染：先按 mode 脱敏，再对 `Show` 字段 Debug-转义（#1360 F3）——
/// Show 字段含换行 / 控制字符时不污染 `Type { f: .. }` 渲染结构（与 derive(Debug) 对 `String` 字段一致）。
/// `Fixed`/`Last4`/`EmailMask`/`Hash`/`Drop` 产物是受控占位 / 掩码片段，不转义（避免给 `<redacted>` 加引号）。
fn render_field(mode: RedactionMode, value: RedactValue<'_>) -> String {
    let masked = mode.mask(value);
    if mode == RedactionMode::Show {
        format!("{masked:?}")
    } else {
        masked
    }
}

pub fn redact_struct(
    type_name: &'static str,
    is_tuple: bool,
    fields: &[FieldRedaction<'_>],
) -> String {
    let rendered: Vec<(Option<&'static str>, String)> = fields
        .iter()
        .filter(|f| f.mode != RedactionMode::Drop)
        .map(|f| (f.name, render_field(f.mode, f.value)))
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
pub fn redact_error(error: &dyn std::error::Error) -> Redacted {
    Redacted::new(error.to_string())
}

/// 统一脱敏 funnel：按敏感 key 判定清洗单个字段值（敏感 key → 脱敏，否则原样）。
///
/// 重构为字段级模型的一行入口（#1360）：key 判敏感经 [`Sensitivity::from_key`] 单源、脱敏经
/// [`RedactionCtx`]——非第二份实现，无双路径。敏感 key → `Secret`→`Fixed`→`<redacted>`；普通 key →
/// `Public`→`Show`→原样。
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

#[cfg(test)]
mod tests {
    use super::{
        FieldRedaction, PiiKind, RedactField, RedactValue, Redacted, RedactionCtx, RedactionMode,
        Sensitivity, redact_error, redact_field, redact_struct, redact_url_credentials,
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
        let ctx = RedactionCtx::new(Sensitivity::Secret, None);
        assert_eq!(ctx.mode(), RedactionMode::Fixed);
        assert_eq!(ctx.sensitivity(), Sensitivity::Secret);
        assert_eq!(ctx.apply(RedactValue::Str("k")).as_str(), "<redacted>");
    }

    #[test]
    fn redaction_ctx_explicit_mode_overrides_default() {
        let ctx = RedactionCtx::new(
            Sensitivity::Pii(PiiKind::Generic),
            Some(RedactionMode::Hash),
        );
        assert_eq!(ctx.mode(), RedactionMode::Hash);
        assert!(
            ctx.apply(RedactValue::Str("x"))
                .as_str()
                .starts_with("sha256:")
        );
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

    // --- redact_struct 渲染 ---

    #[test]
    fn redact_struct_tuple_newtype_render() {
        let r = redact_struct(
            "Ct",
            true,
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
            &[FieldRedaction {
                name: None,
                mode: RedactionMode::Drop,
                value: RedactValue::Str("x"),
            }],
        );
        assert_eq!(r.as_str(), "T");
    }

    // --- #[derive(Redactable)] 端到端（secure 内自用，验证派生 Debug + 多 mode 渲染）---

    #[derive(secure::Redactable)]
    struct DerivedNewtype(#[redact(sensitivity = secret)] Vec<u8>);

    #[derive(secure::Redactable)]
    // `gone`（mode = drop）经 F2 后取 RedactValue::Absent、不被 redact 读取 ⇒ field never read。
    #[allow(dead_code)]
    struct DerivedMixed {
        #[redact(mode = show)]
        visible: String,
        #[redact(sensitivity = secret)]
        secret: String,
        #[redact(mode = last4)]
        card: String,
        #[redact(mode = email_mask)]
        email: String,
        #[redact(mode = drop)]
        gone: String,
    }

    // F2 回归（#1360）：自定义类型字段标显式 `mode = fixed`/`drop` **不要求** impl `RedactField`
    //（compile-pass 即证）——对标 serde `skip` 字段不走默认 Serialize bound。
    struct NotRedactField; // 故意不 impl RedactField

    #[derive(secure::Redactable)]
    #[allow(dead_code)] // fixed/drop 字段取 Absent、不被读取
    struct CustomFixedDrop {
        #[redact(mode = fixed)]
        a: NotRedactField,
        #[redact(mode = drop)]
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
    fn derive_impls_redactable_trait() {
        // 派生同时实现 trait `Redactable`（Debug 委托它）；redact 返回脱敏 String（非 Redacted，#1360 F1）。
        let v = DerivedNewtype(vec![1]);
        let r: String = secure::Redactable::redact(&v);
        assert_eq!(r, "DerivedNewtype(<redacted>)");
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
