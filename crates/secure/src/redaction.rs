//! 敏感值脱敏 + 统一脱敏 funnel。
//!
//! span error / tracing sink / last_error 一律经 [`redact_error`] / [`redact_field`]
//! 收口（`docs/rules/observability.md` §redaction）——敏感 key 判定与 free-form scrub 不散落在
//! 各 consumer。`bootstrap::shutdown` 等已把 `secure::redact_error` 当既定接缝引用。

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
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // reason: Display 输出已脱敏内容（funnel 产物，安全可记录）；供 `warn!(error = %redact_error(..))`。
        todo!()
    }
}

impl Redacted {
    /// 由已脱敏字符串构造（受控 funnel）。供 [`Redactor`] 实现方返回脱敏值；
    /// 入参须是脱敏后的安全值，不做反向校验（脱敏在 [`Redactor::redact`] / [`redact_field`] 完成）。
    pub fn new(_redacted: impl Into<String>) -> Self {
        todo!()
    }

    pub fn as_str(&self) -> &str {
        todo!()
    }
}

/// 统一脱敏 funnel：清洗任意 error 的 Display / source 链为可记录的安全摘要。
/// span error / tracing sink / last_error 一律经此（observability.md §redaction），不裸打印 error。
pub fn redact_error(_error: &dyn std::error::Error) -> Redacted {
    todo!()
}

/// 统一脱敏 funnel：按敏感 key 判定清洗单个字段值（敏感 key → 脱敏，否则原样）。
pub fn redact_field(_key: &str, _value: &str) -> Redacted {
    todo!()
}
