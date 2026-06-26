//! Cookie 编解码接缝。

/// Cookie 编解码器（sync）。
pub trait CookieCodec {
    /// 编码为线格字符串。
    fn encode(&self, value: &CookieValue) -> String;
    /// 解码并校验。
    fn decode(&self, raw: &str) -> Result<CookieValue, CookieError>;
}

/// Cookie 值（私有字段）。`Debug` 经 `#[derive(Redactable)]` 字段级脱敏（渲染 `CookieValue(<redacted>)`），
/// 替换手写 impl（#1360）。
#[derive(Clone, PartialEq, Eq, secure::Redactable)]
pub struct CookieValue(#[redact(sensitivity = secret)] String);

impl CookieValue {
    /// 解析 cookie 值；拒绝空值 / 非法字符。
    /// 与 codec 的 [`CookieError`] 区分：此为值构造 grammar 错误，非签名/解码错误。
    ///
    /// 合法字符集遵循 RFC 6265 cookie-octet：US-ASCII 可见字符，排除控制字符、空格、双引号、
    /// 逗号、分号、反斜杠。
    pub fn parse(raw: &str) -> Result<Self, CookieValueError> {
        if raw.is_empty() {
            return Err(CookieValueError::Empty);
        }
        // 字节级 RFC 6265 cookie-octet 校验：US-ASCII 可见范围。自动排除控制字符、空格、DQUOTE、
        // 逗号、分号、反斜杠、DEL，以及**所有非 ASCII**（多字节 UTF-8 首/续字节均 ≥0x80 → 拒）。
        if !raw.bytes().all(is_cookie_octet) {
            return Err(CookieValueError::Format);
        }
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// RFC 6265 cookie-octet 合法字节判定：`%x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E`。
fn is_cookie_octet(b: u8) -> bool {
    matches!(b, 0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E)
}

#[cfg(test)]
mod tests {
    use super::{CookieValue, CookieValueError};

    // item-level carve-out：测试辅助断言结果，expect/unwrap_err 在此是意图清晰的 programmer-error
    // 信号（error-handling.md §Carve-out / workspace 测试模块 #[allow] 约定）。
    #[allow(clippy::expect_used)]
    #[test]
    fn accepts_valid_value() {
        let v = CookieValue::parse("session_abc123").expect("valid");
        assert_eq!(v.as_str(), "session_abc123");
    }

    #[allow(clippy::expect_used)]
    #[test]
    fn debug_redacts_content() {
        // #[derive(Redactable)] 派生 Debug 脱敏（#1360）：原值不经 `{:?}` 泄漏。
        let v = CookieValue::parse("session_abc123").expect("valid");
        let dbg = format!("{v:?}");
        assert_eq!(dbg, "CookieValue(<redacted>)");
        assert!(
            !dbg.contains("session_abc123"),
            "Debug 泄漏 cookie 值: {dbg}"
        );
    }

    #[allow(clippy::expect_used)]
    #[test]
    fn accepts_alphanumeric_with_hyphen() {
        let v = CookieValue::parse("tok-XYZ").expect("valid");
        assert_eq!(v.as_str(), "tok-XYZ");
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn rejects_empty() {
        let err = CookieValue::parse("").unwrap_err();
        assert!(matches!(err, CookieValueError::Empty));
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn rejects_semicolon() {
        let err = CookieValue::parse("val;ue").unwrap_err();
        assert!(matches!(err, CookieValueError::Format));
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn rejects_comma() {
        let err = CookieValue::parse("val,ue").unwrap_err();
        assert!(matches!(err, CookieValueError::Format));
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn rejects_control_character() {
        let err = CookieValue::parse("val\x00ue").unwrap_err();
        assert!(matches!(err, CookieValueError::Format));
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn rejects_whitespace() {
        let err = CookieValue::parse("val ue").unwrap_err();
        assert!(matches!(err, CookieValueError::Format));
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn rejects_tab() {
        let err = CookieValue::parse("val\tue").unwrap_err();
        assert!(matches!(err, CookieValueError::Format));
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn rejects_double_quote() {
        let err = CookieValue::parse("val\"ue").unwrap_err();
        assert!(matches!(err, CookieValueError::Format));
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn rejects_backslash() {
        let err = CookieValue::parse("val\\ue").unwrap_err();
        assert!(matches!(err, CookieValueError::Format));
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn rejects_non_ascii() {
        // 字节级 cookie-octet 拒非 ASCII（如 'é' = U+00E9，UTF-8 字节 ≥0x80）。
        let err = CookieValue::parse("valué").unwrap_err();
        assert!(matches!(err, CookieValueError::Format));
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn rejects_del_and_high_control() {
        let err = CookieValue::parse("val\x7fue").unwrap_err();
        assert!(matches!(err, CookieValueError::Format));
    }
}

/// `CookieValue` 解析错误（值构造 grammar，区别于 codec 的 [`CookieError`]）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CookieValueError {
    #[error("cookie value is empty")]
    Empty,
    #[error("cookie value has invalid format")]
    Format,
}

/// Cookie 错误词汇。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CookieError {
    #[error("cookie signature invalid")]
    Signature,
    #[error("cookie malformed")]
    Malformed,
}
