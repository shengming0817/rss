/// A validated identifier for correlating diagnostic events across asynchronous work.
///
/// The value has a private representation and can only be created through [`CorrelationId::parse`].
/// Parsing rejects empty, oversized, and non-ASCII-allowlisted input before it can be copied into
/// headers, logs, or persistent diagnostic metadata.
pub struct CorrelationId(String);

impl CorrelationId {
    /// Maximum accepted identifier length in bytes.
    pub const MAX_LEN: usize = 128;

    /// Parses an identifier using the ASCII allowlist `[A-Za-z0-9._-]`.
    ///
    /// Validation runs in this order: empty, longer than [`Self::MAX_LEN`] bytes, then invalid
    /// characters. The returned error never contains the input value.
    pub fn parse(raw: &str) -> Result<Self, CorrelationIdError> {
        if raw.is_empty() {
            return Err(CorrelationIdError::Empty);
        }
        if raw.len() > Self::MAX_LEN {
            return Err(CorrelationIdError::TooLong);
        }
        if !raw.bytes().all(is_allowed_byte) {
            return Err(CorrelationIdError::InvalidChar);
        }
        Ok(Self(raw.to_string()))
    }

    /// Returns the validated identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[cfg(feature = "task-local")]
    pub(crate) fn snapshot(&self) -> Self {
        Self(self.0.clone())
    }
}

/// 字符集白名单：ASCII 字母数字 + `-` `_` `.`（覆盖 UUID / hex+连字符等 W3C trace/correlation id 常见形态）。
/// 排除空白 / 控制字符 ⇒ 阻断换行注入日志、注入 header 等。
fn is_allowed_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')
}

/// A closed reason why [`CorrelationId::parse`] rejected an input.
#[derive(Debug, thiserror::Error)]
pub enum CorrelationIdError {
    /// The input was empty.
    #[error("correlation id is empty")]
    Empty,
    /// The input exceeded [`CorrelationId::MAX_LEN`] bytes.
    #[error("correlation id exceeds max length")]
    TooLong,
    /// The input contained a character outside `[A-Za-z0-9._-]`.
    #[error("correlation id contains a disallowed character")]
    InvalidChar,
}

/// An owned diagnostic context containing one validated correlation identifier.
///
/// This context carries observability data only. It does not represent identity, tenancy,
/// authentication, authorization, or a security decision.
pub struct DiagnosticCtx {
    correlation: CorrelationId,
}

impl DiagnosticCtx {
    /// Creates a diagnostic context from a validated correlation identifier.
    pub fn new(correlation: CorrelationId) -> Self {
        Self { correlation }
    }

    /// Borrows the context's correlation identifier.
    pub fn correlation(&self) -> &CorrelationId {
        &self.correlation
    }

    #[cfg(feature = "task-local")]
    pub(crate) fn snapshot(&self) -> Self {
        Self::new(self.correlation.snapshot())
    }
}

#[cfg(test)]
mod tests {
    use super::{CorrelationId, CorrelationIdError, DiagnosticCtx};

    // 测试 fixture：构造合法 CorrelationId。item-level carve-out（workspace expect_used=deny）。
    // reason: 仅测试 fixture，输入恒为白名单合法串。
    #[allow(clippy::expect_used)]
    fn corr(raw: &str) -> CorrelationId {
        CorrelationId::parse(raw).expect("test fixture must be a valid correlation id")
    }

    #[test]
    fn parse_accepts_valid_ids() {
        for raw in ["abc-123", "9f8e7d6c", "trace.id_42", "A1B2"] {
            assert_eq!(corr(raw).as_str(), raw);
        }
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(matches!(
            CorrelationId::parse(""),
            Err(CorrelationIdError::Empty)
        ));
    }

    #[test]
    fn parse_rejects_too_long() {
        let long = "a".repeat(CorrelationId::MAX_LEN + 1);
        assert!(matches!(
            CorrelationId::parse(&long),
            Err(CorrelationIdError::TooLong)
        ));
        // 边界：恰好 MAX 长度合法（anti-vacuity，证明拒绝不是恒真）。
        let at_max = "a".repeat(CorrelationId::MAX_LEN);
        assert!(CorrelationId::parse(&at_max).is_ok());
    }

    #[test]
    fn parse_rejects_injection_chars() {
        // 换行 / 空格 / 控制字符 / 引号 / 零宽——log / header / json 注入向量，必须拒。
        for raw in [
            "bad id",
            "line\nbreak",
            "tab\tx",
            "quote\"x",
            "semi;col",
            "uni\u{200b}code",
        ] {
            assert!(
                matches!(
                    CorrelationId::parse(raw),
                    Err(CorrelationIdError::InvalidChar)
                ),
                "应拒注入字符: {raw:?}"
            );
        }
    }

    #[test]
    fn parse_errors_never_echo_raw_input_and_length_precedes_charset() {
        let raw = format!("{}\nprivate", "x".repeat(CorrelationId::MAX_LEN));
        let error = CorrelationId::parse(&raw).err();
        assert!(matches!(error, Some(CorrelationIdError::TooLong)));
        let rendered = error.map(|error| error.to_string()).unwrap_or_default();
        assert!(!rendered.contains("private"));
        assert!(!rendered.contains('\n'));
    }

    #[test]
    fn public_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CorrelationId>();
        assert_send_sync::<CorrelationIdError>();
        assert_send_sync::<DiagnosticCtx>();
    }

    #[test]
    fn diagnostic_ctx_borrows_correlation() {
        let ctx = DiagnosticCtx::new(corr("corr-1"));
        assert_eq!(ctx.correlation().as_str(), "corr-1");
    }
}
