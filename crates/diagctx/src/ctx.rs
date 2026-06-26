//! [`DiagnosticCtx`] 值类型 + [`CorrelationId`] newtype。
//!
//! 诊断 ID（correlation 等）是**可观测信号**，非授权控制流值——故归本 crate（与 `runctx` 物理隔离），
//! 失败语义 fail-open（缺失 = 省略，见 [`crate::local`]），与 `runctx` 的 fail-closed 刻意相反。

/// correlation id 最大长度——防 attacker-controlled 入站 `X-Correlation-ID` 撑爆持久 metadata / 日志。
pub const MAX_CORRELATION_ID_LEN: usize = 128;

/// 跨服务关联 ID newtype——funnel（私有字段 + 单一受控构造入口 [`CorrelationId::parse`]）。
///
/// 入站 `X-Correlation-ID` 是 attacker-controlled 且会落进持久 `outbox.metadata` + tracing span / 日志：
/// [`CorrelationId::parse`] 强制非空 + 长度上限（[`MAX_CORRELATION_ID_LEN`]）+ 字符集白名单
/// （`[A-Za-z0-9._-]`），把 log / header / metadata 注入从构造面挡掉（安全控制，非洁癖）。
/// 诊断 ID 非凭据（对齐 `request_id` / `TenantId` 可观测约定），`Debug` 有意可见、不脱敏。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationId(String);

impl CorrelationId {
    /// 校验并构造 correlation id。fail-closed 拒空 / 超长 / 非白名单字符（防注入）。
    pub fn parse(raw: &str) -> Result<Self, CorrelationIdError> {
        if raw.is_empty() {
            return Err(CorrelationIdError::Empty);
        }
        if raw.len() > MAX_CORRELATION_ID_LEN {
            return Err(CorrelationIdError::TooLong);
        }
        if !raw.bytes().all(is_allowed_byte) {
            return Err(CorrelationIdError::InvalidChar);
        }
        Ok(Self(raw.to_string()))
    }

    /// 借出底层标识。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 字符集白名单：ASCII 字母数字 + `-` `_` `.`（覆盖 UUID / hex+连字符等 W3C trace/correlation id 常见形态）。
/// 排除空白 / 控制字符 ⇒ 阻断换行注入日志、注入 header 等。
fn is_allowed_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')
}

/// [`CorrelationId::parse`] 失败原因。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CorrelationIdError {
    /// 空串。
    #[error("correlation id is empty")]
    Empty,
    /// 超过 [`MAX_CORRELATION_ID_LEN`]。
    #[error("correlation id exceeds max length")]
    TooLong,
    /// 含非白名单字符（注入防护）。
    #[error("correlation id contains a disallowed character")]
    InvalidChar,
}

/// 请求级**诊断** context——当前仅承载 correlation；trace / cell / request 为后续扩展槽
/// （trace 待 OTel #1076、principal 待安全决策）。不被任何授权闸门读取（ADR-002 §D1-bis）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticCtx {
    correlation: CorrelationId,
}

impl DiagnosticCtx {
    /// 由 correlation 构造诊断 context。
    pub fn new(correlation: CorrelationId) -> Self {
        Self { correlation }
    }

    /// 借出 correlation。
    pub fn correlation(&self) -> &CorrelationId {
        &self.correlation
    }
}

#[cfg(test)]
mod tests {
    use super::{CorrelationId, CorrelationIdError, DiagnosticCtx, MAX_CORRELATION_ID_LEN};

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
        assert_eq!(CorrelationId::parse(""), Err(CorrelationIdError::Empty));
    }

    #[test]
    fn parse_rejects_too_long() {
        let long = "a".repeat(MAX_CORRELATION_ID_LEN + 1);
        assert_eq!(
            CorrelationId::parse(&long),
            Err(CorrelationIdError::TooLong)
        );
        // 边界：恰好 MAX 长度合法（anti-vacuity，证明拒绝不是恒真）。
        let at_max = "a".repeat(MAX_CORRELATION_ID_LEN);
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
            assert_eq!(
                CorrelationId::parse(raw),
                Err(CorrelationIdError::InvalidChar),
                "应拒注入字符: {raw:?}"
            );
        }
    }

    #[test]
    fn debug_is_visible_not_redacted() {
        // 诊断 ID 非凭据，Debug 有意可见（对齐 request_id / TenantId）。
        assert!(format!("{:?}", corr("corr-visible-42")).contains("corr-visible-42"));
    }

    #[test]
    fn diagnostic_ctx_borrows_correlation() {
        let id = corr("corr-1");
        let ctx = DiagnosticCtx::new(id.clone());
        assert_eq!(ctx.correlation(), &id);
    }
}
