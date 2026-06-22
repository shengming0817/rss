//! HTTP 杂项 helper。

/// Bearer 解析错误。区分缺失 / 错误 scheme / 空 token / 畸形 header——
/// 不把四类折叠成同一 `None`，wire 层据此统一映射 401（不泄露 token）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BearerParseError {
    #[error("authorization header missing or not bearer scheme")]
    NotBearer,
    #[error("bearer token is empty")]
    EmptyToken,
    #[error("authorization header is malformed")]
    Malformed,
}

/// 从 `Authorization` header 取 Bearer token（不含 "Bearer " 前缀）。
/// 缺凭证 / 错误 scheme / 空 token / 畸形 header 返回 typed [`BearerParseError`]，
/// 由调用方区分处理；wire 层统一映射 401（不回显 token）。
pub fn parse_bearer(header: &str) -> Result<&str, BearerParseError> {
    // RFC 7235 §2.1：token68 前缀 "Bearer "（scheme 不区分大小写）
    const PREFIX: &str = "Bearer ";
    if !header
        .get(..PREFIX.len())
        .is_some_and(|s| s.eq_ignore_ascii_case(PREFIX))
    {
        return Err(BearerParseError::NotBearer);
    }
    // 仅去 OWS（SP/HTAB，RFC 7230）；**不** trim CR/LF——否则尾部 CRLF 被静默吞掉、漏检注入。
    let token = header[PREFIX.len()..].trim_matches([' ', '\t']);
    if token.is_empty() {
        return Err(BearerParseError::EmptyToken);
    }
    // token68 字符集（RFC 7235 §2.1）：ALPHA / DIGIT / `-._~+/` + 尾部 `=` padding。
    // 字节级校验拒嵌入空白、CR/LF、非 ASCII 等畸形（防 header 注入 + 解析歧义）。
    if !token.bytes().all(is_token68_byte) {
        return Err(BearerParseError::Malformed);
    }
    Ok(token)
}

/// RFC 7235 token68 合法字节判定。
fn is_token68_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bearer_valid_returns_token() {
        assert_eq!(parse_bearer("Bearer mytoken123"), Ok("mytoken123"));
    }

    #[test]
    fn parse_bearer_valid_trims_trailing_whitespace() {
        assert_eq!(parse_bearer("Bearer   mytoken  "), Ok("mytoken"));
    }

    #[test]
    fn parse_bearer_case_insensitive_scheme() {
        assert_eq!(parse_bearer("bearer mytoken"), Ok("mytoken"));
        assert_eq!(parse_bearer("BEARER mytoken"), Ok("mytoken"));
    }

    #[test]
    fn parse_bearer_wrong_scheme_is_not_bearer() {
        assert!(matches!(
            parse_bearer("Basic dXNlcjpwYXNz"),
            Err(BearerParseError::NotBearer)
        ));
    }

    #[test]
    fn parse_bearer_empty_header_is_not_bearer() {
        assert!(matches!(parse_bearer(""), Err(BearerParseError::NotBearer)));
    }

    #[test]
    fn parse_bearer_empty_token_after_prefix() {
        assert!(matches!(
            parse_bearer("Bearer "),
            Err(BearerParseError::EmptyToken)
        ));
    }

    #[test]
    fn parse_bearer_whitespace_only_token_is_empty() {
        assert!(matches!(
            parse_bearer("Bearer    "),
            Err(BearerParseError::EmptyToken)
        ));
    }

    #[test]
    fn parse_bearer_no_space_after_scheme_is_not_bearer() {
        // "Bearer" 没有空格，不符合 "Bearer " 前缀
        assert!(matches!(
            parse_bearer("Bearertoken"),
            Err(BearerParseError::NotBearer)
        ));
    }

    #[test]
    fn parse_bearer_crlf_injection_is_malformed() {
        assert!(matches!(
            parse_bearer("Bearer ab\r\ncd"),
            Err(BearerParseError::Malformed)
        ));
    }

    #[test]
    fn parse_bearer_trailing_crlf_is_malformed() {
        // 尾部 CRLF 不再被 trim 静默吞掉，按畸形拒。
        assert!(matches!(
            parse_bearer("Bearer mytoken\r\n"),
            Err(BearerParseError::Malformed)
        ));
    }

    #[test]
    fn parse_bearer_embedded_whitespace_is_malformed() {
        // "a b" 含嵌入空格，非 token68。
        assert!(matches!(
            parse_bearer("Bearer ab cd"),
            Err(BearerParseError::Malformed)
        ));
    }

    #[test]
    fn parse_bearer_non_ascii_is_malformed() {
        assert!(matches!(
            parse_bearer("Bearer tøken"),
            Err(BearerParseError::Malformed)
        ));
    }

    #[test]
    fn parse_bearer_jwt_dotted_token_ok() {
        // JWT（base64url + '.' 分隔）是合法 token68。
        assert_eq!(
            parse_bearer("Bearer eyJ.payLOAD-_.sig+/="),
            Ok("eyJ.payLOAD-_.sig+/=")
        );
    }

    #[test]
    fn parse_bearer_valid_simple_token_ok() {
        assert_eq!(parse_bearer("Bearer ok"), Ok("ok"));
    }
}
