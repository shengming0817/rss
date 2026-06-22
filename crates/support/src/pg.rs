//! Postgres 杂项 helper（与具体 adapter 无关的纯函数）。

use crate::validation::ValidationError;

/// 校验并转义 SQL 标识符（防注入）。非法标识符返回 `ValidationError`。
///
/// 按 PostgreSQL 标准：内部双引号转义为 `""`，整体用双引号包裹。
/// 空标识符返回 [`ValidationError::Empty`]。
pub fn quote_ident(ident: &str) -> Result<String, ValidationError> {
    if ident.is_empty() {
        return Err(ValidationError::Empty);
    }
    // 拒绝 NUL 字节（防 C 层截断绕过注入防护）。
    if ident.contains('\0') {
        return Err(ValidationError::Format);
    }
    Ok(format!("\"{}\"", ident.replace('"', "\"\"")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::unwrap_used)]
    #[test]
    fn quote_ident_simple_identifier() {
        assert_eq!(quote_ident("users").unwrap(), "\"users\"");
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn quote_ident_with_internal_double_quote() {
        // 内部 " 转义为 ""
        assert_eq!(quote_ident("tab\"name").unwrap(), "\"tab\"\"name\"");
    }

    #[test]
    fn quote_ident_empty_returns_empty_error() {
        assert!(matches!(quote_ident(""), Err(ValidationError::Empty)));
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn quote_ident_with_spaces() {
        assert_eq!(quote_ident("my table").unwrap(), "\"my table\"");
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn quote_ident_multiple_double_quotes() {
        assert_eq!(quote_ident("a\"b\"c").unwrap(), "\"a\"\"b\"\"c\"");
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn quote_ident_single_char() {
        assert_eq!(quote_ident("x").unwrap(), "\"x\"");
    }

    #[test]
    fn quote_ident_nul_byte_returns_format_error() {
        assert!(matches!(quote_ident("a\0b"), Err(ValidationError::Format)));
    }

    #[test]
    fn quote_ident_nul_only_returns_format_error() {
        assert!(matches!(quote_ident("\0"), Err(ValidationError::Format)));
    }
}
