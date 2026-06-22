//! 通用校验 helper + 错误词汇。

/// 校验错误词汇（message const literal）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ValidationError {
    #[error("value is empty")]
    Empty,
    #[error("value exceeds maximum length")]
    TooLong,
    #[error("value has invalid format")]
    Format,
}

/// 校验非空。
pub fn non_empty(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        Err(ValidationError::Empty)
    } else {
        Ok(())
    }
}

/// 校验最大长度（字节数）。
pub fn max_len(value: &str, max: usize) -> Result<(), ValidationError> {
    if value.len() > max {
        Err(ValidationError::TooLong)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // non_empty
    #[test]
    fn non_empty_empty_string_is_err() {
        assert!(matches!(non_empty(""), Err(ValidationError::Empty)));
    }

    #[test]
    fn non_empty_nonempty_string_is_ok() {
        assert!(non_empty("a").is_ok());
        assert!(non_empty("hello world").is_ok());
    }

    // max_len
    #[test]
    fn max_len_within_limit_is_ok() {
        assert!(max_len("abc", 3).is_ok());
        assert!(max_len("abc", 10).is_ok());
    }

    #[test]
    fn max_len_exactly_at_limit_is_ok() {
        assert!(max_len("abc", 3).is_ok());
    }

    #[test]
    fn max_len_exceeds_limit_is_err() {
        assert!(matches!(max_len("abcd", 3), Err(ValidationError::TooLong)));
    }

    #[test]
    fn max_len_empty_string_is_ok() {
        assert!(max_len("", 0).is_ok());
        assert!(max_len("", 5).is_ok());
    }

    #[test]
    fn max_len_zero_limit_nonempty_is_err() {
        assert!(matches!(max_len("a", 0), Err(ValidationError::TooLong)));
    }
}
