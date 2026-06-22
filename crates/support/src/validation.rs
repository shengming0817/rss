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
pub fn non_empty(_value: &str) -> Result<(), ValidationError> {
    todo!()
}

/// 校验最大长度。
pub fn max_len(_value: &str, _max: usize) -> Result<(), ValidationError> {
    todo!()
}
