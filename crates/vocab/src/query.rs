//! 基础查询上限词汇。分页 token 由 `rss_contract::PageCursor` 拥有；查询数量边界由 [`Limit`] 定义。

/// 分页上限校验错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LimitError {
    #[error("limit exceeds maximum of 500")]
    TooLarge,
}

/// 查询数量上限，合法范围为 0 到 500（含两端）。
///
/// 最大值限制单次查询的请求规模；0 保留给仅计数查询。默认页大小及业务下限由调用方决定。
/// 私有字段保证取值经过 [`Self::new`] 校验。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit(u16);

impl Limit {
    /// 按 [`Limit`] 的范围构造查询上限，超出范围返回 [`LimitError::TooLarge`]。
    pub fn new(value: u16) -> Result<Self, LimitError> {
        if value > 500 {
            Err(LimitError::TooLarge)
        } else {
            Ok(Self(value))
        }
    }

    pub fn get(&self) -> u16 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Limit;

    // --- Limit ---

    #[test]
    fn limit_accepts_zero_and_500() {
        let cases: &[u16] = &[0, 1, 100, 499, 500];
        for &v in cases {
            let result = Limit::new(v);
            assert!(result.is_ok(), "expected Ok for value={v}");
            #[allow(clippy::unwrap_used)]
            let limit = result.unwrap();
            assert_eq!(limit.get(), v);
        }
    }

    #[test]
    fn limit_rejects_above_500() {
        let cases: &[u16] = &[501, 1000, u16::MAX];
        for &v in cases {
            assert!(
                matches!(Limit::new(v), Err(super::LimitError::TooLarge)),
                "expected TooLarge for value={v}"
            );
        }
    }
}
