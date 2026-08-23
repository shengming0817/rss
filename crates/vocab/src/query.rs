//! 基础查询上限词汇。分页 token 由 `rss_contract::PageCursor` 拥有。limit 上限语义见 rust-standards（≤500）。

/// 分页上限校验错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LimitError {
    #[error("limit exceeds maximum of 500")]
    TooLarge,
}

/// 分页上限 newtype（私有字段，构造时校验 ≤500）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit(u16);

impl Limit {
    /// 构造，上限 500（超出拒绝）。
    // reason: limit=0 合法（count-only 查询）；默认页大小与下限由调用方/handler 决定。
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
