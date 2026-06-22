//! 基础查询/分页词汇。`Cursor`/`Limit` 已实现；扩展分页参数按需 additive 添加。limit 上限语义见 rust-standards（≤500）。

use base64::Engine as _;

/// 分页上限校验错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LimitError {
    #[error("limit exceeds maximum of 500")]
    TooLarge,
}

/// 分页游标解析错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CursorError {
    #[error("cursor is malformed")]
    Malformed,
}

/// 分页游标 newtype（私有字段，构造经 fallible funnel）。
///
/// 入站游标是不透明 token，解码可失败——冻结为可失败构造，拒绝畸形游标。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor(String);

impl Cursor {
    /// 解析不透明游标 token；空串或非 base64url（URL_SAFE_NO_PAD）即拒。
    ///
    /// 首页传 `None`，勿调 `parse("")`（空串视为畸形 `Malformed`）。
    pub fn parse(raw: &str) -> Result<Self, CursorError> {
        if raw.is_empty() {
            return Err(CursorError::Malformed);
        }
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(raw)
            .map_err(|_| CursorError::Malformed)?;
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
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
    use super::{Cursor, Limit};
    use base64::Engine as _;

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

    // --- Cursor ---

    #[allow(clippy::unwrap_used)]
    fn encode_url_safe_no_pad(input: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
    }

    #[test]
    fn cursor_accepts_valid_base64url_and_round_trips() {
        let cases: &[&[u8]] = &[b"hello", b"page:42", b"\x00\xff\xfe"];
        for input in cases {
            let encoded = encode_url_safe_no_pad(input);
            let cursor = Cursor::parse(&encoded);
            assert!(cursor.is_ok(), "expected Ok for encoded={encoded:?}");
            #[allow(clippy::unwrap_used)]
            let c = cursor.unwrap();
            assert_eq!(c.as_str(), encoded);
        }
    }

    #[test]
    fn cursor_rejects_empty() {
        assert!(
            matches!(Cursor::parse(""), Err(super::CursorError::Malformed)),
            "expected Malformed for empty cursor"
        );
    }

    #[test]
    fn cursor_rejects_non_base64url() {
        // standard base64 chars that are NOT url-safe: '+', '/'
        // also '=' padding is invalid for URL_SAFE_NO_PAD
        let cases: &[&str] = &[
            "abc+def",     // standard base64, not url-safe
            "abc/def",     // standard base64, not url-safe
            "abc=",        // padding not allowed in NO_PAD
            "not valid!!", // 含特殊字符
            " ",           // 空白
        ];
        for &raw in cases {
            assert!(
                matches!(Cursor::parse(raw), Err(super::CursorError::Malformed)),
                "expected Malformed for raw={raw:?}"
            );
        }
    }
}
