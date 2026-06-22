//! Cookie 编解码接缝。

/// Cookie 编解码器（sync）。
pub trait CookieCodec {
    /// 编码为线格字符串。
    fn encode(&self, value: &CookieValue) -> String;
    /// 解码并校验。
    fn decode(&self, raw: &str) -> Result<CookieValue, CookieError>;
}

/// Cookie 值（私有字段）。
#[derive(Clone, PartialEq, Eq)]
pub struct CookieValue(String);

impl std::fmt::Debug for CookieValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CookieValue(<redacted>)")
    }
}

impl CookieValue {
    /// 解析 cookie 值；拒绝空值 / 非法字符（校验在行为 PR 兑现）。
    /// 与 codec 的 [`CookieError`] 区分：此为值构造 grammar 错误，非签名/解码错误。
    pub fn parse(_raw: &str) -> Result<Self, CookieValueError> {
        todo!()
    }
    pub fn as_str(&self) -> &str {
        todo!()
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
