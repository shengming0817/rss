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
pub fn parse_bearer(_header: &str) -> Result<&str, BearerParseError> {
    todo!()
}
