//! Postgres 杂项 helper（与具体 adapter 无关的纯函数）。

use crate::validation::ValidationError;

/// 校验并转义 SQL 标识符（防注入）。非法标识符返回 `ValidationError`。
pub fn quote_ident(_ident: &str) -> Result<String, ValidationError> {
    todo!()
}
