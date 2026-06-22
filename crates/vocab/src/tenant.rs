//! 租户词汇。TenantId 归 vocab（ADR-002 D3）。

/// `TenantId` 解析错误。空值 / nil UUID / 非 canonical UUID 均非法（`docs/rules/tenancy.md` fail-closed）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TenantIdError {
    #[error("tenant id is empty")]
    Empty,
    #[error("tenant id is nil uuid")]
    Nil,
    #[error("tenant id is not a canonical uuid")]
    Format,
}

/// 租户标识 newtype（私有字段，canonical UUID 背书；构造经 fallible funnel）。
///
/// 隔离域边界类型——空值与 nil UUID 非法、非空必须 canonical UUID（`docs/rules/tenancy.md`）。
/// 用 UUID 内部表示让「非 canonical 租户」从类型层不可表达；不提供 infallible 构造入口。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TenantId(uuid::Uuid);

impl TenantId {
    /// 解析 canonical UUID 字符串；拒绝 empty / nil / 非 canonical（fail-closed）。
    pub fn parse(_raw: &str) -> Result<Self, TenantIdError> {
        todo!()
    }

    /// 取底层 uuid。
    pub fn as_uuid(&self) -> uuid::Uuid {
        todo!()
    }
}
