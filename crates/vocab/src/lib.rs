//! vocab — RSS 跨域错误词汇 / 契约归属 / 基础授权·租户·查询词汇的单源（基础层，仅 std+外部 crate）。

pub mod authz;
pub mod contract;
pub mod error;
pub mod query;
pub mod tenant;

/// crate-name 形标识符校验：`[a-z][a-z0-9_]*`，整串非空（单一事实源，供 authz / contract 复用）。
pub(crate) fn is_crate_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        None => false,
        Some(first) => {
            first.is_ascii_lowercase()
                && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        }
    }
}

pub use authz::{Action, ActionError, Decision};
pub use contract::owner::{ContractOwner, DomainName, DomainNameError};
pub use error::{CoreError, CoreErrorKind, InternalAttr, PublicDetail};
pub use query::{Cursor, CursorError, Limit, LimitError};
pub use tenant::{
    CrossTenantVisibility, RowScope, RowVisibility, ScopedTenant, TenantId, TenantIdError,
};
