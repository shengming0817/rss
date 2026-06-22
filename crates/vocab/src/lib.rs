//! vocab — RSS 跨域错误词汇 / 契约归属 / 基础授权·租户·查询词汇的单源（基础层，仅 std+外部 crate）。

pub mod authz;
pub mod contract;
pub mod error;
pub mod query;
pub mod tenant;

pub use authz::{Action, ActionError, Decision};
pub use contract::owner::{ContractOwner, DomainName, DomainNameError};
pub use error::{CoreError, CoreErrorKind, InternalAttr, PublicDetail};
pub use query::{Cursor, CursorError, Limit, LimitError};
pub use tenant::{TenantId, TenantIdError};
