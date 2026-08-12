//! vocab — RSS 跨域错误词汇 / 契约归属 / 基础授权·租户·查询词汇 / 分布式协调原语（[`Epoch`] fencing token）
//! 的单源（基础层，仅 std+外部 crate）。

pub mod authz;
pub mod contract;
mod digest;
pub mod epoch;
pub mod error;
pub mod http;
pub mod projection;
pub mod query;
pub mod service;
pub mod tenant;
pub mod time;

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

pub use authz::{
    Action, ActionError, Decision, GrantPermission, POLICY_MANAGE_PERMISSION_PREFIX,
    PermissionParseError, RoutePermissionId,
};
pub use contract::binding::{
    ContractBinding, EventFactBinding, ProjectionInputBinding, SagaBackoff, SagaContractBinding,
    SagaJitter, SagaRetryClass, SagaRuntimePolicySpec, SagaStepBinding,
};
pub use contract::owner::{DomainName, DomainNameError};
pub use contract::step::{StepName, StepNameError};
pub use digest::{CanonicalSha256Digest, CanonicalSha256DigestError};
pub use epoch::Epoch;
pub use error::{CoreError, CoreErrorKind, InternalAttr, PublicDetail};
pub use http::{
    HttpConsistencyLevel, HttpContractOwner, HttpEffectKind, HttpEffectProfile, HttpIdempotency,
    HttpRouteAuth, HttpRouteBinding, HttpRouteEvidence, HttpSuccessStatus, LocalTxBoundary,
    LocalTxCommitUnknown, LocalTxModel, LocalTxRetry,
};
pub use projection::{
    AUDIT_ACTOR_FIELD_OBLIGATION, AUDIT_FIELD_ACTOR_PERMISSION, AUDIT_FIELD_RESOURCE_ID_PERMISSION,
    AUDIT_FIELD_TENANT_ID_PERMISSION, AUDIT_READ_PERMISSION, AUDIT_RESOURCE_ID_FIELD_OBLIGATION,
    AUDIT_TENANT_ID_FIELD_OBLIGATION, IDENTITY_PROFILE_FIELD_SUBJECT_PERMISSION,
    IDENTITY_PROFILE_FIELD_TENANT_ID_PERMISSION, IDENTITY_PROFILE_SUBJECT_FIELD_OBLIGATION,
    IDENTITY_PROFILE_TENANT_ID_FIELD_OBLIGATION, ProjectionField,
};
pub use query::{Cursor, CursorError, Limit, LimitError};
pub use service::ServiceCallerDomain;
pub use tenant::{CrossTenantVisibility, RowVisibility, VisibilityScope};
pub use time::{UnixEpochSeconds, UnixEpochSecondsError};

/// Closed policy for effects outside a durable ConsumerTx database transaction.
///
/// This vocabulary is shared by generated subscription metadata, bootstrap registration, and the
/// runtime executor bridge. Keeping one type makes policy drift a type error instead of requiring
/// conversions between parallel enums.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExternalEffectPolicy {
    /// Handler effects are limited to the ConsumerTx database transaction.
    TransactionalOnly,
    /// External calls use a stable idempotency key.
    IdempotencyKey,
    /// External state converges from an authoritative source.
    Reconcile,
    /// External effects have a durable compensation path.
    Compensated,
}
