//! vocab — RSS 跨域错误词汇 / 契约归属 / 基础授权·租户·查询词汇 / 分布式协调原语（[`Epoch`] fencing token）
//! 的单源（基础层，仅 std+外部 crate）。

pub mod authz;
pub mod contract;
mod digest;
pub mod epoch;
pub mod error;
pub mod http;
pub mod query;
pub mod service;

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

pub use authz::{PermissionParseError, RoutePermissionId};
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
pub use query::{Limit, LimitError};
pub use service::ServiceCallerDomain;

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
