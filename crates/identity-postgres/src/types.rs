use rss_identity_core::account::{AccountKey, AccountState, PasswordError};
use rss_transactional_messaging::policy::OperationDeadline;
use std::time::Instant;
use uuid::Uuid;

/// Internal password verification evidence.
pub(crate) struct AuthenticationCandidate {
    pub(crate) binding: rss_transactional_messaging::fence::ExecutionBinding,
    pub(crate) state: AccountState,
    pub(crate) authority: Uuid,
    pub(crate) expires: Instant,
    pub(crate) authenticated_at: i64,
}
impl AuthenticationCandidate {
    pub fn account(&self) -> AccountKey {
        self.state.key()
    }
}
impl std::fmt::Debug for AuthenticationCandidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthenticationCandidate(<private>)")
    }
}
/// Trusted adapter attribution. Network adapters must derive this from the transport, not headers.
#[derive(Clone)]
pub struct AttemptSource(String);
impl AttemptSource {
    pub fn parse(value: &str) -> Result<Self, AuthorityError> {
        if value.is_empty()
            || value.len() > 255
            || !value.is_ascii()
            || value.chars().any(char::is_control)
        {
            return Err(AuthorityError::InvalidInput);
        }
        Ok(Self(value.into()))
    }
    pub(crate) fn value(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityError {
    #[error("account cursor invalidated")]
    CursorInvalidated,
    #[error("user interaction required")]
    InteractionRequired,
    #[error("authentication cancelled")]
    Cancelled,
    #[error("invalid authority configuration")]
    Configuration,
    #[error("profile receipt capacity reached")]
    ProfileReceiptCapacityReached,
    #[error("profile operation expired")]
    ProfileOperationExpired,
    #[error("profile revision conflict")]
    RevisionConflict,
    #[error("operation identifier reused with different input")]
    OperationConflict,
    #[error("invalid operation input")]
    InvalidInput,
    #[error("operation deadline elapsed")]
    DeadlineElapsed,
    #[error(transparent)]
    Federation(#[from] rss_identity_core::federation::FederationError),
    #[error("authentication or operation rejected")]
    Rejected,
    #[error("current password rejected")]
    ReauthenticationFailed,
    #[error("transaction rolled back: {0}")]
    RuleRejected(rss_identity_core::account::AccountRuleError),
    #[error("attempt budget exhausted")]
    RateLimited {
        retry_after_seconds: std::num::NonZeroU32,
    },
    #[error("password computation capacity exhausted")]
    Busy,
    #[error("authority unavailable")]
    Unavailable,
    #[error("incompatible Identity storage: {0}")]
    StorageIncompatible(StorageMismatch),
    #[error("transaction not started ({0})")]
    NotStarted(StorageFailure),
    #[error("transaction rolled back ({0})")]
    RolledBack(StorageFailure),
    #[error("rollback not confirmed ({0})")]
    RollbackFailed(StorageFailure),
    #[error("commit not confirmed ({0})")]
    CommitUnknown(StorageFailure),
    #[error("execution fenced")]
    Fenced,
}
/// Non-secret deployment diagnostics, independent of provider/SQL error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StorageMismatch {
    #[error("authentication instance mismatch")]
    DeploymentIdentity,
    #[error("unsupported authentication schema version")]
    SchemaVersion,
    #[error(
        "database role does not match the operation; use the matching runtime or maintenance configuration"
    )]
    Role,
    #[error(
        "database privileges differ from the required profile; ask the deployment owner to check grants"
    )]
    Privileges,
    #[error(
        "schema constraints or tenant policies differ from the required contract; ask the deployment owner to check the schema"
    )]
    SchemaContract,
}

impl From<PasswordError> for AuthorityError {
    fn from(e: PasswordError) -> Self {
        match e {
            PasswordError::Invalid => Self::InvalidInput,
            PasswordError::Busy => Self::Busy,
            PasswordError::Unavailable => Self::Unavailable,
        }
    }
}

pub(crate) struct Budget(pub rss_request_context::Deadline);
impl Budget {
    pub fn new(deadline: OperationDeadline) -> Result<Self, AuthorityError> {
        if deadline.timeout().is_zero() {
            return Err(AuthorityError::DeadlineElapsed);
        }
        Instant::now()
            .checked_add(deadline.timeout())
            .map(|at| Self(rss_request_context::Deadline::at(at)))
            .ok_or(AuthorityError::InvalidInput)
    }
    pub fn remaining(&self) -> OperationDeadline {
        OperationDeadline::from_remaining(self.0.remaining(Instant::now()).unwrap_or_default())
    }
    pub async fn password<T>(
        &self,
        future: impl std::future::Future<Output = Result<T, PasswordError>>,
    ) -> Result<T, AuthorityError> {
        tokio::time::timeout_at(self.0.instant().into(), future)
            .await
            .map_err(|_| AuthorityError::DeadlineElapsed)?
            .map_err(Into::into)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StorageFailure {
    #[error("temporarily unavailable")]
    Transient,
    #[error("invalid operation")]
    Permanent,
    #[error("conflicting state")]
    Conflict,
    #[error("ownership lost")]
    OwnershipLost,
    #[error("invalid stored state")]
    Invariant,
    #[error("deadline elapsed")]
    DeadlineElapsed,
}
impl From<rss_transactional_messaging::error::MessagingErrorKind> for StorageFailure {
    fn from(k: rss_transactional_messaging::error::MessagingErrorKind) -> Self {
        use rss_transactional_messaging::error::MessagingErrorKind as K;
        match k {
            K::Transient => Self::Transient,
            K::Permanent => Self::Permanent,
            K::Conflict => Self::Conflict,
            K::OwnershipLost => Self::OwnershipLost,
            K::Invariant => Self::Invariant,
            K::DeadlineElapsed => Self::DeadlineElapsed,
        }
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    #[test]
    fn host_configuration_input_and_deadline_are_distinct() {
        let keys = crate::CredentialKeys::new("absent".into(), vec![])
            .err()
            .unwrap();
        assert_eq!(keys.to_string(), "invalid authority configuration");
        assert_eq!(
            AttemptSource::parse("").err().unwrap().to_string(),
            "invalid operation input"
        );
        assert_eq!(
            Budget::new(OperationDeadline::from_remaining(std::time::Duration::ZERO))
                .err()
                .unwrap()
                .to_string(),
            "operation deadline elapsed"
        );
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityProfile {
    Runtime,
    Maintenance,
    /// Account insertion and source-session inspection, without credential recovery.
    Provisioning,
}
