//! One private settlement path. ref: RSS transaction.rs @ bf5dd1350997d01aa834094a3347fce30247814e.
use crate::{AccountKey, Authority, AuthorityError};
use futures::future::BoxFuture;

use rss_request_context::Deadline;
use rss_transactional_messaging::error::{MessagingError, MessagingErrorKind};
use rss_transactional_messaging::fence::ExecutionBinding;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use serde::Serialize;
use uuid::Uuid;

use rss_identity_core::account::{AccountRuleError, AccountState, SecurityAction};
#[derive(Serialize)]
pub(crate) struct AccountEvent {
    pub action: &'static str,
    pub tenant: String,
    pub principal: Uuid,
    pub actor: Option<Uuid>,
    pub epoch: i64,
    pub state: EventState,
}
#[derive(Serialize)]
pub(crate) struct EventState {
    pub(crate) enabled: bool,
    pub(crate) member_active: bool,
    pub(crate) membership_epoch: i64,
}
impl AccountEvent {
    pub fn account(action: SecurityAction, state: AccountState, actor: Option<AccountKey>) -> Self {
        Self {
            action: action.as_str(),
            tenant: state.key().tenant.to_string(),
            principal: state.key().principal.as_uuid(),
            actor: actor.map(|a| a.principal.as_uuid()),
            epoch: state.epoch(),
            state: EventState {
                enabled: state.enabled(),
                member_active: state.member_active(),
                membership_epoch: state.membership_epoch(),
            },
        }
    }
}
#[derive(Serialize)]
pub(crate) struct ProvisioningEvent {
    #[serde(flatten)]
    pub(crate) account: AccountEvent,
    pub(crate) actor_tenant: String,
    pub(crate) actor_instance: String,
}
/// Closed set of event contracts using the same settlement path.
#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum SecurityEvent {
    Authentication(crate::step_up::AuthenticationEvent),
    Profile(crate::profiles::ProfileEvent),
    Account(AccountEvent),
    Provisioned(ProvisioningEvent),
    Session(crate::sessions::SessionEvent),
    Federation(crate::federation::FederationEvent),
}
impl SecurityEvent {
    pub(crate) fn provisioned(
        state: AccountState,
        actor: AccountKey,
        instance: rss_identity_core::InstanceId,
    ) -> Self {
        Self::Provisioned(ProvisioningEvent {
            account: AccountEvent::account(SecurityAction::AccountCreated, state, Some(actor)),
            actor_tenant: actor.tenant.to_string(),
            actor_instance: instance.to_string(),
        })
    }

    pub fn account(action: SecurityAction, state: AccountState, actor: Option<AccountKey>) -> Self {
        Self::Account(AccountEvent::account(action, state, actor))
    }
    pub(crate) fn tenant(&self) -> &str {
        match self {
            Self::Authentication(v) => &v.tenant,
            Self::Profile(v) => &v.tenant,
            Self::Account(v) => &v.tenant,
            Self::Provisioned(v) => &v.account.tenant,
            Self::Session(v) => &v.tenant,
            Self::Federation(v) => &v.tenant,
        }
    }
}
#[derive(Debug, thiserror::Error)]
pub(crate) enum MutationError {
    #[error("invalid account query")]
    InvalidInput,
    #[error("account cursor invalidated")]
    CursorInvalidated,
    #[error(transparent)]
    Storage(#[from] PgError),
    #[error(transparent)]
    Rule(#[from] AccountRuleError),
    #[error("profile receipt capacity reached")]
    ProfileReceiptCapacityReached,
    #[error("profile revision conflict")]
    RevisionConflict,
    #[error("profile operation conflict")]
    OperationConflict,
    #[error(transparent)]
    Federation(#[from] rss_identity_core::federation::FederationError),
}
impl From<sqlx::Error> for MutationError {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(error.into())
    }
}
pub(crate) const MAX_MUTATION_EVENTS: usize = 8;
pub(crate) fn reject() -> PgError {
    MessagingError::new(
        MessagingErrorKind::Conflict,
        std::io::Error::other("account operation rejected"),
    )
    .into()
}
pub(crate) fn corrupt() -> PgError {
    MessagingError::new(
        MessagingErrorKind::Invariant,
        std::io::Error::other("invalid authority state"),
    )
    .into()
}

impl Authority {
    pub(crate) async fn read<T: Send, F>(
        &self,
        binding: ExecutionBinding,
        deadline: Deadline,
        operation: F,
    ) -> Result<T, AuthorityError>
    where
        F: for<'a> FnOnce(&'a mut PgTransaction<'_>) -> BoxFuture<'a, Result<T, PgError>>
            + Send
            + 'static,
    {
        let bundle = self.runtime.clone();
        Self::read_bundle(bundle, binding, deadline, true, operation).await
    }
    pub(crate) async fn read_bundle<T: Send, F>(
        bundle: std::sync::Arc<crate::runtime::RuntimeBundle>,
        binding: ExecutionBinding,
        deadline: Deadline,
        verify_instance: bool,
        operation: F,
    ) -> Result<T, AuthorityError>
    where
        F: for<'a> FnOnce(&'a mut PgTransaction<'_>) -> BoxFuture<'a, Result<T, PgError>>
            + Send
            + 'static,
    {
        let instance = bundle.instance;
        if deadline.is_expired(rss_request_context::Clock::now(
            bundle.runtime.execution_timer(),
        )) {
            return Err(AuthorityError::NotStarted(
                crate::StorageFailure::DeadlineElapsed,
            ));
        }
        bundle
            .runtime
            .local_tx_until(binding, deadline, move |tx| {
                Box::pin(async move {
                    if verify_instance {
                        let actual =
                            connection(tx, move |c| Box::pin(crate::storage::authority_id(c)))
                                .await?;
                        if actual != instance.as_uuid() {
                            return Err(reject());
                        }
                    }
                    operation(tx).await
                })
            })
            .await
            .fold(
                Ok,
                |e| Err(AuthorityError::NotStarted(e.kind().into())),
                |e| {
                    Err(if e.kind() == MessagingErrorKind::Conflict {
                        AuthorityError::Rejected
                    } else {
                        AuthorityError::RolledBack(e.kind().into())
                    })
                },
                |e| Err(AuthorityError::RollbackFailed(e.kind().into())),
                |e| Err(AuthorityError::CommitUnknown(e.kind().into())),
                |_| Err(AuthorityError::Fenced),
            )
    }
    pub(crate) async fn read_sql<T: Send + 'static, F>(
        &self,
        binding: ExecutionBinding,
        deadline: Deadline,
        work: F,
    ) -> Result<T, AuthorityError>
    where
        F: for<'a> FnOnce(&'a mut sqlx::PgConnection) -> BoxFuture<'a, Result<T, MutationError>>
            + Send
            + 'static,
    {
        let reason = std::sync::Arc::new(std::sync::OnceLock::new());
        let slot = reason.clone();
        let result = self
            .read(binding, deadline, move |tx| {
                Box::pin(async move {
                    connection(tx, work)
                        .await
                        .map_err(|e| sql_failure(e, &slot))
                })
            })
            .await;
        domain_result(result, reason.get().copied())
    }
    pub(crate) async fn write_sql<T: Send + 'static, F>(
        &self,
        binding: ExecutionBinding,
        deadline: Deadline,
        work: F,
    ) -> Result<T, AuthorityError>
    where
        F: for<'a> FnOnce(
                &'a mut sqlx::PgConnection,
            )
                -> BoxFuture<'a, Result<(T, Vec<SecurityEvent>), MutationError>>
            + Send
            + 'static,
    {
        self.mutate_events(binding, deadline, move |tx| {
            Box::pin(async move { connection(tx, work).await })
        })
        .await
    }
    pub(crate) async fn mutate<T: Send, F>(
        &self,
        binding: ExecutionBinding,
        deadline: Deadline,
        operation: F,
    ) -> Result<T, AuthorityError>
    where
        F: for<'a> FnOnce(
                &'a mut PgTransaction<'_>,
            ) -> BoxFuture<'a, Result<(T, SecurityEvent), MutationError>>
            + Send
            + 'static,
    {
        self.mutate_events(binding, deadline, move |tx| {
            Box::pin(async move {
                let (value, event) = operation(tx).await?;
                Ok((value, vec![event]))
            })
        })
        .await
    }
    pub(crate) async fn mutate_events<T: Send, F>(
        &self,
        binding: ExecutionBinding,
        deadline: Deadline,
        operation: F,
    ) -> Result<T, AuthorityError>
    where
        F: for<'a> FnOnce(
                &'a mut PgTransaction<'_>,
            )
                -> BoxFuture<'a, Result<(T, Vec<SecurityEvent>), MutationError>>
            + Send
            + 'static,
    {
        self.settle_events(binding, deadline, operation, true).await
    }
    /// Conditional domain transition: empty events are permitted only for unchanged business state.
    pub(crate) async fn conditional_write_sql<T: Send + 'static, F>(
        &self,
        binding: ExecutionBinding,
        deadline: Deadline,
        work: F,
    ) -> Result<T, AuthorityError>
    where
        F: for<'a> FnOnce(
                &'a mut sqlx::PgConnection,
            )
                -> BoxFuture<'a, Result<(T, Vec<SecurityEvent>), MutationError>>
            + Send
            + 'static,
    {
        self.settle_events(
            binding,
            deadline,
            move |tx| Box::pin(async move { connection(tx, work).await }),
            false,
        )
        .await
    }
    async fn settle_events<T: Send, F>(
        &self,
        binding: ExecutionBinding,
        deadline: Deadline,
        operation: F,
        require_event: bool,
    ) -> Result<T, AuthorityError>
    where
        F: for<'a> FnOnce(
                &'a mut PgTransaction<'_>,
            )
                -> BoxFuture<'a, Result<(T, Vec<SecurityEvent>), MutationError>>
            + Send
            + 'static,
    {
        let bundle = self.runtime.clone();
        let audit = bundle.audit.clone();
        let audit_budget = bundle.audit_budget.clone();
        let instance = bundle.instance;
        let reason = std::sync::Arc::new(std::sync::OnceLock::new());
        let reason_slot = reason.clone();
        let result = Self::read_bundle(bundle, binding, deadline, true, move |tx| {
            Box::pin(async move {
                if !matches!(&audit, rss_audit_postgres::Integrity::Plain) {
                    rss_audit_postgres::lock_head_in(tx, &audit)
                        .await
                        .map_err(PgError::from)?;
                }
                let (result, events) = operation(tx)
                    .await
                    .map_err(|e| sql_failure(e, &reason_slot))?;
                if (require_event && events.is_empty()) || events.len() > MAX_MUTATION_EVENTS {
                    return Err(corrupt());
                }
                crate::audit::append_events(
                    tx,
                    &audit,
                    &audit_budget,
                    instance,
                    binding.tenant(),
                    events,
                )
                .await?;
                Ok(result)
            })
        })
        .await;
        domain_result(result, reason.get().copied())
    }
}

/// Compare the existing transaction context with the proof's original execution coordinates.
/// This never replaces the context or discovers a newer epoch.
pub(crate) async fn check_binding(
    c: &mut sqlx::PgConnection,
    binding: ExecutionBinding,
) -> Result<(), PgError> {
    let matches: Option<bool> = sqlx::query_scalar("SELECT current_setting('rss.tenant_id',true)=$1 AND decode(NULLIF(current_setting('rss.storage_target',true),''),'hex')=$2 AND decode(NULLIF(current_setting('rss.storage_lineage',true),''),'hex')=$3 AND NULLIF(current_setting('rss.execution_epoch',true),'')::bigint=$4")
        .bind(binding.tenant().to_string())
        .bind(binding.storage().target().as_slice())
        .bind(binding.storage().lineage().as_slice())
        .bind(binding.epoch().get())
        .fetch_one(c).await?;
    if matches != Some(true) {
        return Err(reject());
    }
    Ok(())
}

// Carry domain rejection through SQLx's connection callback, then abort the outer transaction.
pub(crate) async fn connection<T: Send + 'static, E: Send + From<PgError> + 'static, F>(
    tx: &mut PgTransaction<'_>,
    work: F,
) -> Result<T, E>
where
    F: for<'a> FnOnce(&'a mut sqlx::PgConnection) -> BoxFuture<'a, Result<T, E>> + Send,
{
    tx.with_connection(move |c| {
        let future = work(c);
        Box::pin(async move { Ok(future.await) })
    })
    .await
    .map_err(E::from)?
}

fn sql_failure(error: MutationError, reason: &std::sync::OnceLock<AuthorityError>) -> PgError {
    match error {
        MutationError::InvalidInput => {
            let _ = reason.set(AuthorityError::InvalidInput);
            reject()
        }
        MutationError::CursorInvalidated => {
            let _ = reason.set(AuthorityError::CursorInvalidated);
            reject()
        }
        MutationError::ProfileReceiptCapacityReached => {
            let _ = reason.set(AuthorityError::ProfileReceiptCapacityReached);
            reject()
        }
        MutationError::RevisionConflict => {
            let _ = reason.set(AuthorityError::RevisionConflict);
            reject()
        }
        MutationError::OperationConflict => {
            let _ = reason.set(AuthorityError::OperationConflict);
            reject()
        }
        MutationError::Storage(e) => e,
        MutationError::Rule(e) => {
            let _ = reason.set(AuthorityError::RuleRejected(e));
            reject()
        }
        MutationError::Federation(e) => {
            let _ = reason.set(AuthorityError::Federation(e));
            reject()
        }
    }
}
fn domain_result<T>(
    result: Result<T, AuthorityError>,
    reason: Option<AuthorityError>,
) -> Result<T, AuthorityError> {
    match (result, reason) {
        (Err(AuthorityError::Rejected), Some(reason)) => Err(reason),
        (result, _) => result,
    }
}

#[cfg(test)]
mod settlement_tests {
    use super::*;

    #[test]
    fn domain_rejection_preserves_reason_only_after_confirmed_rollback() {
        let reason = AuthorityError::RuleRejected(AccountRuleError::Rejected);
        assert_eq!(
            domain_result::<()>(Err(AuthorityError::Rejected), Some(reason)),
            Err(reason)
        );
        for failure in [
            AuthorityError::RollbackFailed(crate::StorageFailure::DeadlineElapsed),
            AuthorityError::CommitUnknown(crate::StorageFailure::DeadlineElapsed),
            AuthorityError::Fenced,
        ] {
            assert_eq!(
                domain_result::<()>(Err(failure), Some(reason)),
                Err(failure)
            );
        }
    }
}
