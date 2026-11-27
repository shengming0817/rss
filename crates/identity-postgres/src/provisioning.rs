//! Host-authorized account provisioning inside a caller-owned target transaction.
//! ref: sqlx sqlx-core/src/transaction.rs@v0.9.0 (borrowed transaction ownership).
use crate::{
    AuthenticatedSession, Authority, AuthorityConfig, AuthorityError, AuthorityProfile, Budget,
    ExecutionBinding, ManagementOperation, ManagementPolicy,
    storage::{account_state_locked, authority_id, insert_account},
    transaction::{self, MutationError, SecurityEvent},
};
use rss_identity_core::{
    PrincipalId,
    account::{AccountKey, AccountState, LoginKey, Password, PasswordEncoding, PasswordKdf},
};
use rss_request_context::TenantId;
use rss_transactional_messaging::policy::OperationDeadline;
use rss_transactional_messaging_postgres::{PgError, PgRuntime, PgTransaction};
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum ProvisioningError {
    #[error("account provisioning rejected")]
    Rejected,
    #[error(transparent)]
    Authority(#[from] AuthorityError),
    #[error(transparent)]
    Storage(#[from] PgError),
    #[error(transparent)]
    Rule(#[from] rss_identity_core::account::AccountRuleError),
}
impl From<sqlx::Error> for ProvisioningError {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(error.into())
    }
}
impl From<MutationError> for ProvisioningError {
    fn from(error: MutationError) -> Self {
        match error {
            MutationError::ProfileReceiptCapacityReached
            | MutationError::InvalidInput
            | MutationError::CursorInvalidated
            | MutationError::RevisionConflict => Self::Rejected,
            MutationError::OperationConflict => Self::Rejected,
            MutationError::Storage(e) => Self::Storage(e),
            MutationError::Rule(e) => Self::Rule(e),
            MutationError::Federation(_) => Self::Rejected,
        }
    }
}
/// Prepared secrets have no public representation, serialization or debug output.
pub struct PreparedLocalAccount {
    login: LoginKey,
    hash: PasswordEncoding,
}
/// Owns no pool lifecycle. This profile cannot authenticate, reset credentials or manage IdPs.
pub struct AccountProvisioner {
    authority: Authority,
    source: TenantId,
}
impl AccountProvisioner {
    pub async fn connect(
        runtime: Arc<PgRuntime>,
        kdf: Arc<PasswordKdf>,
        config: AuthorityConfig,
        probe: ExecutionBinding,
        source: TenantId,
        policy: Arc<dyn ManagementPolicy>,
        deadline: OperationDeadline,
    ) -> Result<Self, AuthorityError> {
        Ok(Self {
            authority: Authority::connect(
                runtime,
                kdf,
                config,
                probe,
                AuthorityProfile::Provisioning,
                policy,
                deadline,
            )
            .await?,
            source,
        })
    }
    pub async fn prepare_local_account(
        &self,
        login: LoginKey,
        password: Password,
        deadline: OperationDeadline,
    ) -> Result<PreparedLocalAccount, AuthorityError> {
        let budget = Budget::new(deadline)?;
        let hash = budget.password(self.authority.kdf.hash(password)).await?;
        Ok(PreparedLocalAccount { login, hash })
    }
    /// Revalidate before any host receipt replay. Holds the source guard until the target
    /// transaction ends; does not renew idle time or mint a target-tenant session.
    pub async fn authorize_in(
        &self,
        tx: &mut PgTransaction<'_>,
        actor: Arc<AuthenticatedSession>,
    ) -> Result<(), ProvisioningError> {
        let bundle = self.authority.runtime.clone();
        bundle.runtime.validate_transaction(tx)?;
        if !matches!(&bundle.audit, rss_audit_postgres::Integrity::Plain) {
            rss_audit_postgres::lock_head_in(tx, &bundle.audit)
                .await
                .map_err(PgError::from)?;
        }
        let target = tx.tenant_id();
        if actor.key.tenant != self.source
            || target == self.source
            || actor.authority != self.authority.instance.as_uuid()
        {
            return Err(ProvisioningError::Rejected);
        }
        let source = actor.binding;
        let instance = self.authority.instance;
        let policy = self.authority.policy.clone();
        tx.with_tenant_connection(source, move |c| {
            Box::pin(async move {
                Ok(async {
                    if authority_id(c).await? != instance.as_uuid() {
                        return Err(ProvisioningError::Rejected);
                    }
                    let loaded = crate::session_storage::recheck_collection(c, &actor).await?;
                    crate::management::authorize(
                        policy.as_ref(),
                        instance,
                        &loaded,
                        ManagementOperation::ProvisionAccount(target),
                        None,
                        c,
                    )
                    .await?;
                    Ok::<_, ProvisioningError>(())
                }
                .await)
            })
        })
        .await?
    }
    /// Append account and security event without committing. The host must propagate every
    /// failure and roll back; its authorization, product audit and receipt share this transaction.
    pub async fn create_local_account_in(
        &self,
        tx: &mut PgTransaction<'_>,
        actor: Arc<AuthenticatedSession>,
        prepared: PreparedLocalAccount,
    ) -> Result<AccountState, ProvisioningError> {
        self.authorize_in(tx, actor.clone()).await?;
        let target = tx.tenant_id();
        let key = AccountKey {
            tenant: target,
            principal: PrincipalId::generate(),
        };
        let state = transaction::connection(tx, move |c| Box::pin(async move {
            sqlx::query("INSERT INTO identity_authority.tenants(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING")
                .bind(target.to_string()).execute(&mut *c).await?;
            crate::storage::lock_tenant_collection(c, target).await?;
            insert_account(c, key, prepared.login.as_str(), prepared.hash.as_str()).await?;
            Ok::<_, ProvisioningError>(account_state_locked(c, key).await?)
        })).await?;
        let bundle = self.authority.runtime.clone();
        crate::audit::append_events(
            tx,
            &bundle.audit,
            &bundle.audit_budget,
            self.authority.instance,
            target,
            vec![SecurityEvent::provisioned(
                state,
                actor.key,
                self.authority.instance,
            )],
        )
        .await?;
        Ok(state)
    }
}
