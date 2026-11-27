//! Controlled maintenance without transferable authorization tickets.
//! ref: kanidm server/core/src/actors/internal.rs@c6ca0f2a79a57267060f95f0ceeafdb4dd6f5696.
use crate::{
    storage::*,
    transaction::{SecurityEvent, reject},
    *,
};
use rss_identity_core::account::{LoginKey, Password, SecurityAction};
use rss_transactional_messaging::policy::OperationDeadline;

impl Authority {
    /// Initialize an admitted tenant once using its independently held maintenance identity.
    pub async fn initialize(
        &self,
        binding: ExecutionBinding,
        key: AccountKey,
        login: LoginKey,
        password: Password,
        deadline: OperationDeadline,
    ) -> Result<AccountState, AuthorityError> {
        self.require_maintenance()?;
        if binding.tenant() != key.tenant {
            return Err(AuthorityError::Rejected);
        }
        let budget = Budget::new(deadline)?;
        let hash = budget.password(self.kdf.hash(password)).await?;
        self.mutate(binding, budget.remaining(), move |tx| {
            Box::pin(async move {
                crate::transaction::connection(tx, move |c| {
                    Box::pin(async move {
                        let inserted = sqlx::query("INSERT INTO identity_authority.tenants(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING")
                            .bind(key.tenant.to_string()).execute(&mut *c).await?.rows_affected();
                        if inserted != 1 { return Err(reject().into()); }
                        insert_account(c, key, login.as_str(), hash.as_str()).await?;
                        let state = account_state_locked(c, key).await?;
                        Ok((state, SecurityEvent::account(SecurityAction::AccountCreated, state, None)))
                    })
                })
                .await
            })
        })
        .await
    }

    /// Replace only an existing local account's password, retaining all access states.
    /// Concurrent maintenance writes serialize; the last committed password wins.
    pub async fn recover_local_password(
        &self,
        binding: ExecutionBinding,
        key: AccountKey,
        password: Password,
        deadline: OperationDeadline,
    ) -> Result<AccountState, AuthorityError> {
        self.require_maintenance()?;
        if binding.tenant() != key.tenant {
            return Err(AuthorityError::Rejected);
        }
        let budget = Budget::new(deadline)?;
        let hash = budget.password(self.kdf.hash(password)).await?;
        self.mutate(binding, budget.remaining(), move |tx| {
            Box::pin(async move {
                crate::transaction::connection(tx, move |c| {
                    Box::pin(async move {
                        lock_tenant_scope(c, key.tenant).await?;
                        lock_account(c,key,true).await?;
                        lock_attempt_capacity(c,key.tenant).await?;
                        let old = account_state_locked(c, key).await?;
                        let (next, action) = old.recover()?;
                        sqlx::query(
                            "UPDATE identity_authority.accounts SET auth_epoch=$3
                             WHERE tenant_id=$1::uuid AND principal_id=$2::uuid",
                        )
                        .bind(key.tenant.to_string())
                        .bind(key.principal.as_uuid().to_string())
                        .bind(next.epoch())
                        .execute(&mut *c)
                        .await?;
                        sqlx::query(concat!("UPDATE identity_authority.local_credentials SET password_hash=$3 WHERE tenant_id","=$1::uuid AND principal_id=$2::uuid")).bind(key.tenant.to_string()).bind(key.principal.as_uuid().to_string()).bind(hash.as_str()).execute(&mut *c).await?;
                        crate::password_attempts::clear(c, key).await?;
                        Ok((next, SecurityEvent::account(action, next, None)))
                    })
                })
                .await
            })
        })
        .await
    }
}
